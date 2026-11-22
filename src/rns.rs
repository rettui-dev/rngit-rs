//! [`Transport`] over a live Reticulum link, using rsReticulum.

use std::time::Duration;

use rns_identity::identity::Identity;
use rns_runtime::prelude::*;
use tokio::sync::Mutex;

use crate::error::Error;
use crate::sign::Signer;
use crate::transport::{Response, Transport};

/// Talks to one rngit node: the `git.repositories` destination at `destination`.
///
/// The link is opened on first use, identified with `identity`, and reopened
/// when it has dropped. Only one request runs at a time.
pub struct RnsTransport {
    runtime: ReticulumHandle,
    identity: Identity,
    destination: [u8; 16],
    request_timeout: Duration,
    session: Mutex<Option<LinkSession>>,
}

impl RnsTransport {
    /// `identity` is the long-lived client identity the node authorizes.
    pub fn new(runtime: ReticulumHandle, identity: Identity, destination: [u8; 16]) -> Self {
        RnsTransport { runtime, identity, destination, request_timeout: Duration::from_secs(120), session: Mutex::new(None) }
    }

    /// How long one request may take, including a bulk transfer.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    async fn connect(&self) -> Result<LinkSession, Error> {
        let options = LinkConnectOptions { identify: true, client_label: "rngit".to_string(), ..LinkConnectOptions::default() };
        self.runtime
            .connect_link(self.destination, self.identity.clone(), options)
            .await
            .map_err(|e| Error::Transport(format!("could not open a link: {e}")))
    }

    /// Close the link. The next request opens a new one.
    pub async fn disconnect(&self) {
        if let Some(session) = self.session.lock().await.take() {
            session.handle.close().await;
        }
    }
}

/// The most a file reply is read back into memory: what a Resource may hold.
/// [`crate::client::Limits`] defaults to the same, so its caps can be reached.
const MAX_FILE_REPLY: u64 = crate::client::MAX_RESOURCE_BYTES as u64;

/// Sort a link response into a plain reply or a bulk file. rsReticulum hands a
/// plain reply back already unwrapped (status byte then payload); only a
/// Resource reply carries metadata, and that is how a file is told apart.
/// rsReticulum 1.5 saves a file reply to a file of its own: it is read back
/// and removed here.
pub(crate) async fn classify(response: LinkSessionResponse) -> Result<Response, Error> {
    let LinkSessionResponse { data, metadata, file, .. } = response;
    let data = match file {
        None => data,
        Some(path) => tokio::task::spawn_blocking(move || {
            let read = read_capped(&path, MAX_FILE_REPLY);
            let _ = std::fs::remove_file(&path);
            read
        })
        .await
        .map_err(|e| Error::Transport(format!("reading the reply stopped: {e}")))?
        .map_err(|e| Error::Transport(format!("could not read the reply: {e}")))?,
    };
    Ok(match metadata {
        None => Response::Packet(data),
        metadata => Response::File { data, metadata },
    })
}

fn read_capped(path: &std::path::Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut data = Vec::new();
    file.take(max + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(std::io::Error::other("the reply is larger than a Resource may be"));
    }
    Ok(data)
}

impl Transport for RnsTransport {
    async fn request(&self, path: &str, data: Vec<u8>) -> Result<Response, Error> {
        let mut guard = self.session.lock().await;
        let repeatable = safe_to_repeat(path, &request_value(&data));
        for attempt in 0..2 {
            if guard.is_none() {
                *guard = Some(self.connect().await?);
            }
            let session = guard.as_ref().ok_or_else(|| Error::Transport("no link".into()))?;
            let options = RequestOptions { timeout: Some(self.request_timeout), ..RequestOptions::default() };
            match session.handle.request_with_options(path, request_value(&data), options).await {
                Ok(response) => return classify(response).await,
                // A dead link is worth one fresh try, but only for a request
                // that does no harm if the node got it the first time: the
                // link can drop after the request went out, and a second
                // comment, document or release must not be made.
                Err(LinkSessionError::SessionClosed | LinkSessionError::LinkNotActive) if attempt == 0 && repeatable => {
                    *guard = None;
                }
                Err(e @ (LinkSessionError::SessionClosed | LinkSessionError::LinkNotActive)) => {
                    *guard = None;
                    return Err(Error::Transport(format!("{e}; the node may or may not have got the request")));
                }
                Err(e) => return Err(Error::Transport(e.to_string())),
            }
        }
        Err(Error::Transport("link kept dropping".into()))
    }
}

/// Whether a request only reads, so sending it twice changes nothing on the
/// node: ref lists, fetches, and the list, view, fetch and permission reads.
fn safe_to_repeat(path: &str, request: &rmpv::Value) -> bool {
    let map = crate::wire::MapRef::new(request).ok();
    let field = |key: &str| map.as_ref().and_then(|m| m.str(key));
    let (operation, step) = (field("operation"), field("step"));
    match path {
        "/git/list" | "/git/fetch" => true,
        "/mgmt/release" => matches!(operation.as_deref(), Some("list" | "view" | "fetch")),
        "/mgmt/work" => match operation.as_deref() {
            Some("list" | "view") => true,
            Some("perms") => step.as_deref() == Some("get"),
            _ => false,
        },
        "/mgmt/perms" => step.as_deref() == Some("get"),
        _ => false,
    }
}

/// The request as the value stock rngit reads: the map itself, not a byte
/// string holding it (Python nodes answer "Invalid request" to that).
fn request_value(data: &[u8]) -> rmpv::Value {
    let mut rest = data;
    match rmpv::decode::read_value(&mut rest) {
        Ok(value) if rest.is_empty() => value,
        _ => rmpv::Value::Binary(data.to_vec()),
    }
}

/// Lets a Reticulum [`Identity`] sign releases and work documents.
pub struct IdentitySigner<'a>(pub &'a Identity);

impl Signer for IdentitySigner<'_> {
    fn identity_hash(&self) -> [u8; 16] {
        self.0.hash
    }

    fn public_key(&self) -> [u8; 64] {
        self.0.get_public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        self.0.sign(message).ok_or_else(|| Error::InvalidInput("identity has no private key".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(data: Vec<u8>, metadata: Option<Vec<u8>>) -> LinkSessionResponse {
        LinkSessionResponse {
            request_id: [0; 16],
            data,
            value: rmpv::Value::Nil,
            metadata,
            file: None,
            response_time: Duration::ZERO,
            response_size: None,
            response_transfer_size: None,
            started_at: None,
            response_concluded_at: None,
        }
    }

    #[tokio::test]
    async fn reply_without_metadata_is_a_packet() {
        assert_eq!(classify(response(b"\x00ok".to_vec(), None)).await.unwrap(), Response::Packet(b"\x00ok".to_vec()));
    }

    #[tokio::test]
    async fn resource_reply_is_a_file() {
        let bundle = b"# v2 git bundle\n".to_vec();
        assert_eq!(
            classify(response(bundle.clone(), Some(vec![0x81, 0x01, 0x00]))).await.unwrap(),
            Response::File { data: bundle.clone(), metadata: Some(vec![0x81, 0x01, 0x00]) }
        );
    }

    #[tokio::test]
    async fn a_reply_saved_to_a_file_is_read_back_and_the_file_removed() {
        let path = std::env::temp_dir().join(format!("rngit-reply-{}", std::process::id()));
        std::fs::write(&path, b"bundle bytes").unwrap();
        let mut saved = response(Vec::new(), Some(vec![0x81, 0x01, 0x00]));
        saved.file = Some(path.clone());
        assert_eq!(
            classify(saved).await.unwrap(),
            Response::File { data: b"bundle bytes".to_vec(), metadata: Some(vec![0x81, 0x01, 0x00]) }
        );
        assert!(!path.exists());
    }

    #[test]
    fn a_request_goes_as_the_map_not_as_bytes_holding_it() {
        let data = crate::wire::Request::group("public").put("for_push", false).encode();
        let rmpv::Value::Map(map) = request_value(&data) else { panic!("not a map") };
        assert_eq!(map.len(), 2);
        // Bytes that aren't MessagePack stay bytes.
        assert_eq!(request_value(&[0x92, 0x01]), rmpv::Value::Binary(vec![0x92, 0x01]));
    }

    #[test]
    fn only_requests_that_read_are_sent_again_after_a_drop() {
        use crate::wire::Request;
        let value = |request: Request| request_value(&request.encode());
        let repo = || Request::repo("public/demo.git");
        for (path, request) in [
            ("/git/list", repo().put("for_push", true)),
            ("/git/fetch", repo()),
            ("/mgmt/release", repo().put("operation", "list")),
            ("/mgmt/release", repo().put("operation", "view")),
            ("/mgmt/release", repo().put("operation", "fetch")),
            ("/mgmt/work", repo().put("operation", "view")),
            ("/mgmt/work", repo().put("operation", "perms").put("step", "get")),
            ("/mgmt/perms", repo().put("operation", "rperms").put("step", "get")),
        ] {
            assert!(safe_to_repeat(path, &value(request)), "{path}");
        }
        for (path, request) in [
            ("/git/push", repo()),
            ("/git/delete", repo()),
            ("/git/create", repo()),
            ("/git/fork", repo()),
            ("/git/sync", repo()),
            ("/mgmt/release", repo().put("operation", "create").put("step", "artifact")),
            ("/mgmt/release", repo().put("operation", "delete")),
            ("/mgmt/release", repo().put("operation", "latest")),
            ("/mgmt/release", repo()),
            ("/mgmt/work", repo().put("operation", "comment")),
            ("/mgmt/work", repo().put("operation", "create")),
            ("/mgmt/work", repo().put("operation", "perms").put("step", "set")),
            ("/mgmt/perms", repo().put("operation", "rperms").put("step", "set")),
            ("/unknown", repo()),
        ] {
            assert!(!safe_to_repeat(path, &value(request)), "{path}");
        }
        assert!(!safe_to_repeat("/mgmt/work", &rmpv::Value::Binary(vec![1])));
    }

    #[test]
    fn identity_signer_signs_with_the_identity() {
        let identity = Identity::new();
        let signer = IdentitySigner(&identity);
        let sig = signer.sign(b"hello").unwrap();
        crate::sign::verify_signature(&signer.public_key(), b"hello", &sig).unwrap();
        assert_eq!(crate::sign::identity_hash(&signer.public_key()), signer.identity_hash());
    }
}
