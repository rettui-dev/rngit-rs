//! What a node that lies can and can't do to a client.

mod common;

use common::*;
use rmpv::Value;
use rngit::bundle;
use rngit::client::{WorkScope, check_artifact_name};
use rngit::server::{Node, Rule};
use rngit::sign::{self, Signer};
use rngit::{Client, Error, RepoUrl, Response, Transport};

const ME: [u8; 16] = [7; 16];

fn url() -> RepoUrl {
    "rns://727ca184e3d7e83e0e35146940920442/public/demo".parse().unwrap()
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

struct Key(ed25519_dalek::SigningKey, [u8; 64]);

impl Key {
    fn new(seed: u8) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut public = [seed; 64];
        public[32..].copy_from_slice(key.verifying_key().as_bytes());
        Key(key, public)
    }
}

impl Signer for Key {
    fn identity_hash(&self) -> [u8; 16] {
        sign::identity_hash(&self.1)
    }
    fn public_key(&self) -> [u8; 64] {
        self.1
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes())
    }
}

/// A node that answers with whatever `answer` says, logging what it was asked.
struct Scripted<F> {
    answer: F,
    log: std::sync::Mutex<Vec<(String, Value)>>,
}

impl<F: Fn(&str, &Value) -> Response + Send + Sync> Scripted<F> {
    fn new(answer: F) -> Self {
        Scripted { answer, log: std::sync::Mutex::new(Vec::new()) }
    }

    fn asked(&self) -> Vec<(String, Value)> {
        self.log.lock().unwrap().clone()
    }
}

impl<F: Fn(&str, &Value) -> Response + Send + Sync> Transport for Scripted<F> {
    async fn request(&self, path: &str, data: Vec<u8>) -> Result<Response, Error> {
        let request = rmpv::decode::read_value(&mut data.as_slice()).unwrap();
        self.log.lock().unwrap().push((path.to_string(), request.clone()));
        Ok((self.answer)(path, &request))
    }
}

fn file(data: Vec<u8>) -> Response {
    Response::File { data, metadata: Some(vec![0x81, 0x01, 0x00]) }
}

// --- artifact names ------------------------------------------------------

#[test]
fn names_that_escape_a_folder_or_open_a_device_are_refused() {
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "C:x",
        "C:",
        "c:\\windows",
        "a:b",
        "a<b",
        "a>b",
        "a\"b",
        "a|b",
        "a?b",
        "a*b",
        "nul\0",
        "bell\x07",
        "new\nline",
        "dot.",
        "space ",
        "CON",
        "con",
        "Con.txt",
        "aux.tar.gz",
        "NUL",
        "prn.",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt9.txt",
        "COM¹",
        "CON .txt",
    ] {
        assert!(check_artifact_name(bad).is_err(), "{bad:?}");
    }
    assert!(check_artifact_name(&"a".repeat(256)).is_err());
    for good in ["app.tar.gz", "COM10", "LPT0.txt", "console.log", "auxiliary", "nul-device", ".hidden", "a b.txt", "v1.0", "ünïcode"] {
        assert!(check_artifact_name(good).is_ok(), "{good:?}");
    }
}

#[tokio::test]
async fn an_unsafe_artifact_name_is_never_asked_for() {
    let node = Scripted::new(|_, _| file(b"x".to_vec()));
    let client = Client::new(node);
    for bad in ["C:evil", "..", "CON"] {
        assert!(matches!(client.fetch_artifact(&url(), "v1", bad).await, Err(Error::InvalidInput(_))));
    }
    assert!(client.transport().asked().is_empty());
}

// --- releases ------------------------------------------------------------

struct Release {
    rsm: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
}

fn release(key: &Key, version: &str, origin: [u8; 16], path: &str, names: &[&str]) -> Release {
    let files: Vec<(String, Vec<u8>)> = names.iter().map(|n| (n.to_string(), format!("contents of {n}").into_bytes())).collect();
    let artifacts: Vec<(String, Vec<u8>)> = files.iter().map(|(n, d)| (n.clone(), sign::make_rsg(key, d, 10).unwrap())).collect();
    let input = sign::ManifestInput {
        name: "demo.git",
        version,
        released: "2026-01-01T00:00:00Z",
        origin,
        path,
        commit: "",
        message: b"notes",
        artifacts: &artifacts,
    };
    Release { rsm: sign::make_rsm(key, &input, 10).unwrap(), files }
}

fn serving(release: Release) -> Client<Scripted<impl Fn(&str, &Value) -> Response + Send + Sync>> {
    Client::new(Scripted::new(move |_, request| {
        let name = field(request, "artifact").and_then(Value::as_str).unwrap_or_default();
        if name == "manifest.rsm" {
            return file(release.rsm.clone());
        }
        match release.files.iter().find(|(n, _)| n == name) {
            Some((_, data)) => file(data.clone()),
            None => status(3, "Release not found"),
        }
    }))
}

#[tokio::test]
async fn a_manifest_for_another_tag_repository_or_node_is_refused() {
    let key = Key::new(5);
    let here = url().destination;
    // An older release handed out for the one asked for.
    let old = serving(release(&key, "v1", here, "public/demo.git", &["app.bin"]));
    assert!(matches!(old.fetch_verified_release(&url(), "v2").await, Err(Error::Verify(m)) if m.contains("\"v1\"")));
    assert_eq!(old.transport().asked().len(), 1, "nothing past the manifest is fetched");
    // Asked for the latest, any version will do.
    let (manifest, files) = old.fetch_verified_release(&url(), "latest").await.unwrap();
    assert_eq!((manifest.version.as_str(), files.len()), ("v1", 1));
    old.fetch_verified_release(&url(), "v1").await.unwrap();

    let elsewhere = serving(release(&key, "v1", here, "public/other.git", &["app.bin"]));
    assert!(matches!(elsewhere.fetch_verified_release(&url(), "v1").await, Err(Error::Verify(_))));
    assert!(matches!(elsewhere.fetch_verified_release(&url(), "latest").await, Err(Error::Verify(_))));
    let other_node = serving(release(&key, "v1", [9; 16], "public/demo.git", &["app.bin"]));
    assert!(matches!(other_node.fetch_verified_release(&url(), "v1").await, Err(Error::Verify(_))));
}

#[tokio::test]
async fn a_release_signed_by_anyone_but_the_expected_identity_is_refused() {
    let (author, stranger) = (Key::new(5), Key::new(6));
    let client = serving(release(&stranger, "v1", url().destination, "public/demo.git", &["app.bin"]));
    // The signature itself is fine: it is just not the author's.
    let (manifest, _) = client.fetch_verified_release(&url(), "v1").await.unwrap();
    assert_eq!(manifest.signer.signer, stranger.identity_hash());
    let refused = client.fetch_release_signed_by(&url(), "v1", &author.identity_hash()).await.unwrap_err();
    assert!(matches!(&refused, Error::Verify(m) if m.contains(&hex::encode(stranger.identity_hash()))), "{refused}");
    let asked = client.transport().asked().len();
    client.fetch_release_signed_by(&url(), "v1", &stranger.identity_hash()).await.unwrap();
    assert_eq!(client.transport().asked().len(), asked + 2, "the manifest and its one file");
}

#[tokio::test]
async fn a_manifest_listing_an_unsafe_or_repeated_name_is_refused() {
    let key = Key::new(5);
    for names in [&["C:x"][..], &["CON"], &["a.bin", "a.bin"]] {
        let client = serving(release(&key, "v1", url().destination, "public/demo.git", names));
        assert!(matches!(client.fetch_verified_release(&url(), "v1").await, Err(Error::Verify(_))), "{names:?}");
        assert_eq!(client.transport().asked().len(), 1, "{names:?}");
    }
}

#[tokio::test]
async fn a_release_with_a_file_named_twice_is_refused_before_anything_is_sent() {
    let client = Client::new(Scripted::new(|_, _| ok(b"")));
    let files = vec![("a.bin".to_string(), vec![1]), ("a.bin".to_string(), vec![2])];
    let err = client.create_release(&url(), &Key::new(1), "v1", None, "", &files, "", 0).await.unwrap_err();
    assert!(matches!(err, Error::InvalidInput(m) if m.contains("twice")));
    assert!(client.transport().asked().is_empty());
}

async fn cli<T: Transport>(client: &Client<T>, args: &[&str], stdin: &[u8]) -> (Result<(), Error>, String) {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let mut out = Vec::new();
    let result = rngit::cli::run(client, &Key::new(1), 1_793_033_000, &args, &mut &stdin[..], &mut out).await;
    (result, String::from_utf8(out).unwrap())
}

#[tokio::test]
async fn release_get_says_who_signed_and_can_insist_on_one_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let (author, stranger) = (Key::new(5), Key::new(6));
    let client = serving(release(&author, "v1", url().destination, "public/demo.git", &["app.bin"]));
    let (dir, link) = (tmp.path().join("dl"), "rns://727ca184e3d7e83e0e35146940920442/public/demo");
    let dir_arg = dir.to_str().unwrap();
    let who = hex::encode(author.identity_hash());

    let (result, text) = cli(&client, &["release-get", link, "v1", "app.bin", dir_arg], b"").await;
    result.unwrap();
    assert!(text.contains(&format!("signed by {who}; check")), "{text}");
    assert_eq!(std::fs::read(dir.join("app.bin")).unwrap(), b"contents of app.bin");
    let (result, text) = cli(&client, &["release-get", link, "v1", "manifest.rsm", dir_arg, "--signer", &who], b"").await;
    result.unwrap();
    assert!(text.contains("the identity asked for"), "{text}");

    std::fs::remove_dir_all(&dir).unwrap();
    let other = hex::encode(stranger.identity_hash());
    for name in ["app.bin", "manifest.rsm"] {
        let (result, _) = cli(&client, &["release-get", link, "v1", name, dir_arg, "--signer", &other], b"").await;
        assert!(matches!(result, Err(Error::Verify(_))), "{name}");
    }
    // A downgrade is refused for the manifest too.
    let (result, _) = cli(&client, &["release-get", link, "v2", "manifest.rsm", dir_arg], b"").await;
    assert!(matches!(result, Err(Error::Verify(_))));
    assert!(!dir.exists() || std::fs::read_dir(&dir).unwrap().next().is_none(), "nothing saved");

    for args in [&["--signer", "nothex"][..], &["--signer"], &["--other", "x"]] {
        let mut full = vec!["release-get", link, "v1", "app.bin", dir_arg];
        full.extend_from_slice(args);
        assert!(matches!(cli(&client, &full, b"").await.0, Err(Error::InvalidInput(_))), "{args:?}");
    }
}

// --- work documents ------------------------------------------------------

fn showing(content: &str, meta: Vec<(&str, Value)>) -> Client<Scripted<impl Fn(&str, &Value) -> Response + Send + Sync>> {
    let reply = map(vec![("id", Value::from(1)), ("scope", Value::from("active")), ("content", Value::from(content)), ("meta", map(meta))]);
    let mut packed = vec![0u8];
    rmpv::encode::write_value(&mut packed, &reply).unwrap();
    Client::new(Scripted::new(move |_, _| Response::Packet(packed.clone())))
}

#[tokio::test]
async fn a_document_signed_with_someone_elses_key_is_not_verified() {
    let (victim, forger) = (Key::new(1), Key::new(2));
    let signed = |key: &Key| Value::Binary(key.sign(b"Pay me").unwrap().to_vec());
    let doc = |author: Value, key: &Key| {
        showing("Pay me", vec![("author", author), ("identity", Value::Binary(key.public_key().to_vec())), ("signature", signed(key))])
    };
    // The forger signs with their own key but names the victim as the author.
    for author in [Value::from(hex::encode(victim.identity_hash())), Value::Binary(victim.identity_hash().to_vec())] {
        let shown = doc(author, &forger).work_view(&url(), 1, WorkScope::All).await.unwrap();
        assert!(!shown.verified, "{shown:?}");
    }
    // The author as the node sends it (hex, either case) or as 16 bytes.
    for author in [
        Value::from(hex::encode(victim.identity_hash())),
        Value::from(hex::encode_upper(victim.identity_hash())),
        Value::Binary(victim.identity_hash().to_vec()),
    ] {
        assert!(doc(author, &victim).work_view(&url(), 1, WorkScope::All).await.unwrap().verified);
    }
    // No author, or one that isn't a hash, verifies nothing.
    for author in [Value::Nil, Value::from("ab"), Value::Binary(vec![1; 15]), Value::from(7)] {
        assert!(!doc(author, &victim).work_view(&url(), 1, WorkScope::All).await.unwrap().verified);
    }
}

// --- fetching ------------------------------------------------------------

/// A work repository with `main`, and a bundle of it that also names
/// `refs/stash` and a note.
fn bundle_with_extra_refs(tmp: &std::path::Path) -> (Vec<u8>, gix::ObjectId) {
    let work = tmp.join("work");
    work_repo(&work, 2);
    let main = git(&work, &["rev-parse", "main"]);
    git(&work, &["update-ref", "refs/stash", "main~1"]);
    git(&work, &["update-ref", "refs/notes/x", "main"]);
    let out = std::process::Command::new("git")
        .current_dir(&work)
        .args(["bundle", "create", "-", "refs/heads/main", "refs/stash", "refs/notes/x"])
        .output()
        .unwrap();
    assert!(out.status.success());
    (out.stdout, gix::ObjectId::from_hex(main.as_bytes()).unwrap())
}

#[tokio::test]
async fn refs_the_node_adds_to_a_fetch_bundle_are_not_written() {
    let tmp = tempfile::tempdir().unwrap();
    let (data, main) = bundle_with_extra_refs(tmp.path());
    let listing = format!("{main} refs/heads/main\n@refs/heads/main HEAD\n");
    let client = Client::new(Scripted::new(move |path, _| if path == "/git/list" { ok(listing.as_bytes()) } else { file(data.clone()) }));
    let dest = tmp.path().join("clone.git");
    client.clone_into(&url(), &dest).await.unwrap();
    let copy = gix::open(&dest).unwrap();
    assert_eq!(bundle::resolve_ref(&copy, "refs/heads/main").unwrap(), main);
    for extra in ["refs/stash", "refs/notes/x"] {
        assert!(copy.find_reference(extra).is_err(), "{extra}");
    }

    // A wanted ref the bundle has at another object than was listed (a push
    // landed in between) is set to the bundle's, and the unwanted ones are
    // still dropped.
    let elsewhere = tmp.path().join("elsewhere.git");
    let want = rngit::Want { sha: gix::ObjectId::from_hex("1".repeat(40).as_bytes()).unwrap(), name: "refs/heads/main".into() };
    let set = client.fetch_into(&url(), &[want], &elsewhere).await.unwrap();
    assert_eq!(set, [(main, "refs/heads/main".to_string())]);
    let copy = gix::open(&elsewhere).unwrap();
    assert_eq!(bundle::resolve_ref(&copy, "refs/heads/main").unwrap(), main);
    for extra in ["refs/stash", "refs/notes/x"] {
        assert!(copy.find_reference(extra).is_err(), "{extra}");
    }
}

#[test]
fn ingest_wanted_sets_only_what_was_asked_for() {
    let tmp = tempfile::tempdir().unwrap();
    let (data, main) = bundle_with_extra_refs(tmp.path());
    let repo = bundle::open_or_init_bare(&tmp.path().join("r.git")).unwrap();
    let limits = bundle::PackLimits::default();
    let set = bundle::ingest_wanted(&repo, &data, limits, &[("refs/heads/main", None), ("refs/heads/absent", None)]).unwrap();
    assert_eq!(set, [(main, "refs/heads/main".to_string())]);
    assert!(repo.find_reference("refs/stash").is_err());
    // A listed object that differs from the bundle's doesn't refuse it.
    let other = gix::ObjectId::from_hex("2".repeat(40).as_bytes()).unwrap();
    let set = bundle::ingest_wanted(&repo, &data, limits, &[("refs/heads/main", Some(other)), ("refs/stash", Some(other))]).unwrap();
    assert_eq!(set.len(), 2);
    assert_eq!(bundle::resolve_ref(&repo, "refs/heads/main").unwrap(), main);
    // A bundle whose ref points at an object its pack lacks is still refused.
    let missing = format!("# v2 git bundle\n{other} refs/heads/main\n\n");
    assert!(bundle::ingest_wanted(&repo, missing.as_bytes(), limits, &[("refs/heads/main", None)]).is_err());
    assert!(bundle::ingest_wanted(&repo, &data, limits, &[]).unwrap().is_empty());
    // A HEAD line names no ref to write here.
    let head = format!("# v2 git bundle\n{main} HEAD\n\n");
    assert!(bundle::ingest_wanted(&repo, head.as_bytes(), limits, &[("HEAD", None)]).is_err());
    assert!(bundle::ingest(&repo, head.as_bytes()).is_err());
}

#[tokio::test]
async fn a_failed_clone_leaves_nothing_and_can_be_tried_again() {
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    work_repo(&work, 2);
    let server = tmp.path().join("server.git");
    bare_repo(&server);
    git(&work, &["push", "-q", server.to_str().unwrap(), "main"]);
    let parent = tmp.path().join("clones");
    std::fs::create_dir_all(&parent).unwrap();
    let dest = parent.join("demo.git");

    let mut broken = MockNode::new(server.clone());
    broken.extra = Box::new(|path, _| (path == "/git/fetch").then(|| file(b"# v2 git bundle\nnot a ref\n\n".to_vec())));
    assert!(Client::new(broken).clone_into(&url(), &dest).await.is_err());
    assert!(std::fs::read_dir(&parent).unwrap().next().is_none(), "nothing is left in the folder");

    // An empty folder is fine to clone into, and is where the clone ends up.
    std::fs::create_dir(&dest).unwrap();
    let mut broken = MockNode::new(server.clone());
    broken.extra = Box::new(|path, _| (path == "/git/fetch").then(|| status(0xff, "gone")));
    assert!(Client::new(broken).clone_into(&url(), &dest).await.is_err());
    let left: Vec<_> = std::fs::read_dir(&parent).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(left, ["demo.git"]);
    assert!(std::fs::read_dir(&dest).unwrap().next().is_none(), "the empty folder is as it was");

    Client::new(MockNode::new(server.clone())).clone_into(&url(), &dest).await.unwrap();
    git(&dest, &["fsck", "--strict"]);
    assert_eq!(git(&dest, &["rev-parse", "main"]), git(&work, &["rev-parse", "main"]));
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 1);

    // A folder that holds something else is left alone.
    let other = parent.join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("keep.txt"), "mine").unwrap();
    assert!(matches!(Client::new(MockNode::new(server)).clone_into(&url(), &other).await, Err(Error::InvalidInput(_))));
    assert_eq!(std::fs::read_to_string(other.join("keep.txt")).unwrap(), "mine");
}

// --- pushing -------------------------------------------------------------

fn push_request(remote_ref: &str, bundle: Vec<u8>) -> Vec<u8> {
    let request = Value::Map(vec![
        (Value::from(0), Value::from("public/new.git")),
        (Value::from("local_ref"), Value::from("refs/heads/main")),
        (Value::from("remote_ref"), Value::from(remote_ref)),
        (Value::from("force"), Value::Boolean(false)),
        (Value::from("bundle"), Value::Binary(bundle)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &request).unwrap();
    out
}

fn answer(response: Response) -> (u8, String) {
    match response {
        Response::Packet(p) => (p[0], String::from_utf8_lossy(&p[1..]).into_owned()),
        Response::File { .. } => (0, "file".into()),
    }
}

#[test]
fn a_node_takes_a_push_bundle_shaped_like_stock_rngits() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("repos/public")).unwrap();
    let mut node = Node::new(tmp.path().join("repos"));
    node.default_rules = Rule::parse("c:all");
    let create = {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(vec![(Value::from(0), Value::from("public/new.git"))])).unwrap();
        out
    };
    assert_eq!(answer(node.handle("/git/create", &create, Some(ME)).unwrap()).0, 0);
    let work = tmp.path().join("work");
    work_repo(&work, 3);
    let made = |range: &str| {
        let out = std::process::Command::new("git").current_dir(&work).args(["bundle", "create", "-", range]).output().unwrap();
        assert!(out.status.success());
        out.stdout
    };
    let served = tmp.path().join("repos/public/new.git");

    // `<new sha> HEAD`, the whole history; then a thin one on top of it.
    git(&work, &["checkout", "-q", "--detach", "main~1"]);
    let first = made("HEAD");
    assert!(String::from_utf8_lossy(&first).lines().nth(1).unwrap().ends_with(" HEAD"));
    assert_eq!(answer(node.handle("/git/push", &push_request("refs/heads/main", first), Some(ME)).unwrap()), (0, "\0".into()));
    assert_eq!(git(&served, &["rev-parse", "main"]), git(&work, &["rev-parse", "main~1"]));
    git(&work, &["checkout", "-q", "main"]);
    let thin = made("main~1..HEAD");
    assert!(String::from_utf8_lossy(&thin).lines().nth(1).unwrap().starts_with('-'));
    assert_eq!(answer(node.handle("/git/push", &push_request("refs/heads/main", thin), Some(ME)).unwrap()).0, 0);
    assert_eq!(git(&served, &["rev-parse", "main"]), git(&work, &["rev-parse", "main"]));
    git(&served, &["fsck", "--strict"]);
    // The node never makes a ref called HEAD from it.
    assert_eq!(git(&served, &["symbolic-ref", "HEAD"]), "refs/heads/master");
}

#[tokio::test]
async fn an_annotated_tag_the_node_already_has_is_up_to_date() {
    let tmp = tempfile::tempdir().unwrap();
    let (work, server) = (tmp.path().join("work"), tmp.path().join("server.git"));
    work_repo(&work, 2);
    git(&work, &["tag", "-a", "-m", "release", "v1"]);
    bare_repo(&server);
    git(&work, &["push", "-q", server.to_str().unwrap(), "main", "v1"]);
    let client = Client::new(MockNode::new(server));
    client.push_from(&url(), &work, "refs/tags/v1", "refs/tags/v1", false).await.unwrap();
    let paths: Vec<String> = client.transport().requests().into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/git/list"], "nothing is sent");
}

#[tokio::test]
async fn push_all_stops_at_a_local_ref_it_cannot_read_and_deletes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (work, server, copy) = (tmp.path().join("work"), tmp.path().join("server.git"), tmp.path().join("copy.git"));
    work_repo(&work, 2);
    git(&work, &["branch", "kept"]);
    bare_repo(&server);
    git(&work, &["push", "-q", server.to_str().unwrap(), "main", "kept"]);
    bare_repo(&copy);
    git(&work, &["push", "-q", copy.to_str().unwrap(), "main", "kept"]);
    // The copy's ref file is damaged: it is there, but can't be read.
    std::fs::write(copy.join("refs/heads/kept"), "not an object id\n").unwrap();
    let client = Client::new(MockNode::new(server.clone()));
    let err = client.push_all(&url(), &copy, false, true).await.unwrap_err();
    assert!(err.to_string().contains("refs/heads/kept"), "{err}");
    assert!(gix::open(&server).unwrap().find_reference("refs/heads/kept").is_ok());
    assert!(!client.transport().requests().iter().any(|(p, _)| p == "/git/delete"));
}

#[test]
fn a_capped_build_stops_once_the_bundle_passes_the_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    work_repo(&work, 5);
    let repo = gix::open(&work).unwrap();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let wants = [("refs/heads/main", None)];
    let whole = bundle::build_many(&repo, &wants, &[]).unwrap();
    assert_eq!(bundle::build_capped(&repo, &wants, &[], &stop, whole.len()).unwrap(), whole);
    for cap in [0, 20, whole.len() / 2, whole.len() - 1] {
        let err = bundle::build_capped(&repo, &wants, &[], &stop, cap).unwrap_err();
        assert!(matches!(err, Error::TooLarge { what: "bundle", limit, .. } if limit == cap), "{cap}: {err}");
    }
    assert_eq!(bundle::build(&repo, "refs/heads/main", None).unwrap(), whole);
}

// --- what is printed and read --------------------------------------------

#[tokio::test]
async fn a_nodes_error_text_cannot_drive_the_terminal() {
    let client = Client::new(Scripted::new(|_, _| status(0xff, "\x1b[2J\x1b[31mfake prompt$ \x07\r")));
    let err = client.list(&url(), false).await.unwrap_err().to_string();
    assert!(!err.chars().any(char::is_control), "{err:?}");
    assert!(err.contains("\\u{1b}[2J"), "{err:?}");
}

#[tokio::test]
async fn standard_input_over_the_cap_is_refused_not_cut_short() {
    let client = Client::new(Scripted::new(|_, _| ok(b"\0")));
    let link = "rns://727ca184e3d7e83e0e35146940920442/public/demo";
    let over = vec![b'r'; 1024 * 1024 + 1];
    let (result, _) = cli(&client, &["perms", link, "-"], &over).await;
    assert!(matches!(result, Err(Error::TooLarge { what: "standard input", .. })), "{result:?}");
    assert!(client.transport().asked().is_empty(), "nothing was sent");
    let (result, _) = cli(&client, &["perms", link, "-"], &over[1..]).await;
    result.unwrap();
    let sent = client.transport().asked().pop().unwrap().1;
    assert_eq!(field(&sent, "content").and_then(Value::as_str).map(str::len), Some(1024 * 1024));
    let (result, _) = cli(&client, &["perms", link, "-"], b"\xff\xfe").await;
    assert!(matches!(result, Err(Error::InvalidInput(_))));
}
