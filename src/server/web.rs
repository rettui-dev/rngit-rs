//! Fetching a fork's or mirror's source from an `https://` repository, in
//! this process with gix. Nothing is run: stock rngit runs `git` for this and
//! also takes `ssh`, which gix can only do by running `ssh`, so it isn't taken.
//!
//! A sender picks the address, so a node asked to fetch is a way to reach
//! what only the node can: addresses on its own network are refused, redirects
//! aren't followed, a source can't carry a password (it would be kept in the
//! repository's config) and what is fetched is cut off at the size a repository
//! may come to and at the time a request may take. The fetch connects to the
//! addresses that were checked, so a name that answers differently when asked
//! again can't send it elsewhere.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

/// Whether a source is one this node fetches: `https://` to a public address
/// (`open` also allows `http://` and addresses on the node's own network, for
/// labs and tests). Gives the addresses checked, for [`pull`] to connect to
/// (none when `open`).
pub(super) fn check(source: &str, open: bool) -> Result<Vec<SocketAddr>, String> {
    let url = gix::Url::from_bytes(source.into()).map_err(|_| "Invalid source URL".to_string())?;
    let scheme = match url.scheme {
        gix::url::Scheme::Https => "https",
        gix::url::Scheme::Http if open => "http",
        _ => return Err("Prohibited source URL: this node forks and mirrors from rns:// and https:// repositories only".into()),
    };
    if url.user().is_some() || url.password().is_some() {
        return Err("Prohibited source URL: it can't carry a login".into());
    }
    let host = url.host().filter(|h| !h.is_empty()).ok_or("Invalid source URL")?;
    if open {
        return Ok(Vec::new());
    }
    // The checked addresses are pinned to the name the HTTP client reads from
    // the URL; a URL it reads another name from would go unpinned.
    if http_host(source).as_deref() != Some(&host.trim_matches(['[', ']']).to_ascii_lowercase()) {
        return Err("Invalid source URL".into());
    }
    let port = url.port.unwrap_or(if scheme == "https" { 443 } else { 80 });
    let found: Vec<_> = (host.trim_matches(['[', ']']), port).to_socket_addrs().map_err(|_| "The source's address isn't known")?.collect();
    if found.is_empty() || found.iter().any(|a| !public(a.ip())) {
        return Err("Prohibited source URL: it isn't a public address".into());
    }
    Ok(found)
}

/// The host the HTTP client connects to for `source`, as it reads the URL.
fn http_host(source: &str) -> Option<String> {
    let url = reqwest::Url::parse(source).ok()?;
    Some(url.host_str()?.trim_matches(['[', ']']).to_ascii_lowercase())
}

/// Whether an address is one on the open internet. An IPv6 address that
/// carries an IPv4 one (mapped, NAT64, 6to4) is judged by that too.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => public_v4(v4) && public_v6(v6),
            None => public_v6(v6),
        },
    }
}

/// The IPv4 address an IPv6 one stands for, if it is made from one.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let low = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    match s {
        // ::ffff:a.b.c.d, mapped.
        [0, 0, 0, 0, 0, 0xffff, ..] => Some(low),
        // 64:ff9b::a.b.c.d, NAT64's well-known prefix: a gateway reaches the IPv4 address.
        [0x64, 0xff9b, 0, 0, 0, 0, ..] => Some(low),
        // 2002:aabb:ccdd::/48, 6to4: the IPv4 address follows the prefix.
        [0x2002, high, low_half, ..] => Some(Ipv4Addr::new((high >> 8) as u8, high as u8, (low_half >> 8) as u8, low_half as u8)),
        _ => None,
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // 0.0.0.0/8, "this network".
        || o[0] == 0
        // 100.64.0.0/10, carrier-grade NAT.
        || (o[0] == 100 && (64..128).contains(&o[1]))
        // 192.0.0.0/24, protocol assignments.
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 192.88.99.0/24, the old 6to4 relays.
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        // 198.18.0.0/15, benchmarking.
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        // 240.0.0.0/4, reserved, and the broadcast address in it.
        || o[0] >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7, unique local.
        || s[0] & 0xfe00 == 0xfc00
        // fe80::/10, link-local, and fec0::/10, the old site-local.
        || s[0] & 0xffc0 == 0xfe80
        || s[0] & 0xffc0 == 0xfec0
        // ::a.b.c.d, the old IPv4-compatible form, which nothing routes (with :: and ::1).
        || matches!(s, [0, 0, 0, 0, 0, 0, ..])
        // ::ffff:0:a.b.c.d, IPv4-translated.
        || matches!(s, [0, 0, 0, 0, 0xffff, 0, ..])
        // 64:ff9b:1::/48, NAT64 for local use.
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
        // 100::/64, discard.
        || matches!(s, [0x100, 0, 0, 0, ..])
        // 2001::/23, protocol assignments (Teredo among them), and 2001:db8::/32, documentation.
        || (s[0] == 0x2001 && s[1] < 0x200)
        || (s[0] == 0x2001 && s[1] == 0xdb8)
        // 3fff::/20, documentation.
        || (s[0] == 0x3fff && s[1] < 0x1000)
        // 5f00::/16, segment routing.
        || s[0] == 0x5f00)
}

/// Fetch every branch and tag of `source` into the bare repository at `dest`
/// and point HEAD where the source's does. Gives the names of the refs the
/// source has. Gives up after `timeout`, or once `dest` is bigger than `max_bytes`.
/// No object bigger than `max_object` is unpacked. With `pinned` (what [`check`]
/// gave), the source's name is taken to mean those addresses and isn't looked up again.
pub(super) fn pull(
    source: &str,
    pinned: &[SocketAddr],
    dest: &Path,
    timeout: Duration,
    max_bytes: u64,
    max_object: u64,
) -> Result<Vec<String>, String> {
    use gix::protocol::handshake::Ref;
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut repo = gix::open(dest).map_err(|e| e.to_string())?;
    limit(&mut repo, max_object)?;
    let remote = repo
        .remote_at(source)
        .and_then(|r| r.with_refspecs(["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*", "HEAD"], gix::remote::Direction::Fetch))
        .map_err(|e| e.to_string())?;

    // Set once the fetch should stop: it is out of time or has grown too large.
    let stop = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    let fetched = std::thread::scope(|scope| {
        scope.spawn(|| {
            let started = std::time::Instant::now();
            while !done.load(Ordering::Relaxed) {
                if started.elapsed() > timeout || super::dir_size(dest) > max_bytes {
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let result = (|| {
            let connection = remote
                .connect(gix::remote::Direction::Fetch)
                .map_err(|e| e.to_string())?
                .with_transport_options(options(&repo, source, pinned)?);
            let prepared = connection.prepare_fetch(gix::progress::Discard, Default::default()).map_err(|e| why(&e))?;
            let refs = prepared.ref_map().remote_refs.clone();
            prepared.receive(gix::progress::Discard, &stop).map_err(|e| why(&e))?;
            Ok::<_, String>(refs)
        })();
        done.store(true, Ordering::Relaxed);
        result
    });
    if stop.load(Ordering::Relaxed) {
        return Err("The fetch took too long or came to more than a repository may".into());
    }
    let refs = fetched?;

    let mut head = None;
    let mut kept = std::collections::HashSet::new();
    for r in &refs {
        match r {
            Ref::Symbolic { full_ref_name, target, .. } if full_ref_name == "HEAD" => head = Some(target.to_string()),
            Ref::Unborn { full_ref_name, target } if full_ref_name == "HEAD" => head = Some(target.to_string()),
            Ref::Direct { full_ref_name, .. } | Ref::Peeled { full_ref_name, .. } | Ref::Symbolic { full_ref_name, .. } => {
                kept.insert(full_ref_name.to_string());
            }
            Ref::Unborn { .. } => {}
        }
    }
    if let Some(head) = head.filter(|h| h.starts_with("refs/heads/") && !h.contains(['\n', '\0'])) {
        super::support::write_file(&dest.join("HEAD"), format!("ref: {head}\n").as_bytes())
            .map_err(|_| "Could not set HEAD".to_string())?;
    }
    Ok(kept.into_iter().collect())
}

/// Set up `repo` for a fetch from a source a sender picked: no redirects, a
/// connect timeout, and gix refuses to unpack an object over `max_object`
/// (the pack streams straight into gix, so it can't be checked first, and a
/// pack of a few hundred bytes can declare gigabytes).
fn limit(repo: &mut gix::Repository, max_object: u64) -> Result<(), String> {
    let mut config = repo.config_snapshot_mut();
    config.set_raw_value_by("http", None, "followRedirects", "false").map_err(|e| e.to_string())?;
    config.set_raw_value_by("gitoxide", Some("http".into()), "connectTimeout", "30000").map_err(|e| e.to_string())?;
    config.set_raw_value_by("gitoxide", Some("objects".into()), "allocLimit", max_object.to_string()).map_err(|e| e.to_string())?;
    config.commit().map(drop).map_err(|e| e.to_string())
}

/// gix's HTTP options for `source`, trusting the root certificates rngit comes
/// with as well as the system's: a small container image has no store of its
/// own, and without one no https source could be reached. The source's name
/// is resolved to `pinned`, if there are any.
fn options(repo: &gix::Repository, source: &str, pinned: &[SocketAddr]) -> Result<Box<dyn std::any::Any>, String> {
    use gix::protocol::transport::client::blocking_io::http;
    use std::sync::{Arc, Mutex};

    let configured = repo.transport_options(source, None).map_err(|e| e.to_string())?;
    let mut options = configured.and_then(|o| o.downcast::<http::Options>().ok()).map(|o| *o).unwrap_or_default();
    let pin = http_host(source).filter(|_| !pinned.is_empty()).map(|host| (host, pinned.to_vec()));
    let backend = http::reqwest::Options {
        configure_client: Some(Box::new(move |builder| {
            let builder = builder.tls_certs_merge(bundled_roots());
            Ok(match &pin {
                Some((host, addresses)) => builder.resolve_to_addrs(host, addresses),
                None => builder,
            })
        })),
        configure_request: None,
    };
    options.backend = Some(Arc::new(Mutex::new(backend)));
    Ok(Box::new(options))
}

/// An error and the innermost reason for it: gix's own message is often only
/// "Transport handshake failed".
fn why(e: &dyn std::error::Error) -> String {
    let mut root = e;
    while let Some(next) = root.source() {
        root = next;
    }
    let (said, reason) = (e.to_string(), root.to_string());
    if said == reason { said } else { format!("{said}: {reason}") }
}

fn bundled_roots() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().filter_map(|der| reqwest::Certificate::from_der(der).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_roots_are_trusted_whatever_the_system_has() {
        assert_eq!(bundled_roots().len(), webpki_root_certs::TLS_SERVER_ROOT_CERTS.len());
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let options = options(&repo, "https://example.com/a/b.git", &[]).unwrap();
        let options = options.downcast_ref::<gix::protocol::transport::client::blocking_io::http::Options>().unwrap();
        let backend = options.backend.as_ref().unwrap().lock().unwrap();
        let backend = backend.downcast_ref::<gix::protocol::transport::client::blocking_io::http::reqwest::Options>().unwrap();
        assert!(backend.configure_client.is_some());
    }

    #[test]
    fn a_failure_says_why() {
        let e = std::io::Error::other(std::io::Error::other("invalid peer certificate: UnknownIssuer"));
        assert_eq!(why(&e), "invalid peer certificate: UnknownIssuer");
        #[derive(Debug)]
        struct Handshake(std::io::Error);
        impl std::fmt::Display for Handshake {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("Transport handshake failed")
            }
        }
        impl std::error::Error for Handshake {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let e = Handshake(std::io::Error::other("No CA certificates were loaded from the system"));
        assert_eq!(why(&e), "Transport handshake failed: No CA certificates were loaded from the system");
    }

    #[test]
    fn the_fetch_connects_to_the_checked_address_without_looking_the_name_up_again() {
        // A port nothing listens on: a refused connection shows where it went.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let source = format!("http://Pinned.invalid:{port}/a.git");
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let checked: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let options = options(&repo, &source, &[checked]).unwrap();
        let options = options.downcast_ref::<gix::protocol::transport::client::blocking_io::http::Options>().unwrap();
        let mut backend = options.backend.as_ref().unwrap().lock().unwrap();
        let backend = backend.downcast_mut::<gix::protocol::transport::client::blocking_io::http::reqwest::Options>().unwrap();
        let configure = backend.configure_client.as_mut().unwrap();
        let client = configure(reqwest::blocking::Client::builder()).unwrap().build().unwrap();
        // `.invalid` names never resolve: only the pin can reach an address.
        let err = client.get(&source).send().unwrap_err();
        assert!(why(&err).to_ascii_lowercase().contains("refused"), "{}", why(&err));
    }

    #[test]
    fn a_url_the_http_client_reads_another_host_from_is_refused() {
        assert_eq!(http_host("https://Example.COM:8443/a.git").as_deref(), Some("example.com"));
        assert_eq!(http_host("https://[2606:4700::1111]/a.git").as_deref(), Some("2606:4700::1111"));
        // Read as 8.8.8.8 by the HTTP client, and as a name by gix.
        for other in ["https://0x08080808/a.git", "https://010.010.010.010/a.git", "https://134744072/a.git"] {
            assert_eq!(check(other, false), Err("Invalid source URL".into()), "{other}");
        }
    }

    #[test]
    fn a_fetch_unpacks_no_object_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = gix::init_bare(dir.path()).unwrap();
        limit(&mut repo, 1234).unwrap();
        let config = repo.config_snapshot();
        assert_eq!(config.integer("gitoxide.objects.allocLimit"), Some(1234));
        assert_eq!(config.boolean("http.followRedirects"), Some(false));
    }

    #[test]
    fn only_public_addresses_count() {
        for ip in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            // NAT64 and 6to4 of private and loopback addresses.
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::808:808",
            "2002:7f00:1::1",
            "2002:c0a8:101::",
            // IPv4-compatible and -translated.
            "::8.8.8.8",
            "::7f00:1",
            "::ffff:0:808:808",
            "fec0::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "5f00::1",
            "ff02::1",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.0.8",
            "192.88.99.1",
            "100.127.255.255",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in
            ["8.8.8.8", "140.82.112.3", "2606:4700::1111", "64:ff9b::808:808", "2002:808:808::1", "2001:4860:4860::8888", "198.20.0.1"]
        {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn sources_are_https_without_a_login_to_a_public_address() {
        for bad in [
            "http://example.com/a/b.git",
            "ssh://git@example.com/a/b.git",
            "git@example.com:a/b.git",
            "file:///tmp/x",
            "/tmp/x",
            "https://user:pw@example.com/a.git",
            "https://127.0.0.1/a.git",
            "https://[::1]/a.git",
            "https://169.254.169.254/latest",
            "https://",
        ] {
            assert!(check(bad, false).is_err(), "{bad}");
        }
        assert_eq!(check("https://8.8.8.8/a/b.git", false), Ok(vec!["8.8.8.8:443".parse().unwrap()]));
        assert_eq!(check("https://8.8.8.8:8443/a/b.git", false), Ok(vec!["8.8.8.8:8443".parse().unwrap()]));
        assert_eq!(check("http://127.0.0.1:8000/a.git", true), Ok(vec![]));
        assert!(check("ssh://git@example.com/a.git", true).is_err());
    }
}
