//! Git bundles (v2) built and read with gix, with no `git` binary.

use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;

use gix::ObjectId;
use gix_pack::data::output;

use crate::error::{Error, Result};

static NO_INTERRUPT: AtomicBool = AtomicBool::new(false);

/// Longest bundle header we will read before giving up.
const MAX_HEADER_BYTES: usize = 1024 * 1024;
const MAX_HEADER_LINES: usize = 100_000;

/// A parsed bundle header. `pack_offset` is where the pack data starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleHeader {
    pub prerequisites: Vec<ObjectId>,
    pub refs: Vec<(ObjectId, String)>,
    pub pack_offset: usize,
}

/// Parse the text header of a v2 bundle. Never panics on bad input.
pub fn parse_header(data: &[u8]) -> Result<BundleHeader> {
    let bad = |what: &str| Error::Protocol(format!("bad bundle: {what}"));
    let mut pos = 0;
    let mut first = true;
    let mut header = BundleHeader { prerequisites: Vec::new(), refs: Vec::new(), pack_offset: 0 };
    let mut lines = 0;
    loop {
        let window = &data[pos..data.len().min(MAX_HEADER_BYTES)];
        let nl = window.iter().position(|b| *b == b'\n').ok_or_else(|| bad("header not terminated"))?;
        let line = std::str::from_utf8(&window[..nl]).map_err(|_| bad("header is not UTF-8"))?;
        pos += nl + 1;
        if first {
            if line != "# v2 git bundle" {
                return Err(bad("not a v2 bundle"));
            }
            first = false;
            continue;
        }
        if line.is_empty() {
            break;
        }
        lines += 1;
        if lines > MAX_HEADER_LINES {
            return Err(bad("too many header lines"));
        }
        if let Some(rest) = line.strip_prefix('-') {
            let sha = rest.split(' ').next().unwrap_or_default();
            header.prerequisites.push(ObjectId::from_hex(sha.as_bytes()).map_err(|_| bad("bad prerequisite id"))?);
        } else {
            let (sha, name) = line.split_once(' ').ok_or_else(|| bad("bad ref line"))?;
            header.refs.push((ObjectId::from_hex(sha.as_bytes()).map_err(|_| bad("bad ref id"))?, name.to_string()));
        }
    }
    header.pack_offset = pos;
    Ok(header)
}

/// Open the repository at `path`, creating a bare one if there is none yet.
pub fn open_or_init_bare(path: &Path) -> Result<gix::Repository> {
    match gix::open(path) {
        Ok(repo) => Ok(repo),
        Err(_) => {
            std::fs::create_dir_all(path).map_err(Error::git)?;
            gix::init_bare(path).map_err(Error::git)
        }
    }
}

pub(crate) fn valid_ref_name(name: &str) -> bool {
    name.starts_with("refs/") && gix::validate::reference::name(name.as_bytes().into()).is_ok()
}

/// Write the bundle's pack into `repo` without touching any ref. Returns the
/// refs the bundle names, each checked to exist in `repo` afterwards.
///
/// Besides refs under `refs/`, the bundle may name `HEAD`, as the push
/// bundles stock rngit makes do (`<new sha> HEAD`). That is fine here
/// because nothing is written from the names: a node takes the ref being
/// pushed from the request, and git sets the refs a remote helper fetched.
pub fn ingest_objects(repo: &gix::Repository, data: &[u8]) -> Result<Vec<(ObjectId, String)>> {
    let header = parse_header(data)?;
    ingest_objects_with(repo, data, header, &NO_INTERRUPT, true)
}

fn ingest_objects_with(
    repo: &gix::Repository,
    data: &[u8],
    header: BundleHeader,
    interrupt: &AtomicBool,
    allow_head: bool,
) -> Result<Vec<(ObjectId, String)>> {
    for (_, name) in &header.refs {
        if !(valid_ref_name(name) || (allow_head && name == "HEAD")) {
            return Err(Error::Protocol(format!("bundle names an unsafe ref: {name:?}")));
        }
    }
    // A thin bundle builds on objects we said we had; refuse one that doesn't.
    for id in &header.prerequisites {
        repo.find_object(*id).map_err(|_| Error::Protocol(format!("bundle needs {id}, which we don't have")))?;
    }
    let mut pack: &[u8] = &data[header.pack_offset..];
    if !pack.is_empty() {
        let dir = repo.objects.store_ref().path().join("pack");
        let mut progress = gix::progress::Discard;
        gix_pack::Bundle::write_to_directory(
            &mut pack as &mut dyn BufRead,
            Some(&dir),
            &mut progress,
            interrupt,
            Some(repo.objects.clone()),
            repo.object_hash(),
            Default::default(),
        )
        .map_err(Error::git)?;
    }
    for (id, name) in &header.refs {
        // A ref must never point at an object we don't have.
        repo.find_object(*id).map_err(|_| Error::Protocol(format!("bundle did not contain {id} for {name}")))?;
    }
    Ok(header.refs)
}

/// What a pack received may come to, so a small one can't grow into a huge
/// repository.
#[derive(Debug, Clone, Copy)]
pub struct PackLimits {
    pub max_objects: u32,
    /// Largest one object may be once unpacked, deltas applied.
    pub max_object_bytes: u64,
    /// All objects together, once unpacked.
    pub max_total_bytes: u64,
}

impl Default for PackLimits {
    /// What a node takes in a push, and a client in a fetch. Unpacking holds
    /// objects in memory whole, so these bound what a pack can cost to take in.
    fn default() -> Self {
        PackLimits { max_objects: 2_000_000, max_object_bytes: 128 * 1024 * 1024, max_total_bytes: 2 * 1024 * 1024 * 1024 }
    }
}

/// The size a delta says its result has: the second number at the start of
/// the delta, after the size of its base.
fn delta_result_size(compressed: &[u8]) -> Option<u64> {
    use std::io::Read;
    let mut head = [0u8; 24];
    let mut inflate = flate2::read::ZlibDecoder::new(compressed);
    let mut have = 0;
    // Both sizes are varints of at most 10 bytes each.
    while have < head.len() {
        match inflate.read(&mut head[have..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => have += n,
        }
    }
    let mut pos = 0;
    let mut varint = || -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = *head[..have].get(pos)?;
            pos += 1;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    };
    varint()?;
    varint()
}

/// Read through `pack` and refuse it if it holds too many objects, or any is
/// too big once unpacked, or all are together. This reads the sizes the
/// pack declares (a delta's result size is read from the delta), so nothing
/// is unpacked to find out.
pub fn check_pack(mut pack: &[u8], hash: gix::hash::Kind, limits: PackLimits) -> Result<()> {
    use gix_pack::data::input::{BytesToEntriesIter, EntryDataMode, Mode};
    let too_big = |what: &str| Error::Protocol(format!("pack is too big: {what}"));
    let reader: &mut dyn BufRead = &mut pack;
    let entries = BytesToEntriesIter::new_from_header(reader, Mode::AsIs, EntryDataMode::Keep, hash).map_err(Error::git)?;
    if entries.size_hint().0 as u64 > u64::from(limits.max_objects) {
        return Err(too_big("too many objects"));
    }
    let mut total = 0u64;
    for (seen, entry) in entries.enumerate() {
        if seen as u64 >= u64::from(limits.max_objects) {
            return Err(too_big("too many objects"));
        }
        let entry = entry.map_err(Error::git)?;
        let size = if entry.header.is_delta() {
            entry
                .compressed
                .as_deref()
                .and_then(delta_result_size)
                .ok_or_else(|| Error::Protocol("pack has a delta that can't be read".into()))?
        } else {
            entry.decompressed_size
        };
        if size > limits.max_object_bytes {
            return Err(too_big("an object is over the limit"));
        }
        total = total.saturating_add(size);
        if total > limits.max_total_bytes {
            return Err(too_big("everything in it is over the limit"));
        }
    }
    Ok(())
}

/// [`ingest_objects`], refusing a pack over `limits` first and giving up
/// soon after `interrupt` is set. Like it, this accepts a `HEAD` line.
pub fn ingest_objects_checked(
    repo: &gix::Repository,
    data: &[u8],
    limits: PackLimits,
    interrupt: &AtomicBool,
) -> Result<Vec<(ObjectId, String)>> {
    ingest_checked_with(repo, data, limits, interrupt, true)
}

fn ingest_checked_with(
    repo: &gix::Repository,
    data: &[u8],
    limits: PackLimits,
    interrupt: &AtomicBool,
    allow_head: bool,
) -> Result<Vec<(ObjectId, String)>> {
    let header = parse_header(data)?;
    let pack = &data[header.pack_offset..];
    // A bundle of nothing new has no pack, which is not unpacked either.
    if !pack.is_empty() {
        check_pack(pack, repo.object_hash(), limits)?;
    }
    ingest_objects_with(repo, data, header, interrupt, allow_head)
}

/// Write the bundle's pack into `repo` and point its refs at the new tips.
/// Returns the refs that were set. Every ref the bundle names is set, and
/// nothing limits what the pack unpacks to: for a bundle from a node, use
/// [`ingest_wanted`].
pub fn ingest(repo: &gix::Repository, data: &[u8]) -> Result<Vec<(ObjectId, String)>> {
    let header = parse_header(data)?;
    let refs = ingest_objects_with(repo, data, header, &NO_INTERRUPT, false)?;
    set_refs(repo, &refs)?;
    Ok(refs)
}

/// [`ingest`], refusing a pack over `limits` first. Every ref the bundle
/// names is still set: for a bundle from a node, use [`ingest_wanted`].
pub fn ingest_checked(repo: &gix::Repository, data: &[u8], limits: PackLimits) -> Result<Vec<(ObjectId, String)>> {
    let refs = ingest_checked_with(repo, data, limits, &NO_INTERRUPT, false)?;
    set_refs(repo, &refs)?;
    Ok(refs)
}

/// [`ingest_checked`] for a bundle from a node that was asked for `wanted`
/// refs: only those refs are set, so a node can't add `refs/stash`, notes or
/// anything else to the repository by naming them in the bundle. Each entry
/// is a full ref name and, when known, the object the node listed for it.
/// A wanted ref is set to the object the bundle names, which may differ
/// from the one listed when a push landed between the list and the fetch;
/// the bundle's objects are checked to be there first either way. A wanted
/// ref the bundle leaves out is not set. Returns the refs that were set.
pub fn ingest_wanted(
    repo: &gix::Repository,
    data: &[u8],
    limits: PackLimits,
    wanted: &[(&str, Option<ObjectId>)],
) -> Result<Vec<(ObjectId, String)>> {
    let mut refs = ingest_checked_with(repo, data, limits, &NO_INTERRUPT, false)?;
    refs.retain(|(_, name)| wanted.iter().any(|(want, _)| want == name));
    set_refs(repo, &refs)?;
    Ok(refs)
}

fn set_refs(repo: &gix::Repository, refs: &[(ObjectId, String)]) -> Result<()> {
    for (id, name) in refs {
        repo.reference(name.as_str(), *id, gix::refs::transaction::PreviousValue::Any, "rngit fetch").map_err(Error::git)?;
    }
    Ok(())
}

/// The most local tips sent as `have` in one fetch request.
pub const MAX_HAVES: usize = 256;

/// What the local repository already holds, to tell the node what it can leave
/// out of a bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Haves {
    /// The local value of each ref being fetched, by remote ref name.
    pub per_ref: Vec<(String, ObjectId)>,
    /// The tip of every local ref, up to [`MAX_HAVES`], as stock rngit sends them.
    pub tips: Vec<ObjectId>,
}

/// Collect the haves for fetching `wanted` ref names into `repo`.
pub fn local_haves(repo: &gix::Repository, wanted: &[&str]) -> Haves {
    let mut haves = Haves::default();
    let Ok(platform) = repo.references() else { return haves };
    let Ok(all) = platform.all() else { return haves };
    for mut reference in all.flatten() {
        // The object the ref names, so an annotated tag is offered as a tag.
        let id = match reference.target() {
            gix::refs::TargetRef::Object(id) => id.to_owned(),
            gix::refs::TargetRef::Symbolic(_) => match reference.peel_to_id() {
                Ok(id) => id.detach(),
                Err(_) => continue,
            },
        };
        let name = reference.name().as_bstr().to_string();
        if wanted.contains(&name.as_str()) {
            haves.per_ref.push((name, id));
        }
        if haves.tips.len() < MAX_HAVES {
            haves.tips.push(id);
        }
    }
    haves
}

/// Whether the node can be assumed to hold `id` already: some ref there points
/// at it, or at a commit that has it in its history. Only commits can be
/// reachable, so a tag object has to be named by a ref itself.
pub fn held_by_remote(repo: &gix::Repository, id: ObjectId, tips: &[ObjectId]) -> bool {
    if tips.contains(&id) {
        return true;
    }
    let Ok(object) = repo.find_object(id) else { return false };
    if object.kind != gix::object::Kind::Commit {
        return false;
    }
    let commits: Vec<ObjectId> =
        tips.iter().take(MAX_HAVES).filter_map(|tip| Some(repo.find_object(*tip).ok()?.peel_to_commit().ok()?.id)).collect();
    if commits.is_empty() {
        return false;
    }
    let Ok(walk) = repo.rev_walk(commits).all() else { return false };
    walk.flatten().any(|info| info.id == id)
}

/// Whether `ancestor` is reachable from `tip`. A missing object counts as no.
pub fn is_ancestor(repo: &gix::Repository, ancestor: ObjectId, tip: ObjectId) -> Result<bool> {
    if ancestor == tip {
        return Ok(true);
    }
    if repo.find_object(ancestor).is_err() {
        return Ok(false);
    }
    for info in repo.rev_walk([tip]).all().map_err(Error::git)? {
        if info.map_err(Error::git)?.id == ancestor {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolve a full ref name to its object id.
pub fn resolve_ref(repo: &gix::Repository, name: &str) -> Result<ObjectId> {
    let mut reference = repo.find_reference(name).map_err(|_| Error::Git(format!("no such ref: {name}")))?;
    Ok(reference.peel_to_id().map_err(Error::git)?.detach())
}

/// The object a ref points at directly: for an annotated tag, the tag
/// object itself rather than the commit it names.
pub fn direct_id(repo: &gix::Repository, name: &str) -> Result<ObjectId> {
    let reference = repo.find_reference(name).map_err(|_| Error::Git(format!("no such ref: {name}")))?;
    match reference.target() {
        gix::refs::TargetRef::Object(id) => Ok(id.to_owned()),
        gix::refs::TargetRef::Symbolic(_) => resolve_ref(repo, name),
    }
}

/// Build a v2 bundle of `refname`. History reachable from `have` is left out
/// and listed as a prerequisite, when `have` is an object we hold. An
/// annotated tag travels as the tag object, so the node keeps it.
pub fn build(repo: &gix::Repository, refname: &str, have: Option<ObjectId>) -> Result<Vec<u8>> {
    build_many(repo, &[(refname, have)], &[])
}

/// Build one v2 bundle of several refs. For each ref, `have` is what the
/// receiver holds of it, and `others` are further tips it holds. Anything
/// reachable from those that we hold ourselves is left out and listed as a
/// prerequisite.
pub fn build_many(repo: &gix::Repository, wants: &[(&str, Option<ObjectId>)], others: &[ObjectId]) -> Result<Vec<u8>> {
    build_many_until(repo, wants, others, &NO_INTERRUPT)
}

/// [`build_many`], giving up with an error soon after `interrupt` is set.
pub fn build_many_until(
    repo: &gix::Repository,
    wants: &[(&str, Option<ObjectId>)],
    others: &[ObjectId],
    interrupt: &AtomicBool,
) -> Result<Vec<u8>> {
    build_into(repo, wants, others, interrupt, usize::MAX)
}

/// [`build_many_until`], giving up as soon as the bundle grows past
/// `max_bytes`, with [`Error::TooLarge`] (`what` is `"bundle"`), so a node
/// doesn't build a bundle in memory that it would refuse to send.
pub fn build_capped(
    repo: &gix::Repository,
    wants: &[(&str, Option<ObjectId>)],
    others: &[ObjectId],
    interrupt: &AtomicBool,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    build_into(repo, wants, others, interrupt, max_bytes)
}

/// Appends to a buffer and fails a write that would take it past `max`.
struct Capped<'a> {
    out: &'a mut Vec<u8>,
    max: usize,
    /// Set once a write was refused.
    over: bool,
}

impl Write for Capped<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.out.len().saturating_add(data.len()) > self.max {
            self.over = true;
            return Err(std::io::Error::other("over the size limit"));
        }
        self.out.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn build_into(
    repo: &gix::Repository,
    wants: &[(&str, Option<ObjectId>)],
    others: &[ObjectId],
    interrupt: &AtomicBool,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    use std::sync::atomic::Ordering;
    let stopped = || Error::Git("took too long".into());
    let mut tags = Vec::new();
    let mut tips = Vec::new();
    let mut heads = Vec::new();
    for (refname, _) in wants {
        let direct = direct_id(repo, refname)?;
        let mut tip = direct;
        loop {
            let object = repo.find_object(tip).map_err(Error::git)?;
            if object.kind != gix::object::Kind::Tag {
                break;
            }
            tags.push(tip);
            tip = object.into_tag().target_id().map_err(Error::git)?.detach();
        }
        tips.push(tip);
        heads.push((direct, *refname));
    }
    let mut haves: Vec<ObjectId> = Vec::new();
    for have in wants.iter().filter_map(|(_, h)| *h).chain(others.iter().copied()) {
        // Only commits can be left out, and only ones we hold.
        let commit = repo.find_object(have).ok().filter(|o| o.kind == gix::object::Kind::Commit);
        if commit.is_some() && !haves.contains(&have) {
            haves.push(have);
        }
    }
    let mut walk = repo.rev_walk(tips);
    if !haves.is_empty() {
        walk = walk.with_hidden(haves.clone());
    }
    let mut ids: Vec<ObjectId> = Vec::new();
    for info in walk.all().map_err(Error::git)? {
        if interrupt.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        ids.push(info.map_err(Error::git)?.id);
    }
    ids.extend(tags);

    let mut db = repo.objects.clone().into_arc().map_err(Error::git)?.into_inner();
    db.prevent_pack_unload();
    let (counts, _) = output::count::objects(
        db.clone(),
        Box::new(ids.into_iter().map(Ok)),
        &gix::progress::Discard,
        interrupt,
        output::count::objects::Options {
            input_object_expansion: output::count::objects::ObjectExpansion::TreeAdditionsComparedToAncestor,
            ..Default::default()
        },
    )
    .map_err(Error::git)?;
    let count = counts.len() as u32;
    let entries = output::entry::iter_from_counts(
        counts,
        db,
        Box::new(gix::progress::Discard),
        // One thread keeps the entries in sequence order, which FromEntriesIter needs.
        output::entry::iter_from_counts::Options { allow_thin_pack: false, thread_limit: Some(1), ..Default::default() },
    )
    .map_err(Error::git)?;
    let mut out = Vec::new();
    writeln!(out, "# v2 git bundle").map_err(Error::git)?;
    for h in &haves {
        writeln!(out, "-{h} prerequisite").map_err(Error::git)?;
    }
    for (direct, refname) in &heads {
        writeln!(out, "{direct} {refname}").map_err(Error::git)?;
    }
    writeln!(out).map_err(Error::git)?;
    let too_large = |size: usize| Error::TooLarge { what: "bundle", size, limit: max_bytes };
    if out.len() > max_bytes {
        return Err(too_large(out.len()));
    }
    let mut capped = Capped { out: &mut out, max: max_bytes, over: false };
    let writer = output::bytes::FromEntriesIter::new(
        entries.map(|r| r.map(|(_, e)| e)),
        &mut capped,
        count,
        gix_pack::data::Version::V2,
        repo.object_hash(),
    );
    let mut failed = None;
    for step in writer {
        if interrupt.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        if let Err(e) = step {
            failed = Some(e);
            break;
        }
    }
    if let Some(e) = failed {
        return Err(if capped.over { too_large(max_bytes.saturating_add(1)) } else { Error::git(e) });
    }
    Ok(out)
}
