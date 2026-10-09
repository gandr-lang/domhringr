//! The evidence store: values committed beside a peer's tree store, read only
//! through their manifest's profile check and their complete closure.
//!
//! ```text
//! evidence/
//!   chunks/<chunk digest>        a chunk image, named by its BLAKE3
//!   closures/<manifest digest>   the closure's chunk digests, 32 bytes each
//!   manifests/<manifest digest>  the manifest image, named by its identity
//! ```
//!
//! A value is kept chunks first, then its closure, then its manifest, each
//! file written beside its name, synced and renamed into place, so a held
//! manifest names a value whose chunks were written before it. The closure
//! file is an index the read loads ahead of the walk; the walk is the check,
//! and a chunk the index omits is looked for under its own name before the
//! read refuses it.

use alloc::collections::BTreeMap;
use core::fmt;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use domhringr_record_tree::Content;
use domhringr_record_tree::StateDir;
use gandr_storage_values::CHUNK_DIGEST_LEN;
use gandr_storage_values::ChunkDigest;
use gandr_storage_values::ChunkImage;
use gandr_storage_values::ChunkImageBuf;
use gandr_storage_values::ChunkStore;
use gandr_storage_values::ManifestDigest;
use gandr_storage_values::ManifestImageBuf;
use gandr_storage_values::StoredChunkRef;
use gandr_storage_values::ValueClosure;
use gandr_storage_values::ValueError;
use gandr_storage_values::ValueManifest;
use gandr_storage_values::ValueProfile;
use gandr_storage_values::VerifiedChunk;
use gandr_storage_values::cam_commit;
use gandr_storage_values::verify_chunk_image;

use crate::lines::Lines;
use crate::profile::profile;

/// Directory, beneath the evidence directory, holding chunk images.
const CHUNKS: &str = "chunks";

/// Directory, beneath the evidence directory, holding closure indexes.
const CLOSURES: &str = "closures";

/// Directory, beneath the evidence directory, holding manifest images.
const MANIFESTS: &str = "manifests";

/// Chunk images by digest, verified on every load: the store a commit writes
/// into, a read walks and a fetch assembles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Chunks(BTreeMap<ChunkDigest, ChunkImageBuf>);

impl Chunks
{
    /// Hold `image` under `digest` once it hashes to it and its frame reads.
    ///
    /// # Specification
    /// - ensures: on success the image is held under `digest`, taken over
    ///   without a copy; a digest already held keeps its image, the same one.
    /// - fails: [`verify_chunk_image`]'s refusals:
    ///   [`ValueError::DigestMismatch`] naming both digests first.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    pub fn admit(
        &mut self,
        digest: ChunkDigest,
        image: ChunkImageBuf,
    ) -> Result<(), ValueError>
    {
        verify_chunk_image(StoredChunkRef::new(digest, image.as_image())).map(|_verified| ())?;
        let _held = self.0.entry(digest).or_insert(image);
        Ok(())
    }

    /// The chunks held, in digest order.
    ///
    /// # Specification
    /// trivial.
    pub fn iter(&self) -> impl Iterator<Item = (ChunkDigest, ChunkImage<'_>)>
    {
        self.0
            .iter()
            .map(|(digest, image)| (*digest, image.as_image()))
    }
}

impl ChunkStore for Chunks
{
    /// Hold a verified chunk, copying its image once if it is new.
    ///
    /// # Specification
    /// - ensures: the digest maps to the chunk's image; a digest already held
    ///   keeps the image it has, which is the same image.
    /// - fails: never.
    /// - panics: none.
    ///
    /// # Errors
    /// None; the signature is the trait's.
    fn insert(
        &mut self,
        chunk: VerifiedChunk<'_>,
    ) -> Result<(), ValueError>
    {
        let _held = self
            .0
            .entry(chunk.digest())
            .or_insert_with(|| ChunkImageBuf::from(Box::<[u8]>::from(chunk.image().as_ref())));
        Ok(())
    }

    /// Load and re-verify the image held under a digest.
    ///
    /// # Specification
    /// - ensures: as [`ChunkStore::load`].
    /// - fails: [`ValueError::UnknownChunk`] naming the digest when it is not
    ///   held, and [`verify_chunk_image`]'s refusals.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    fn load(
        &self,
        digest: ChunkDigest,
    ) -> Result<VerifiedChunk<'_>, ValueError>
    {
        let Some(image) = self.0.get(&digest)
        else {
            return Err(ValueError::UnknownChunk { digest });
        };
        verify_chunk_image(StoredChunkRef::new(digest, image.as_image()))
    }
}

/// A content committed in memory under the evidence profile: its manifest and
/// the chunks of its closure, ready to keep or to name.
#[derive(Clone, Debug)]
pub struct Staged
{
    /// The manifest's identity: the name receipts give the content.
    digest: ManifestDigest,
    /// The manifest.
    manifest: ValueManifest,
    /// Every chunk the commit wrote: the value's closure.
    chunks: Chunks,
}

impl Staged
{
    /// Commit `content` under the evidence profile, in memory.
    ///
    /// # Specification
    /// - ensures: the manifest and closure every peer computes for the same
    ///   bytes, so equal contents are named alike wherever they are staged.
    /// - fails: [`EvidenceError::Commit`] when the value plane refuses the
    ///   value.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError::Commit`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a staged content kept and read back is the content,
    ///   and its digest is the manifest the store holds; the corpus's contents
    ///   stage to the pinned chunk counts.
    /// - witness: `store::tests::a_committed_content_reads_back`
    /// - witness: `corpus::tests::the_cuts_of_the_corpus_are_pinned`
    #[inline]
    pub fn new(content: &Content) -> Result<Self, EvidenceError>
    {
        stage(content, &profile())
    }

    /// The manifest's identity: the name a receipt gives the content.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn digest(&self) -> ManifestDigest
    {
        self.digest
    }

    /// The chunks of the value's closure, in digest order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    pub fn chunks(&self) -> impl Iterator<Item = (ChunkDigest, ChunkImage<'_>)>
    {
        self.chunks.iter()
    }
}

/// Commit `content` under `profile`, in memory.
///
/// # Specification
/// - ensures: as [`Staged::new`], under the profile given.
/// - fails: as [`Staged::new`].
/// - panics: none.
///
/// # Errors
/// - [`EvidenceError::Commit`]: as listed above.
fn stage(
    content: &Content,
    profile: &ValueProfile,
) -> Result<Staged, EvidenceError>
{
    let mut chunks = Chunks::default();
    let manifest =
        cam_commit(&mut chunks, profile, &Lines::of(content)).map_err(EvidenceError::Commit)?;
    Ok(Staged {
        digest: manifest.identity(),
        manifest,
        chunks,
    })
}

/// What a store holds of a value, as a fetch answer carries it: the manifest
/// and the chunks of its closure the store could find.
#[derive(Debug)]
pub struct Held
{
    /// The manifest image.
    manifest: ManifestImageBuf,
    /// The chunks found.
    chunks: Chunks,
}

impl Held
{
    /// The manifest image.
    ///
    /// # Specification
    /// trivial.
    pub const fn manifest(&self) -> &ManifestImageBuf
    {
        &self.manifest
    }

    /// The chunks found.
    ///
    /// # Specification
    /// trivial.
    pub const fn chunks(&self) -> &Chunks
    {
        &self.chunks
    }
}

/// A file looked for by its name.
enum Found<Bytes>
{
    /// The file holds these bytes.
    Held(Bytes),
    /// No file has the name.
    Absent,
}

/// A closure index: chunk digests, 32 bytes each.
#[repr(transparent)]
struct Index(Box<[u8]>);

impl From<Box<[u8]>> for Index
{
    /// Take a closure file's bytes as an index.
    ///
    /// # Specification
    /// trivial.
    fn from(bytes: Box<[u8]>) -> Self
    {
        Self(bytes)
    }
}

impl Index
{
    /// The digests the index lists; a trailing partial digest is ignored, the
    /// walk finding what it would have named.
    ///
    /// # Specification
    /// trivial.
    fn digests(&self) -> impl Iterator<Item = ChunkDigest>
    {
        let (digests, _partial) = self.0.as_chunks::<CHUNK_DIGEST_LEN>();
        digests.iter().map(|digest| ChunkDigest::from(*digest))
    }
}

/// A peer's evidence store, beneath its state directory.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Evidence(PathBuf);

impl Evidence
{
    /// The evidence store of the peer whose state directory is `state`.
    ///
    /// # Specification
    /// - ensures: names the store at [`StateDir::evidence_dir`]; nothing is
    ///   read or created until a value is kept or read.
    /// - panics: none.
    #[inline]
    #[must_use]
    pub fn open(state: &StateDir) -> Self
    {
        Self(state.evidence_dir())
    }

    /// Commit `content` and keep it, returning its name.
    ///
    /// # Specification
    /// - ensures: as [`Staged::new`] then [`Evidence::keep`]; returns the
    ///   manifest's identity.
    /// - fails: as those two.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError::Commit`], [`EvidenceError::Store`]: as those two.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a committed content reads back equal from a store
    ///   opened again on the same directory.
    /// - witness: `store::tests::a_committed_content_reads_back`
    #[inline]
    pub fn commit(
        &self,
        content: &Content,
    ) -> Result<ManifestDigest, EvidenceError>
    {
        let staged = Staged::new(content)?;
        self.keep(&staged)?;
        Ok(staged.digest())
    }

    /// Keep a staged value: its chunks, its closure, then its manifest.
    ///
    /// # Specification
    /// - ensures: on success every chunk of the closure, its index and the
    ///   manifest are held, each file synced before its rename; a file already
    ///   held is left as it is, its name fixing its bytes.
    /// - fails: [`EvidenceError::Store`] naming the path that cannot be created
    ///   or written.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError::Store`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a kept value reads back, and keeping it again changes
    ///   nothing.
    /// - witness: `store::tests::a_committed_content_reads_back`
    #[inline]
    pub fn keep(
        &self,
        staged: &Staged,
    ) -> Result<(), EvidenceError>
    {
        self.persist(
            &staged.manifest,
            &staged.chunks,
            staged.chunks.iter().map(|(digest, _image)| digest),
        )
    }

    /// Read the content `digest` names.
    ///
    /// # Specification
    /// - ensures: the content the manifest held under `digest` describes, read
    ///   only after the manifest decoded, named itself `digest`, matched the
    ///   evidence profile in every field and its closure was walked whole:
    ///   every chunk present and verified, delivering the manifest's token
    ///   count.
    /// - fails: [`EvidenceError::Unheld`] when no manifest is held under
    ///   `digest`; [`EvidenceError::Refused`] with
    ///   [`ValueError::MalformedManifest`] for a manifest image of a foreign
    ///   domain, [`ValueError::IncompatibleProfile`] naming the first field
    ///   that differs from the evidence profile, before any chunk is loaded,
    ///   and [`ValueError::UnknownChunk`] naming the first chunk of the closure
    ///   the store does not hold; [`EvidenceError::Mislabeled`] for a manifest
    ///   held under another's name; [`EvidenceError::Store`] when a file cannot
    ///   be read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a committed content reads back; a value cut under
    ///   another kappa, a record-plane image held as a manifest, a chunk file
    ///   removed, an unheld digest and a manifest held under another's name are
    ///   each refused by name.
    /// - witness: `store::tests::a_committed_content_reads_back`
    /// - witness: `store::tests::each_refusal_names_what_it_refuses`
    #[inline]
    pub fn read(
        &self,
        digest: ManifestDigest,
    ) -> Result<Content, EvidenceError>
    {
        let refused = |refusal| EvidenceError::Refused { digest, refusal };
        let manifest = self.manifest(digest)?;
        manifest
            .profile()
            .ensure_matches(&profile())
            .map_err(refused)?;
        let mut chunks = self.indexed(digest)?;
        let _closure = self.complete(digest, &manifest, &mut chunks)?;
        manifest
            .read_under::<Lines<'_>>(&chunks, &profile())
            .map(Content::from)
            .map_err(refused)
    }

    /// What the store holds of the value `digest` names, to send.
    ///
    /// # Specification
    /// - ensures: the manifest held under `digest`, checked as
    ///   [`Evidence::read`] checks it, and every chunk of its closure the store
    ///   holds: those its index lists, then those the walk finds under their
    ///   own names until it meets one absent.
    /// - fails: as [`Evidence::read`] for the manifest and for a held chunk
    ///   that does not verify.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError`]: as listed above.
    pub(crate) fn held(
        &self,
        digest: ManifestDigest,
    ) -> Result<Held, EvidenceError>
    {
        let manifest = self.manifest(digest)?;
        let mut chunks = self.indexed(digest)?;
        match self.complete(digest, &manifest, &mut chunks) {
            | Ok(_)
            | Err(EvidenceError::Refused {
                refusal: ValueError::UnknownChunk { .. },
                ..
            }) => {},
            | Err(failure) => return Err(failure),
        }
        Ok(Held {
            manifest: manifest.encode(),
            chunks,
        })
    }

    /// Admit a fetched value: its manifest and the chunks received, the local
    /// store filling what they lack, then keep it and return its content.
    ///
    /// # Specification
    /// - requires: `manifest` decoded from the answer, named `digest` and
    ///   matched the evidence profile; `chunks` were each verified against the
    ///   digest they were received under.
    /// - ensures: the content is returned only after the closure was walked
    ///   whole over the chunks received and those held, and the value read; the
    ///   closure's chunks, its index and the manifest are then held.
    /// - fails: as [`Evidence::read`] for the walk and the read, and as
    ///   [`Evidence::keep`] for the store.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError`]: as listed above.
    pub(crate) fn receive(
        &self,
        digest: ManifestDigest,
        manifest: &ValueManifest,
        mut chunks: Chunks,
    ) -> Result<Content, EvidenceError>
    {
        let refused = |refusal| EvidenceError::Refused { digest, refusal };
        let closure = self.complete(digest, manifest, &mut chunks)?;
        let content = manifest
            .read_under::<Lines<'_>>(&chunks, &profile())
            .map(Content::from)
            .map_err(refused)?;
        self.persist(manifest, &chunks, closure.digests().iter().copied())?;
        Ok(content)
    }

    /// The manifest held under `digest`.
    ///
    /// # Specification
    /// - ensures: the manifest decoded from the file named `digest`, whose
    ///   identity is `digest`.
    /// - fails: [`EvidenceError::Unheld`] when no such file is held,
    ///   [`EvidenceError::Refused`] when its image does not decode — a foreign
    ///   domain refused as [`ValueError::MalformedManifest`] —
    ///   [`EvidenceError::Mislabeled`] when it is another's, and
    ///   [`EvidenceError::Store`] when it cannot be read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError`]: as listed above.
    pub(crate) fn manifest(
        &self,
        digest: ManifestDigest,
    ) -> Result<ValueManifest, EvidenceError>
    {
        let path = self.0.join(MANIFESTS).join(digest.to_string());
        let image = found::<ManifestImageBuf>(&path)?;
        let image = match image {
            | Found::Held(image) => image,
            | Found::Absent => return Err(EvidenceError::Unheld(digest)),
        };
        let manifest = ValueManifest::decode(image.as_image())
            .map_err(|refusal| EvidenceError::Refused { digest, refusal })?;
        let actual = manifest.identity();
        if actual != digest {
            return Err(EvidenceError::Mislabeled {
                held: digest,
                actual,
            });
        }
        Ok(manifest)
    }

    /// The chunks the closure index of `digest` lists that the store holds.
    ///
    /// # Specification
    /// - ensures: each listed chunk whose file is present, verified; nothing
    ///   when no index is held.
    /// - fails: [`EvidenceError::Refused`] for a held chunk that does not
    ///   verify, [`EvidenceError::Store`] for a file that cannot be read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError`]: as listed above.
    fn indexed(
        &self,
        digest: ManifestDigest,
    ) -> Result<Chunks, EvidenceError>
    {
        let mut chunks = Chunks::default();
        let path = self.0.join(CLOSURES).join(digest.to_string());
        let index = found::<Index>(&path)?;
        let index = match index {
            | Found::Held(index) => index,
            | Found::Absent => return Ok(chunks),
        };
        for listed in index.digests() {
            let image = self.chunk(listed)?;
            if let Found::Held(image) = image {
                chunks
                    .admit(listed, image)
                    .map_err(|refusal| EvidenceError::Refused { digest, refusal })?;
            }
        }
        Ok(chunks)
    }

    /// Walk the closure of `manifest` over `chunks`, filling each chunk it
    /// lacks from the store, until it is whole or a chunk is absent.
    ///
    /// # Specification
    /// - ensures: on success `chunks` holds the whole closure, walked and
    ///   verified, its records numbering the manifest's token count. Each round
    ///   adds the chunk the walk last missed, so the walk ends.
    /// - fails: [`EvidenceError::Refused`] with [`ValueError::UnknownChunk`]
    ///   naming the first chunk in stream order neither `chunks` nor the store
    ///   holds, and with the walk's other refusals; [`EvidenceError::Store`]
    ///   for a file that cannot be read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError`]: as listed above.
    fn complete(
        &self,
        digest: ManifestDigest,
        manifest: &ValueManifest,
        chunks: &mut Chunks,
    ) -> Result<ValueClosure, EvidenceError>
    {
        let refused = |refusal| EvidenceError::Refused { digest, refusal };
        loop {
            let missing = match manifest.closure(&*chunks) {
                | Ok(closure) => return Ok(closure),
                | Err(ValueError::UnknownChunk { digest: missing }) => missing,
                | Err(refusal) => return Err(refused(refusal)),
            };
            let image = self.chunk(missing)?;
            match image {
                | Found::Held(image) => {
                    chunks.admit(missing, image).map_err(refused)?;
                },
                | Found::Absent => {
                    return Err(refused(ValueError::UnknownChunk { digest: missing }));
                },
            }
        }
    }

    /// The image of the chunk `digest` names, unverified.
    ///
    /// # Specification
    /// trivial.
    fn chunk(
        &self,
        digest: ChunkDigest,
    ) -> Result<Found<ChunkImageBuf>, EvidenceError>
    {
        found(&self.0.join(CHUNKS).join(digest.to_string()))
    }

    /// Hold the chunks `closure` lists, the index listing them, then the
    /// manifest.
    ///
    /// # Specification
    /// - requires: `chunks` holds every digest `closure` yields.
    /// - ensures: as [`Evidence::keep`].
    /// - fails: as [`Evidence::keep`].
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError::Store`]: as listed above.
    fn persist(
        &self,
        manifest: &ValueManifest,
        chunks: &Chunks,
        closure: impl Iterator<Item = ChunkDigest>,
    ) -> Result<(), EvidenceError>
    {
        let digest = manifest.identity();
        let (chunk_dir, closure_dir, manifest_dir) = (
            self.0.join(CHUNKS),
            self.0.join(CLOSURES),
            self.0.join(MANIFESTS),
        );
        for dir in [&chunk_dir, &closure_dir, &manifest_dir] {
            std::fs::create_dir_all(dir).map_err(failed(StoreAction::Create, dir))?;
        }
        let mut index = Vec::new();
        for listed in closure {
            index.extend_from_slice(listed.as_ref());
            if let Some(image) = chunks.0.get(&listed) {
                put(&chunk_dir, &chunk_dir.join(listed.to_string()), image)?;
            }
        }
        put(&closure_dir, &closure_dir.join(digest.to_string()), &index)?;
        put(
            &manifest_dir,
            &manifest_dir.join(digest.to_string()),
            &manifest.encode(),
        )
    }
}

/// The file at `path`, or its absence.
///
/// # Specification
/// - ensures: the file's bytes, taken over by `Bytes`, or [`Found::Absent`]
///   when nothing is at `path`.
/// - fails: [`EvidenceError::Store`] for any other read failure.
/// - panics: none.
///
/// # Errors
/// - [`EvidenceError::Store`]: as listed above.
fn found<Bytes>(path: &Path) -> Result<Found<Bytes>, EvidenceError>
where
    Bytes: From<Box<[u8]>>,
{
    match std::fs::read(path) {
        | Ok(bytes) => Ok(Found::Held(Bytes::from(bytes.into_boxed_slice()))),
        | Err(failure) if failure.kind() == io::ErrorKind::NotFound => Ok(Found::Absent),
        | Err(failure) => Err(failed(StoreAction::Read, path)(failure)),
    }
}

/// Write `bytes` to `path` in `dir`, unless a file already has the name.
///
/// # Specification
/// - ensures: the bytes are written to a fresh file in `dir`, synced, then
///   renamed to `path`, so a reader sees no file or the whole one; a file
///   already at `path` is kept, its name fixing its bytes.
/// - fails: [`EvidenceError::Store`] naming `path` when a step fails.
/// - panics: none.
///
/// # Errors
/// - [`EvidenceError::Store`]: as listed above.
fn put<Bytes>(
    dir: &Path,
    path: &Path,
    bytes: &Bytes,
) -> Result<(), EvidenceError>
where
    Bytes: AsRef<[u8]> + ?Sized,
{
    let held = path.try_exists().map_err(failed(StoreAction::Read, path))?;
    if held {
        return Ok(());
    }
    let write = failed(StoreAction::Write, path);
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(&write)?;
    file.write_all(bytes.as_ref()).map_err(&write)?;
    file.as_file().sync_all().map_err(&write)?;
    let _file = file.persist(path).map_err(|failure| write(failure.error))?;
    Ok(())
}

/// The refusal for `action` on `path`, from the failure's source.
///
/// # Specification
/// trivial.
fn failed(
    action: StoreAction,
    path: &Path,
) -> impl Fn(io::Error) -> EvidenceError
{
    let path = path.to_path_buf();
    move |source| EvidenceError::Store {
        action,
        path: path.clone(),
        source,
    }
}

/// What the store was doing when a file failed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreAction
{
    /// Creating a directory.
    Create,
    /// Reading a file.
    Read,
    /// Writing a file.
    Write,
}

impl fmt::Display for StoreAction
{
    /// Write the action as a verb.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Create => "create",
            | Self::Read => "read",
            | Self::Write => "write",
        })
    }
}

/// Why evidence cannot be committed, kept or read.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError
{
    /// The value plane refuses the content as a value.
    #[error("cannot commit the content as evidence: {0}")]
    Commit(ValueError),
    /// No manifest is held under the digest.
    #[error("evidence {0} is not held")]
    Unheld(ManifestDigest),
    /// The manifest held under one digest is another's.
    #[error("the manifest held as {held} is {actual}")]
    Mislabeled
    {
        /// The digest it is held under.
        held: ManifestDigest,
        /// The manifest's identity.
        actual: ManifestDigest,
    },
    /// The value plane refuses the evidence the digest names, by the refusal
    /// it names: a foreign domain, a profile mismatch, a missing or invalid
    /// chunk.
    #[error("evidence {digest} is refused: {refusal}")]
    Refused
    {
        /// The evidence.
        digest: ManifestDigest,
        /// The refusal.
        refusal: ValueError,
    },
    /// A file of the store cannot be created, read or written.
    #[error("cannot {action} {}", path.display())]
    Store
    {
        /// What failed.
        action: StoreAction,
        /// The path.
        path: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests
{
    use core::fmt::Write as _;
    use core::num::NonZeroU64;

    use domhringr_record_tree::Content;
    use domhringr_record_tree::StateDir;
    use gandr_storage_chunker::Kappa;
    use gandr_storage_chunker::TypedChunkerParams;
    use gandr_storage_values::ManifestField;
    use gandr_storage_values::ProfileField;
    use gandr_storage_values::ValueError;
    use gandr_storage_values::ValueProfile;

    use super::CHUNKS;
    use super::Evidence;
    use super::EvidenceError;
    use super::MANIFESTS;
    use super::Staged;
    use super::stage;
    use crate::profile::profile;

    /// A content of many lines: enough to cut into several chunks.
    ///
    /// # Specification
    /// trivial.
    fn lines() -> Content
    {
        let mut text = String::new();
        for line in 0_u32 .. 2000_u32 {
            writeln!(text, "line {line} of the evidence").unwrap();
        }
        Content::from(text.into_bytes())
    }

    #[test]
    fn a_committed_content_reads_back()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let content = lines();
        let staged = Staged::new(&content).unwrap();
        assert!(
            staged.chunks().count() > 1,
            "the content spans several chunks"
        );
        let digest = Evidence::open(&state).commit(&content).unwrap();
        assert_eq!(digest, staged.digest(), "the name is the staged manifest's");
        let reopened = Evidence::open(&state);
        assert_eq!(reopened.read(digest).unwrap(), content);
        reopened.keep(&staged).unwrap();
        assert_eq!(
            reopened.read(digest).unwrap(),
            content,
            "keeping it again changes nothing"
        );
        let empty = Content::from(Vec::new());
        let named = reopened.commit(&empty).unwrap();
        assert_eq!(
            reopened.read(named).unwrap(),
            empty,
            "an empty content reads back"
        );
    }

    #[test]
    fn each_refusal_names_what_it_refuses()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let evidence = Evidence::open(&state);
        let content = lines();

        // A value cut under another kappa is refused for its chunker
        // commitment before any chunk is read.
        let base = profile();
        let other = ValueProfile::new(
            TypedChunkerParams::new(
                Kappa::from(NonZeroU64::new(32).unwrap()),
                base.params().cap(),
            ),
            base.codec(),
            base.index_base(),
        );
        let foreign = stage(&content, &other).unwrap();
        evidence.keep(&foreign).unwrap();
        assert!(matches!(
            evidence.read(foreign.digest()),
            Err(EvidenceError::Refused {
                digest,
                refusal: ValueError::IncompatibleProfile {
                    field: ProfileField::ChunkerCommitment
                },
            }) if digest == foreign.digest()
        ));

        // A chunk image held as a manifest is refused for its domain.
        let staged = Staged::new(&content).unwrap();
        evidence.keep(&staged).unwrap();
        let (chunk, image) = staged.chunks().next().unwrap();
        let manifests = root.path().join("evidence").join(MANIFESTS);
        std::fs::write(manifests.join(chunk.to_string()), image.as_ref()).unwrap();
        let posing = gandr_storage_values::ManifestDigest::from(
            <[u8; 32]>::try_from(chunk.as_ref()).unwrap(),
        );
        assert!(matches!(
            evidence.read(posing),
            Err(EvidenceError::Refused {
                refusal: ValueError::MalformedManifest {
                    field: ManifestField::Domain
                },
                ..
            })
        ));

        // A chunk removed from the store is refused by its digest.
        std::fs::remove_file(
            root.path()
                .join("evidence")
                .join(CHUNKS)
                .join(chunk.to_string()),
        )
        .unwrap();
        assert!(matches!(
            evidence.read(staged.digest()),
            Err(EvidenceError::Refused {
                refusal: ValueError::UnknownChunk { digest },
                ..
            }) if digest == chunk
        ));

        // A digest no manifest is held under is unheld; a manifest held
        // under another's name is mislabeled.
        let unheld = Staged::new(&Content::from(b"never kept\n".to_vec())).unwrap();
        assert!(matches!(
            evidence.read(unheld.digest()),
            Err(EvidenceError::Unheld(digest)) if digest == unheld.digest()
        ));
        std::fs::copy(
            manifests.join(staged.digest().to_string()),
            manifests.join(unheld.digest().to_string()),
        )
        .unwrap();
        assert!(matches!(
            evidence.read(unheld.digest()),
            Err(EvidenceError::Mislabeled { held, actual })
                if held == unheld.digest() && actual == staged.digest()
        ));
    }
}
