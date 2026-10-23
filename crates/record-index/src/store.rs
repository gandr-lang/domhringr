//! Content-addressed node files, published before their store manifest.
//!
//! State lives beneath `index/nodes/<node identity>` and
//! `index/manifests/<store root>`. A commit publishes every node of every
//! table, synced, before the manifest image naming them. Publishing retains
//! valid files and atomically repairs damaged ones. Loading authenticates
//! every node through the record plane and reopens the store, which rebuilds
//! each table and requires its root and count to match the manifest. Every
//! committed root stays held; there is no collection policy.
//!
//! `index/projects/<project>` holds the root of the last local derivation.
//! This atomic cursor lets `open` refresh without attesting and reuse that
//! refresh on its next invocation; it is published only after the complete
//! store. When no cursor exists, the local author's latest attestation seeds
//! the cache. Another author's claim never does.

use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use anodized::spec;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::TreeId;
use gandr_storage_records::BlockStore;
use gandr_storage_records::ChildRef;
use gandr_storage_records::DecodeWork;
use gandr_storage_records::DecodedNode;
use gandr_storage_records::InMemoryBlockStore;
use gandr_storage_records::NodeHash;
use gandr_storage_records::OwnedEncodedNode;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::StoredNode;
use gandr_storage_records::decode_node;
use gandr_storage_schema::ManifestImage;
use gandr_storage_schema::STORE_ROOT_LEN;
use gandr_storage_schema::StoreManifest;
use gandr_storage_schema::StoreRoot;

use crate::keyed;
use crate::keyed::Keyed;
use crate::wire::Body;

/// A peer's committed project stores. No manifest or node is collected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Store(PathBuf);

/// Whether a local project cursor has been published.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Cached
{
    /// No derivation has been retained for this project.
    Absent,
    /// The root of the last complete local derivation.
    Root(StoreRoot),
}

/// Why a project store cannot be written or authenticated.
#[derive(Debug, thiserror::Error)]
pub enum StoreError
{
    /// No manifest is held under this root.
    #[error("unheld {0}")]
    Unheld(StoreRoot),
    /// A named file failed an I/O operation.
    #[error("index file {}: {source}", path.display())]
    File
    {
        /// The file or directory involved.
        path: PathBuf,
        /// The underlying I/O failure.
        source: io::Error,
    },
    /// Node authentication failed.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
    /// The project store refused its manifest, a table or a commit.
    #[error(transparent)]
    Project(#[from] gandr_storage_schema::StoreError),
    /// The manifest's root differs from the requested name.
    #[error("manifest {named} contains {actual}")]
    Mislabeled
    {
        /// The requested root.
        named: StoreRoot,
        /// The root computed over the held image.
        actual: StoreRoot,
    },
}

/// A block store that publishes each node it admits as a file.
#[derive(Debug)]
struct Publish<'files>
{
    /// The node directory.
    nodes: &'files Path,
    /// The admitted nodes, for the commit's own reads.
    held: InMemoryBlockStore,
    /// Whether every node so far was published, or the first failure; the
    /// record plane's error has no room for it.
    published: Result<(), StoreError>,
}

impl BlockStore for Publish<'_>
{
    /// Admit a node, then publish it.
    ///
    /// # Specification
    /// - ensures: on success the node is held and its file holds its bytes.
    /// - fails: the record plane refuses the node, or the file can't be
    ///   published; the failure is kept for [`Store::keep`].
    /// - panics: none.
    /// - executable: none — publication is effectful; reopening is the oracle.
    ///
    /// # Errors
    /// - [`RecordTreeError`]: the node is refused or wasn't published.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — a committed store reopens from its files.
    /// - witness: `store::tests::a_reopened_store_proves_as_the_committed_one`
    fn insert(
        &mut self,
        node: StoredNode<'_>,
    ) -> Result<(), RecordTreeError>
    {
        let identity = node.identity();
        let path = self.nodes.join(identity.to_string());
        if let Err(failure) = put(self.nodes, &path, Body(node.bytes().as_ref())) {
            if self.published.is_ok() {
                self.published = Err(failure);
            }
            return Err(RecordTreeError::UnknownNode { hash: identity });
        }
        self.held.insert(node)
    }

    /// Load an admitted node.
    ///
    /// # Specification
    /// trivial.
    fn load(
        &self,
        hash: NodeHash,
    ) -> Result<StoredNode<'_>, RecordTreeError>
    {
        self.held.load(hash)
    }
}

impl Store
{
    /// Select the keyed plane's directory without creating it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn open(state: &StateDir) -> Self
    {
        Self(state.index_dir())
    }

    /// Commit a project store, publishing every node and then its manifest.
    ///
    /// # Specification
    /// - ensures: on success every node and the manifest are held under the
    ///   returned root, which is the store's; valid existing files remain
    ///   unchanged and damaged ones are repaired.
    /// - fails: the commit is refused, or a file can't be published.
    /// - panics: none.
    /// - executable: none — durable publication and repair can't be replayed in
    ///   a predicate; reopening and deliberately damaged files are the oracle.
    ///
    /// # Errors
    /// - [`StoreError`]: a refused commit or failed persistence.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — reopening reproduces the committed store's proofs; L3
    ///   — publishing again repairs damaged node and manifest files.
    /// - witness: `store::tests::a_reopened_store_proves_as_the_committed_one`
    /// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
    #[inline]
    pub fn keep(
        &self,
        project: &mut gandr_storage_schema::Store,
    ) -> Result<StoreRoot, StoreError>
    {
        let nodes = self.0.join("nodes");
        let manifests = self.0.join("manifests");
        for directory in [&nodes, &manifests] {
            std::fs::create_dir_all(directory).map_err(failed(directory))?;
        }
        let mut publish = Publish {
            nodes: &nodes,
            held: InMemoryBlockStore::new(),
            published: Ok(()),
        };
        let committed = project.commit(&mut publish);
        publish.published?;
        let root = committed?;
        let image = project.manifest().encode();
        put(
            &manifests,
            &manifests.join(root.to_string()),
            Body(image.as_ref()),
        )?;
        Ok(root)
    }

    /// Read and authenticate a manifest before opening any node file.
    ///
    /// # Specification
    /// - ensures: the returned manifest hashes to the requested root.
    /// - fails: absence, a malformed image, mislabeling or file failure.
    /// - panics: none.
    /// - executable: none — filesystem lookup and authentication are the
    ///   boundary itself; a mislabeled manifest in an empty node store is the
    ///   oracle.
    ///
    /// # Errors
    /// - [`StoreError`]: lookup, decoding or identity failure.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a damaged manifest fails before any node is read.
    /// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
    #[inline]
    pub fn manifest(
        &self,
        root: StoreRoot,
    ) -> Result<StoreManifest, StoreError>
    {
        let path = self.0.join("manifests").join(root.to_string());
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(failure) if failure.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Unheld(root));
            },
            Err(source) => return Err(failed(&path)(source)),
        };
        let manifest = StoreManifest::decode(ManifestImage::from(bytes.as_slice()))?;
        let actual = manifest.identity();
        if actual != root {
            return Err(StoreError::Mislabeled {
                named: root,
                actual,
            });
        }
        Ok(manifest)
    }

    /// Reopen a committed project store from authenticated nodes.
    ///
    /// # Specification
    /// - ensures: on success the store's root is `root`.
    /// - fails: manifest refusal, absent or altered nodes, or tables the
    ///   project store refuses to reopen.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StoreError`]: storage, authentication or reopening failure.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — a reopened store proves as the committed one; L3 —
    ///   changed node bytes fail authentication before decoding.
    /// - witness: `store::tests::a_reopened_store_proves_as_the_committed_one`
    /// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |store| store.root() == root))]
    #[inline]
    pub fn load(
        &self,
        keyed: &Keyed,
        root: StoreRoot,
    ) -> Result<gandr_storage_schema::Store, StoreError>
    {
        let manifest = self.manifest(root)?;
        let mut blocks = InMemoryBlockStore::new();
        let mut work = DecodeWork::new();
        for table in manifest.tables() {
            self.gather(table.root_node(), &mut blocks, &mut work)?;
        }
        Ok(gandr_storage_schema::Store::open(
            keyed.schema.clone(),
            keyed::params(),
            &manifest,
            &blocks,
        )?)
    }

    /// Read this store's last locally derived project.
    ///
    /// # Specification
    /// - ensures: absence is a cold cache; a present cursor names one root.
    /// - fails: file access or an incorrectly sized cursor.
    /// - panics: none.
    /// - executable: none — filesystem lookup is effectful; refreshing the
    ///   local derivation is compared with a whole rebuild.
    ///
    /// # Errors
    /// - [`StoreError::File`]: the cursor cannot be read.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a stored project cursor seeds a refresh whose
    ///   contents equal a whole rebuild.
    /// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
    pub(crate) fn cached(
        &self,
        project: TreeId,
    ) -> Result<Cached, StoreError>
    {
        let path = self.0.join("projects").join(project.to_string());
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(failure) if failure.kind() == io::ErrorKind::NotFound => {
                return Ok(Cached::Absent);
            },
            Err(source) => return Err(failed(&path)(source)),
        };
        let bytes: [u8; STORE_ROOT_LEN] = bytes.try_into().map_err(|_bytes| {
            failed(&path)(io::Error::new(
                io::ErrorKind::InvalidData,
                "project cursor must hold one store root",
            ))
        })?;
        Ok(Cached::Root(StoreRoot::from(bytes)))
    }

    /// Publish the cursor only after the store has been kept.
    ///
    /// # Specification
    /// - requires: `root` names a complete, locally derived project.
    /// - ensures: the next refresh can reuse this store without attesting.
    /// - fails: directory creation or atomic publication failure.
    /// - panics: none.
    /// - executable: none — atomic cursor publication is effectful; the
    ///   subsequent refresh must reproduce a whole derivation.
    ///
    /// # Errors
    /// - [`StoreError::File`]: persistence failed.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — publication makes the next refresh reproduce the
    ///   independently rebuilt store.
    /// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
    pub(crate) fn remember(
        &self,
        project: TreeId,
        root: StoreRoot,
    ) -> Result<(), StoreError>
    {
        let directory = self.0.join("projects");
        std::fs::create_dir_all(&directory).map_err(failed(&directory))?;
        put(
            &directory,
            &directory.join(project.to_string()),
            Body(root.as_ref()),
        )
    }

    /// Read a held node's bytes, unauthenticated.
    ///
    /// # Specification
    /// - ensures: the file's bytes; a reader authenticates them by identity.
    /// - fails: absence or file failure.
    /// - panics: none.
    /// - executable: none — a file read is its own specification.
    ///
    /// # Errors
    /// - [`StoreError::File`]: the node isn't held or can't be read.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — a reader holding nothing fetches every node of a
    ///   served store.
    /// - witness: `stream::tests::a_fetched_store_is_the_served_one`
    pub(crate) fn node(
        &self,
        hash: NodeHash,
    ) -> Result<OwnedEncodedNode, StoreError>
    {
        let path = self.0.join("nodes").join(hash.to_string());
        std::fs::read(&path)
            .map(OwnedEncodedNode::from)
            .map_err(failed(&path))
    }

    /// Publish an authenticated node.
    ///
    /// # Specification
    /// - requires: `bytes` hash to `hash`.
    /// - ensures: as [`put`].
    /// - fails: as [`put`].
    /// - panics: none.
    /// - executable: none — publication is effectful; reopening is the oracle.
    ///
    /// # Errors
    /// - [`StoreError::File`]: persistence failed.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — a fetched store reopens from its files.
    /// - witness: `stream::tests::a_fetched_store_is_the_served_one`
    pub(crate) fn hold_node(
        &self,
        hash: NodeHash,
        bytes: Body<'_>,
    ) -> Result<(), StoreError>
    {
        let nodes = self.0.join("nodes");
        std::fs::create_dir_all(&nodes).map_err(failed(&nodes))?;
        put(&nodes, &nodes.join(hash.to_string()), bytes)
    }

    /// Publish an authenticated manifest image, after its nodes.
    ///
    /// # Specification
    /// - requires: `image` hashes to `root`, and every node it names is held.
    /// - ensures: as [`put`].
    /// - fails: as [`put`].
    /// - panics: none.
    /// - executable: none — publication is effectful; reopening is the oracle.
    ///
    /// # Errors
    /// - [`StoreError::File`]: persistence failed.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — a fetched store reopens from its files.
    /// - witness: `stream::tests::a_fetched_store_is_the_served_one`
    pub(crate) fn hold_manifest(
        &self,
        root: StoreRoot,
        image: Body<'_>,
    ) -> Result<(), StoreError>
    {
        let manifests = self.0.join("manifests");
        std::fs::create_dir_all(&manifests).map_err(failed(&manifests))?;
        put(&manifests, &manifests.join(root.to_string()), image)
    }

    /// Admit a table's nodes from its root down, each authenticated before
    /// it is decoded.
    ///
    /// # Specification
    /// - ensures: on success every node of the tree is held in `blocks`.
    /// - fails: file, identity, node language or decode-work refusal.
    /// - panics: none.
    /// - executable: none — node I/O and authentication are effectful; the
    ///   corruption witness checks the independent hash refusal.
    ///
    /// # Errors
    /// - [`StoreError`]: a node cannot be read or authenticated.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — corruption is refused by the store's hash variant.
    /// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
    fn gather(
        &self,
        root: NodeHash,
        blocks: &mut InMemoryBlockStore,
        work: &mut DecodeWork,
    ) -> Result<(), StoreError>
    {
        let mut pending = vec![root];
        while let Some(hash) = pending.pop() {
            let bytes = self.node(hash)?;
            blocks.insert(StoredNode::new(hash, bytes.as_borrowed()))?;
            if let DecodedNode::Internal(internal) = decode_node(blocks.load(hash)?.bytes(), work)?
            {
                pending.extend(internal.children().iter().map(ChildRef::identity));
            }
        }
        Ok(())
    }
}

/// Atomically publish a synced image beside its content-addressed name.
///
/// # Specification
/// - ensures: success leaves the complete image named, retains an identical
///   file or atomically repairs a damaged one; failed writes expose no partial
///   image.
/// - fails: file comparison, creation, write, sync or rename refusal.
/// - panics: none.
/// - executable: none — atomic filesystem publication is not observable through
///   the return value; reopening and damaged-file repair provide the oracle.
///
/// # Errors
/// - [`StoreError::File`]: persistence failed at the named path.
///
/// # Adequacy
/// - hypothesis: L2 — reopened storage reproduces complete proofs; L3 — damaged
///   files are repaired on publication.
/// - witness: `store::tests::a_reopened_store_proves_as_the_committed_one`
/// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
fn put(
    directory: &Path,
    path: &Path,
    bytes: Body<'_>,
) -> Result<(), StoreError>
{
    match std::fs::File::open(path) {
        Ok(mut existing) => {
            let mut remaining = bytes.0;
            let mut buffer = [0_u8; 8192];
            loop {
                let count = existing.read(&mut buffer).map_err(failed(path))?;
                if count == 0 {
                    if remaining.is_empty() {
                        return Ok(());
                    }
                    break;
                }
                let Some((expected, rest)) = remaining.split_at_checked(count)
                else {
                    break;
                };
                if buffer.get(.. count) != Some(expected) {
                    break;
                }
                remaining = rest;
            }
        },
        Err(failure) if failure.kind() == io::ErrorKind::NotFound => {},
        Err(failure) => return Err(failed(path)(failure)),
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(failed(path))?;
    temporary.write_all(bytes.0).map_err(failed(path))?;
    temporary.as_file().sync_all().map_err(failed(path))?;
    let _file = temporary
        .persist(path)
        .map_err(|failure| failed(path)(failure.error))?;
    Ok(())
}

/// Attach the local path to a file failure.
///
/// # Specification
/// trivial.
fn failed(path: &Path) -> impl Fn(io::Error) -> StoreError + '_
{
    |source| StoreError::File {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests
{
    use domhringr_record_tree::StateDir;
    use gandr_storage_records::RecordTreeError;
    use gandr_storage_schema::Question;
    use gandr_storage_schema::Row;

    use super::Store;
    use super::StoreError;
    use crate::keyed;
    use crate::keyed::Keyed;
    use crate::keyed::Number;
    use crate::keyed::Standing;

    /// A store of 256 tasks, each with one attempt.
    ///
    /// # Specification
    /// trivial.
    fn tasks(keyed: &Keyed) -> gandr_storage_schema::Store
    {
        use core::fmt::Write as _;
        let mut store =
            gandr_storage_schema::Store::new(keyed.schema.clone(), keyed::params()).unwrap();
        let mut name = String::new();
        for index in 0 .. 256_u32 {
            name.clear();
            write!(name, "task-{index}").unwrap();
            let task = store
                .add_part(
                    keyed.task,
                    &Row::new()
                        .value(keyed.task_name, keyed::text(keyed::Text(&name)))
                        .value(keyed.task_standing, Standing::Undispatched.value())
                        .value(
                            keyed.task_heads,
                            keyed::heads(&domhringr_record_tree::Heads::from_iter([])),
                        ),
                )
                .unwrap();
            let _attempt = store
                .add_part(
                    keyed.attempt,
                    &Row::new()
                        .arrow(keyed.attempt_task, task)
                        .value(keyed.attempt_number, keyed::number(Number(1))),
                )
                .unwrap();
        }
        store
    }

    #[test]
    fn a_reopened_store_proves_as_the_committed_one()
    {
        let keyed = Keyed::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let mut built = tasks(&keyed);
        let committed = Store::open(&state).keep(&mut built).unwrap();
        let loaded = Store::open(&state).load(&keyed, committed).unwrap();
        assert_eq!(loaded.root(), committed);
        for task in built.parts(keyed.task).unwrap() {
            let questions = [
                Question::Value {
                    attribute: keyed.task_name,
                    part: task,
                },
                Question::Preimage {
                    arrow: keyed.attempt_task,
                    target: task,
                },
            ];
            for question in questions {
                let proof = loaded.prove(&question).unwrap();
                assert_eq!(proof, built.prove(&question).unwrap());
                let _answer = proof
                    .verify(committed, &keyed.schema, keyed::params(), &question)
                    .unwrap();
            }
        }
        let mut empty =
            gandr_storage_schema::Store::new(keyed.schema.clone(), keyed::params()).unwrap();
        let committed = Store::open(&state).keep(&mut empty).unwrap();
        let loaded = Store::open(&state).load(&keyed, committed).unwrap();
        let question = Question::ValuePreimage {
            attribute: keyed.task_name,
            value: keyed::text(keyed::Text("missing")),
        };
        assert_eq!(
            loaded.prove(&question).unwrap(),
            empty.prove(&question).unwrap()
        );
    }

    #[test]
    fn a_tampered_node_file_is_refused_at_load()
    {
        let keyed = Keyed::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let mut built = tasks(&keyed);
        let store = Store::open(&state);
        let committed = store.keep(&mut built).unwrap();
        let node = built.manifest().tables()[usize::from(keyed.task)].root_node();
        let path = state.index_dir().join("nodes").join(node.to_string());
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(path, bytes).unwrap();
        assert!(
            matches!(store.load(&keyed, committed), Err(StoreError::Records(RecordTreeError::HashMismatch { expected, .. })) if expected == node)
        );
        assert_eq!(store.keep(&mut built).unwrap(), committed);
        assert_eq!(store.load(&keyed, committed).unwrap().root(), committed);
        let manifest = state
            .index_dir()
            .join("manifests")
            .join(committed.to_string());
        std::fs::write(manifest, b"damaged manifest").unwrap();
        assert!(matches!(
            store.load(&keyed, committed),
            Err(StoreError::Project(_))
        ));
        assert_eq!(store.keep(&mut built).unwrap(), committed);
        assert_eq!(store.load(&keyed, committed).unwrap().root(), committed);
    }
}
