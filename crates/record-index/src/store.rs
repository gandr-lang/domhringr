//! Content-addressed node files, published before their manifest.

use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use anodized::spec;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::StateDir;
use gandr_storage_records::BlockStore as _;
use gandr_storage_records::DecodeWork;
use gandr_storage_records::DecodedNode;
use gandr_storage_records::EncodedNode;
use gandr_storage_records::InMemoryBlockStore;
use gandr_storage_records::NodeHash;
use gandr_storage_records::Record;
use gandr_storage_records::RecordTree;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::StoredNode;
use gandr_storage_records::TreeParams;
use gandr_storage_records::decode_node;

use crate::Index;
use crate::IndexKind;
use crate::Manifest;
use crate::ManifestError;
use crate::WireImage;
use crate::wire::Body;
use crate::wire::WireError;

/// A peer's derived index files. No manifest or node is garbage-collected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Store(PathBuf);

/// Why a named index cannot be written or authenticated.
#[derive(Debug, thiserror::Error)]
pub enum StoreError
{
    /// No manifest is held under this identity.
    #[error("unheld {0}")]
    Unheld(IndexDigest),
    /// A named file failed an I/O operation.
    #[error("index file {}: {source}", path.display())]
    File
    {
        /// The file or directory involved.
        path: PathBuf,
        /// The underlying I/O failure.
        source: io::Error,
    },
    /// A manifest carries unsupported fields or malformed framing.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A byte length cannot be represented.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Node authentication or reconstruction failed.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
    /// The manifest's content identity differs from the requested name.
    #[error("manifest {named} contains {actual}")]
    Mislabeled
    {
        /// The requested content address.
        named: IndexDigest,
        /// The identity computed over the held image.
        actual: IndexDigest,
    },
    /// The rebuilt tree does not match the manifest's root and count.
    #[error("rebuilt tree disagrees with manifest {0}")]
    Root(IndexDigest),
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

    /// Publish all immutable node images, then the manifest naming them.
    ///
    /// # Specification
    /// - ensures: a successful write leaves all nodes and the manifest held;
    ///   valid existing files remain unchanged and damaged images are repaired.
    /// - fails: inconsistent manifest, node encoding, framing or file failures.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StoreError`]: invalid supplied tree or failed persistence.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — reopening reproduces built proofs; L3 — publishing
    ///   derived images repairs damaged node and manifest files.
    /// - witness: `store::tests::a_hydrated_tree_proves_as_the_built_one`
    /// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
    #[inline]
    pub fn keep(
        &self,
        index: &Index,
    ) -> Result<IndexDigest, StoreError>
    {
        let digest = index.manifest.identity()?;
        if Manifest::new(index.manifest.kind(), &index.tree) != index.manifest {
            return Err(StoreError::Root(digest));
        }
        let nodes = self.0.join("nodes");
        let manifests = self.0.join("manifests");
        for directory in [&nodes, &manifests] {
            std::fs::create_dir_all(directory).map_err(failed(directory))?;
        }
        // economy: the record API exposes owned proof nodes, not borrowed
        // encodings. This one clone per publication is removed when it does.
        for node in index.tree.nodes() {
            put(
                &nodes,
                &nodes.join(node.identity().to_string()),
                Body(node.bytes().as_ref()),
            )?;
        }
        let image = index.manifest.encode()?;
        put(
            &manifests,
            &manifests.join(digest.to_string()),
            Body(image.as_ref()),
        )?;
        Ok(digest)
    }

    /// Read and authenticate the manifest before opening any node file.
    ///
    /// # Specification
    /// - ensures: the returned supported manifest hashes to the requested name.
    /// - fails: absence, unsupported fields, mislabeling or file failure.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StoreError`]: manifest lookup, framing or identity failure.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — unsupported manifests fail with an empty node store.
    /// - witness: `manifest::tests::a_foreign_kind_layout_or_commitment_is_refused_before_any_node`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |manifest| manifest.identity().is_ok_and(|identity| identity == digest)))]
    #[inline]
    pub fn manifest(
        &self,
        digest: IndexDigest,
    ) -> Result<Manifest, StoreError>
    {
        let path = self.0.join("manifests").join(digest.to_string());
        let bytes = match std::fs::read(&path) {
            | Ok(bytes) => bytes,
            | Err(failure) if failure.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Unheld(digest));
            },
            | Err(source) => return Err(failed(&path)(source)),
        };
        let image = WireImage(bytes);
        let kind = match image.as_ref().get(27) {
            | Some(&1) => IndexKind::Dialogue,
            | Some(&2) => IndexKind::Project,
            | Some(&3) => IndexKind::Provenance,
            | Some(_) => return Err(ManifestError::Kind.into()),
            | None => return Err(WireError::Truncated.into()),
        };
        let manifest = Manifest::decode(&image, kind)?;
        let actual = manifest.identity()?;
        if actual != digest {
            return Err(StoreError::Mislabeled {
                named: digest,
                actual,
            });
        }
        Ok(manifest)
    }

    /// Hydrate only authenticated nodes and require the rebuilt root to agree.
    ///
    /// # Specification
    /// - ensures: returned records rebuild the named manifest's node and count.
    /// - fails: manifest refusal, absent or altered nodes, internal children,
    ///   unsorted records or a different rebuilt root.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StoreError`]: named storage or authentication failure.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — hydrated proofs equal built proofs; L3 — changed node
    ///   bytes fail authentication before decoding.
    /// - witness: `store::tests::a_hydrated_tree_proves_as_the_built_one`
    /// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |index|
        index.manifest.identity().is_ok_and(|identity| identity == digest)
        && Manifest::new(index.manifest.kind(), &index.tree) == index.manifest))]
    #[inline]
    pub fn load(
        &self,
        digest: IndexDigest,
    ) -> Result<Index, StoreError>
    {
        let manifest = self.manifest(digest)?;
        let mut store = InMemoryBlockStore::new();
        let mut work = DecodeWork::new();
        let root = self.node(manifest.node(), &mut store, &mut work)?;
        let mut leaves = Vec::new();
        match root {
            | DecodedNode::Leaf(leaf) => leaves.push(leaf),
            | DecodedNode::Internal(internal) => {
                for child in internal.children() {
                    let node = self.node(child.identity(), &mut store, &mut work)?;
                    match node {
                        | DecodedNode::Leaf(leaf) => leaves.push(leaf),
                        | DecodedNode::Internal(_) => {
                            return Err(RecordTreeError::InvalidProofShape {
                                context: "an index child must be a leaf".into(),
                            }
                            .into());
                        },
                    }
                }
            },
        }
        // The decoded leaves own their records; release the admission cache
        // before rebuilding so hydration does not retain duplicate node images.
        drop(store);
        let records: Vec<_> = leaves
            .iter()
            .flat_map(gandr_storage_records::LeafNode::records)
            .map(Record::as_record_ref)
            .collect();
        let tree = RecordTree::build(&records, TreeParams::current())?;
        if Manifest::new(manifest.kind(), &tree) != manifest {
            return Err(StoreError::Root(digest));
        }
        Ok(Index { manifest, tree })
    }

    /// Admit one named node into the verifying store before decoding its shape.
    ///
    /// # Specification
    /// - ensures: decoded records come from bytes authenticated under `hash`.
    /// - fails: file, identity, node language or decode-work refusal.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StoreError`]: the node cannot be read or authenticated.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — corruption is refused by the store's hash variant.
    /// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
    fn node(
        &self,
        hash: NodeHash,
        store: &mut InMemoryBlockStore,
        work: &mut DecodeWork,
    ) -> Result<DecodedNode, StoreError>
    {
        let path = self.0.join("nodes").join(hash.to_string());
        let bytes = std::fs::read(&path).map_err(failed(&path))?;
        store.insert(StoredNode::new(hash, EncodedNode::from(bytes.as_slice())))?;
        let node = store.load(hash)?;
        let decoded = decode_node(node.bytes(), work)?;
        Ok(decoded)
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
///
/// # Errors
/// - [`StoreError::File`]: persistence failed at the named path.
///
/// # Adequacy
/// - hypothesis: L2 — reopened storage reproduces complete proofs; L3 — damaged
///   files are repaired on publication.
/// - witness: `store::tests::a_hydrated_tree_proves_as_the_built_one`
/// - witness: `store::tests::a_tampered_node_file_is_refused_at_load`
fn put(
    directory: &Path,
    path: &Path,
    bytes: Body<'_>,
) -> Result<(), StoreError>
{
    match std::fs::File::open(path) {
        | Ok(mut existing) => {
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
        | Err(failure) if failure.kind() == io::ErrorKind::NotFound => {},
        | Err(failure) => return Err(failed(path)(failure)),
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
    use gandr_storage_records::RecordRef;
    use gandr_storage_records::RecordTree;
    use gandr_storage_records::RecordTreeError;
    use gandr_storage_records::TreeParams;

    use super::Store;
    use super::StoreError;
    use crate::Index;
    use crate::IndexKind;

    #[test]
    fn a_hydrated_tree_proves_as_the_built_one()
    {
        let keys: Vec<_> = (0 .. 256_u32).map(u32::to_be_bytes).collect();
        let records: Vec<_> = keys
            .iter()
            .map(|key| RecordRef::new(key.as_slice(), b"stored value"))
            .collect();
        let built = Index::new(
            IndexKind::Dialogue,
            RecordTree::build(&records, TreeParams::current()).unwrap(),
        );
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let digest = Store::open(&state).keep(&built).unwrap();
        let loaded = Store::open(&state).load(digest).unwrap();
        assert_eq!(loaded.manifest, built.manifest);
        assert_eq!(loaded.tree.records(), built.tree.records());
        for record in loaded.tree.records() {
            let proof = loaded.tree.prove_membership(record.key()).unwrap();
            assert_eq!(proof, built.tree.prove_membership(record.key()).unwrap());
            proof
                .verify(
                    &loaded.manifest.root().unwrap(),
                    record.key(),
                    record.value(),
                )
                .unwrap();
        }
        let empty = Index::new(
            IndexKind::Dialogue,
            RecordTree::build(&[], TreeParams::current()).unwrap(),
        );
        let digest = Store::open(&state).keep(&empty).unwrap();
        let loaded = Store::open(&state).load(digest).unwrap();
        let absent = loaded.tree.prove_non_membership(b"missing".into()).unwrap();
        assert_eq!(
            absent,
            empty.tree.prove_non_membership(b"missing".into()).unwrap()
        );
    }

    #[test]
    fn a_tampered_node_file_is_refused_at_load()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let tree =
            RecordTree::build(&[RecordRef::new(b"key", b"value")], TreeParams::current()).unwrap();
        let index = Index::new(IndexKind::Dialogue, tree);
        let store = Store::open(&state);
        let digest = store.keep(&index).unwrap();
        let node = index.manifest.node();
        let path = state.index_dir().join("nodes").join(node.to_string());
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(path, bytes).unwrap();
        assert!(
            matches!(store.load(digest), Err(StoreError::Records(RecordTreeError::HashMismatch { expected, .. })) if expected == node)
        );
        assert_eq!(store.keep(&index).unwrap(), digest);
        let repaired = store.load(digest).unwrap();
        assert_eq!(repaired.tree.records(), index.tree.records());
        let manifest = state.index_dir().join("manifests").join(digest.to_string());
        std::fs::write(manifest, b"damaged manifest").unwrap();
        assert_eq!(store.keep(&index).unwrap(), digest);
        assert_eq!(store.load(digest).unwrap().manifest, index.manifest);
    }
}
