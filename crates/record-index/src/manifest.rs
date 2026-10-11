//! A typed, loadable identity binding one ordered tree.

use anodized::spec;
use domhringr_record_tree::IndexDigest;
use gandr_storage_records::NodeHash;
use gandr_storage_records::RecordCount;
use gandr_storage_records::RecordTree;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::TreeParams;
use gandr_storage_records::TreeRoot;

use crate::wire::Body;
use crate::wire::Cursor;
use crate::wire::Length;
use crate::wire::WireError;
use crate::wire::WireImage;

/// The manifest image's domain separator.
const DOMAIN: &[u8; 27] = b"domhringr:index:manifest:v1";

/// The semantic language of the records an index carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum IndexKind
{
    /// One task's admitted moves.
    Dialogue = 1,
    /// A project's task entries and nested manifests.
    Project = 2,
    /// Reverse references from values or revisions to dialogue moves.
    Provenance = 3,
}

impl From<IndexKind> for u8
{
    /// Read the manifest discriminator.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(kind: IndexKind) -> Self
    {
        match kind {
            | IndexKind::Dialogue => 1,
            | IndexKind::Project => 2,
            | IndexKind::Provenance => 3,
        }
    }
}

/// A supported manifest, checked independently of any node store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest
{
    /// The tree's semantic language.
    kind: IndexKind,
    /// The number of records the root commits to.
    count: RecordCount,
    /// The identity a holder can load as the root node.
    node: NodeHash,
}

/// A manifest is malformed or names an unsupported field.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError
{
    /// The image has the wrong domain separator.
    #[error("foreign index manifest domain")]
    Domain,
    /// The image does not name the expected kind.
    #[error("foreign index kind")]
    Kind,
    /// The image uses another layout.
    #[error("foreign index layout")]
    Layout,
    /// The boundary rule differs from the supported record plane.
    #[error("foreign index boundary commitment")]
    Commitment,
    /// The expected digest does not name the supplied bytes.
    #[error("index manifest identity mismatch")]
    Identity,
    /// Framing failed before interpretation.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The record plane refused the resealed root.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
}

impl Manifest
{
    /// Bind a built tree to its semantic language.
    ///
    /// # Specification
    /// - ensures: count and root node are exactly those of the built tree.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — each bound field changes the encoded identity.
    /// - witness: `manifest::tests::every_field_moves_the_identity`
    #[spec(ensures: |ret| ret.kind == kind && ret.count == tree.root().record_count() && ret.node == tree.root_node_hash())]
    #[inline]
    #[must_use]
    pub fn new(
        kind: IndexKind,
        tree: &RecordTree,
    ) -> Self
    {
        Self {
            kind,
            count: tree.root().record_count(),
            node: tree.root_node_hash(),
        }
    }

    /// The index language bound by this manifest.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> IndexKind
    {
        self.kind
    }

    /// The committed record count.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn count(self) -> RecordCount
    {
        self.count
    }

    /// The loadable root node identity.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn node(self) -> NodeHash
    {
        self.node
    }

    /// Write the layout-one manifest image.
    ///
    /// # Specification
    /// - ensures: writes domain, kind, little-endian layout, length-prefixed
    ///   opaque boundary commitment, count and node identity in that order.
    /// - fails: the boundary image length exceeds the u64 framing.
    ///
    /// # Errors
    /// - [`WireError::Length`]: the commitment length is unrepresentable.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — mutations of every field distinguish what identity
    ///   binds.
    /// - witness: `manifest::tests::every_field_moves_the_identity`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |image| Self::decode(image, self.kind).is_ok_and(|decoded| decoded == *self)))]
    #[inline]
    pub fn encode(&self) -> Result<WireImage, WireError>
    {
        let commitment = TreeParams::current().boundary_commitment();
        let length =
            u64::try_from(commitment.as_ref().len()).map_err(|_overflow| WireError::Length)?;
        let mut image = Vec::with_capacity(96);
        image.extend_from_slice(DOMAIN);
        image.push(u8::from(self.kind));
        image.extend_from_slice(&1_u16.to_le_bytes());
        image.extend_from_slice(&length.to_le_bytes());
        image.extend_from_slice(commitment.as_ref());
        image.extend_from_slice(&u64::from(self.count).to_le_bytes());
        image.extend_from_slice(self.node.as_ref());
        Ok(WireImage(image))
    }

    /// Name the complete manifest image by its BLAKE3 digest.
    ///
    /// # Specification
    /// - ensures: the identity is BLAKE3 over precisely the encoded image.
    /// - fails: the boundary image length exceeds the u64 framing.
    ///
    /// # Errors
    /// - [`WireError::Length`]: the commitment length is unrepresentable.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — independent hashing observes every bound field.
    /// - witness: `manifest::tests::every_field_moves_the_identity`
    #[spec(ensures: |ret| match (ret, self.encode()) {
        (Ok(digest), Ok(image)) => digest.as_ref() == blake3::hash(image.as_ref()).as_bytes(),
        (Err(_), Err(_)) => true,
        _ => false,
    })]
    #[inline]
    pub fn identity(&self) -> Result<IndexDigest, WireError>
    {
        let commitment = TreeParams::current().boundary_commitment();
        let length =
            u64::try_from(commitment.as_ref().len()).map_err(|_overflow| WireError::Length)?;
        let mut hasher = blake3::Hasher::new();
        let _domain = hasher.update(DOMAIN);
        let _kind = hasher.update(&[u8::from(self.kind)]);
        let _layout = hasher.update(&1_u16.to_le_bytes());
        let _length = hasher.update(&length.to_le_bytes());
        let _boundary = hasher.update(commitment.as_ref());
        let _count = hasher.update(&u64::from(self.count).to_le_bytes());
        let _node = hasher.update(self.node.as_ref());
        Ok(IndexDigest::from(*hasher.finalize().as_bytes()))
    }

    /// Validate a manifest before consulting any node.
    ///
    /// # Specification
    /// - ensures: accepts only the expected kind, layout one and the current
    ///   boundary commitment, with exactly one count and root identity.
    /// - fails: foreign fields, truncated fields and trailing bytes are named.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ManifestError`]: domain, kind, layout, commitment or framing
    ///   mismatch.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — each incompatible field is refused without node I/O.
    /// - witness: `manifest::tests::a_foreign_kind_layout_or_commitment_is_refused_before_any_node`
    #[spec(ensures: |ret| ret.as_ref().is_ok_and(|manifest| manifest.kind == expected) || ret.is_err())]
    #[inline]
    pub fn decode(
        image: &WireImage,
        expected: IndexKind,
    ) -> Result<Self, ManifestError>
    {
        let mut cursor = Cursor::new(Body(image.as_ref()));
        let domain = cursor.fixed::<27>()?;
        if &domain.0 != DOMAIN {
            return Err(ManifestError::Domain);
        }
        let kind = cursor.fixed::<1>()?;
        if kind.0 != [u8::from(expected)] {
            return Err(ManifestError::Kind);
        }
        let layout = cursor.fixed::<2>()?;
        if u16::from_le_bytes(layout.0) != 1 {
            return Err(ManifestError::Layout);
        }
        let length = cursor.fixed::<8>()?;
        let length =
            usize::try_from(u64::from_le_bytes(length.0)).map_err(|_overflow| WireError::Length)?;
        let commitment = cursor.take(Length(length))?;
        if commitment.0 != TreeParams::current().boundary_commitment().as_ref() {
            return Err(ManifestError::Commitment);
        }
        let count = cursor.fixed::<8>()?;
        let node = cursor.fixed::<32>()?;
        cursor.finish()?;
        Ok(Self {
            kind: expected,
            count: RecordCount::from(u64::from_le_bytes(count.0)),
            node: NodeHash::from(node.0),
        })
    }

    /// Reseal the trusted manifest's record-plane root.
    ///
    /// # Specification
    /// - ensures: the resulting root binds current parameters, count and node.
    /// - fails: record-plane parameter refusal is preserved.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RecordTreeError`]: the record plane cannot seal its current
    ///   parameters.
    ///
    /// # Adequacy
    /// - hypothesis: L1 — proofs verify using the manifest alone.
    /// - witness: `prove::tests::every_key_proves_against_the_manifest_alone`
    #[inline]
    pub fn root(self) -> Result<TreeRoot, RecordTreeError>
    {
        TreeRoot::seal(TreeParams::current(), self.count, self.node)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn every_field_moves_the_identity()
    {
        let tree = RecordTree::build(&[], TreeParams::current()).unwrap();
        let manifest = Manifest::new(IndexKind::Dialogue, &tree);
        let image = manifest.encode().unwrap();
        assert_eq!(
            manifest.identity().unwrap().as_ref(),
            blake3::hash(image.as_ref()).as_bytes()
        );
        // Kind, layout, commitment body, count and root node, independently.
        for offset in [27, 28, 38, 48, 56] {
            let mut changed = image.clone();
            changed.0[offset] ^= 1;
            assert_ne!(
                blake3::hash(changed.as_ref()).as_bytes(),
                manifest.identity().unwrap().as_ref()
            );
        }
        assert_eq!(
            Manifest::decode(&image, IndexKind::Dialogue).unwrap(),
            manifest
        );
        assert_eq!(manifest.root().unwrap(), tree.root());
    }

    #[test]
    fn a_foreign_kind_layout_or_commitment_is_refused_before_any_node()
    {
        let tree = RecordTree::build(&[], TreeParams::current()).unwrap();
        let image = Manifest::new(IndexKind::Dialogue, &tree).encode().unwrap();
        assert!(matches!(
            Manifest::decode(&image, IndexKind::Project),
            Err(ManifestError::Kind)
        ));
        let mut layout = image.clone();
        layout.0[28] = 2;
        assert!(matches!(
            Manifest::decode(&layout, IndexKind::Dialogue),
            Err(ManifestError::Layout)
        ));
        let mut commitment = image.clone();
        commitment.0[38] ^= 1;
        assert!(matches!(
            Manifest::decode(&commitment, IndexKind::Dialogue),
            Err(ManifestError::Commitment)
        ));
        let root = tempfile::tempdir().unwrap();
        let state = domhringr_record_tree::StateDir::from(root.path().to_path_buf());
        let manifests = state.index_dir().join("manifests");
        std::fs::create_dir_all(&manifests).unwrap();
        let store = crate::store::Store::open(&state);
        let mut kind = image.clone();
        kind.0[27] = 0xff;
        for (invalid, expected) in [
            (kind, ManifestError::Kind),
            (layout, ManifestError::Layout),
            (commitment, ManifestError::Commitment),
        ] {
            let digest = IndexDigest::from(*blake3::hash(invalid.as_ref()).as_bytes());
            std::fs::write(manifests.join(digest.to_string()), invalid.as_ref()).unwrap();
            assert!(matches!(
                (store.load(digest), expected),
                (
                    Err(crate::store::StoreError::Manifest(ManifestError::Kind)),
                    ManifestError::Kind
                ) | (
                    Err(crate::store::StoreError::Manifest(ManifestError::Layout)),
                    ManifestError::Layout
                ) | (
                    Err(crate::store::StoreError::Manifest(
                        ManifestError::Commitment
                    )),
                    ManifestError::Commitment
                )
            ));
        }
        for length in 0 .. image.0.len() {
            assert!(
                Manifest::decode(&WireImage(image.0[.. length].to_vec()), IndexKind::Dialogue)
                    .is_err()
            );
        }
        let mut trailing = image;
        trailing.0.push(0);
        assert!(matches!(
            Manifest::decode(&trailing, IndexKind::Dialogue),
            Err(ManifestError::Wire(WireError::Trailing))
        ));
    }
}
