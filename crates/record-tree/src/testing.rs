//! Signed commits made by hand for the library's tests: any author, any
//! parents, any blob, as a remote peer could send them.

use alloc::collections::BTreeSet;

use future_form::Sendable;
use sedimentree_core::blob::Blob;
use sedimentree_core::blob::verified::VerifiedBlobMeta;
use sedimentree_core::crypto::digest::Digest;
use sedimentree_core::loose_commit::LooseCommit;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::peer::id::PeerId;
use subduction_crypto::signer::memory::MemorySigner;
use subduction_crypto::verified_meta::VerifiedMeta;

use crate::id::PeerKey;
use crate::id::TreeId;
use crate::identity::TreeKey;
use crate::receipt::Receipt;

/// A multi-threaded runtime, as the peer binary runs.
///
/// # Specification
/// trivial.
pub fn runtime() -> tokio::runtime::Runtime
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The signer every test's tree owner signs with.
///
/// # Specification
/// trivial.
pub fn owner() -> MemorySigner
{
    MemorySigner::from_bytes(&[1; 32])
}

/// The signer of a second peer, a member only once granted.
///
/// # Specification
/// trivial.
pub fn other() -> MemorySigner
{
    MemorySigner::from_bytes(&[2; 32])
}

/// The peer key `signer` authors as.
///
/// # Specification
/// trivial.
pub fn key(signer: &MemorySigner) -> PeerKey
{
    PeerKey::new(PeerId::from(signer.verifying_key()))
}

/// The key of the tree the tests open.
///
/// # Specification
/// trivial.
pub fn tree_key() -> TreeKey
{
    TreeKey::new(iroh::SecretKey::from_bytes(&[3; 32]))
}

/// The key of another tree, which a misplaced receipt names.
///
/// # Specification
/// trivial.
pub fn elsewhere_key() -> TreeKey
{
    TreeKey::new(iroh::SecretKey::from_bytes(&[4; 32]))
}

/// The id of `commit`.
///
/// # Specification
/// trivial.
pub fn id(commit: &VerifiedMeta<LooseCommit>) -> CommitId
{
    commit.payload().head()
}

/// The id a commit of `receipt` takes: the BLAKE3 digest of its encoding.
///
/// # Specification
/// trivial.
pub fn digest(receipt: &Receipt) -> CommitId
{
    CommitId::new(Digest::<Blob>::hash(&receipt.encode().unwrap()).into_bytes())
}

/// A commit of `blob` to `tree` naming the commit ids `parents`, signed by
/// `signer`, its id the blob's BLAKE3 digest.
///
/// # Specification
/// trivial.
pub async fn seal_on(
    signer: &MemorySigner,
    tree: TreeId,
    parents: BTreeSet<CommitId>,
    blob: Blob,
) -> VerifiedMeta<LooseCommit>
{
    let head = CommitId::new(Digest::<Blob>::hash(&blob).into_bytes());
    VerifiedMeta::seal::<Sendable, _>(
        signer,
        (tree.sedimentree(), head, parents),
        VerifiedBlobMeta::new(blob),
    )
    .await
}

/// A commit of `blob` to `tree` on `parents`, signed by `signer`, its id the
/// blob's BLAKE3 digest.
///
/// # Specification
/// trivial.
pub async fn seal(
    signer: &MemorySigner,
    tree: TreeId,
    parents: &[&VerifiedMeta<LooseCommit>],
    blob: Blob,
) -> VerifiedMeta<LooseCommit>
{
    let parents = parents.iter().map(|parent| id(parent)).collect();
    seal_on(signer, tree, parents, blob).await
}

/// A commit of `receipt` to `tree` on `parents`, signed by `signer`.
///
/// # Specification
/// trivial.
pub async fn commit(
    signer: &MemorySigner,
    tree: TreeId,
    parents: &[&VerifiedMeta<LooseCommit>],
    receipt: &Receipt,
) -> VerifiedMeta<LooseCommit>
{
    seal(signer, tree, parents, receipt.encode().unwrap()).await
}
