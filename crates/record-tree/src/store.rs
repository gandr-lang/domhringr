//! The tree store: a subduction peer over one redb file, committing content
//! into sedimentrees and reading their heads.

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use std::path::PathBuf;

use future_form::Sendable;
use sedimentree_core::blob::Blob;
use sedimentree_core::crypto::digest::Digest;
use sedimentree_core::depth::CountLeadingZeroBytes;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::connection::message::SyncMessage;
use subduction_core::handler::sync::SyncHandler;
use subduction_core::policy::open::OpenPolicy;
use subduction_core::subduction::Subduction;
use subduction_core::subduction::builder::SubductionBuilder;
use subduction_core::subduction::error::WriteError;
use subduction_core::transport::message::MessageTransport;
use subduction_crypto::signer::memory::MemorySigner;
use subduction_iroh::transport::IrohTransport;
use subduction_redb_storage::RedbStorage;
use subduction_redb_storage::RedbStorageError;

use crate::id::TreeId;
use crate::identity::Identity;
use crate::identity::StateDir;
use crate::runtime::TokioSpawner;
use crate::runtime::TokioTimer;

/// The connection type every peer speaks: subduction messages over iroh.
pub type Transport = MessageTransport<IrohTransport>;

/// The subduction peer this crate runs: redb storage, an open policy, the
/// Tokio glue, iroh connections.
pub type Engine = Subduction<
    'static,
    Sendable,
    RedbStorage,
    Transport,
    SyncHandler<Sendable, RedbStorage, Transport, OpenPolicy, CountLeadingZeroBytes, TokioSpawner>,
    OpenPolicy,
    MemorySigner,
    TokioTimer,
    TokioSpawner,
    CountLeadingZeroBytes,
>;

/// A failed local write, as subduction reports it for this engine.
type EngineWriteError = WriteError<Sendable, RedbStorage, Transport, SyncMessage>;

/// The bytes a commit carries.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Content(Blob);

impl From<Vec<u8>> for Content
{
    /// Take bytes as commit content.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(bytes: Vec<u8>) -> Self
    {
        Self(Blob::new(bytes))
    }
}

/// A tree's heads: the commits no other commit in the tree names as a
/// parent, ordered by commit id.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Heads(BTreeSet<CommitId>);

impl Heads
{
    /// The heads in ascending commit-id order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &CommitId>
    {
        self.0.iter()
    }
}

impl core::fmt::Display for Heads
{
    /// Write each head as 64 lowercase hex digits on its own line, in
    /// ascending order.
    ///
    /// # Specification
    /// - ensures: one line per head, each terminated by a newline; nothing for
    ///   a tree without heads. Lowercase hex of equal length sorts as the bytes
    ///   it spells, so the lines are sorted as text too.
    /// - panics: none.
    #[inline]
    fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
    ) -> core::fmt::Result
    {
        for head in &self.0 {
            writeln!(f, "{head}")?;
        }
        Ok(())
    }
}

/// A peer's tree store, open on its state directory.
///
/// Concurrency: the store owns a subduction engine whose listener and
/// connection-manager tasks run detached on the Tokio runtime the store was
/// opened on; they end when the engine shuts down ([`Node::close`]) or the
/// runtime does. The redb file is held exclusively for the store's lifetime:
/// a second process opening the same state directory is refused until this
/// one exits.
///
/// [`Node::close`]: crate::node::Node::close
pub struct Peer
{
    /// The subduction engine over the store.
    engine: Arc<Engine>,
    /// The identity the engine signs with and the endpoint binds.
    identity: Identity,
    /// The runtime the engine's tasks and its connections' tasks run on.
    runtime: tokio::runtime::Handle,
}

impl Peer
{
    /// Open the tree store beneath `state` and start its engine.
    ///
    /// # Specification
    /// - requires: called from within a Tokio runtime, which runs the engine.
    /// - ensures: the store's redb file exists beneath `state` and is held by
    ///   this peer; the engine signs with `identity`'s signer and admits every
    ///   peer and every write (the open policy).
    /// - fails: [`OpenError::Runtime`] outside a Tokio runtime,
    ///   [`OpenError::Storage`] when the store cannot be created or opened,
    ///   including when another process holds it.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`OpenError::Runtime`]: there is no current Tokio runtime.
    /// - [`OpenError::Storage`]: the store cannot be created or opened.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — opening a fresh directory and reopening it after a
    ///   commit separate creation from reuse; the commit read back after the
    ///   reopen shows the store, not a fresh one, was opened.
    /// - witness: `store::tests::commits_chain_on_the_heads_and_survive_a_reopen`
    #[inline]
    pub fn open(
        state: &StateDir,
        identity: Identity,
    ) -> Result<Self, OpenError>
    {
        let runtime = tokio::runtime::Handle::try_current().map_err(OpenError::Runtime)?;
        let path = state.store_dir();
        let storage =
            RedbStorage::new(&path).map_err(|source| OpenError::Storage { path, source })?;
        let (engine, _handler, listener, manager) = SubductionBuilder::new()
            .signer(identity.signer().clone())
            .storage(storage, Arc::new(OpenPolicy))
            .spawner(TokioSpawner::new(runtime.clone()))
            .timer(TokioTimer)
            .build::<Sendable, Transport>();
        drop(runtime.spawn(listener));
        drop(runtime.spawn(manager));
        Ok(Self {
            engine,
            identity,
            runtime,
        })
    }

    /// The identity this peer signs with and binds its endpoint to.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn identity(&self) -> &Identity
    {
        &self.identity
    }

    /// The subduction engine over the store.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn engine(&self) -> &Arc<Engine>
    {
        &self.engine
    }

    /// The runtime the engine and its connections run on.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn runtime(&self) -> &tokio::runtime::Handle
    {
        &self.runtime
    }

    /// Append `content` to `tree` as a commit on the tree's current heads.
    ///
    /// # Specification
    /// - ensures: returns the commit id, the BLAKE3 digest of `content`; on
    ///   success the commit is durable in the store and its parents are the
    ///   tree's heads as they stood before the call, so after it the tree's
    ///   heads are exactly this commit.
    /// - ensures: content already committed to `tree` is the commit already
    ///   there: the call writes nothing and returns that commit's id, so a
    ///   commit never names itself or a descendant as a parent.
    /// - fails: [`CommitError::Read`] when the tree cannot be read from
    ///   storage, [`CommitError::Write`] when the commit cannot be stored.
    /// - panics: none.
    /// - intension: a commit at a fragment boundary is stored as a loose
    ///   commit; no fragment is built for it.
    ///
    /// # Errors
    /// - [`CommitError::Read`]: the tree's heads cannot be read.
    /// - [`CommitError::Write`]: the commit cannot be stored.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two distinct contents committed in turn, then the
    ///   first again, separate chaining from re-commit: the ids are compared
    ///   with independently computed digests, and the heads after each step are
    ///   compared exactly.
    /// - witness: `store::tests::commits_chain_on_the_heads_and_survive_a_reopen`
    /// - witness: `store::tests::committing_present_content_changes_nothing`
    #[inline]
    pub async fn commit(
        &self,
        tree: TreeId,
        content: Content,
    ) -> Result<CommitId, CommitError>
    {
        let blob = content.0;
        let id = CommitId::new(Digest::<Blob>::hash(&blob).into_bytes());
        let heads = self.heads(tree).await.map_err(CommitError::Read)?;
        // `heads` has just hydrated the tree into the engine's resident set,
        // which is unbounded here, so this read is served from memory.
        let present = self.engine.get_commits(tree.sedimentree()).await;
        if present.iter().flatten().any(|commit| commit.head() == id) {
            return Ok(id);
        }
        // economy: a commit at a fragment boundary stays loose; subduction
        // asks for a fragment there, which compacts sync and storage. Build
        // and add the fragment once trees grow long enough for it to matter.
        let _fragment_request = self
            .engine
            .add_commit(tree.sedimentree(), id, heads.0, blob)
            .await
            .map_err(CommitError::Write)?;
        Ok(id)
    }

    /// Read `tree`'s heads from the store.
    ///
    /// # Specification
    /// - ensures: returns the tree's current heads; a tree the store has never
    ///   seen has none, as subduction's sync treats it.
    /// - fails: [`HeadsError`] when the tree cannot be loaded from storage.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`HeadsError`]: the storage read fails.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an unknown tree, a one-commit tree and a two-commit
    ///   chain separate the empty answer, the single head and the replacement
    ///   of a parent by its child.
    /// - witness: `store::tests::commits_chain_on_the_heads_and_survive_a_reopen`
    #[inline]
    pub async fn heads(
        &self,
        tree: TreeId,
    ) -> Result<Heads, HeadsError>
    {
        let heads = self
            .engine
            .get_heads(tree.sedimentree())
            .await
            .map_err(HeadsError)?;
        Ok(Heads(heads.into_iter().flatten().collect()))
    }
}

/// Why a tree store cannot be opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError
{
    /// There is no current Tokio runtime to run the engine on.
    #[error("the tree store needs a Tokio runtime")]
    Runtime(#[source] tokio::runtime::TryCurrentError),
    /// The store cannot be created or opened.
    #[error("cannot open the tree store {}", path.display())]
    Storage
    {
        /// The store's directory.
        path: PathBuf,
        /// The storage failure.
        source: RedbStorageError,
    },
}

/// Why a commit cannot be appended.
#[derive(Debug, thiserror::Error)]
pub enum CommitError
{
    /// The tree's heads cannot be read.
    #[error("cannot read the tree")]
    Read(#[source] HeadsError),
    /// The commit cannot be stored.
    #[error("cannot store the commit")]
    Write(#[source] EngineWriteError),
}

/// Why a tree's heads cannot be read.
#[derive(Debug, thiserror::Error)]
#[error("cannot read the tree's heads")]
#[repr(transparent)]
pub struct HeadsError(#[source] RedbStorageError);

#[cfg(test)]
mod tests
{
    use sedimentree_core::loose_commit::id::CommitId;

    use super::Content;
    use super::Peer;
    use crate::id::TreeId;
    use crate::identity::Identity;
    use crate::identity::StateDir;

    /// The tree every test commits to.
    const TREE: &str = "7472656574726565747265657472656574726565747265657472656574726565";

    /// A multi-threaded runtime, as the peer binary runs.
    ///
    /// # Specification
    /// trivial.
    fn runtime() -> tokio::runtime::Runtime
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// The commit id the store must assign to `content`: its BLAKE3 digest,
    /// computed here with the reference implementation, independently of
    /// the store.
    ///
    /// # Specification
    /// trivial.
    fn digest(content: &Content) -> CommitId
    {
        CommitId::new(*blake3::hash(content.0.as_slice()).as_bytes())
    }

    /// The first content committed.
    ///
    /// # Specification
    /// trivial.
    fn first() -> Content
    {
        Content::from(b"first".to_vec())
    }

    /// The second content committed.
    ///
    /// # Specification
    /// trivial.
    fn second() -> Content
    {
        Content::from(b"second".to_vec())
    }

    /// Open a peer on `state`, creating its identity as needed.
    ///
    /// # Specification
    /// trivial.
    fn open(state: &StateDir) -> Peer
    {
        Peer::open(state, Identity::load_or_create(state).unwrap()).unwrap()
    }

    #[test]
    fn commits_chain_on_the_heads_and_survive_a_reopen()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let tree = TREE.parse::<TreeId>().unwrap();
        runtime().block_on(async {
            let peer = open(&state);
            let unknown = peer.heads(tree).await.unwrap();
            assert_eq!(unknown.iter().count(), 0, "an unknown tree has no heads");
            let first_id = peer.commit(tree, first()).await.unwrap();
            assert_eq!(
                first_id,
                digest(&first()),
                "a commit id is the content's BLAKE3 digest"
            );
            let heads = peer.heads(tree).await.unwrap();
            assert_eq!(
                heads.iter().copied().collect::<Vec<_>>(),
                [first_id],
                "one commit is the head"
            );
            let second_id = peer.commit(tree, second()).await.unwrap();
            assert_eq!(
                second_id,
                digest(&second()),
                "a commit id is the content's BLAKE3 digest"
            );
            let heads = peer.heads(tree).await.unwrap();
            assert_eq!(
                heads.iter().copied().collect::<Vec<_>>(),
                [second_id],
                "the child replaces its parent as head"
            );
            let commits = peer.engine.get_commits(tree.sedimentree()).await.unwrap();
            let child = commits
                .iter()
                .find(|commit| commit.head() == second_id)
                .unwrap();
            assert_eq!(
                child.parents().iter().copied().collect::<Vec<_>>(),
                [first_id],
                "the child's parent is the previous head"
            );
            assert_eq!(
                heads.to_string(),
                format!("{second_id}\n"),
                "heads print one hex line each"
            );
            drop(peer);
        });
        runtime().block_on(async {
            let peer = open(&state);
            let heads = peer.heads(tree).await.unwrap();
            assert_eq!(
                heads.iter().copied().collect::<Vec<_>>(),
                [digest(&second())],
                "the store survives a reopen"
            );
            drop(peer);
        });
    }

    #[test]
    fn committing_present_content_changes_nothing()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let tree = TREE.parse::<TreeId>().unwrap();
        runtime().block_on(async {
            let peer = open(&state);
            let first_id = peer.commit(tree, first()).await.unwrap();
            let second_id = peer.commit(tree, second()).await.unwrap();
            let again = peer.commit(tree, first()).await.unwrap();
            assert_eq!(
                again, first_id,
                "present content is the commit already there"
            );
            let heads = peer.heads(tree).await.unwrap();
            assert_eq!(
                heads.iter().copied().collect::<Vec<_>>(),
                [second_id],
                "re-committing an ancestor leaves the heads alone"
            );
            let commits = peer.engine.get_commits(tree.sedimentree()).await.unwrap();
            assert_eq!(commits.len(), 2, "nothing was written for the re-commit");
            drop(peer);
        });
    }
}
