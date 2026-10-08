//! The tree store: a subduction peer over one redb file, committing receipts
//! into sedimentrees, reading their heads, and folding them into views.

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use std::path::PathBuf;

use future_form::Sendable;
use gandr_storage_values::ValueError;
use sedimentree_core::blob::Blob;
use sedimentree_core::crypto::digest::Digest;
use sedimentree_core::depth::CountLeadingZeroBytes;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::connection::message::SyncMessage;
use subduction_core::handler::sync::SyncHandler;
use subduction_core::policy::open::OpenPolicy;
use subduction_core::storage::traits::Storage;
use subduction_core::subduction::Subduction;
use subduction_core::subduction::builder::SubductionBuilder;
use subduction_core::subduction::error::WriteError;
use subduction_core::transport::message::MessageTransport;
use subduction_crypto::signer::memory::MemorySigner;
use subduction_iroh::transport::IrohTransport;
use subduction_redb_storage::RedbStorage;
use subduction_redb_storage::RedbStorageError;

use crate::anchor::Anchor;
use crate::anchor::Resolution;
use crate::fold::Unopened;
use crate::fold::View;
use crate::fold::fold;
use crate::id::TreeId;
use crate::identity::Identity;
use crate::identity::StateDir;
use crate::receipt::Receipt;
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
    /// The store itself, read directly for the signed commits a view folds.
    storage: RedbStorage,
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
    ///   peer and every write (the open policy): authority is the fold's
    ///   concern ([`Peer::view`]), not storage's.
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
            .storage(storage.clone(), Arc::new(OpenPolicy))
            .spawner(TokioSpawner::new(runtime.clone()))
            .timer(TokioTimer)
            .build::<Sendable, Transport>();
        drop(runtime.spawn(listener));
        drop(runtime.spawn(manager));
        Ok(Self {
            engine,
            storage,
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

    /// Append `receipt` to `tree` as a commit on the tree's current heads.
    ///
    /// # Specification
    /// - ensures: the commit's blob is the receipt's encoding and its id the
    ///   BLAKE3 digest of that blob, which the call returns; on success the
    ///   commit is durable in the store, signed by this peer, and its parents
    ///   are the tree's heads as they stood before the call, so after it the
    ///   tree's heads are exactly this commit.
    /// - ensures: a receipt already committed to `tree` is the commit already
    ///   there: the call writes nothing and returns that commit's id, so a
    ///   commit never names itself or a descendant as a parent.
    /// - ensures: the receipt is stored under `tree` whatever tree it names;
    ///   the fold refuses one that names another ([`Peer::view`]).
    /// - fails: [`CommitError::Encode`] when the receipt cannot be encoded,
    ///   [`CommitError::Read`] when the tree cannot be read from storage,
    ///   [`CommitError::Write`] when the commit cannot be stored.
    /// - panics: none.
    /// - intension: a commit at a fragment boundary is stored as a loose
    ///   commit; no fragment is built for it.
    ///
    /// # Errors
    /// - [`CommitError::Encode`]: the value plane refused to encode the
    ///   receipt.
    /// - [`CommitError::Read`]: the tree's heads cannot be read.
    /// - [`CommitError::Write`]: the commit cannot be stored.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two distinct receipts committed in turn, then the
    ///   first again, separate chaining from re-commit: the ids are compared
    ///   with independently computed digests of the encodings, and the heads
    ///   after each step are compared exactly.
    /// - witness: `store::tests::commits_chain_on_the_heads_and_survive_a_reopen`
    /// - witness: `store::tests::committing_a_present_receipt_changes_nothing`
    #[inline]
    pub async fn commit(
        &self,
        tree: TreeId,
        receipt: Receipt,
    ) -> Result<CommitId, CommitError>
    {
        let blob = receipt.encode().map_err(CommitError::Encode)?;
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

    /// Fold `tree`'s stored commits into its view.
    ///
    /// # Specification
    /// - ensures: the view is the fold of every loose commit stored for `tree`,
    ///   each authored by its verified signer, so two peers holding the same
    ///   commits compute equal views whatever order they arrived in.
    /// - fails: [`ViewError::Load`] when the commits cannot be read,
    ///   [`ViewError::Unopened`] when none of them is the tree's Open,
    ///   including for a tree the store has never seen.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ViewError::Load`]: the storage read fails.
    /// - [`ViewError::Unopened`]: the tree has no Open.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the same signed commits, by two authors, saved into
    ///   two stores in opposite orders yield equal views whose owner, member,
    ///   notes and refusal are compared exactly; an unknown tree is unopened.
    /// - witness: `store::tests::two_stores_given_one_commit_set_in_two_orders_agree`
    #[inline]
    pub async fn view(
        &self,
        tree: TreeId,
    ) -> Result<View, ViewError>
    {
        let commits = Storage::<Sendable>::load_loose_commits(&self.storage, tree.sedimentree())
            .await
            .map_err(ViewError::Load)?;
        let view = fold(tree, commits)?;
        Ok(view)
    }

    /// Resolve `anchor` by folding its tree's stored commits.
    ///
    /// # Specification
    /// - ensures: for a path anchor, what its path resolves to in the tree's
    ///   view ([`View::resolve`]): the binding the fold admitted last in
    ///   canonical order, or [`Resolution::Unbound`]; a bare tree anchor names
    ///   no path, which no bind binds, so it is unbound. The answer reads only
    ///   the local store: nothing is synced.
    /// - fails: as [`Peer::view`] for the anchor's tree.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ViewError::Load`]: the storage read fails.
    /// - [`ViewError::Unopened`]: the anchor's tree has no Open.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — after an Open, a note and a bind committed through
    ///   the store, the bound path resolves to the note's commit under the
    ///   peer's key, an unbound path and the bare tree are unbound, and an
    ///   anchor in a tree the store has never seen is unopened.
    /// - witness: `store::tests::whence_resolves_an_anchor_by_fold`
    #[inline]
    pub async fn whence(
        &self,
        anchor: &Anchor,
    ) -> Result<Resolution, ViewError>
    {
        let view = self.view(anchor.tree()).await?;
        Ok(match *anchor {
            | Anchor::Tree(_) => Resolution::Unbound,
            | Anchor::Path { ref path, .. } => view.resolve(path),
        })
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
    /// The value plane refused to encode the receipt.
    #[error("cannot encode the receipt")]
    Encode(#[source] ValueError),
    /// The tree's heads cannot be read.
    #[error("cannot read the tree")]
    Read(#[source] HeadsError),
    /// The commit cannot be stored.
    #[error("cannot store the commit")]
    Write(#[source] EngineWriteError),
}

/// Why a tree has no view.
#[derive(Debug, thiserror::Error)]
pub enum ViewError
{
    /// The tree's commits cannot be read.
    #[error("cannot read the tree's commits")]
    Load(#[source] RedbStorageError),
    /// No commit is the tree's Open.
    #[error(transparent)]
    Unopened(#[from] Unopened),
}

/// Why a tree's heads cannot be read.
#[derive(Debug, thiserror::Error)]
#[error("cannot read the tree's heads")]
#[repr(transparent)]
pub struct HeadsError(#[source] RedbStorageError);

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeSet;
    use alloc::string::String;

    use future_form::Sendable;
    use sedimentree_core::loose_commit::id::CommitId;
    use subduction_core::storage::traits::Storage;

    use super::Peer;
    use super::ViewError;
    use crate::anchor::Anchor;
    use crate::anchor::Resolution;
    use crate::anchor::Target;
    use crate::fold::Refusal;
    use crate::id::TreeId;
    use crate::identity::Identity;
    use crate::identity::StateDir;
    use crate::receipt::Receipt;
    use crate::testing::commit;
    use crate::testing::elsewhere_key;
    use crate::testing::id;
    use crate::testing::key;
    use crate::testing::other;
    use crate::testing::owner;
    use crate::testing::runtime;
    use crate::testing::tree_key;

    /// The tree every test commits to.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        tree_key().tree()
    }

    /// The commit id the store must assign to `receipt`: the BLAKE3 digest of
    /// its encoding, computed here with the reference implementation,
    /// independently of the store.
    ///
    /// # Specification
    /// trivial.
    fn digest(receipt: &Receipt) -> CommitId
    {
        CommitId::new(*blake3::hash(receipt.encode().unwrap().as_slice()).as_bytes())
    }

    /// A note of `text` on the test tree.
    ///
    /// # Specification
    /// trivial.
    fn note(text: String) -> Receipt
    {
        Receipt::note(tree(), text).unwrap()
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
        let tree = tree();
        let (first, second) = (note("first".into()), note("second".into()));
        runtime().block_on(async {
            let peer = open(&state);
            let unknown = peer.heads(tree).await.unwrap();
            assert_eq!(unknown.iter().count(), 0, "an unknown tree has no heads");
            let first_id = peer.commit(tree, first.clone()).await.unwrap();
            assert_eq!(
                first_id,
                digest(&first),
                "a commit id is the BLAKE3 digest of the receipt's encoding"
            );
            let heads = peer.heads(tree).await.unwrap();
            assert_eq!(
                heads.iter().copied().collect::<Vec<_>>(),
                [first_id],
                "one commit is the head"
            );
            let second_id = peer.commit(tree, second.clone()).await.unwrap();
            assert_eq!(
                second_id,
                digest(&second),
                "a commit id is the BLAKE3 digest of the receipt's encoding"
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
                [digest(&second)],
                "the store survives a reopen"
            );
            drop(peer);
        });
    }

    #[test]
    fn committing_a_present_receipt_changes_nothing()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let tree = tree();
        let first = note("first".into());
        runtime().block_on(async {
            let peer = open(&state);
            let first_id = peer.commit(tree, first.clone()).await.unwrap();
            let second_id = peer.commit(tree, note("second".into())).await.unwrap();
            let again = peer.commit(tree, first).await.unwrap();
            assert_eq!(
                again, first_id,
                "a present receipt is the commit already there"
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

    #[test]
    fn two_stores_given_one_commit_set_in_two_orders_agree()
    {
        let (root_a, root_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let tree = tree();
        let (owner, other) = (owner(), other());
        runtime().block_on(async {
            let opened = Receipt::open(&tree_key(), key(&owner)).unwrap();
            let opened = commit(&owner, tree, &[], &opened).await;
            let early = commit(&other, tree, &[&opened], &note("early".into())).await;
            let granted = Receipt::grant(tree, key(&other)).unwrap();
            let granted = commit(&owner, tree, &[&early], &granted).await;
            let late = commit(&other, tree, &[&granted], &note("late".into())).await;
            let arrivals = [opened, early.clone(), granted, late];

            let a = open(&StateDir::from(root_a.path().to_path_buf()));
            let b = open(&StateDir::from(root_b.path().to_path_buf()));
            for commit in arrivals.iter().cloned() {
                Storage::<Sendable>::save_loose_commit(&a.storage, tree.sedimentree(), commit)
                    .await
                    .unwrap();
            }
            for commit in arrivals.iter().rev().cloned() {
                Storage::<Sendable>::save_loose_commit(&b.storage, tree.sedimentree(), commit)
                    .await
                    .unwrap();
            }
            let view = a.view(tree).await.unwrap();
            assert_eq!(
                b.view(tree).await.unwrap(),
                view,
                "the order the commits arrived in leaves no trace"
            );
            assert_eq!(view.owner(), key(&owner), "the Open's signer owns the tree");
            assert_eq!(
                *view.members(),
                BTreeSet::from([key(&other)]),
                "the grant's peer is a member"
            );
            assert_eq!(
                view.notes(),
                [(key(&other), String::from("late"))],
                "the note made after the grant is admitted"
            );
            assert_eq!(
                view.refused(),
                [(id(&early), Refusal::NoAuthority)],
                "the note made before the grant stays refused"
            );
            assert!(
                matches!(
                    a.view(elsewhere_key().tree()).await,
                    Err(ViewError::Unopened(_))
                ),
                "a tree never seen has no Open"
            );
            drop((a, b));
        });
    }

    #[test]
    fn whence_resolves_an_anchor_by_fold()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let path = |text: &str| Anchor::Path {
            tree: tree(),
            path: text.parse().unwrap(),
        };
        runtime().block_on(async {
            let peer = open(&state);
            let me = peer.identity().peer_key();
            let opened = Receipt::open(&tree_key(), me).unwrap();
            peer.commit(tree(), opened).await.unwrap();
            let noted = peer.commit(tree(), note("bound".into())).await.unwrap();
            let bind = Receipt::bind(tree(), "x".parse().unwrap(), Target::Commit(noted));
            peer.commit(tree(), bind.unwrap()).await.unwrap();
            assert_eq!(
                peer.whence(&path("x")).await.unwrap(),
                Resolution::Bound(me, Target::Commit(noted)),
                "the bound path resolves to the note's commit under the binder's key"
            );
            assert_eq!(
                peer.whence(&path("x/y")).await.unwrap(),
                Resolution::Unbound,
                "a path below a bound one is a path of its own, unbound"
            );
            assert_eq!(
                peer.whence(&Anchor::Tree(tree())).await.unwrap(),
                Resolution::Unbound,
                "the bare tree names no path, so nothing binds it"
            );
            let unknown = Anchor::Path {
                tree: elsewhere_key().tree(),
                path: "x".parse().unwrap(),
            };
            assert!(
                matches!(peer.whence(&unknown).await, Err(ViewError::Unopened(_))),
                "an anchor in a tree never seen has no view to resolve in"
            );
            drop(peer);
        });
    }
}
