//! The tree store: a subduction peer over one redb file, committing receipts
//! into sedimentrees, reading their heads, and folding them into views.

use alloc::collections::BTreeMap;
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
use crate::anchor::Authority;
use crate::anchor::Resolution;
use crate::anchor::Scope;
use crate::anchor::Target;
use crate::fold::Unopened;
use crate::fold::View;
use crate::fold::fold;
use crate::id::PeerKey;
use crate::id::TreeId;
use crate::identity::Identity;
use crate::identity::StateDir;
use crate::name::Domain;
use crate::name::Label;
use crate::receipt::Receipt;
use crate::runtime::TokioSpawner;
use crate::runtime::TokioTimer;
use crate::witness::Witness;
use crate::witness::WitnessError;

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

    /// Resolve `anchor` by folding what the store holds, asking `witness` for
    /// the candidate trees of a DNS name and reading a label in `scope`.
    ///
    /// # Specification
    /// - ensures: the anchor's authority names a tree first. A key names its
    ///   own tree. A DNS name names the one tree, among those `witness` names
    ///   for it, whose local view holds the owner's claim of it
    ///   ([`View::claims`]); a tree the store does not hold claims nothing
    ///   here. A label names the tree the introductions of `scope`'s tree name
    ///   for it ([`View::introductions`]), and the introductions of no other
    ///   tree are read.
    /// - ensures: then a path anchor resolves to what its path resolves to in
    ///   the named tree's view ([`View::resolve`]): the binding the fold
    ///   admitted last in canonical order, or [`Resolution::Unbound`]. A bare
    ///   anchor named by a DNS name or a label resolves to the claim or the
    ///   introduction naming its tree: [`Resolution::Bound`] to
    ///   [`Target::Tree`], under the owner who claimed or the author who
    ///   introduced. A bare key anchor names no path and nothing binds a key,
    ///   so it resolves to [`Resolution::Unbound`] once its tree folds.
    /// - ensures: `witness` is consulted only for a DNS name and `scope` only
    ///   for a label. Nothing is synced and nothing dialed: the answer reads
    ///   the local store and the witness alone.
    /// - fails: [`WhenceError::Witness`] when the witness cannot be read,
    ///   [`WhenceError::Unwitnessed`] when it names no tree for the domain,
    ///   [`WhenceError::Unclaimed`] when no tree it names claims the domain
    ///   here, [`WhenceError::Ambiguous`] when more than one does,
    ///   [`WhenceError::Unscoped`] for a label read in no tree,
    ///   [`WhenceError::Unintroduced`] for a label the scope's tree does not
    ///   introduce, and [`WhenceError::View`] when a tree the resolution must
    ///   fold has no view: the key's tree, the scope's tree, the tree a label
    ///   names for a path anchor, or a witnessed tree whose commits cannot be
    ///   read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WhenceError::Witness`]: the witness cannot be read.
    /// - [`WhenceError::Unwitnessed`]: the witness names no tree.
    /// - [`WhenceError::Unclaimed`]: no witnessed tree claims the domain.
    /// - [`WhenceError::Ambiguous`]: several witnessed trees claim it.
    /// - [`WhenceError::Unscoped`]: a label is read in no tree.
    /// - [`WhenceError::Unintroduced`]: the scope's tree does not introduce the
    ///   label.
    /// - [`WhenceError::View`]: a tree the resolution folds has no view.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — in a store holding two trees, the key form resolves a
    ///   bound path, an unbound path and the bare tree, and an unknown tree is
    ///   refused; a DNS anchor resolves through the one witnessed tree that
    ///   claims it, to the same binding as the key form and, bare, to that
    ///   tree, while a witness naming an unclaiming, an unheld or no tree, or
    ///   two claiming trees, is refused by its own reason; a label resolves in
    ///   the tree that introduced it, bare and through a path, and is refused
    ///   read in the introduced tree, read in no tree, or read in a tree the
    ///   store does not hold.
    /// - witness: `store::tests::whence_resolves_an_anchor_by_fold`
    /// - witness: `store::tests::a_dns_anchor_resolves_through_the_claim_of_the_tree_its_witness_names`
    /// - witness: `store::tests::a_witnessed_tree_without_the_claim_is_unclaimed`
    /// - witness: `store::tests::two_witnessed_trees_claiming_one_domain_are_ambiguous`
    /// - witness: `store::tests::an_empty_witness_is_unwitnessed`
    /// - witness: `store::tests::a_label_resolves_in_the_tree_that_introduced_it_alone`
    #[inline]
    pub async fn whence<W>(
        &self,
        anchor: &Anchor,
        witness: &W,
        scope: Scope,
    ) -> Result<Resolution, WhenceError>
    where
        W: Witness + Sync,
    {
        match *anchor.authority() {
            | Authority::Key(tree) => {
                let view = self.folded(tree).await?;
                Ok(match *anchor {
                    | Anchor::Tree(_) => Resolution::Unbound,
                    | Anchor::Path { ref path, .. } => view.resolve(path),
                })
            },
            | Authority::Domain(ref domain) => {
                let (tree, view) = self.claimant(domain, witness).await?;
                Ok(match *anchor {
                    | Anchor::Tree(_) => Resolution::Bound(view.owner(), Target::Tree(tree)),
                    | Anchor::Path { ref path, .. } => view.resolve(path),
                })
            },
            | Authority::Label(ref label) => {
                let (introducer, tree) = self.introduced(label, scope).await?;
                match *anchor {
                    | Anchor::Tree(_) => Ok(Resolution::Bound(introducer, Target::Tree(tree))),
                    | Anchor::Path { ref path, .. } => {
                        let view = self.folded(tree).await?;
                        Ok(view.resolve(path))
                    },
                }
            },
        }
    }

    /// Fold `tree` for a resolution.
    ///
    /// # Specification
    /// - ensures: the tree's view, as [`Peer::view`] folds it.
    /// - fails: [`WhenceError::View`] naming `tree`, carrying why it has no
    ///   view.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WhenceError::View`]: the tree has no view.
    async fn folded(
        &self,
        tree: TreeId,
    ) -> Result<View, WhenceError>
    {
        self.view(tree)
            .await
            .map_err(|source| WhenceError::View { tree, source })
    }

    /// The one tree, among those `witness` names for `domain`, whose local
    /// view holds the owner's claim of `domain`, with that view.
    ///
    /// # Specification
    /// - ensures: each witnessed tree is folded once; a tree the store does not
    ///   hold (unopened here) claims nothing.
    /// - fails: [`WhenceError::Witness`], [`WhenceError::Unwitnessed`],
    ///   [`WhenceError::Unclaimed`], [`WhenceError::Ambiguous`] carrying every
    ///   claiming tree, and [`WhenceError::View`] for a witnessed tree whose
    ///   commits cannot be read, as [`Peer::whence`] states them.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WhenceError::Witness`]: the witness cannot be read.
    /// - [`WhenceError::Unwitnessed`]: the witness names no tree.
    /// - [`WhenceError::Unclaimed`]: no witnessed tree claims the domain.
    /// - [`WhenceError::Ambiguous`]: several witnessed trees claim it.
    /// - [`WhenceError::View`]: a witnessed tree's commits cannot be read.
    async fn claimant<W>(
        &self,
        domain: &Domain,
        witness: &W,
    ) -> Result<(TreeId, View), WhenceError>
    where
        W: Witness + Sync,
    {
        let candidates = witness
            .lookup(domain)
            .await
            .map_err(|source| WhenceError::Witness {
                domain: domain.clone(),
                source,
            })?;
        if candidates.is_empty() {
            return Err(WhenceError::Unwitnessed {
                domain: domain.clone(),
            });
        }
        let mut claimants = BTreeMap::new();
        for tree in candidates {
            match self.view(tree).await {
                | Ok(view) if view.claims().contains(domain) => {
                    drop(claimants.insert(tree, view));
                },
                | Ok(_) | Err(ViewError::Unopened(_)) => {},
                | Err(source @ ViewError::Load(_)) => {
                    return Err(WhenceError::View { tree, source });
                },
            }
        }
        let mut claimants = claimants.into_iter();
        let Some((tree, view)) = claimants.next()
        else {
            return Err(WhenceError::Unclaimed {
                domain: domain.clone(),
            });
        };
        let Some((other, _view)) = claimants.next()
        else {
            return Ok((tree, view));
        };
        let claimants = [tree, other]
            .into_iter()
            .chain(claimants.map(|(tree, _view)| tree))
            .collect();
        Err(WhenceError::Ambiguous {
            domain: domain.clone(),
            claimants,
        })
    }

    /// The introduction of `label` in `scope`'s tree: its author and the tree
    /// it names.
    ///
    /// # Specification
    /// - ensures: the introduction of `label` the fold of `scope`'s tree
    ///   admitted last in canonical order; no other tree is read.
    /// - fails: [`WhenceError::Unscoped`] when `scope` names no tree,
    ///   [`WhenceError::View`] when its tree has no view, and
    ///   [`WhenceError::Unintroduced`] when that view introduces no `label`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WhenceError::Unscoped`]: no tree is named to read the label in.
    /// - [`WhenceError::View`]: the scope's tree has no view.
    /// - [`WhenceError::Unintroduced`]: the scope's tree does not introduce the
    ///   label.
    async fn introduced(
        &self,
        label: &Label,
        scope: Scope,
    ) -> Result<(PeerKey, TreeId), WhenceError>
    {
        let Scope::In(within) = scope
        else {
            return Err(WhenceError::Unscoped {
                label: label.clone(),
            });
        };
        let view = self.folded(within).await?;
        match view.introductions().get(label) {
            | Some(&(introducer, tree)) => Ok((introducer, tree)),
            | None => Err(WhenceError::Unintroduced {
                label: label.clone(),
                within,
            }),
        }
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

/// Why an anchor does not resolve.
#[derive(Debug, thiserror::Error)]
pub enum WhenceError
{
    /// A tree the resolution folds has no view.
    #[error("cannot fold the tree {tree}")]
    View
    {
        /// The tree folded.
        tree: TreeId,
        /// Why it has no view.
        source: ViewError,
    },
    /// The witness of a DNS name cannot be read.
    #[error("cannot read the witness of {domain}")]
    Witness
    {
        /// The DNS name whose witness was read.
        domain: Domain,
        /// Why it cannot be read.
        source: WitnessError,
    },
    /// The witness names no tree for the DNS name.
    #[error("unwitnessed {domain}")]
    Unwitnessed
    {
        /// The DNS name.
        domain: Domain,
    },
    /// No tree the witness names claims the DNS name in its local view.
    #[error("unclaimed {domain}")]
    Unclaimed
    {
        /// The DNS name.
        domain: Domain,
    },
    /// More than one tree the witness names claims the DNS name.
    #[error("ambiguous {domain}")]
    Ambiguous
    {
        /// The DNS name.
        domain: Domain,
        /// Every witnessed tree claiming it.
        claimants: BTreeSet<TreeId>,
    },
    /// A label anchor names no tree to be read in.
    #[error("unscoped {label}")]
    Unscoped
    {
        /// The label.
        label: Label,
    },
    /// The tree a label is read in introduces no tree by it.
    #[error("unintroduced {label}")]
    Unintroduced
    {
        /// The label.
        label: Label,
        /// The tree it was read in.
        within: TreeId,
    },
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
    use super::WhenceError;
    use crate::anchor::Anchor;
    use crate::anchor::Authority;
    use crate::anchor::Resolution;
    use crate::anchor::Scope;
    use crate::anchor::Target;
    use crate::fold::Refusal;
    use crate::id::TreeId;
    use crate::identity::Identity;
    use crate::identity::StateDir;
    use crate::name::Domain;
    use crate::name::Label;
    use crate::receipt::Receipt;
    use crate::testing::commit;
    use crate::testing::elsewhere_key;
    use crate::testing::id;
    use crate::testing::key;
    use crate::testing::other;
    use crate::testing::owner;
    use crate::testing::runtime;
    use crate::testing::seal_on;
    use crate::testing::tree_key;
    use crate::witness::Static;

    /// The tree every test commits to.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        tree_key().tree()
    }

    /// The DNS name the resolution tests claim and witness.
    ///
    /// # Specification
    /// trivial.
    fn example() -> Domain
    {
        "example.test".parse().unwrap()
    }

    /// A tree no test's store holds.
    ///
    /// # Specification
    /// trivial.
    fn unheld() -> TreeId
    {
        TreeId::new(iroh::SecretKey::from_bytes(&[6; 32]).public())
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
            authority: Authority::Key(tree()),
            path: text.parse().unwrap(),
        };
        let nobody = Static::default();
        runtime().block_on(async {
            let peer = open(&state);
            let me = peer.identity().peer_key();
            let opened = Receipt::open(&tree_key(), me).unwrap();
            peer.commit(tree(), opened).await.unwrap();
            let noted = peer.commit(tree(), note("bound".into())).await.unwrap();
            let bind = Receipt::bind(tree(), "x".parse().unwrap(), Target::Commit(noted));
            peer.commit(tree(), bind.unwrap()).await.unwrap();
            let whence = |anchor: Anchor| {
                let peer = &peer;
                let nobody = &nobody;
                async move { peer.whence(&anchor, nobody, Scope::Unscoped).await }
            };
            assert_eq!(
                whence(path("x")).await.unwrap(),
                Resolution::Bound(me, Target::Commit(noted)),
                "the bound path resolves to the note's commit under the binder's key"
            );
            assert_eq!(
                whence(path("x/y")).await.unwrap(),
                Resolution::Unbound,
                "a path below a bound one is a path of its own, unbound"
            );
            assert_eq!(
                whence(Anchor::key(tree())).await.unwrap(),
                Resolution::Unbound,
                "the bare tree names no path, so nothing binds it"
            );
            let elsewhere = elsewhere_key().tree();
            let unknown = Anchor::Path {
                authority: Authority::Key(elsewhere),
                path: "x".parse().unwrap(),
            };
            assert!(
                matches!(
                    whence(unknown).await,
                    Err(WhenceError::View { tree, source: ViewError::Unopened(_) }) if tree == elsewhere
                ),
                "an anchor in a tree never seen has no view to resolve in"
            );
            drop(peer);
        });
    }

    #[test]
    fn a_dns_anchor_resolves_through_the_claim_of_the_tree_its_witness_names()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let (a, b, unheld) = (tree(), elsewhere_key().tree(), unheld());
        let witness = [(example(), b), (example(), a), (example(), unheld)]
            .into_iter()
            .collect::<Static>();
        runtime().block_on(async {
            let peer = open(&state);
            let me = peer.identity().peer_key();
            peer.commit(a, Receipt::open(&tree_key(), me).unwrap())
                .await
                .unwrap();
            peer.commit(b, Receipt::open(&elsewhere_key(), me).unwrap())
                .await
                .unwrap();
            let noted = peer.commit(a, note("bound".into())).await.unwrap();
            let bind = Receipt::bind(a, "x".parse().unwrap(), Target::Commit(noted));
            peer.commit(a, bind.unwrap()).await.unwrap();
            let claim = Receipt::claim(a, example()).unwrap();
            peer.commit(a, claim).await.unwrap();
            let whence = |anchor: &str| {
                let anchor = anchor.parse::<Anchor>().unwrap();
                let (peer, witness) = (&peer, &witness);
                async move { peer.whence(&anchor, witness, Scope::Unscoped).await }
            };
            let keyed = Anchor::Path {
                authority: Authority::Key(a),
                path: "x".parse().unwrap(),
            };
            let by_key = peer
                .whence(&keyed, &witness, Scope::Unscoped)
                .await
                .unwrap();
            assert_eq!(
                whence("domhringr://example.test/x").await.unwrap(),
                by_key,
                "the DNS form resolves as the key form of the one witnessed tree that claims it"
            );
            assert_eq!(
                by_key,
                Resolution::Bound(me, Target::Commit(noted)),
                "to the bound note"
            );
            assert_eq!(
                whence("domhringr://example.test/y").await.unwrap(),
                Resolution::Unbound,
                "an unbound path under the name is unbound"
            );
            assert_eq!(
                whence("domhringr://example.test/").await.unwrap(),
                Resolution::Bound(me, Target::Tree(a)),
                "the bare name resolves to the claiming tree under its owner"
            );
            drop(peer);
        });
    }

    #[test]
    fn a_witnessed_tree_without_the_claim_is_unclaimed()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let a = tree();
        let anchor = "domhringr://example.test/x".parse::<Anchor>().unwrap();
        let unclaimed = |result: Result<Resolution, WhenceError>| matches!(result, Err(WhenceError::Unclaimed { domain }) if domain == example());
        runtime().block_on(async {
            let peer = open(&state);
            let me = peer.identity().peer_key();
            peer.commit(a, Receipt::open(&tree_key(), me).unwrap())
                .await
                .unwrap();
            let noted = peer.commit(a, note("bound".into())).await.unwrap();
            let bind = Receipt::bind(a, "x".parse().unwrap(), Target::Commit(noted));
            peer.commit(a, bind.unwrap()).await.unwrap();
            let witness = core::iter::once((example(), a)).collect::<Static>();
            assert!(
                unclaimed(peer.whence(&anchor, &witness, Scope::Unscoped).await),
                "a witness naming a tree that never claimed the name is refused"
            );
            let other_name = Receipt::claim(a, "other.test".parse().unwrap()).unwrap();
            peer.commit(a, other_name).await.unwrap();
            assert!(
                unclaimed(peer.whence(&anchor, &witness, Scope::Unscoped).await),
                "a claim of another name claims nothing here"
            );
            let granted = Receipt::grant(a, key(&other())).unwrap();
            let granted = peer.commit(a, granted).await.unwrap();
            let squat = Receipt::claim(a, example()).unwrap().encode().unwrap();
            let squat = seal_on(&other(), a, BTreeSet::from([granted]), squat).await;
            Storage::<Sendable>::save_loose_commit(&peer.storage, a.sedimentree(), squat.clone())
                .await
                .unwrap();
            assert!(
                peer.view(a)
                    .await
                    .unwrap()
                    .refused()
                    .contains(&(id(&squat), Refusal::NotOwner)),
                "a member's claim of the name is refused by the fold"
            );
            assert!(
                unclaimed(peer.whence(&anchor, &witness, Scope::Unscoped).await),
                "so the member's claim does not make the name resolve"
            );
            let elsewhere = core::iter::once((example(), unheld())).collect::<Static>();
            assert!(
                unclaimed(peer.whence(&anchor, &elsewhere, Scope::Unscoped).await),
                "a witnessed tree the store does not hold claims nothing here"
            );
            drop(peer);
        });
    }

    #[test]
    fn two_witnessed_trees_claiming_one_domain_are_ambiguous()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let (a, b) = (tree(), elsewhere_key().tree());
        let anchor = "domhringr://example.test/".parse::<Anchor>().unwrap();
        runtime().block_on(async {
            let peer = open(&state);
            let me = peer.identity().peer_key();
            peer.commit(a, Receipt::open(&tree_key(), me).unwrap())
                .await
                .unwrap();
            peer.commit(b, Receipt::open(&elsewhere_key(), me).unwrap())
                .await
                .unwrap();
            for claimant in [a, b] {
                let claim = Receipt::claim(claimant, example()).unwrap();
                peer.commit(claimant, claim).await.unwrap();
            }
            let both = [(example(), a), (example(), b)]
                .into_iter()
                .collect::<Static>();
            assert!(
                matches!(
                    peer.whence(&anchor, &both, Scope::Unscoped).await,
                    Err(WhenceError::Ambiguous { domain, claimants })
                        if domain == example() && claimants == BTreeSet::from([a, b])
                ),
                "two witnessed trees claiming the name are refused, naming both"
            );
            let one = core::iter::once((example(), b)).collect::<Static>();
            assert_eq!(
                peer.whence(&anchor, &one, Scope::Unscoped).await.unwrap(),
                Resolution::Bound(me, Target::Tree(b)),
                "a witness naming one of them resolves to it"
            );
            drop(peer);
        });
    }

    #[test]
    fn an_empty_witness_is_unwitnessed()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let a = tree();
        let anchor = "domhringr://example.test/".parse::<Anchor>().unwrap();
        let unwitnessed = |result: Result<Resolution, WhenceError>| matches!(result, Err(WhenceError::Unwitnessed { domain }) if domain == example());
        runtime().block_on(async {
            let peer = open(&state);
            let me = peer.identity().peer_key();
            peer.commit(a, Receipt::open(&tree_key(), me).unwrap())
                .await
                .unwrap();
            peer.commit(a, Receipt::claim(a, example()).unwrap())
                .await
                .unwrap();
            assert!(
                unwitnessed(
                    peer.whence(&anchor, &Static::default(), Scope::Unscoped)
                        .await
                ),
                "a witness naming nothing refuses the name, claimed or not"
            );
            let other_name =
                core::iter::once(("other.test".parse().unwrap(), a)).collect::<Static>();
            assert!(
                unwitnessed(peer.whence(&anchor, &other_name, Scope::Unscoped).await),
                "a witness naming trees for another name alone names none for this one"
            );
            drop(peer);
        });
    }

    #[test]
    fn a_label_resolves_in_the_tree_that_introduced_it_alone()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let (a, b, unheld) = (tree(), elsewhere_key().tree(), unheld());
        let label = |text: &str| text.parse::<Label>().unwrap();
        let nobody = Static::default();
        runtime().block_on(async {
            let peer = open(&state);
            let me = peer.identity().peer_key();
            peer.commit(a, Receipt::open(&tree_key(), me).unwrap())
                .await
                .unwrap();
            peer.commit(b, Receipt::open(&elsewhere_key(), me).unwrap())
                .await
                .unwrap();
            let noted = peer.commit(b, Receipt::note(b, "in b".into()).unwrap())
                .await
                .unwrap();
            let bind = Receipt::bind(b, "x".parse().unwrap(), Target::Commit(noted));
            peer.commit(b, bind.unwrap()).await.unwrap();
            let introduction = Receipt::introduce(a, label("b"), b).unwrap();
            peer.commit(a, introduction).await.unwrap();
            let whence = |anchor: &str, scope: Scope| {
                let anchor = anchor.parse::<Anchor>().unwrap();
                let (peer, nobody) = (&peer, &nobody);
                async move { peer.whence(&anchor, nobody, scope).await }
            };
            assert_eq!(
                whence("domhringr://b/", Scope::In(a)).await.unwrap(),
                Resolution::Bound(me, Target::Tree(b)),
                "read in the tree that introduced it, the label names the introduced tree"
            );
            assert_eq!(
                whence("domhringr://b/x", Scope::In(a)).await.unwrap(),
                Resolution::Bound(me, Target::Commit(noted)),
                "and a path under it resolves in the introduced tree"
            );
            assert!(
                matches!(
                    whence("domhringr://b/", Scope::In(b)).await,
                    Err(WhenceError::Unintroduced { label: read, within }) if read == label("b") && within == b
                ),
                "read in the introduced tree, which introduced nothing, the label is unknown"
            );
            assert!(
                matches!(
                    whence("domhringr://c/", Scope::In(a)).await,
                    Err(WhenceError::Unintroduced { label: read, .. }) if read == label("c")
                ),
                "a label nobody introduced is unknown"
            );
            assert!(
                matches!(
                    whence("domhringr://b/", Scope::Unscoped).await,
                    Err(WhenceError::Unscoped { label: read }) if read == label("b")
                ),
                "a label read in no tree has nowhere to resolve"
            );
            assert!(
                matches!(
                    whence("domhringr://b/", Scope::In(unheld)).await,
                    Err(WhenceError::View { tree, source: ViewError::Unopened(_) }) if tree == unheld
                ),
                "a label read in a tree the store does not hold has no view to be read in"
            );
            drop(peer);
        });
    }
}
