//! Project derivation, as an edit of the previous store.
//!
//! A derive folds each bound task at its current heads. A task whose heads
//! are the ones it was derived at keeps its parts; any other task's parts
//! are removed and added again, and a name the project doesn't bind loses
//! its task.
//! A refreshed store is therefore an edit of the one before, and its root
//! depends on that history; a whole derive, which adds every task in name
//! order to an empty store, is a function of the project alone. Two stores
//! agree when their contents do ([`crate::prove::contents`]), whatever
//! their roots.

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use std::io;

use domhringr_record_tree::Heads;
use domhringr_record_tree::HeadsError;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::Peer;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;
use domhringr_record_tree::ViewAtError;
use domhringr_record_tree::ViewError;
use gandr_storage_schema::PartKey;
use gandr_storage_schema::Refusal;
use gandr_storage_schema::SchemaError;
use gandr_storage_schema::StoreRoot;

use crate::AttemptNumber;
use crate::dialogue;
use crate::dialogue::Dialogue;
use crate::dialogue::DialogueError;
use crate::keyed;
use crate::keyed::Keyed;
use crate::keyed::Standing;
use crate::project;
use crate::project::Carrier;
use crate::project::ProjectError;
use crate::project::Refused;
use crate::project::Subjects;
use crate::project::TaskEntry;
use crate::project::TaskName;
use crate::prove;
use crate::prove::Local;
use crate::prove::ProveError;
use crate::store::Cached;
use crate::store::Store;
use crate::store::StoreError;

/// A derived project store and the entries it holds.
#[derive(Debug)]
pub struct Derived
{
    /// The committed store.
    pub store: gandr_storage_schema::Store,
    /// Entries ordered by their bound names.
    pub entries: BTreeMap<TaskName, TaskEntry>,
}

impl Derived
{
    /// The root an `Indexed` receipt attests for this store.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn root(&self) -> StoreRoot
    {
        self.store.root()
    }
}

/// The store derived here last, or this peer's own attested one.
///
/// Another author's claim never seeds this cache. Task heads, not the
/// standing, decide reuse: a newly refused receipt changes the heads too.
#[derive(Debug, Default)]
pub enum Deriver
{
    /// No previous store is held: the next derive is whole.
    #[default]
    Whole,
    /// The previous store, which the next derive edits.
    Refresh(Box<gandr_storage_schema::Store>),
}

/// A failure reading a frontier, deriving a store or publishing its nodes.
#[derive(Debug, thiserror::Error)]
pub enum DeriveError
{
    /// The task's current frontier could not be read.
    #[error(transparent)]
    Heads(#[from] HeadsError),
    /// The requested historical view could not be read.
    #[error(transparent)]
    View(#[from] ViewAtError),
    /// Admitted moves could not be placed as a dialogue.
    #[error(transparent)]
    Dialogue(#[from] DialogueError),
    /// A task's parts could not be written.
    #[error(transparent)]
    Project(#[from] ProjectError),
    /// The store refused an edit.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// The keyed schema didn't resolve.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// The store couldn't be made.
    #[error(transparent)]
    Make(#[from] gandr_storage_schema::StoreError),
    /// A reused task doesn't read back.
    #[error(transparent)]
    Read(#[from] ProveError),
    /// Node persistence failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A task folded at a frontier, with its dialogue.
#[derive(Debug)]
pub struct Folded
{
    /// The entry.
    pub entry: TaskEntry,
    /// The admitted moves; none when the task is unheld.
    pub dialogue: Dialogue,
}

/// Fold a held task at a frontier.
///
/// # Specification
/// - requires: `view` is the fold of `tree` at `heads`.
/// - ensures: the entry retains that frontier's standing and refusals; its
///   dialogue holds every admitted move and no other receipt.
/// - fails: the dialogue can't be placed.
/// - panics: none.
/// - executable: none — the fold is the oracle; the entry witness compares with
///   it at every standing.
///
/// # Errors
/// - [`DeriveError::Dialogue`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — each reachable standing agrees with an independent fold.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[inline]
pub fn held(
    tree: TreeId,
    heads: &Heads,
    view: &View,
) -> Result<Folded, DeriveError>
{
    let dialogue = dialogue::derive(view.task())?;
    Ok(Folded {
        entry: TaskEntry::Held {
            tree,
            heads: heads.clone(),
            current: view.task().current().clone(),
            attempts: dialogue.attempts,
            refused: view.refused().iter().map(Refused::from).collect(),
        },
        dialogue,
    })
}

/// Fold exactly the named frontier, distinguishing an unopened task from
/// failure.
///
/// # Specification
/// - ensures: a held entry is derived from exactly `heads`; an unopened tree is
///   explicitly unheld, never given an empty or invented standing.
/// - fails: missing heads, storage or derivation failure.
/// - panics: none.
/// - executable: none — historical storage reads can't be replayed in a
///   predicate; reachable standings and an unopened tree are the oracle.
///
/// # Errors
/// - [`DeriveError`]: a required input cannot be read.
///
/// # Adequacy
/// - hypothesis: L3 — an unknown task is unheld beside every reachable
///   standing.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[inline]
pub async fn at(
    peer: &Peer,
    tree: TreeId,
    heads: &Heads,
) -> Result<Folded, DeriveError>
{
    match peer.view_at(tree, heads).await {
        Ok(view) => held(tree, heads, &view),
        Err(ViewAtError::View(ViewError::Unopened(_unopened))) => Ok(Folded {
            entry: TaskEntry::Unheld { tree },
            dialogue: Dialogue::default(),
        }),
        Err(failure) => Err(failure.into()),
    }
}

/// The root an attestation's index digest names.
///
/// # Specification
/// trivial.
#[inline]
#[must_use]
pub fn root(digest: IndexDigest) -> StoreRoot
{
    let mut bytes = [0_u8; gandr_storage_schema::STORE_ROOT_LEN];
    bytes.copy_from_slice(digest.as_ref());
    StoreRoot::from(bytes)
}

/// The index digest an attestation names a root by.
///
/// # Specification
/// trivial.
#[inline]
#[must_use]
pub fn digest(root: StoreRoot) -> IndexDigest
{
    let mut bytes = [0_u8; gandr_storage_schema::STORE_ROOT_LEN];
    bytes.copy_from_slice(root.as_ref());
    IndexDigest::from(bytes)
}

/// Read back a reused task's entry from the store.
///
/// # Specification
/// - requires: `task` is the live task bound to `tree` at `heads`.
/// - ensures: the entry the task was added with: its standing recomputed from
///   its last attempt, its refusals and its number of attempts.
/// - fails: the store's parts don't read back.
/// - panics: none.
/// - executable: none — the refresh witness compares a refreshed entry with one
///   folded whole.
///
/// # Errors
/// - [`DeriveError::Read`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — a refreshed index equals one derived whole.
/// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
async fn reread(
    store: &gandr_storage_schema::Store,
    keyed: &Keyed,
    task: PartKey,
    tree: TreeId,
) -> Result<TaskEntry, DeriveError>
{
    let mut local = Local(store);
    let claim = prove::claim(&mut local, keyed, task).await?;
    if claim.standing == Standing::Unheld {
        return Ok(TaskEntry::Unheld { tree });
    }
    let current = prove::current(&mut local, keyed, &claim).await?;
    let attempts = u32::try_from(claim.attempts.len())
        .map_err(|_width| ProveError::Key(crate::key::KeyError::Overflow))?;
    Ok(TaskEntry::Held {
        tree,
        heads: claim.heads,
        current,
        attempts: AttemptNumber(attempts),
        refused: claim.refused,
    })
}

impl Deriver
{
    /// Restore this peer's last derivation, or its own attested store.
    ///
    /// # Specification
    /// - ensures: another author's claim never seeds a derivation; an absent
    ///   store, or one of another schema, means a whole derivation.
    /// - fails: a damaged held store keeps its storage error.
    /// - panics: none.
    /// - executable: none — cache reads and historical ownership are effectful;
    ///   comparing refreshed and whole derivations is the oracle.
    ///
    /// # Errors
    /// - [`DeriveError`]: the cached store cannot be read.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — refreshing the own cache equals whole derivation.
    /// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
    #[inline]
    pub fn owned(
        peer: &Peer,
        project: TreeId,
        view: &View,
        store: &Store,
    ) -> Result<Self, DeriveError>
    {
        let author = peer.identity().peer_key();
        let cached = match store.cached(project)? {
            Cached::Absent => view.indexes().get(&author).map(|claim| root(claim.index)),
            Cached::Root(root) => Some(root),
        };
        let Some(root) = cached
        else {
            return Ok(Self::default());
        };
        match store.load(Keyed::shared()?, root) {
            Ok(held) => Ok(Self::Refresh(Box::new(held))),
            Err(
                StoreError::Unheld(_)
                | StoreError::Project(gandr_storage_schema::StoreError::SchemaMismatch { .. }),
            ) => Ok(Self::default()),
            Err(StoreError::File { ref source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                Ok(Self::default())
            },
            Err(failure) => Err(failure.into()),
        }
    }

    /// Derive the project's bindings at each task's current heads.
    ///
    /// # Specification
    /// - ensures: one task per direct tree binding, by name; a task at its
    ///   previous heads keeps its parts and isn't folded again; only the first
    ///   name of a tree carries its provenance; no subject is left unnamed. The
    ///   store is kept and remembered before it is returned.
    /// - fails: frontier, fold, edit or persistence failure.
    /// - panics: none.
    /// - executable: none — folding and persistence are effectful; the
    ///   witnesses compare stores derived in other orders and histories.
    ///
    /// # Errors
    /// - [`DeriveError`]: a task or the project cannot be derived.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — opposite arrival orders yield one root; a refreshed
    ///   store has the contents of one derived whole after every kind of
    ///   change.
    /// - witness: `derive::tests::two_stores_given_one_commit_set_in_two_orders_derive_one_manifest`
    /// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
    #[inline]
    pub async fn project(
        &mut self,
        peer: &Peer,
        project: TreeId,
        view: &View,
        files: &Store,
    ) -> Result<Derived, DeriveError>
    {
        let keyed = Keyed::shared()?;
        let mut store = match core::mem::take(self) {
            Self::Refresh(store) => *store,
            Self::Whole => keyed.store()?,
        };
        let mut live = project::names(&store, keyed)?;
        let mut subjects = Subjects::of(&store, keyed)?;
        let mut entries = BTreeMap::new();
        let mut owners = alloc::collections::BTreeSet::new();
        for (name, tree) in project::bindings(view) {
            let heads = peer.heads(tree).await?;
            let owner = owners.insert(tree);
            let reused = match live.remove(&name) {
                Some(task) => {
                    let claimed = keyed::read_heads(store.value(keyed.task_heads, task)?)
                        .map_err(ProveError::from)?;
                    let standing = Standing::read(store.value(keyed.task_standing, task)?)
                        .map_err(ProveError::from)?;
                    let unchanged = claimed == heads
                        && (standing != Standing::Unheld || heads.iter().next().is_none());
                    if unchanged {
                        Some(task)
                    }
                    else {
                        project::remove(&mut store, keyed, task)?;
                        None
                    }
                },
                None => None,
            };
            let entry = if let Some(task) = reused {
                if owner {
                    if store.preimage(keyed.naming_task, task)?.is_empty() {
                        project::rename(&mut store, keyed, task, &mut subjects)?;
                    }
                }
                else {
                    project::unname(&mut store, keyed, task)?;
                }
                reread(&store, keyed, task, tree).await?
            }
            else {
                let folded = at(peer, tree, &heads).await?;
                let _task = project::add(
                    &mut store,
                    keyed,
                    &name,
                    &folded.entry,
                    &folded.dialogue,
                    if owner {
                        Carrier::Owner
                    }
                    else {
                        Carrier::Alias
                    },
                    &mut subjects,
                )?;
                folded.entry
            };
            let _previous = entries.insert(name, entry);
        }
        for (_name, task) in live {
            project::remove(&mut store, keyed, task)?;
        }
        project::prune(&mut store, keyed)?;
        let root = files.keep(&mut store)?;
        files.remember(project, root)?;
        *self = Self::Refresh(Box::new(store.clone()));
        Ok(Derived { store, entries })
    }
}
