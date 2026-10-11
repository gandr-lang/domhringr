//! Per-task derivation, reused only at an identical frontier.

use alloc::collections::BTreeMap;

use anodized::spec;
use domhringr_record_tree::Heads;
use domhringr_record_tree::HeadsError;
use domhringr_record_tree::Peer;
use domhringr_record_tree::Task;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;
use domhringr_record_tree::ViewAtError;
use domhringr_record_tree::ViewError;

use crate::Index;
use crate::dialogue;
use crate::dialogue::DialogueError;
use crate::project;
use crate::project::ProjectError;
use crate::project::TaskEntry;
use crate::project::TaskName;
use crate::store::Store;
use crate::store::StoreError;

/// A project and the task entries from which its records were built.
#[derive(Debug)]
pub struct Derived
{
    /// The project tree, with its reserved nested family empty.
    pub index: Index,
    /// Entries ordered by their bound names.
    pub entries: BTreeMap<TaskName, TaskEntry>,
}

/// Entries derived in this invocation, never imported from an attested claim.
///
/// The cache retains one entry per distinct task in the projects derived by
/// this command. It avoids folding aliases twice and dies with the command.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct Deriver(BTreeMap<TreeId, TaskEntry>);

/// A failure reading a frontier, deriving records or publishing their nodes.
#[derive(Debug, thiserror::Error)]
pub enum DeriveError
{
    /// The task's current frontier could not be read.
    #[error(transparent)]
    Heads(#[from] HeadsError),
    /// The requested historical view could not be read.
    #[error(transparent)]
    View(#[from] ViewAtError),
    /// Admitted moves could not be encoded as a dialogue.
    #[error(transparent)]
    Dialogue(#[from] DialogueError),
    /// Project entries could not be encoded.
    #[error(transparent)]
    Project(#[from] ProjectError),
    /// Node persistence failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Derive and persist a held task's dialogue, retaining its complete standing.
///
/// # Specification
/// - requires: `task` is the fold of `tree` at `heads`.
/// - ensures: the entry names those heads and that standing, and its dialogue
///   contains every admitted move and no other receipt.
/// - fails: dialogue derivation or persistence failure.
/// - panics: none.
///
/// # Errors
/// - [`DeriveError`]: records cannot be built or stored.
///
/// # Adequacy
/// - hypothesis: L2 — each reachable standing agrees with an independent fold.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |entry| matches!(entry,
    TaskEntry::Held { tree: actual, heads: frontier, current, .. }
    if *actual == tree && frontier == heads && current == task.current())))]
#[inline]
pub fn held(
    tree: TreeId,
    heads: &Heads,
    task: &Task,
    store: &Store,
) -> Result<TaskEntry, DeriveError>
{
    let dialogue = dialogue::derive(task)?;
    let digest = store.keep(&dialogue.index)?;
    Ok(TaskEntry::Held {
        tree,
        heads: heads.clone(),
        current: task.current().clone(),
        attempts: dialogue.attempts,
        dialogue: digest,
    })
}

/// Fold exactly the named frontier, distinguishing an unopened task from
/// failure.
///
/// # Specification
/// - ensures: a held entry is derived from exactly `heads`; an unopened tree is
///   explicitly unheld, never given an empty or invented standing.
/// - fails: missing heads, storage, derivation or persistence failure.
/// - panics: none.
///
/// # Errors
/// - [`DeriveError`]: a required input cannot be read or stored.
///
/// # Adequacy
/// - hypothesis: L3 — an unknown task is unheld beside every reachable
///   standing.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |entry| entry.tree() == tree))]
#[inline]
pub async fn at(
    peer: &Peer,
    tree: TreeId,
    heads: &Heads,
    store: &Store,
) -> Result<TaskEntry, DeriveError>
{
    match peer.view_at(tree, heads).await {
        | Ok(view) => held(tree, heads, view.task(), store),
        | Err(ViewAtError::View(ViewError::Unopened(_unopened))) => Ok(TaskEntry::Unheld { tree }),
        | Err(failure) => Err(failure.into()),
    }
}

impl Deriver
{
    /// Derive the project's bindings using each task's current stored heads.
    ///
    /// # Specification
    /// - ensures: task-family records follow exactly the project's direct tree
    ///   bindings; the nested family is empty; every dialogue is stored before
    ///   the project manifest is published.
    /// - fails: frontier, fold, encoding or persistence failure.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`DeriveError`]: a task or project cannot be derived.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — opposite arrival orders yield identical manifests.
    /// - witness: `derive::tests::two_stores_given_one_commit_set_in_two_orders_derive_one_manifest`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |derived|
        derived.entries.len() == project::bindings(view).count()
        && derived.index.tree.records().len() == derived.entries.len()))]
    #[inline]
    pub async fn project(
        &mut self,
        peer: &Peer,
        view: &View,
        store: &Store,
    ) -> Result<Derived, DeriveError>
    {
        let mut entries = BTreeMap::new();
        for (name, tree) in project::bindings(view) {
            let heads = peer.heads(tree).await?;
            let entry = match self.0.get(&tree) {
                | Some(
                    entry @ &TaskEntry::Held {
                        heads: ref cached,
                        ref dialogue,
                        ..
                    },
                ) if cached == &heads => match store.manifest(*dialogue) {
                    | Ok(_manifest) => entry.clone(),
                    | Err(StoreError::Unheld(_digest)) => at(peer, tree, &heads, store).await?,
                    | Err(failure) => return Err(failure.into()),
                },
                | _changed => at(peer, tree, &heads, store).await?,
            };
            let _previous = self.0.insert(tree, entry.clone());
            let _previous = entries.insert(name, entry);
        }
        let index = project::build(&entries, &BTreeMap::new())?;
        let _digest = store.keep(&index)?;
        Ok(Derived { index, entries })
    }
}

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeMap;

    use domhringr_record_tree::StateDir;
    use gandr_storage_records::RecordTree;
    use gandr_storage_records::TreeParams;

    use super::Deriver;
    use crate::Index;
    use crate::IndexKind;
    use crate::project;
    use crate::project::TaskEntry;
    use crate::store::Store;
    use crate::testing;

    #[test]
    fn two_stores_given_one_commit_set_in_two_orders_derive_one_manifest()
    {
        testing::runtime().block_on(async {
            let fixture = testing::Fixture::new().await;
            let (project, commits) = testing::project_fixture().await;
            let commits: Vec<_> = commits.into_iter().chain(fixture.commits).collect();
            let left = tempfile::tempdir().unwrap();
            let right = tempfile::tempdir().unwrap();
            let left_peer = testing::peer(left.path(), commits.iter().cloned()).await;
            let right_peer = testing::peer(right.path(), commits.into_iter().rev()).await;
            let a_store = Store::open(&StateDir::from(left.path().to_path_buf()));
            let b_store = Store::open(&StateDir::from(right.path().to_path_buf()));
            let a_view = left_peer.view(project).await.unwrap();
            let b_view = right_peer.view(project).await.unwrap();
            let mut cache = Deriver::default();
            let a = cache.project(&left_peer, &a_view, &a_store).await.unwrap();
            drop(left_peer);
            let b = Deriver::default()
                .project(&right_peer, &b_view, &b_store)
                .await
                .unwrap();
            drop(right_peer);
            assert_eq!(a.entries, b.entries);
            assert_eq!(a.index.manifest, b.index.manifest);
            assert_eq!(a.index.tree.records(), b.index.tree.records());
            for entry in a.entries.values() {
                if let &TaskEntry::Held { dialogue, .. } = entry {
                    let a = a_store.load(dialogue).unwrap();
                    let b = b_store.load(dialogue).unwrap();
                    assert_eq!(a.manifest, b.manifest);
                    assert_eq!(a.tree.records(), b.tree.records());
                }
            }
        });
    }

    #[test]
    fn the_fixture_manifests_are_pinned()
    {
        testing::runtime().block_on(async {
            let fixture = testing::Fixture::new().await;
            let (project, commits) = testing::project_fixture().await;
            let root = tempfile::tempdir().unwrap();
            let peer = testing::peer(root.path(), commits.into_iter().chain(fixture.commits)).await;
            let store = Store::open(&StateDir::from(root.path().to_path_buf()));
            let view = peer.view(project).await.unwrap();
            let derived = Deriver::default()
                .project(&peer, &view, &store)
                .await
                .unwrap();
            drop(peer);
            let TaskEntry::Held { dialogue, .. } = derived.entries[&"alpha".parse().unwrap()]
            else {
                panic!("held fixture");
            };
            let empty = Index::new(
                IndexKind::Provenance,
                RecordTree::build(&[], TreeParams::current()).unwrap(),
            );
            let nested = empty.manifest.identity().unwrap();
            let nested_project = project::build(
                &derived.entries,
                &BTreeMap::from([(IndexKind::Provenance, nested)]),
            )
            .unwrap();
            let expected =
                if domhringr_record_tree::Edition::CURRENT == domhringr_record_tree::Edition::ONE {
                    [
                        "8f5c4ef6dc54a322b8de87f814bf272a6bb69fbb2d630be41628c3c025180d9e",
                        "3caf88ce0e1cadadc1b4a46bababf8cbd093e5f8acf5c9bc4c37554e27c88bd5",
                        "ad1049e4abcb129bbf0a766e17e8ebe0ba8d3b48857baee8e324b8df7178504e",
                    ]
                }
                else {
                    [
                        "dc161ba45a961718919f401a7b33ece56e65f3bfd2658aacb595a935dcb148fe",
                        "916c343cb75768d22b3db819b2ce40fdb11d77598f1fc46b337cdc51023569ee",
                        "db00c0ef89a8c6143f733f35e6b3b49e165a16b432dd80510b90fa45724be2c8",
                    ]
                };
            assert_eq!(
                [
                    dialogue.to_string(),
                    derived.index.manifest.identity().unwrap().to_string(),
                    nested_project.manifest.identity().unwrap().to_string()
                ],
                expected
            );
            assert_eq!(
                nested.to_string(),
                "cf2e606e6482d3d32b0b78f1c71784c5c72786efa6f947aced4dbdc9c642f6d8"
            );
        });
    }
}
