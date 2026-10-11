//! Per-task derivation, reused only at an identical frontier.

use alloc::collections::BTreeMap;
use std::io;

use anodized::spec;
use domhringr_record_tree::Heads;
use domhringr_record_tree::HeadsError;
use domhringr_record_tree::Peer;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;
use domhringr_record_tree::ViewAtError;
use domhringr_record_tree::ViewError;
use gandr_storage_records::RecordTreeError;
use gandr_storage_values::TokenBody;
use gandr_storage_values::ValueError;
use gandr_storage_values::decode_flat;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::Index;
use crate::IndexKind;
use crate::ManifestError;
use crate::dialogue;
use crate::dialogue::DialogueError;
use crate::project;
use crate::project::ProjectError;
use crate::project::Refused;
use crate::project::TaskEntry;
use crate::project::TaskName;
use crate::provenance;
use crate::provenance::ProvenanceError;
use crate::store::Store;
use crate::store::StoreError;

/// A project and the task entries from which its records were built.
#[derive(Debug)]
pub struct Derived
{
    /// The project tree, including its nested provenance identity.
    pub index: Index,
    /// Entries ordered by their bound names.
    pub entries: BTreeMap<TaskName, TaskEntry>,
}

/// Entries derived here or restored from this peer's own latest attestation.
///
/// Foreign claims never seed this cache. Task heads, not the current standing,
/// determine reuse: a newly refused receipt invalidates the entry too.
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
    /// A cached entry is not a canonical value.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// Cached provenance cannot be rebuilt from its admitted moves.
    #[error(transparent)]
    Provenance(#[from] ProvenanceError),
    /// Provenance record construction failed.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
    /// An own attestation names a non-project index.
    #[error("cached attestation is not a project index")]
    Kind,
}

/// Derive and persist a held task's dialogue, retaining its complete standing.
///
/// # Specification
/// - requires: `view` is the fold of `tree` at `heads`.
/// - ensures: the entry retains that frontier's standing and refusals; its
///   dialogue contains every admitted move and no other receipt.
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
    TaskEntry::Held { attempts, .. } if usize::try_from(attempts.0).is_ok_and(|count|
        count == view.task().steps().iter().filter(|entry| matches!(entry.1, domhringr_record_tree::Step::Dispatch { .. })).count()))))]
#[inline]
pub fn held(
    tree: TreeId,
    heads: &Heads,
    view: &View,
    store: &Store,
) -> Result<TaskEntry, DeriveError>
{
    let dialogue = dialogue::derive(view.task())?;
    let digest = store.keep(&dialogue.index)?;
    Ok(TaskEntry::Held {
        tree,
        heads: heads.clone(),
        current: view.task().current().clone(),
        attempts: dialogue.attempts,
        dialogue: digest,
        refused: view.refused().iter().map(Refused::from).collect(),
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
/// - executable: none — historical storage reads and publication cannot be
///   replayed in a predicate; reachable standings and an unopened tree provide
///   the oracle.
///
/// # Errors
/// - [`DeriveError`]: a required input cannot be read or stored.
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
    store: &Store,
) -> Result<TaskEntry, DeriveError>
{
    match peer.view_at(tree, heads).await {
        | Ok(view) => held(tree, heads, &view, store),
        | Err(ViewAtError::View(ViewError::Unopened(_unopened))) => Ok(TaskEntry::Unheld { tree }),
        | Err(failure) => Err(failure.into()),
    }
}

impl Deriver
{
    /// Restore this store's last derivation, or its own attestation's entries.
    ///
    /// # Specification
    /// - ensures: another author's claim never seeds a derivation; absent or
    ///   foreign-layout cache images require whole derivation.
    /// - fails: malformed current-layout images retain their storage error.
    /// - panics: none.
    /// - executable: none — cache reads and historical ownership are effectful;
    ///   comparing refreshed and whole derivations provides the independent
    ///   oracle.
    ///
    /// # Errors
    /// - [`DeriveError`]: cached records cannot be read or decoded.
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
            | crate::store::Cached::Absent => view.indexes().get(&author).map(|claim| claim.index),
            | crate::store::Cached::Manifest(digest) => Some(digest),
        };
        let Some(digest) = cached
        else {
            return Ok(Self::default());
        };
        let index = match store.load(digest) {
            | Ok(index) => index,
            | Err(StoreError::Unheld(_) | StoreError::Manifest(ManifestError::Layout)) => {
                return Ok(Self::default());
            },
            | Err(StoreError::File { ref source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(Self::default());
            },
            | Err(failure) => return Err(failure.into()),
        };
        if index.manifest.kind() != IndexKind::Project {
            return Err(DeriveError::Kind);
        }
        let mut entries = BTreeMap::new();
        for record in index.tree.records() {
            if record.key().as_ref().first() == Some(&1) {
                let entry = decode_flat::<TaskEntry>(TokenBody::from(record.value().as_ref()))?;
                let _previous = entries.insert(entry.tree(), entry);
            }
        }
        Ok(Self(entries))
    }

    /// Derive the project's bindings using each task's current stored heads.
    ///
    /// # Specification
    /// - ensures: task-family records follow exactly the project's direct tree
    ///   bindings; the nested provenance is rebuilt from cached dialogues;
    ///   unchanged task heads never cause another fold when their nodes exist.
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
        && derived.index.tree.records().len() == usize::from(arith::saturating_add(Int::from(derived.entries.len()), Int::from(1)))))]
    #[inline]
    pub async fn project(
        &mut self,
        peer: &Peer,
        project: TreeId,
        view: &View,
        store: &Store,
    ) -> Result<Derived, DeriveError>
    {
        let mut entries = BTreeMap::new();
        let mut provenance = provenance::Records::default();
        let mut visited = alloc::collections::BTreeSet::new();
        for (name, tree) in project::bindings(view) {
            let heads = peer.heads(tree).await?;
            let cached = match self.0.get(&tree) {
                | Some(
                    entry @ &TaskEntry::Held {
                        heads: ref previous,
                        dialogue,
                        ..
                    },
                ) if previous == &heads => match store.load(dialogue) {
                    | Ok(index) => Some((entry.clone(), Some(index))),
                    | Err(StoreError::Unheld(_)) => None,
                    | Err(StoreError::File { ref source, .. })
                        if source.kind() == io::ErrorKind::NotFound =>
                    {
                        None
                    },
                    | Err(failure) => return Err(failure.into()),
                },
                | Some(entry @ &TaskEntry::Unheld { .. }) if heads.iter().next().is_none() => {
                    Some((entry.clone(), None))
                },
                | _changed => None,
            };
            let (entry, dialogue) = match cached {
                | Some(cached) => cached,
                | None => {
                    let entry = at(peer, tree, &heads, store).await?;
                    let dialogue = match entry {
                        | TaskEntry::Held { dialogue, .. } => Some(store.load(dialogue)?),
                        | TaskEntry::Unheld { .. } => None,
                    };
                    (entry, dialogue)
                },
            };
            let _previous = self.0.insert(tree, entry.clone());
            if visited.insert(tree)
                && let Some(dialogue) = dialogue
            {
                provenance.extend(tree, &dialogue)?;
            }
            let _previous = entries.insert(name, entry);
        }
        let provenance = provenance.build()?;
        let digest = store.keep(&provenance)?;
        let nested = BTreeMap::from([(IndexKind::Provenance, digest)]);
        let index = project::build(&entries, &nested)?;
        let digest = store.keep(&index)?;
        store.remember(project, digest)?;
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

    /// Store transitions that can change a project derivation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Change
    {
        /// No task frontier changes.
        None,
        /// One of two held tasks moves.
        One,
        /// The project binds another held task.
        Added,
        /// An already bound unheld task becomes held.
        Held,
        /// Both held tasks move.
        Every,
        /// Only a refused receipt is added to one task.
        Refusal,
    }

    #[test]
    fn a_refreshed_index_equals_one_derived_whole()
    {
        use domhringr_record_tree::Anchor;
        use domhringr_record_tree::Brief;
        use domhringr_record_tree::Edition;
        use domhringr_record_tree::Receipt;
        use domhringr_record_tree::Revision;
        use domhringr_record_tree::Target;
        use domhringr_record_tree::TreeId;
        for change in [
            Change::None,
            Change::One,
            Change::Added,
            Change::Held,
            Change::Every,
            Change::Refusal,
        ] {
            let root = tempfile::tempdir().unwrap();
            let state = StateDir::from(root.path().to_path_buf());
            let store = Store::open(&state);
            let (before, first, arrivals, project) = testing::runtime().block_on(async {
                let mut first = testing::Fixture::new().await;
                let secret = iroh::SecretKey::from_bytes(&[17; 32]);
                let second_tree = TreeId::try_from(*secret.public().as_bytes()).unwrap();
                let mut second =
                    testing::Fixture::with(&secret, testing::evidence(), Revision::Sha256([9; 32]))
                        .await;
                let (project, mut commits) = testing::project_fixture().await;
                let local = domhringr_record_tree::Identity::load_or_create(&state)
                    .unwrap()
                    .peer_key();
                let parents = commits
                    .last()
                    .map(|commit| commit.payload().head())
                    .into_iter()
                    .collect();
                let grant = testing::seal(
                    &testing::owner(),
                    &Receipt::grant(project, local).unwrap(),
                    parents,
                )
                .await;
                commits.push(grant);
                let peer = testing::peer(
                    root.path(),
                    first
                        .commits
                        .iter()
                        .cloned()
                        .chain(second.commits.iter().cloned())
                        .chain(commits),
                )
                .await;
                peer.commit(
                    project,
                    Receipt::bind(
                        project,
                        "tasks/second".parse().unwrap(),
                        Target::Anchor(Anchor::key(second_tree)),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
                let view = peer.view(project).await.unwrap();
                let before = Deriver::default()
                    .project(&peer, project, &view, &store)
                    .await
                    .unwrap();
                let identity = before.index.manifest.identity().unwrap();
                peer.commit(project, Receipt::indexed(project, identity).unwrap())
                    .await
                    .unwrap();
                let mut arrivals = Vec::new();
                match change {
                    | Change::None => {},
                    | Change::One | Change::Every => {
                        first
                            .push(
                                &testing::owner(),
                                Receipt::dispatch(
                                    testing::tree(),
                                    testing::key(&testing::seat()),
                                    Edition::CURRENT,
                                    Brief::Content(testing::hash()),
                                )
                                .unwrap(),
                                testing::Fence(200),
                            )
                            .await;
                        arrivals.push(first.commits.last().unwrap().clone());
                        if change == Change::Every {
                            second
                                .push(
                                    &testing::owner(),
                                    Receipt::dispatch(
                                        second_tree,
                                        testing::key(&testing::seat()),
                                        Edition::CURRENT,
                                        Brief::Content(testing::hash()),
                                    )
                                    .unwrap(),
                                    testing::Fence(200),
                                )
                                .await;
                            arrivals.push(second.commits.last().unwrap().clone());
                        }
                    },
                    | Change::Added | Change::Held => {
                        let secret = iroh::SecretKey::from_bytes(
                            &[if change == Change::Held { 7 } else { 18 }; 32],
                        );
                        let tree = TreeId::try_from(*secret.public().as_bytes()).unwrap();
                        let added = testing::Fixture::with(
                            &secret,
                            testing::evidence(),
                            Revision::Sha1([19; 20]),
                        )
                        .await;
                        arrivals.extend(added.commits);
                        if change == Change::Added {
                            peer.commit(
                                project,
                                Receipt::bind(
                                    project,
                                    "tasks/added".parse().unwrap(),
                                    Target::Anchor(Anchor::key(tree)),
                                )
                                .unwrap(),
                            )
                            .await
                            .unwrap();
                        }
                    },
                    | Change::Refusal => {
                        first
                            .push(
                                &testing::stranger(),
                                Receipt::report(
                                    testing::tree(),
                                    first.dispatch,
                                    testing::evidence(),
                                    "refused".parse().unwrap(),
                                )
                                .unwrap(),
                                testing::Fence(201),
                            )
                            .await;
                        arrivals.push(first.commits.last().unwrap().clone());
                    },
                }
                drop(peer);
                (before, first, arrivals, project)
            });
            let identity = before.index.manifest.identity().unwrap();
            testing::runtime().block_on(async {
                let peer = testing::peer(root.path(), arrivals).await;
                let view = peer.view(project).await.unwrap();
                let mut cache = Deriver::owned(&peer, project, &view, &store).unwrap();
                let refreshed = cache.project(&peer, project, &view, &store).await.unwrap();
                let whole = Deriver::default()
                    .project(&peer, project, &view, &store)
                    .await
                    .unwrap();
                drop(peer);
                assert_eq!(refreshed.entries, whole.entries, "{change:?}");
                assert_eq!(refreshed.index.manifest, whole.index.manifest, "{change:?}");
                assert_eq!(
                    refreshed.index.tree.records(),
                    whole.index.tree.records(),
                    "{change:?}"
                );
                if change == Change::None {
                    assert_eq!(refreshed.index.manifest.identity().unwrap(), identity);
                }
                else {
                    assert_ne!(
                        refreshed.index.manifest.identity().unwrap(),
                        identity,
                        "{change:?}"
                    );
                }
                if change == Change::Refusal {
                    let name = "alpha".parse().unwrap();
                    let TaskEntry::Held {
                        heads: ref old_heads,
                        current: ref old_current,
                        dialogue: ref old_dialogue,
                        refused: ref old_refused,
                        ..
                    } = before.entries[&name]
                    else {
                        panic!("held before");
                    };
                    let TaskEntry::Held {
                        ref heads,
                        ref current,
                        ref dialogue,
                        ref refused,
                        ..
                    } = refreshed.entries[&name]
                    else {
                        panic!("held after");
                    };
                    assert_ne!(heads, old_heads);
                    assert_eq!(current, old_current);
                    assert_eq!(dialogue, old_dialogue);
                    assert_eq!(&refused[.. old_refused.len()], old_refused);
                    assert_eq!(
                        refused.len(),
                        usize::from(
                            quenchant_arith::arith::checked_add(
                                quenchant_arith::arith::Int::from(old_refused.len()),
                                quenchant_arith::arith::Int::from(1)
                            )
                            .unwrap()
                        )
                    );
                    assert_eq!(
                        refused.last().unwrap().commit,
                        first.commits.last().unwrap().payload().head()
                    );
                }
            });
        }
    }

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
            let a = cache
                .project(&left_peer, project, &a_view, &a_store)
                .await
                .unwrap();
            drop(left_peer);
            let b = Deriver::default()
                .project(&right_peer, project, &b_view, &b_store)
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
                .project(&peer, project, &view, &store)
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
            let nested_record = nested_project
                .tree
                .records()
                .iter()
                .find(|record| record.key().as_ref() == [0, 3])
                .unwrap();
            assert_eq!(
                gandr_storage_values::decode_flat::<project::Nested>(
                    gandr_storage_values::TokenBody::from(nested_record.value().as_ref())
                )
                .unwrap(),
                project::Nested(nested)
            );
            let expected =
                if domhringr_record_tree::Edition::CURRENT == domhringr_record_tree::Edition::ONE {
                    [
                        "1e53abd1731f7187e752196ee36a1423bae927e59b31308fae7910f77b208b38",
                        "2865821f93dba613b063604c9893a19696987ccdb96ace2a2d648b24db124ca7",
                        "96fa08dec905056f59a52f1734cdcda795679c80e29effaf488b71591b9aa666",
                    ]
                }
                else {
                    [
                        "3006cc5d54f34305805b439ce64b57e1673a62bbffe2147061982e6c3ebe1845",
                        "094cabde3d4cabbafca97d1eed90a1317088e83d8c7304dcc77cc79a89311cfc",
                        "784bde00282e0abb97a1e40ffb9de00507f24ea676c7d35745a26cc533184775",
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
                "b6a9cef475d57590978615bd71cdf0e40ed3a8d071d6d2f31482049a00d10e96"
            );
        });
    }
}
