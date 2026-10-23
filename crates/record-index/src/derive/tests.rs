//! Refreshed, reordered and pinned derivations.

use domhringr_record_tree::Anchor;
use domhringr_record_tree::Brief;
use domhringr_record_tree::Edition;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::Target;
use domhringr_record_tree::TreeId;

use super::Derived;
use super::Deriver;
use crate::keyed::Keyed;
use crate::project::TaskEntry;
use crate::prove;
use crate::prove::Contents;
use crate::prove::Local;
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

/// A derived store's contents.
///
/// # Specification
/// trivial.
async fn contents(derived: &Derived) -> Contents
{
    prove::contents(
        &mut Local(&derived.store),
        Keyed::shared().unwrap(),
        derived.entries.keys().cloned(),
    )
    .await
    .unwrap()
}

#[test]
fn a_refreshed_index_equals_one_derived_whole()
{
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
            peer.commit(
                project,
                Receipt::indexed(project, super::digest(before.root())).unwrap(),
            )
            .await
            .unwrap();
            let mut arrivals = Vec::new();
            match change {
                Change::None => {},
                Change::One | Change::Every => {
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
                Change::Added | Change::Held => {
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
                Change::Refusal => {
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
        testing::runtime().block_on(async {
            let before_contents = contents(&before).await;
            let peer = testing::peer(root.path(), arrivals).await;
            let view = peer.view(project).await.unwrap();
            let mut cache = Deriver::owned(&peer, project, &view, &store).unwrap();
            let refreshed = cache.project(&peer, project, &view, &store).await.unwrap();
            let whole_root = tempfile::tempdir().unwrap();
            let whole_store = Store::open(&StateDir::from(whole_root.path().to_path_buf()));
            let whole = Deriver::default()
                .project(&peer, project, &view, &whole_store)
                .await
                .unwrap();
            drop(peer);
            assert_eq!(refreshed.entries, whole.entries, "{change:?}");
            let refreshed_contents = contents(&refreshed).await;
            assert_eq!(refreshed_contents, contents(&whole).await, "{change:?}");
            if change == Change::None {
                assert_eq!(refreshed.root(), before.root());
            }
            else {
                assert_ne!(refreshed_contents, before_contents, "{change:?}");
                assert_ne!(refreshed.root(), before.root(), "{change:?}");
            }
            if change == Change::Refusal {
                let name = "alpha".parse().unwrap();
                let TaskEntry::Held {
                    heads: ref old_heads,
                    current: ref old_current,
                    refused: ref old_refused,
                    ..
                } = before.entries[&name]
                else {
                    panic!("held before");
                };
                let TaskEntry::Held {
                    ref heads,
                    ref current,
                    ref refused,
                    ..
                } = refreshed.entries[&name]
                else {
                    panic!("held after");
                };
                assert_ne!(heads, old_heads);
                assert_eq!(current, old_current);
                assert_eq!(
                    refreshed_contents.0[&name].plays,
                    before_contents.0[&name].plays
                );
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
        let a = Deriver::default()
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
        assert_eq!(a.root(), b.root());
        assert_eq!(a.store.manifest(), b.store.manifest());
    });
}

#[test]
fn the_fixture_store_is_pinned()
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
        let expected = if Edition::CURRENT == Edition::ONE {
            "f21a235cde44fc972c1aaf26082f5e8d2b9fdf11a6a0790743df95ccf19b2fd4"
        }
        else {
            "19472be58de9cf56e63fd372fffd0ba203fa86e7641a0541f61435027ef23fe1"
        };
        assert_eq!(derived.root().to_string(), expected);
    });
}
