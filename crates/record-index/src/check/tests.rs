//! Attestations are claims, checked against their historical inputs.

use alloc::collections::BTreeMap;

use domhringr_record_tree::Anchor;
use domhringr_record_tree::Authority;
use domhringr_record_tree::Current;
use domhringr_record_tree::Heads;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::Target;

use super::Field;
use super::Finding;
use super::Report;
use crate::derive;
use crate::project;
use crate::project::TaskEntry;
use crate::store::Store;
use crate::testing;

#[test]
fn a_forged_entry_is_found_by_re_derivation()
{
    testing::runtime().block_on(async {
        let fixture = testing::Fixture::new().await;
        let (project, commits) = testing::project_fixture().await;
        // Open and the two held aliases; the other mixed bindings are covered
        // by the project witness, not included in this fully checkable claim.
        let mut project_commits: Vec<_> = commits.into_iter().take(3).collect();
        let root = tempfile::tempdir().unwrap();
        let peer = testing::peer(
            root.path(),
            fixture
                .commits
                .iter()
                .cloned()
                .chain(project_commits.iter().cloned()),
        )
        .await;
        let store = Store::open(&StateDir::from(root.path().to_path_buf()));
        let project_view = peer.view(project).await.unwrap();
        let heads = Heads::from_iter([fixture.standings[4]]);
        let mut entries = BTreeMap::new();
        for (name, tree) in project::bindings(&project_view) {
            entries.insert(name, derive::at(&peer, tree, &heads, &store).await.unwrap());
        }
        drop(peer);
        let honest = project::build(&entries, &BTreeMap::new()).unwrap();
        let honest_digest = store.keep(&honest).unwrap();
        let receipt = testing::fenced(
            &Receipt::indexed(project, honest_digest).unwrap(),
            testing::Fence(100),
        );
        let parents = project_commits
            .last()
            .map(|commit| commit.payload().head())
            .into_iter()
            .collect();
        let honest_claim = testing::seal(&testing::owner(), &receipt, parents).await;
        let honest_commit = honest_claim.payload().head();
        project_commits.push(honest_claim);
        let TaskEntry::Held {
            ref mut current, ..
        } = *entries.get_mut(&"alpha".parse().unwrap()).unwrap()
        else {
            panic!("held alias");
        };
        *current = Current::Undispatched;
        let forged = project::build(&entries, &BTreeMap::new()).unwrap();
        let forged_digest = store.keep(&forged).unwrap();
        let receipt = testing::fenced(
            &Receipt::indexed(project, forged_digest).unwrap(),
            testing::Fence(101),
        );
        let forged_claim = testing::seal(
            &testing::owner(),
            &receipt,
            core::iter::once(honest_commit).collect(),
        )
        .await;
        let forged_commit = forged_claim.payload().head();
        project_commits.push(forged_claim);
        let receipt = Receipt::bind(
            project,
            "tasks/later".parse().unwrap(),
            Target::Anchor(Anchor::Tree(Authority::Key(testing::tree()))),
        )
        .unwrap();
        let receipt = testing::fenced(&receipt, testing::Fence(102));
        project_commits.push(
            testing::seal(
                &testing::owner(),
                &receipt,
                core::iter::once(forged_commit).collect(),
            )
            .await,
        );
        let checked_root = tempfile::tempdir().unwrap();
        let checked = testing::peer(
            checked_root.path(),
            fixture
                .commits
                .into_iter()
                .chain(project_commits.iter().cloned()),
        )
        .await;
        let view = checked.view(project).await.unwrap();
        let honest_claim = &view
            .attestations()
            .iter()
            .find(|entry| entry.1.commit == honest_commit)
            .unwrap()
            .1;
        let forged_claim = &view
            .attestations()
            .iter()
            .find(|entry| entry.1.commit == forged_commit)
            .unwrap()
            .1;
        assert_eq!(
            view.indexes()[&testing::key(&testing::owner())].index,
            forged_digest
        );
        assert_eq!(
            super::check(&checked, project, honest_claim, &honest)
                .await
                .unwrap(),
            Report::default()
        );
        assert_eq!(
            super::check(&checked, project, forged_claim, &forged)
                .await
                .unwrap(),
            Report(vec![Finding::Disagrees {
                task: "alpha".parse().unwrap(),
                field: Field::Current
            }])
        );
        drop(checked);
        let lacking_root = tempfile::tempdir().unwrap();
        let lacking = testing::peer(lacking_root.path(), project_commits).await;
        assert_eq!(
            super::check(&lacking, project, honest_claim, &honest)
                .await
                .unwrap(),
            Report(vec![
                Finding::Unchecked("alpha".parse().unwrap()),
                Finding::Unchecked("zeta".parse().unwrap())
            ])
        );
    });
}
