//! Attestations are claims, checked against their historical inputs.

use domhringr_record_tree::Anchor;
use domhringr_record_tree::Authority;
use domhringr_record_tree::Heads;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Target;
use gandr_storage_records::InMemoryBlockStore;

use super::Field;
use super::Finding;
use super::Report;
use crate::derive;
use crate::keyed::Keyed;
use crate::keyed::Standing;
use crate::project;
use crate::project::Subjects;
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
        let keyed = Keyed::shared().unwrap();
        let project_view = peer.view(project).await.unwrap();
        let heads = Heads::from_iter([fixture.standings[4]]);
        let mut honest = keyed.store().unwrap();
        let mut subjects = Subjects::default();
        let mut owners = alloc::collections::BTreeSet::new();
        for (name, tree) in project::bindings(&project_view) {
            let folded = derive::at(&peer, tree, &heads).await.unwrap();
            let _task = project::add(
                &mut honest,
                keyed,
                &name,
                &folded.entry,
                &folded.dialogue,
                if owners.insert(tree) {
                    project::Carrier::Owner
                }
                else {
                    project::Carrier::Alias
                },
                &mut subjects,
            )
            .unwrap();
        }
        drop(peer);
        let honest_root = honest.commit(&mut InMemoryBlockStore::new()).unwrap();
        let receipt = testing::fenced(
            &Receipt::indexed(project, derive::digest(honest_root)).unwrap(),
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
        let mut forged = honest.clone();
        let alpha = project::names(&forged, keyed).unwrap()[&"alpha".parse().unwrap()];
        forged
            .set_value(keyed.task_standing, alpha, Standing::Undispatched.value())
            .unwrap();
        let forged_root = forged.commit(&mut InMemoryBlockStore::new()).unwrap();
        let receipt = testing::fenced(
            &Receipt::indexed(project, derive::digest(forged_root)).unwrap(),
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
            derive::digest(forged_root)
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
        assert!(matches!(
            super::check(&checked, project, honest_claim, &forged).await,
            Err(super::CheckError::Identity)
        ));
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
