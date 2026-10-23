//! Entries written to the store read back as the fold holds them.

use domhringr_record_tree::Answer;
use domhringr_record_tree::Current;
use domhringr_record_tree::Heads;
use domhringr_record_tree::Progress;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::Step;

use super::Subjects;
use super::TaskEntry;
use super::TaskName;
use crate::AttemptNumber;
use crate::derive;
use crate::derive::Deriver;
use crate::keyed::Keyed;
use crate::keyed::Standing;
use crate::prove;
use crate::prove::Local;
use crate::store::Store;
use crate::testing;

#[test]
fn an_entry_agrees_with_the_fold_at_every_standing()
{
    testing::runtime().block_on(async {
        let fixture = testing::Fixture::new().await;
        let (project, bindings) = testing::project_fixture().await;
        let root = tempfile::tempdir().unwrap();
        let peer =
            testing::peer(root.path(), fixture.commits.iter().cloned().chain(bindings)).await;
        let files = Store::open(&StateDir::from(root.path().to_path_buf()));
        let keyed = Keyed::shared().unwrap();
        let name: TaskName = "alpha".parse().unwrap();
        let mut reached = Vec::new();
        for head in &fixture.standings {
            let heads = Heads::from_iter([*head]);
            let view = peer.view_at(testing::tree(), &heads).await.unwrap();
            assert!(view.refused().is_empty());
            let expected = view.task().current();
            let standing = match *expected {
                Current::Undispatched => 0_u8,
                Current::Attempt(ref attempt) => match *attempt.progress() {
                    Progress::Unchecked => match attempt.answer() {
                        Answer::Awaited => 1,
                        Answer::Reported { .. } => 2,
                    },
                    Progress::Verified { .. } => 3,
                    Progress::Graded { .. } => 4,
                    Progress::Decided { .. } => 5,
                    Progress::Landed { .. } => 6,
                },
            };
            reached.push(standing);
            let folded = derive::at(&peer, testing::tree(), &heads).await.unwrap();
            let TaskEntry::Held {
                tree,
                heads: ref actual_heads,
                ref current,
                attempts,
                ref refused,
            } = folded.entry
            else {
                panic!("held task");
            };
            assert_eq!(tree, testing::tree());
            assert_eq!(actual_heads, &heads);
            assert_eq!(current, expected);
            assert_eq!(refused.len(), view.refused().len());
            assert!(
                refused
                    .iter()
                    .zip(view.refused())
                    .all(|(held, viewed)| *held == super::Refused::from(viewed)),
                "the entry holds the view's refusals in order"
            );
            let dispatches = view
                .task()
                .steps()
                .iter()
                .filter(|entry| matches!(entry.1, Step::Dispatch { .. }))
                .count();
            assert_eq!(attempts, AttemptNumber(u32::try_from(dispatches).unwrap()));
            // The store holds the standing's kind and the play; the standing
            // printed from them is the fold's.
            let mut store = keyed.store().unwrap();
            let task = super::add(
                &mut store,
                keyed,
                &name,
                &folded.entry,
                &folded.dialogue,
                super::Carrier::Owner,
                &mut Subjects::default(),
            )
            .unwrap();
            let mut local = Local(&store);
            let claim = prove::claim(&mut local, keyed, task).await.unwrap();
            assert_eq!(claim.standing, Standing::of(expected));
            assert_eq!(claim.heads, heads);
            assert_eq!(&claim.refused, refused);
            assert_eq!(claim.attempts.len(), dispatches);
            // Equal standings print equally: `open` from the tag and the play
            // is the fold's `open`.
            let recomputed = prove::current(&mut local, keyed, &claim).await.unwrap();
            assert_eq!(&recomputed, expected);
            let contents = prove::contents(&mut local, keyed, [name.clone()])
                .await
                .unwrap();
            let moves = contents.0[&name].plays.iter().map(Vec::len).sum::<usize>();
            assert_eq!(moves, view.task().steps().len());
        }
        assert_eq!(reached, [0, 1, 2, 3, 4, 5, 6]);
        let view = peer.view(project).await.unwrap();
        let derived = Deriver::default()
            .project(&peer, project, &view, &files)
            .await
            .unwrap();
        drop(peer);
        let names: Vec<_> = derived.entries.keys().map(TaskName::as_ref).collect();
        assert_eq!(names, ["alpha", "unheld", "zeta"]);
        assert_eq!(
            derived.entries[&"alpha".parse().unwrap()],
            derived.entries[&"zeta".parse().unwrap()]
        );
        assert!(matches!(
            derived.entries[&"unheld".parse().unwrap()],
            TaskEntry::Unheld { .. }
        ));
        let mut local = Local(&derived.store);
        let contents = prove::contents(&mut local, keyed, derived.entries.keys().cloned())
            .await
            .unwrap();
        let [alpha, unheld, zeta] =
            ["alpha", "unheld", "zeta"].map(|name| &contents.0[&name.parse::<TaskName>().unwrap()]);
        // Only the first name of a tree carries its provenance.
        assert!(!alpha.namings.is_empty());
        assert!(zeta.namings.is_empty());
        assert_eq!(alpha.plays, zeta.plays);
        assert_eq!(unheld.standing, Standing::Unheld);
        assert!(unheld.plays.is_empty() && unheld.heads.iter().next().is_none());
    });
}
