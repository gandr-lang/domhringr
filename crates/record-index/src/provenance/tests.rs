//! Provenance checked against independently folded evidence and landings.

use alloc::collections::BTreeMap;

use domhringr_record_tree::Heads;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use domhringr_record_tree::Step;
use domhringr_record_tree::TreeId;
use gandr_storage_values::ManifestDigest;

use super::Attribution;
use super::Field;
use super::Subject;
use crate::derive;
use crate::keyed::Keyed;
use crate::project;
use crate::project::Subjects;
use crate::project::TaskName;
use crate::prove;
use crate::prove::Local;
use crate::testing;

#[test]
fn provenance_agrees_with_every_tasks_evidence()
{
    testing::runtime().block_on(async {
        let keyed = Keyed::shared().unwrap();
        let mut store = keyed.store().unwrap();
        let mut subjects = Subjects::default();
        let mut expected = BTreeMap::new();
        let mut evidence = Vec::new();
        for (index, (secret, digest, revision)) in [
            (
                iroh::SecretKey::from_bytes(&[3; 32]),
                testing::evidence(),
                Revision::Sha1([9; 20]),
            ),
            (
                iroh::SecretKey::from_bytes(&[17; 32]),
                ManifestDigest::from([0xff; 32]),
                Revision::Sha256([10; 32]),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let tree = TreeId::try_from(*secret.public().as_bytes()).unwrap();
            let mut fixture = testing::Fixture::with(&secret, digest, revision).await;
            let refused = fixture
                .push(
                    &testing::stranger(),
                    Receipt::report(
                        tree,
                        fixture.dispatch,
                        ManifestDigest::from([99; 32]),
                        "refused".parse().unwrap(),
                    )
                    .unwrap(),
                    testing::Fence(99),
                )
                .await;
            let root = tempfile::tempdir().unwrap();
            let peer = testing::peer(root.path(), fixture.commits).await;
            let view = peer.view(tree).await.unwrap();
            let folded = derive::at(&peer, tree, &peer.heads(tree).await.unwrap())
                .await
                .unwrap();
            drop(peer);
            assert!(view.refused().iter().any(|entry| entry.0 == refused));
            evidence.extend(
                view.task()
                    .evidence()
                    .map(|(holder, digest)| (tree, holder, digest)),
            );
            for &(commit, ref step) in view.task().steps() {
                let naming = match *step {
                    Step::Report {
                        author, content, ..
                    } => (Subject::Evidence(content), Attribution {
                        field: Field::Content,
                        holder: author,
                    }),
                    Step::Verified { runner, output, .. } => {
                        (Subject::Evidence(output), Attribution {
                            field: Field::Output,
                            holder: runner,
                        })
                    },
                    Step::Verdict {
                        judge, transcript, ..
                    } => (Subject::Evidence(transcript), Attribution {
                        field: Field::Transcript,
                        holder: judge,
                    }),
                    Step::Landed {
                        operator, merge, ..
                    } => (Subject::Revision(merge), Attribution {
                        field: Field::Revision,
                        holder: operator,
                    }),
                    Step::Dispatch { .. }
                    | Step::Handoff { .. }
                    | Step::Retire { .. }
                    | Step::Pause { .. }
                    | Step::Graded { .. }
                    | Step::Decide { .. } => continue,
                };
                assert!(expected.insert((tree, commit), naming).is_none());
            }
            // A second name for the same task must not duplicate its namings.
            for (alias, carrier) in [
                (format!("task-{index}"), project::Carrier::Owner),
                (format!("alias-{index}"), project::Carrier::Alias),
            ] {
                let _task = project::add(
                    &mut store,
                    keyed,
                    &alias.parse::<TaskName>().unwrap(),
                    &folded.entry,
                    &folded.dialogue,
                    carrier,
                    &mut subjects,
                )
                .unwrap();
            }
        }
        let mut local = Local(&store);
        let mut actual = BTreeMap::new();
        let mut found_evidence = Vec::new();
        let mut asked = alloc::collections::BTreeSet::new();
        for subject in expected.values().map(|naming| naming.0) {
            if !asked.insert(subject.value()) {
                continue;
            }
            for named in prove::named(&mut local, keyed, subject).await.unwrap() {
                let tree = named.movement.receipt.tree();
                assert!(named.task.as_ref().starts_with("task-"));
                let attribution = Attribution {
                    field: named.field,
                    holder: named.holder,
                };
                assert!(
                    actual
                        .insert((tree, named.movement.commit), (subject, attribution))
                        .is_none()
                );
                if let Subject::Evidence(digest) = subject {
                    found_evidence.push((tree, named.holder, digest));
                }
            }
        }
        assert_eq!(actual, expected);
        evidence.sort_by(|left, right| {
            (left.0.as_ref(), left.1.as_ref(), left.2.as_ref()).cmp(&(
                right.0.as_ref(),
                right.1.as_ref(),
                right.2.as_ref(),
            ))
        });
        found_evidence.sort_by(|left, right| {
            (left.0.as_ref(), left.1.as_ref(), left.2.as_ref()).cmp(&(
                right.0.as_ref(),
                right.1.as_ref(),
                right.2.as_ref(),
            ))
        });
        assert_eq!(found_evidence, evidence);
    });
}

#[test]
fn a_digest_named_twice_has_two_records()
{
    testing::runtime().block_on(async {
        let keyed = Keyed::shared().unwrap();
        for digest in [testing::evidence(), ManifestDigest::from([0xff; 32])] {
            let fixture = testing::Fixture::with(
                &iroh::SecretKey::from_bytes(&[3; 32]),
                digest,
                Revision::Sha1([9; 20]),
            )
            .await;
            let root = tempfile::tempdir().unwrap();
            let peer = testing::peer(root.path(), fixture.commits).await;
            let folded = derive::at(
                &peer,
                testing::tree(),
                &Heads::from_iter([fixture.standings[2]]),
            )
            .await
            .unwrap();
            drop(peer);
            let mut store = keyed.store().unwrap();
            let _task = project::add(
                &mut store,
                keyed,
                &"task".parse().unwrap(),
                &folded.entry,
                &folded.dialogue,
                project::Carrier::Owner,
                &mut Subjects::default(),
            )
            .unwrap();
            let mut local = Local(&store);
            let named = prove::named(&mut local, keyed, Subject::Evidence(digest))
                .await
                .unwrap();
            let attempts: Vec<_> = named
                .iter()
                .map(|named| {
                    assert_eq!(named.movement.receipt.tree(), testing::tree());
                    assert_eq!(named.field, Field::Content);
                    assert_eq!(named.holder, testing::key(&testing::seat()));
                    named.key.coordinates().0
                })
                .collect();
            assert_eq!(attempts, [crate::AttemptNumber(1), crate::AttemptNumber(2)]);
            // One subject holds both namings.
            assert_eq!(u64::from(store.live_count(keyed.subject).unwrap()), 1);
            // A revision of the digest's bytes is another subject.
            let mut bytes = [0; 32];
            bytes.copy_from_slice(digest.as_ref());
            assert!(
                prove::named(
                    &mut local,
                    keyed,
                    Subject::Revision(Revision::Sha256(bytes))
                )
                .await
                .unwrap()
                .is_empty()
            );
            assert!(
                prove::named(
                    &mut local,
                    keyed,
                    Subject::Evidence(ManifestDigest::from([0; 32]))
                )
                .await
                .unwrap()
                .is_empty()
            );
        }
    });
}
