//! Provenance checked against independently folded evidence and landings.

use alloc::collections::BTreeMap;

use domhringr_record_tree::Heads;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use domhringr_record_tree::Step;
use domhringr_record_tree::TreeId;
use gandr_storage_values::ManifestDigest;
use gandr_storage_values::TokenBody;
use gandr_storage_values::decode_flat;

use super::Attribution;
use super::Field;
use super::Records;
use super::Reference;
use super::Subject;
use crate::IndexKind;
use crate::dialogue;
use crate::dialogue::MoveValue;
use crate::prove;
use crate::prove::Query;
use crate::prove::Verified;
use crate::testing;

#[test]
fn provenance_agrees_with_every_tasks_evidence()
{
    testing::runtime().block_on(async {
        let mut expected = BTreeMap::new();
        let mut evidence = Vec::new();
        let mut dialogues = BTreeMap::new();
        let mut records = Records::default();
        for (secret, digest, revision) in [
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
        ] {
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
            drop(peer);
            assert!(view.refused().iter().any(|entry| entry.0 == refused));
            evidence.extend(
                view.task()
                    .evidence()
                    .map(|(holder, digest)| (tree, holder, digest)),
            );
            for &(commit, ref step) in view.task().steps() {
                let naming = match *step {
                    | Step::Report {
                        author, content, ..
                    } => (Subject::Evidence(content), Attribution {
                        field: Field::Content,
                        holder: author,
                    }),
                    | Step::Verified { runner, output, .. } => {
                        (Subject::Evidence(output), Attribution {
                            field: Field::Output,
                            holder: runner,
                        })
                    },
                    | Step::Verdict {
                        judge, transcript, ..
                    } => (Subject::Evidence(transcript), Attribution {
                        field: Field::Transcript,
                        holder: judge,
                    }),
                    | Step::Landed {
                        operator, merge, ..
                    } => (Subject::Revision(merge), Attribution {
                        field: Field::Revision,
                        holder: operator,
                    }),
                    | Step::Dispatch { .. }
                    | Step::Handoff { .. }
                    | Step::Retire { .. }
                    | Step::Pause { .. }
                    | Step::Graded { .. }
                    | Step::Decide { .. } => continue,
                };
                assert!(expected.insert((tree, commit), naming).is_none());
            }
            let dialogue = dialogue::derive(view.task()).unwrap().index;
            records.extend(tree, &dialogue).unwrap();
            // Binding the same task under another name must not duplicate moves.
            records.extend(tree, &dialogue).unwrap();
            let _previous = dialogues.insert(tree, dialogue);
        }
        let index = records.build().unwrap();
        let mut actual = BTreeMap::new();
        let mut found_evidence = Vec::new();
        for record in index.tree.records() {
            let reference = Reference::try_from(record.key().as_ref()).unwrap();
            let attribution =
                decode_flat::<Attribution>(TokenBody::from(record.value().as_ref())).unwrap();
            let dialogue = &dialogues[&reference.tree];
            let query = Query::Key(reference.position.owned());
            let proof = prove::answer(dialogue, &query).unwrap();
            let Verified::Present(value) = proof
                .verify(
                    dialogue.manifest.identity().unwrap(),
                    IndexKind::Dialogue,
                    &query,
                )
                .unwrap()
            else {
                panic!("provenance must name an admitted move");
            };
            let original = decode_flat::<MoveValue<'_>>(TokenBody::from(value.as_ref())).unwrap();
            let commit = original.commit();
            assert!(
                actual
                    .insert((reference.tree, commit), (reference.subject, attribution))
                    .is_none()
            );
            if let Subject::Evidence(digest) = reference.subject {
                found_evidence.push((reference.tree, attribution.holder, digest));
            }
            let mut trailing = record.key().as_ref().to_vec();
            trailing.push(0);
            assert!(Reference::try_from(trailing.as_slice()).is_err());
            assert!(Reference::try_from(&record.key().as_ref()[.. 32]).is_err());
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
        for digest in [testing::evidence(), ManifestDigest::from([0xff; 32])] {
            let fixture = testing::Fixture::with(
                &iroh::SecretKey::from_bytes(&[3; 32]),
                digest,
                Revision::Sha1([9; 20]),
            )
            .await;
            let root = tempfile::tempdir().unwrap();
            let peer = testing::peer(root.path(), fixture.commits).await;
            let view = peer
                .view_at(testing::tree(), &Heads::from_iter([fixture.standings[2]]))
                .await
                .unwrap();
            drop(peer);
            let dialogue = dialogue::derive(view.task()).unwrap().index;
            let mut records = Records::default();
            records.extend(testing::tree(), &dialogue).unwrap();
            let index = records.build().unwrap();
            let query = Query::Range(Subject::Evidence(digest).range().unwrap());
            let proof = prove::answer(&index, &query).unwrap();
            let Verified::Range(named) = proof
                .verify(
                    index.manifest.identity().unwrap(),
                    IndexKind::Provenance,
                    &query,
                )
                .unwrap()
            else {
                panic!("prefix proof");
            };
            assert_eq!(named.len(), 2);
            let attempts: Vec<_> = named
                .iter()
                .map(|record| {
                    let reference = Reference::try_from(record.key().as_ref()).unwrap();
                    assert_eq!(reference.subject, Subject::Evidence(digest));
                    assert_eq!(reference.tree, testing::tree());
                    assert_eq!(
                        decode_flat::<Attribution>(TokenBody::from(record.value().as_ref()))
                            .unwrap(),
                        Attribution {
                            field: Field::Content,
                            holder: testing::key(&testing::seat())
                        }
                    );
                    reference.position.coordinates().0
                })
                .collect();
            assert_eq!(attempts, [crate::AttemptNumber(1), crate::AttemptNumber(2)]);
            let query = Query::Range(
                Subject::Evidence(ManifestDigest::from([0; 32]))
                    .range()
                    .unwrap(),
            );
            let proof = prove::answer(&index, &query).unwrap();
            assert_eq!(
                proof
                    .verify(
                        index.manifest.identity().unwrap(),
                        IndexKind::Provenance,
                        &query
                    )
                    .unwrap(),
                Verified::Range(Box::new([]))
            );
        }
    });
}
