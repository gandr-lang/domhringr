//! Root-only verification over fixed signed receipt shapes.

use alloc::borrow::Cow;

use domhringr_record_tree::Brief;
use domhringr_record_tree::Edition;
use domhringr_record_tree::Receipt;
use gandr_storage_records::KeyBound;
use gandr_storage_records::KeyRange;
use gandr_storage_records::OwnedKeyRange;
use gandr_storage_records::Record;
use gandr_storage_records::RecordRef;
use gandr_storage_records::RecordTree;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::TreeParams;
use gandr_storage_values::encode_flat;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use super::Answer;
use super::Later;
use super::ProveError;
use super::Query;
use super::Verified;
use crate::AttemptNumber;
use crate::Index;
use crate::IndexKind;
use crate::MoveKey;
use crate::SequenceNumber;
use crate::dialogue;
use crate::dialogue::MoveValue;
use crate::testing;

#[test]
#[expect(
    clippy::big_endian_bytes,
    reason = "ordered numeric test keys separate membership from every adjacent gap"
)]
fn every_key_proves_against_the_manifest_alone()
{
    let keys: Vec<_> = (1 ..= 256_u32)
        .map(|number| {
            u32::from(arith::checked_mul(Int::from(number), Int::from(2)).unwrap()).to_be_bytes()
        })
        .collect();
    let records: Vec<_> = keys
        .iter()
        .map(|key| RecordRef::new(key.as_slice(), key.as_slice()))
        .collect();
    let index = Index::new(
        IndexKind::Dialogue,
        RecordTree::build(&records, TreeParams::current()).unwrap(),
    );
    let digest = index.manifest.identity().unwrap();
    let present: Vec<_> = index
        .tree
        .records()
        .iter()
        .map(|record| {
            let query = Query::Key(record.key().into());
            let answer = super::answer(&index, &query).unwrap();
            (query, answer, record.value().as_ref().to_vec())
        })
        .collect();
    let absent: Vec<_> = (0 ..= 256_u32)
        .map(|number| {
            let doubled = arith::checked_mul(Int::from(number), Int::from(2)).unwrap();
            let bytes = u32::from(arith::checked_add(doubled, Int::from(1)).unwrap()).to_be_bytes();
            let query = Query::Key(bytes.as_slice().into());
            let answer = super::answer(&index, &query).unwrap();
            (query, answer)
        })
        .collect();
    let range = Query::Range(OwnedKeyRange::from_range(
        KeyRange::new(KeyBound::Unbounded, KeyBound::Unbounded).unwrap(),
    ));
    let answer = super::answer(&index, &range).unwrap();
    let expected = index.tree.records().to_vec();
    drop(index);
    for (query, answer, value) in present {
        assert_eq!(
            answer.verify(digest, IndexKind::Dialogue, &query).unwrap(),
            Verified::Present(value.as_slice().into())
        );
    }
    for (position, entry) in absent.iter().enumerate() {
        let Verified::Absent(neighbours) = entry
            .1
            .verify(digest, IndexKind::Dialogue, &entry.0)
            .unwrap()
        else {
            panic!("absence");
        };
        assert_eq!(neighbours.predecessor(), match position {
            | 0 => None,
            | _ => expected.get(usize::from(
                arith::checked_sub(Int::from(position), Int::from(1)).unwrap()
            )),
        });
        assert_eq!(neighbours.successor(), expected.get(position));
    }
    assert_eq!(
        answer.verify(digest, IndexKind::Dialogue, &range).unwrap(),
        Verified::Range(expected.into_boxed_slice())
    );
}

#[test]
fn a_forged_later_attempt_is_refused()
{
    testing::runtime().block_on(async {
        let fixture = testing::Fixture::new().await;
        let root = tempfile::tempdir().unwrap();
        let peer = testing::peer(root.path(), fixture.commits.iter().cloned()).await;
        let view = peer.view(testing::tree()).await.unwrap();
        drop(peer);
        let dialogue = dialogue::derive(view.task()).unwrap();
        let digest = dialogue.index.manifest.identity().unwrap();
        let next = dialogue.attempts.next().unwrap();
        let query = Query::Key(MoveKey::new(next, SequenceNumber(0)).owned());
        let honest = super::answer(&dialogue.index, &query).unwrap();
        let verified = honest.verify(digest, IndexKind::Dialogue, &query).unwrap();
        assert_eq!(
            super::later(testing::tree(), &verified).unwrap(),
            Later::None
        );
        let receipt = testing::fenced(
            &Receipt::dispatch(
                testing::tree(),
                testing::key(&testing::seat()),
                Edition::CURRENT,
                Brief::Content(testing::hash()),
            )
            .unwrap(),
            testing::Fence(500),
        );
        let forged = testing::seal(
            &testing::stranger(),
            &receipt,
            fixture
                .commits
                .last()
                .map(|commit| commit.payload().head())
                .into_iter()
                .collect(),
        )
        .await;
        let forged_id = forged.payload().head();
        let mut commits = fixture.commits;
        commits.push(forged);
        let other = tempfile::tempdir().unwrap();
        let peer = testing::peer(other.path(), commits).await;
        let view = peer.view(testing::tree()).await.unwrap();
        drop(peer);
        assert!(view.refused().iter().any(|entry| entry.0 == forged_id));
        let receipt = encode_flat(&receipt).unwrap();
        let value = encode_flat(&MoveValue {
            author: testing::key(&testing::stranger()),
            blob: Cow::Borrowed(receipt.as_ref()),
        })
        .unwrap();
        let mut records = dialogue.index.tree.records().to_vec();
        records.push(Record::new(
            MoveKey::new(next, SequenceNumber(0)).as_ref(),
            value.as_ref(),
        ));
        let refs: Vec<_> = records.iter().map(Record::as_record_ref).collect();
        let forged = Index::new(
            IndexKind::Dialogue,
            RecordTree::build(&refs, TreeParams::current()).unwrap(),
        );
        let forged = super::answer(&forged, &query).unwrap();
        let forged = Answer {
            manifest: dialogue.index.manifest,
            proof: forged.proof,
        };
        assert!(matches!(
            forged.verify(digest, IndexKind::Dialogue, &query),
            Err(ProveError::Records(
                RecordTreeError::InvalidProofShape { .. }
            ))
        ));
        // A correctly authenticated gap before later records is not the end.
        let gap = super::answer(
            &dialogue.index,
            &Query::Key(MoveKey::new(AttemptNumber(0), SequenceNumber(0)).owned()),
        )
        .unwrap();
        let gap_query = Query::Key(MoveKey::new(AttemptNumber(0), SequenceNumber(0)).owned());
        let verified = gap.verify(digest, IndexKind::Dialogue, &gap_query).unwrap();
        assert!(matches!(
            super::later(testing::tree(), &verified),
            Err(ProveError::MissingDispatch)
        ));
    });
}

#[test]
fn a_move_naming_another_tree_is_refused()
{
    let receipt = testing::fenced(
        &Receipt::dispatch(
            testing::tree(),
            testing::key(&testing::seat()),
            Edition::CURRENT,
            Brief::Content(testing::hash()),
        )
        .unwrap(),
        testing::Fence(600),
    );
    let blob = encode_flat(&receipt).unwrap();
    let value = encode_flat(&MoveValue {
        author: testing::key(&testing::owner()),
        blob: Cow::Borrowed(blob.as_ref()),
    })
    .unwrap();
    let key = MoveKey::new(AttemptNumber(1), SequenceNumber(0));
    let index = Index::new(
        IndexKind::Dialogue,
        RecordTree::build(
            &[RecordRef::new(key.as_ref(), value.as_ref())],
            TreeParams::current(),
        )
        .unwrap(),
    );
    let digest = index.manifest.identity().unwrap();
    let query = Query::Key(key.owned());
    let answer = super::answer(&index, &query).unwrap();
    let Verified::Present(value) = answer.verify(digest, IndexKind::Dialogue, &query).unwrap()
    else {
        panic!("membership");
    };
    let other = domhringr_record_tree::TreeId::try_from(
        *iroh::SecretKey::from_bytes(&[7; 32]).public().as_bytes(),
    )
    .unwrap();
    assert!(
        matches!(super::read_move(other, value), Err(ProveError::Tree { expected, actual }) if expected == other && actual == testing::tree())
    );
}
