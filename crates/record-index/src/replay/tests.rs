//! Authenticated membership and protocol admission have different witnesses.

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt::Write as _;

use domhringr_arena_session::Arena;
use domhringr_arena_session::Movement;
use domhringr_record_tree::Brief;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Current;
use domhringr_record_tree::Decision;
use domhringr_record_tree::Edition;
use domhringr_record_tree::Heads;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use gandr_storage_records::RecordRef;
use gandr_storage_records::RecordTree;
use gandr_storage_records::TreeParams;
use gandr_storage_values::encode_flat;

use super::Reason;
use super::ReplayError;
use crate::AttemptNumber;
use crate::Index;
use crate::IndexKind;
use crate::MoveKey;
use crate::SequenceNumber;
use crate::dialogue::MoveValue;
use crate::prove;
use crate::prove::Query;
use crate::testing;

/// Build an attester's claim independently of the receipt fold.
///
/// # Specification
/// trivial.
fn index(receipts: &[Receipt]) -> Index
{
    let encoded: Vec<_> = receipts
        .iter()
        .enumerate()
        .map(|(seq, receipt)| {
            let blob = encode_flat(receipt).unwrap();
            let value = encode_flat(&MoveValue {
                author: testing::key(&testing::owner()),
                blob: Cow::Borrowed(blob.as_ref()),
            })
            .unwrap();
            (
                MoveKey::new(
                    AttemptNumber(1),
                    SequenceNumber(u32::try_from(seq).unwrap()),
                ),
                value,
            )
        })
        .collect();
    let records: Vec<_> = encoded
        .iter()
        .map(|entry| RecordRef::new(entry.0.as_ref(), entry.1.as_ref()))
        .collect();
    Index::new(
        IndexKind::Dialogue,
        RecordTree::build(&records, TreeParams::current()).unwrap(),
    )
}

/// The original receipt identity, independent of the replay implementation.
///
/// # Specification
/// trivial.
fn commit(receipt: &Receipt) -> CommitId
{
    let encoded = encode_flat(receipt).unwrap();
    CommitId::new(*blake3::hash(encoded.as_ref()).as_bytes())
}

/// Authenticate an independently claimed attempt before replay.
///
/// # Specification
/// trivial.
fn proved(receipts: &[Receipt]) -> Vec<(MoveKey, prove::Move)>
{
    let index = index(receipts);
    let query = Query::Range(AttemptNumber(1).range().unwrap());
    let proof = prove::answer(&index, &query).unwrap();
    let digest = index.manifest.identity().unwrap();
    assert!(matches!(
        proof.verify(digest, IndexKind::Dialogue, &query).unwrap(),
        prove::Verified::Range(_)
    ));
    prove::play(&proof, digest, testing::tree(), AttemptNumber(1)).unwrap()
}

/// Replay the authenticated claim through the public boundary.
///
/// # Specification
/// trivial.
fn played(receipts: &[Receipt]) -> Result<super::Replayed, ReplayError>
{
    super::replay(
        &Arena::new().map_err(Box::new)?,
        AttemptNumber(1),
        &proved(receipts),
    )
}

#[test]
#[cfg_attr(
    dylint_lib = "quenchant_dylints",
    expect(
        linear_search_in_loop,
        reason = "bounded: the fixture task's few sources and steps, searched once per move of one attempt"
    )
)]
fn proved_attempts_replay_every_standing()
{
    testing::runtime().block_on(async {
        let fixture = testing::Fixture::new().await;
        let root = tempfile::tempdir().unwrap();
        let peer = testing::peer(root.path(), fixture.commits).await;
        let arena = Arena::new().unwrap();
        let mut standings = Vec::new();
        // Each standing's display, one buffer refilled per head.
        let mut shown = String::new();
        for head in fixture.standings {
            let view = peer
                .view_at(testing::tree(), &Heads::from_iter([head]))
                .await
                .unwrap();
            let dialogue = crate::dialogue::derive(view.task()).unwrap();
            let digest = dialogue.index.manifest.identity().unwrap();
            let mut reached = Current::Undispatched;
            for number in 1 ..= dialogue.attempts.0 {
                let attempt = AttemptNumber(number);
                let query = Query::Range(attempt.range().unwrap());
                let answer = prove::answer(&dialogue.index, &query).unwrap();
                let moves = prove::play(&answer, digest, testing::tree(), attempt).unwrap();
                for entry in &moves {
                    let movement = &entry.1;
                    let original = view
                        .task()
                        .sources()
                        .iter()
                        .find(|source| source.commit == movement.commit)
                        .unwrap();
                    assert_eq!(movement.image.as_ref(), original.blob.as_slice());
                    assert_eq!(movement.author, original.author);
                }
                let played = super::replay(&arena, attempt, &moves).unwrap();
                for step in &played.steps {
                    assert!(view.task().steps().contains(step));
                }
                reached = played.current;
                assert!(matches!(
                    prove::play(&answer, digest, testing::tree(), AttemptNumber(0)),
                    Err(prove::ProveError::Records(
                        gandr_storage_records::RecordTreeError::InvalidProofShape { .. }
                    ))
                ));
            }
            assert_eq!(&reached, view.task().current());
            shown.clear();
            write!(shown, "{reached}").unwrap();
            standings.push(shown.split_whitespace().next().unwrap().to_owned());
        }
        drop(peer);
        assert_eq!(standings, [
            "undispatched",
            "dispatched",
            "reported",
            "verified",
            "graded",
            "decided",
            "landed"
        ]);
    });
}

#[test]
fn proof_membership_does_not_admit_a_play()
{
    let tree = testing::tree();
    let owner = testing::key(&testing::owner());
    let dispatch =
        Receipt::dispatch(tree, owner, Edition::ONE, Brief::Content(testing::hash())).unwrap();
    let dispatched = commit(&dispatch);
    let report = Receipt::report(
        tree,
        dispatched,
        testing::evidence(),
        "first".parse().unwrap(),
    )
    .unwrap();
    let retire = Receipt::retire(tree, dispatched).unwrap();
    let late = Receipt::report(
        tree,
        dispatched,
        testing::evidence(),
        "late".parse().unwrap(),
    )
    .unwrap();
    let land = Receipt::landed(tree, CommitId::new([9; 32]), Revision::Sha1([9; 20])).unwrap();
    let verdict = Receipt::verdict(
        tree,
        dispatched,
        owner,
        testing::hash(),
        testing::evidence(),
        vec![],
    )
    .unwrap();
    let graded = Receipt::graded(
        tree,
        commit(&verdict),
        vec![],
        domhringr_record_tree::Grade::Met,
    )
    .unwrap();
    let decided = Receipt::decide(tree, dispatched, owner, Decision::Land).unwrap();
    let landed = Receipt::landed(tree, commit(&decided), Revision::Sha1([9; 20])).unwrap();
    for (receipts, seq, expected) in [
        (
            vec![dispatch.clone(), report.clone(), retire, late],
            SequenceNumber(3),
            Movement::Report,
        ),
        (
            vec![dispatch.clone(), land],
            SequenceNumber(1),
            Movement::Landed,
        ),
        (
            vec![dispatch.clone(), graded.clone()],
            SequenceNumber(1),
            Movement::Graded,
        ),
        (
            vec![dispatch.clone(), verdict, graded.clone(), graded],
            SequenceNumber(3),
            Movement::Graded,
        ),
        (
            vec![dispatch.clone(), decided.clone(), decided.clone()],
            SequenceNumber(2),
            Movement::Decide(domhringr_arena_session::Choice::Land),
        ),
        (
            vec![dispatch.clone(), decided, landed.clone(), landed],
            SequenceNumber(3),
            Movement::Landed,
        ),
    ] {
        let ReplayError::Move(refusal) = played(&receipts).unwrap_err()
        else {
            panic!("move refusal");
        };
        assert_eq!((refusal.attempt, refusal.seq), (AttemptNumber(1), seq));
        let Reason::Protocol(reason) = refusal.reason
        else {
            panic!("monitor refusal");
        };
        assert_eq!(reason.movement, expected);
        assert_eq!(reason.edition, Edition::ONE);
    }
    for decision in [
        Decision::Rework {
            reason: "again".parse().unwrap(),
        },
        Decision::Abandon,
    ] {
        let decide = Receipt::decide(tree, dispatched, owner, decision.clone()).unwrap();
        let landed = Receipt::landed(tree, commit(&decide), Revision::Sha1([9; 20])).unwrap();
        let accepted = played(&[dispatch.clone(), decide.clone()]).unwrap();
        assert!(
            matches!(accepted.current, Current::Attempt(ref attempt) if matches!(attempt.progress(), domhringr_record_tree::Progress::Decided { decision: actual, .. } if actual == &decision))
        );
        let ReplayError::Move(refusal) = played(&[dispatch.clone(), decide, landed]).unwrap_err()
        else {
            panic!("move refusal");
        };
        assert_eq!(refusal.seq, SequenceNumber(2));
        assert!(
            matches!(refusal.reason, Reason::Protocol(ref reason) if reason.movement == Movement::Landed)
        );
    }
    let unknown = Receipt::dispatch(
        tree,
        owner,
        Edition::from(99),
        Brief::Content(testing::hash()),
    )
    .unwrap();
    let ReplayError::Move(refusal) = played(&[unknown]).unwrap_err()
    else {
        panic!("move refusal");
    };
    assert_eq!(refusal.seq, SequenceNumber(0));
    assert!(
        matches!(refusal.reason, Reason::Protocol(ref reason) if reason.edition == Edition::from(99) && reason.movement == Movement::Dispatch && matches!(reason.reason, domhringr_arena_session::Reason::Unknown(_)))
    );
    let ReplayError::Move(refusal) = played(&[report]).unwrap_err()
    else {
        panic!("dispatch refusal");
    };
    assert!(matches!(refusal.reason, Reason::Dispatch));
    let foreign = Receipt::report(
        tree,
        CommitId::new([8; 32]),
        testing::evidence(),
        "foreign".parse().unwrap(),
    )
    .unwrap();
    let ReplayError::Move(refusal) = played(&[dispatch, foreign]).unwrap_err()
    else {
        panic!("reference refusal");
    };
    assert!(matches!(
        refusal.reason,
        Reason::Reference(Movement::Report)
    ));
    assert_eq!(refusal.seq, SequenceNumber(1));
    assert!(matches!(
        played(&[]),
        Err(ReplayError::Absent(AttemptNumber(1)))
    ));
}
