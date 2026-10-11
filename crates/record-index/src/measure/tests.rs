//! Fixed receipt shapes and exhaustive extrema witnesses.

use gandr_storage_records::OwnedRecordValue;
use gandr_storage_records::Record;
use gandr_storage_records::RecordCount;
use gandr_storage_records::RecordTree;
use gandr_storage_records::TreeParams;
use gandr_storage_values::encode_flat;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use super::ByteSize;
use super::Levels;
use super::Measurement;
use super::measure;
use crate::AttemptNumber;
use crate::Index;
use crate::IndexKind;
use crate::MoveKey;
use crate::SequenceNumber;
use crate::derive;
use crate::dialogue;
use crate::store::Store;
use crate::testing;

/// Real encoded moves and task standings from the fixed-key receipt fixture.
///
/// # Specification
/// trivial.
async fn shapes() -> (Vec<OwnedRecordValue>, Vec<OwnedRecordValue>)
{
    let fixture = testing::Fixture::new().await;
    let directory = tempfile::tempdir().unwrap();
    let peer = testing::peer(directory.path(), fixture.commits).await;
    let state = domhringr_record_tree::StateDir::from(directory.path().to_path_buf());
    let store = Store::open(&state);
    let view = peer.view(testing::tree()).await.unwrap();
    let dialogue = dialogue::derive(view.task()).unwrap();
    let moves = dialogue
        .index
        .tree
        .records()
        .iter()
        .map(|record| OwnedRecordValue::from(record.value().as_ref()))
        .collect();
    let mut entries = Vec::new();
    for head in fixture.standings {
        let heads = domhringr_record_tree::Heads::from_iter([head]);
        let entry = derive::at(&peer, testing::tree(), &heads, &store)
            .await
            .unwrap();
        let image = encode_flat(&entry).unwrap();
        entries.push(OwnedRecordValue::from(image.as_ref()));
    }
    drop(peer);
    (moves, entries)
}

/// Repeat real value shapes at distinct coordinates of the index's key
/// language.
///
/// # Specification
/// trivial.
fn index(
    kind: IndexKind,
    count: RecordCount,
    shapes: &[OwnedRecordValue],
) -> Index
{
    let count = usize::try_from(u64::from(count)).unwrap();
    let records: Vec<_> = shapes
        .iter()
        .cycle()
        .take(count)
        .enumerate()
        .map(|(position, value)| {
            let key = match kind {
                | IndexKind::Dialogue => MoveKey::new(
                    AttemptNumber(1),
                    SequenceNumber(u32::try_from(position).unwrap()),
                )
                .owned(),
                | IndexKind::Project => format!("task-{position:08}")
                    .parse::<crate::project::TaskName>()
                    .unwrap()
                    .key(),
                | IndexKind::Provenance => panic!("provenance has its own measurement fixture"),
            };
            Record::new(key, value.clone())
        })
        .collect();
    let records: Vec<_> = records.iter().map(Record::as_record_ref).collect();
    Index::new(
        kind,
        RecordTree::build(&records, TreeParams::current()).unwrap(),
    )
}

/// Encoded measurement columns in the public table order.
#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
struct Row([u64; 5]);

/// Comparable numeric measurement, retaining the crossing signal.
///
/// # Specification
/// trivial.
fn row(measurement: Measurement) -> (Row, Levels)
{
    (
        Row([
            u64::from(measurement.records),
            u64::try_from(measurement.children.0).unwrap(),
            measurement.root.0,
            measurement.leaf.0,
            measurement.proof.0,
        ]),
        measurement.levels,
    )
}

#[test]
fn the_proof_sizes_are_pinned()
{
    testing::runtime().block_on(async {
        let (moves, entries) = shapes().await;
        let (dialogue, project) =
            if domhringr_record_tree::Edition::CURRENT == domhringr_record_tree::Edition::ONE {
                (
                    [
                        [16, 2, 160, 2672, 5017],
                        [32, 3, 216, 5544, 7945],
                        [64, 6, 384, 5544, 8587],
                        [128, 10, 608, 6533, 11677],
                        [256, 15, 888, 16815, 19828],
                        [512, 30, 1728, 16815, 23281],
                        [1024, 64, 3632, 16815, 25185],
                        [2048, 109, 6152, 16815, 37934],
                        [4096, 226, 12704, 16815, 44486],
                        [5153, 300, 16848, 16815, 48630],
                    ],
                    [
                        [16, 0, 5552, 5552, 6478],
                        [32, 2, 172, 9636, 12477],
                        [64, 3, 234, 10245, 14163],
                        [128, 8, 544, 16097, 20905],
                        [256, 14, 916, 23009, 28872],
                        [512, 35, 2218, 23009, 30174],
                        [1024, 81, 5070, 23009, 33026],
                        [2048, 152, 9472, 23009, 37428],
                        [4096, 280, 17408, 23035, 47336],
                        [5608, 371, 23050, 23035, 55614],
                    ],
                )
            }
            else {
                (
                    [
                        [16, 2, 160, 2655, 4868],
                        [32, 4, 272, 4291, 6616],
                        [64, 6, 384, 4606, 9398],
                        [128, 9, 552, 6182, 13360],
                        [256, 20, 1168, 11028, 18822],
                        [512, 35, 2008, 11028, 19662],
                        [1024, 68, 3856, 12324, 21510],
                        [2048, 136, 7664, 13516, 27648],
                        [4096, 255, 14328, 16359, 38508],
                        [4691, 293, 16456, 16439, 46041],
                    ],
                    [
                        [16, 0, 5552, 5552, 6478],
                        [32, 2, 172, 6723, 12451],
                        [64, 4, 296, 7561, 15488],
                        [128, 9, 606, 14152, 23685],
                        [256, 18, 1164, 14152, 24243],
                        [512, 26, 1660, 23035, 39238],
                        [1024, 56, 3520, 23035, 41098],
                        [2048, 117, 7302, 23035, 46701],
                        [4096, 253, 15734, 23035, 61801],
                        [6079, 371, 23050, 23035, 69117],
                    ],
                )
            };
        for (kind, shapes, expected) in [
            (IndexKind::Dialogue, moves, dialogue),
            (IndexKind::Project, entries, project),
        ] {
            for (position, expected) in expected.into_iter().enumerate() {
                let count = expected[0];
                let built = index(kind, RecordCount::from(count), &shapes);
                let levels = if position == 9 {
                    Levels::Open
                }
                else {
                    Levels::Closed
                };
                assert_eq!(
                    row(measure(&built).unwrap()),
                    (Row(expected), levels),
                    "{kind:?}"
                );
                if levels == Levels::Open {
                    let before = index(
                        kind,
                        RecordCount::from(u64::from(
                            arith::checked_sub(Int::from(count), Int::from(1)).unwrap(),
                        )),
                        &shapes,
                    );
                    assert_eq!(measure(&before).unwrap().levels, Levels::Closed, "{kind:?}");
                }
            }
        }
    });
}

#[test]
#[expect(
    clippy::big_endian_bytes,
    reason = "ordered numeric test keys exercise prefix and adjacent-key proof extrema"
)]
fn extrema_equal_exhaustive_answers()
{
    for count in [0_usize, 5, 512] {
        let mut records: Vec<_> = (0 .. count)
            .map(|position| {
                let key = u32::try_from(position).unwrap().to_be_bytes().to_vec();
                let length = arith::checked_mul(Int::from(position), Int::from(97)).unwrap();
                let length = arith::checked_rem(length, Int::from(1024)).unwrap();
                let value = vec![7; usize::from(length)];
                Record::new(key, value)
            })
            .collect();
        if count != 0 {
            records.extend([
                Record::new(vec![0], vec![5; 63]),
                Record::new(vec![0, 0], vec![6; 17]),
                Record::new(Vec::new(), vec![8; 91]),
            ]);
            records.sort_by(|left, right| left.key().cmp(&right.key()));
        }
        let borrowed: Vec<_> = records.iter().map(Record::as_record_ref).collect();
        let index = Index::new(
            IndexKind::Dialogue,
            RecordTree::build(&borrowed, TreeParams::current()).unwrap(),
        );
        let mut exhaustive = ByteSize::default();
        super::probe(&index, Vec::new().into(), &mut exhaustive).unwrap();
        for record in index.tree.records() {
            super::probe(&index, record.key().as_ref().into(), &mut exhaustive).unwrap();
            super::probe(&index, super::successor(record), &mut exhaustive).unwrap();
        }
        assert_eq!(measure(&index).unwrap().proof, exhaustive);
    }
}
