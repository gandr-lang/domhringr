//! Fixed receipt shapes measured table by table.

use core::fmt::Write as _;

use domhringr_record_tree::Heads;

use super::Levels;
use super::Measurement;
use super::measure;
use crate::derive;
use crate::keyed::Keyed;
use crate::project;
use crate::project::Subjects;
use crate::testing;

/// Encoded measurement columns in the public table order.
#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
struct Row([u64; 5]);

/// Comparable numeric measurement, retaining the crossing signal.
///
/// # Specification
/// trivial.
fn row(measurement: &Measurement) -> (Row, Levels)
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

/// A pinned row with the levels signal it implies.
///
/// # Specification
/// trivial.
fn implied(expected: Row) -> (Row, Levels)
{
    let levels = if expected.0[1] != 0 && expected.0[2] >= expected.0[3] {
        Levels::Open
    }
    else {
        Levels::Closed
    };
    (expected, levels)
}

#[test]
fn the_proof_sizes_are_pinned()
{
    testing::runtime().block_on(async {
        let fixture = testing::Fixture::new().await;
        let root = tempfile::tempdir().unwrap();
        let peer = testing::peer(root.path(), fixture.commits).await;
        let mut folded = Vec::new();
        for head in &fixture.standings {
            folded.push(
                derive::at(&peer, testing::tree(), &Heads::from_iter([*head]))
                    .await
                    .unwrap(),
            );
        }
        drop(peer);
        let keyed = Keyed::shared().unwrap();
        let pinned: [(usize, [[u64; 5]; 6]); 2] =
            if domhringr_record_tree::Edition::CURRENT == domhringr_record_tree::Edition::ONE {
                [
                    (7, [
                        [44, 3, 235, 965, 1963],
                        [215, 10, 666, 9744, 11183],
                        [144, 5, 365, 2134, 4494],
                        [0, 0, 40, 40, 451],
                        [6, 0, 322, 322, 799],
                        [42, 8, 560, 581, 1685],
                    ]),
                    (56, [
                        [352, 29, 1865, 1779, 4071],
                        [1720, 110, 6806, 10470, 18049],
                        [1152, 64, 4112, 2297, 16473],
                        [0, 0, 40, 40, 451],
                        [6, 0, 322, 322, 799],
                        [336, 26, 1692, 1598, 3797],
                    ]),
                ]
            }
            else {
                [
                    (7, [
                        [44, 3, 235, 965, 1963],
                        [240, 14, 906, 6967, 8646],
                        [144, 7, 511, 2081, 3064],
                        [0, 0, 40, 40, 451],
                        [6, 0, 322, 322, 799],
                        [42, 8, 560, 398, 1685],
                    ]),
                    (56, [
                        [352, 29, 1865, 1779, 4071],
                        [1920, 137, 8469, 13458, 22700],
                        [1152, 72, 4648, 2297, 17527],
                        [0, 0, 40, 40, 451],
                        [6, 0, 322, 322, 799],
                        [336, 23, 1509, 1598, 3614],
                    ]),
                ]
            };
        let mut name = String::new();
        for (count, expected) in pinned {
            let mut store = keyed.store().unwrap();
            let mut subjects = Subjects::default();
            for (index, task) in folded.iter().cycle().take(count).enumerate() {
                name.clear();
                write!(name, "task-{index:04}").unwrap();
                let _task = project::add(
                    &mut store,
                    keyed,
                    &name.parse().unwrap(),
                    &task.entry,
                    &task.dialogue,
                    project::Carrier::Owner,
                    &mut subjects,
                )
                .unwrap();
            }
            let measured = measure(&store).unwrap();
            let names: Vec<_> = measured.iter().map(|table| table.table.as_ref()).collect();
            assert_eq!(names, [
                "Attempt", "Move", "Naming", "Refusal", "Subject", "Task"
            ]);
            let actual: Vec<_> = measured.iter().map(row).collect();
            let expected: Vec<_> = expected.into_iter().map(|row| implied(Row(row))).collect();
            assert_eq!(actual, expected, "{count} tasks");
        }
    });
}
