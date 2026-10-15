//! Tree extents and complete single-key answer sizes.
//!
//! `index measure` reports record count, root children, root bytes, largest
//! leaf bytes and the largest complete single-key answer, including
//! membership and absence framing. An internal root at least as large as its
//! largest leaf prints `levels open`; a tree consisting of one leaf does not
//! request another level. The pinned measurements in this module's tests use
//! the fixture's original move values and full task-entry standings under
//! each compiled edition, at powers of two from 16 through 4,096 records and
//! at both sides of each root/leaf crossing.
//!
//! The provenance crossing is 1,204 records in either edition: root 8,639
//! bytes, largest leaf 8,552 bytes and largest complete single-key proof
//! 23,977 bytes. Project crossings with refusal-bearing entries are 6,143
//! records in edition 1 and 6,189 in edition 2.

use anodized::spec;
use gandr_storage_records::DecodeWork;
use gandr_storage_records::DecodedNode;
use gandr_storage_records::OwnedRecordKey;
use gandr_storage_records::Record;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::decode_node;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::Index;
use crate::prove;
use crate::prove::Query;
use crate::stream;
use crate::stream::ByteSize;
use crate::stream::StreamError;

/// Number of immediate children of the root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct RootChildren(pub usize);

/// Whether the internal root has reached the largest leaf's extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Levels
{
    /// A leaf remains the larger cost, or the whole tree is one leaf.
    Closed,
    /// The internal root is at least as large as every leaf.
    Open,
}

/// Measured extents of one canonical index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement
{
    /// Records committed by the manifest.
    pub records: gandr_storage_records::RecordCount,
    /// Immediate root fanout, zero for a leaf root.
    pub children: RootChildren,
    /// Complete encoded root node.
    pub root: ByteSize,
    /// Largest encoded leaf node.
    pub leaf: ByteSize,
    /// Largest fully framed membership or absence answer.
    pub proof: ByteSize,
    /// The root-to-leaf crossing signal.
    pub levels: Levels,
}

/// Why a tree cannot be measured.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError
{
    /// A supposedly built tree has no root or an internal child.
    #[error("index has no two-level record tree")]
    Shape,
    /// A node cannot be decoded.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
    /// A selected proof cannot be constructed.
    #[error(transparent)]
    Proof(#[from] prove::ProveError),
    /// Complete answer framing cannot be measured.
    #[error(transparent)]
    Stream(#[from] StreamError),
}

/// Update the maximum using the same encoder that serves the answer.
///
/// # Specification
/// trivial.
fn probe(
    index: &Index,
    key: OwnedRecordKey,
    largest: &mut ByteSize,
) -> Result<(), MeasureError>
{
    let answer = prove::answer(index, &Query::Key(key))?;
    let size = stream::encoded_size(&answer)?;
    *largest = (*largest).max(size);
    Ok(())
}

/// The shortest byte key strictly after this record.
///
/// # Specification
/// trivial.
fn successor(record: &Record) -> OwnedRecordKey
{
    let length = arith::saturating_add(Int::from(record.key().as_ref().len()), Int::from(1));
    let mut key = Vec::with_capacity(usize::from(length));
    key.extend_from_slice(record.key().as_ref());
    key.push(0);
    OwnedRecordKey::from(key)
}

/// Measure exact node extents and the largest single-key wire answer.
///
/// Within a leaf, proof nodes are identical: the largest value selects the
/// membership maximum, and the largest adjacent pair selects the interior
/// absence maximum. Boundary absences can carry a second leaf and are measured
/// separately. Only those extrema construct proofs; arbitrary probe-key length
/// does not affect an answer because the request already supplies its key.
///
/// # Specification
/// - ensures: counts describe the supplied tree; proof bytes include all
///   framing.
/// - ensures: levels open exactly when an internal root reaches its largest
///   leaf.
/// - fails: malformed nodes or unrepresentable proof framing are refused.
/// - panics: none.
///
/// # Errors
/// - [`MeasureError`]: tree structure, proof construction or framing failed.
///
/// # Adequacy
/// - hypothesis: L2 — exhaustive answers bound the optimized extrema; pinned
///   real receipt shapes distinguish all measured extents and crossings.
/// - witness: `measure::tests::the_proof_sizes_are_pinned`
/// - witness: `measure::tests::extrema_equal_exhaustive_answers`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |measurement|
    usize::try_from(u64::from(measurement.records)).is_ok_and(|count| count == index.tree.records().len())
    && measurement.proof >= measurement.root && measurement.proof >= measurement.leaf))]
#[inline]
pub fn measure(index: &Index) -> Result<Measurement, MeasureError>
{
    // The record API owns its node enumeration; one copy also supplies all leaves.
    let nodes = index.tree.nodes();
    let (root, children) = nodes.split_first().ok_or(MeasureError::Shape)?;
    let root_size =
        u64::try_from(root.bytes().as_ref().len()).map_err(|_width| MeasureError::Shape)?;
    let root_size = ByteSize(root_size);
    let root_node = decode_node(root.bytes(), &mut DecodeWork::new())?;
    let fanout = match root_node {
        DecodedNode::Leaf(_) => RootChildren(0),
        DecodedNode::Internal(ref internal) => RootChildren(internal.children().len()),
    };
    let leaves = if fanout.0 == 0 {
        nodes.as_ref()
    }
    else {
        children
    };
    let mut largest_leaf = ByteSize::default();
    let mut largest_proof = ByteSize::default();
    let mut decoded = root_node;
    for node in leaves {
        let length =
            u64::try_from(node.bytes().as_ref().len()).map_err(|_width| MeasureError::Shape)?;
        largest_leaf = largest_leaf.max(ByteSize(length));
        if fanout.0 != 0 {
            decoded = decode_node(node.bytes(), &mut DecodeWork::new())?;
        }
        let DecodedNode::Leaf(ref leaf) = decoded
        else {
            return Err(MeasureError::Shape);
        };
        if let Some(record) = leaf
            .records()
            .iter()
            .max_by_key(|record| record.value().as_ref().len())
        {
            probe(
                index,
                OwnedRecordKey::from(record.key().as_ref()),
                &mut largest_proof,
            )?;
        }
        let interior = leaf
            .records()
            .array_windows::<2>()
            .filter(|pair| {
                let [left, right] = pair.each_ref();
                right.key().as_ref().strip_prefix(left.key().as_ref()) != Some([0].as_slice())
            })
            .max_by_key(|pair| {
                pair.iter().fold(Int::from(0_usize), |size, record| {
                    let size = arith::saturating_add(size, Int::from(record.key().as_ref().len()));
                    arith::saturating_add(size, Int::from(record.value().as_ref().len()))
                })
            });
        if let Some(pair) = interior {
            let [left, _right] = pair.each_ref();
            probe(index, successor(left), &mut largest_proof)?;
        }
        if let Some(last) = leaf.records().last() {
            let key = successor(last);
            // Adjacent byte keys have no gap; the membership was measured above.
            if index.tree.lookup(key.as_borrowed()).is_none() {
                probe(index, key, &mut largest_proof)?;
            }
        }
    }
    if index
        .tree
        .records()
        .first()
        .is_none_or(|record| !record.key().as_ref().is_empty())
    {
        probe(
            index,
            OwnedRecordKey::from([].as_slice()),
            &mut largest_proof,
        )?;
    }
    let records = gandr_storage_records::RecordCount::of_slice(index.tree.records())?;
    Ok(Measurement {
        records,
        children: fanout,
        root: root_size,
        leaf: largest_leaf,
        proof: largest_proof,
        levels: if fanout.0 != 0 && root_size >= largest_leaf {
            Levels::Open
        }
        else {
            Levels::Closed
        },
    })
}

#[cfg(test)]
mod tests;
