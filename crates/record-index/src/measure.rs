//! Table extents and complete answer sizes.
//!
//! `index measure` reports, for each table of a project store: its record
//! count, root children, root bytes, largest leaf bytes and the largest
//! complete answer to a question about it, framing included. A question is
//! about the table of the object its element belongs to: a part's or a
//! value's object, or an arrow's source. Every question a reader can ask of
//! a live part or a held value is proved, so the largest answer is exact,
//! not a bound. An internal root at least as large as its largest leaf
//! prints `levels open`; a table of one leaf does not request another level.
//!
//! The pinned measurements in this module's tests repeat the fixture task
//! at every reachable standing under each compiled edition.

#[cfg(test)]
mod tests;

use alloc::collections::BTreeSet;

use anodized::spec;
use gandr_storage_records::BlockStore as _;
use gandr_storage_records::ChildRef;
use gandr_storage_records::DecodeWork;
use gandr_storage_records::DecodedNode;
use gandr_storage_records::EncodedNode;
use gandr_storage_records::InMemoryBlockStore;
use gandr_storage_records::NodeHash;
use gandr_storage_records::RecordCount;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::decode_node;
use gandr_storage_schema::Indexing;
use gandr_storage_schema::Name;
use gandr_storage_schema::ObjectId;
use gandr_storage_schema::Question;
use gandr_storage_schema::Refusal;
use gandr_storage_schema::SchemaError;
use gandr_storage_schema::Store;
use gandr_storage_schema::StoreError;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::stream::ByteSize;

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

/// Measured extents of one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement
{
    /// The table's object.
    pub table: Name,
    /// Records committed by the manifest.
    pub records: RecordCount,
    /// Immediate root fanout, zero for a leaf root.
    pub children: RootChildren,
    /// Complete encoded root node.
    pub root: ByteSize,
    /// Largest encoded leaf node.
    pub leaf: ByteSize,
    /// Largest fully framed answer to a question about the table.
    pub proof: ByteSize,
    /// The root-to-leaf crossing signal.
    pub levels: Levels,
}

/// Why a store cannot be measured.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError
{
    /// A node cannot be decoded.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
    /// The store refused a commit or a proof.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The store refused a read.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// The schema refused an element.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// An extent is past 64 bits.
    #[error("an extent is past 64 bits")]
    Width,
}

/// A node's encoded extent.
///
/// # Specification
/// trivial.
fn size(node: EncodedNode<'_>) -> Result<ByteSize, MeasureError>
{
    u64::try_from(node.as_ref().len())
        .map(ByteSize)
        .map_err(|_width| MeasureError::Width)
}

/// Every question a reader can ask of a store, with the table it is about.
///
/// # Specification
/// - ensures: each live part's liveness, arrows and values; each indexed
///   arrow's preimage of each live target; each indexed attribute's preimage of
///   each held value.
/// - fails: the store refuses a read.
/// - panics: none.
/// - executable: none — the enumeration is its own specification; the pinned
///   sizes observe it.
///
/// # Errors
/// - [`MeasureError`]: a refused read.
///
/// # Adequacy
/// - hypothesis: L2 — pinned sizes change when a question kind is dropped.
/// - witness: `measure::tests::the_proof_sizes_are_pinned`
fn questions(store: &Store) -> Result<Vec<(ObjectId, Question)>, MeasureError>
{
    let schema = store.schema();
    let mut questions = Vec::new();
    for object in schema.objects() {
        for part in store.parts(object)? {
            questions.push((object, Question::Part { object, part }));
        }
    }
    for arrow in schema.arrows() {
        let spec = schema.arrow_at(arrow)?;
        for part in store.parts(spec.source())? {
            questions.push((spec.source(), Question::Arrow { arrow, part }));
        }
        if spec.indexing() == Indexing::Indexed {
            for target in store.parts(spec.target())? {
                questions.push((spec.source(), Question::Preimage { arrow, target }));
            }
        }
    }
    for attribute in schema.attributes() {
        let spec = schema.attribute_at(attribute)?;
        let mut values = BTreeSet::new();
        for part in store.parts(spec.object())? {
            questions.push((spec.object(), Question::Value { attribute, part }));
            if spec.indexing() == Indexing::Indexed {
                let _new = values.insert(store.value(attribute, part)?.clone());
            }
        }
        for value in values {
            questions.push((spec.object(), Question::ValuePreimage { attribute, value }));
        }
    }
    Ok(questions)
}

/// Measure each table's node extents and its largest answer.
///
/// # Specification
/// - ensures: one measurement per table, in object order, of the store as it
///   would commit with its edits so far; proof bytes are the largest answer
///   image the stream would send, its tag included.
/// - ensures: levels open exactly when an internal root reaches its largest
///   leaf.
/// - fails: a refused commit, malformed nodes, or a refused proof.
/// - panics: none.
///
/// # Errors
/// - [`MeasureError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — pinned real receipt shapes distinguish every measured
///   extent.
/// - witness: `measure::tests::the_proof_sizes_are_pinned`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |measured| measured.len() == store.schema().objects().len()))]
#[inline]
pub fn measure(store: &Store) -> Result<Vec<Measurement>, MeasureError>
{
    let mut blocks = InMemoryBlockStore::new();
    let mut committed = store.clone();
    let _root = committed.commit(&mut blocks)?;
    let schema = committed.schema();
    let mut proofs = vec![ByteSize::default(); schema.objects().len()];
    for (object, question) in questions(&committed)? {
        let image = committed.prove(&question)?.encode();
        let length = arith::checked_add(Int::from(image.as_ref().len()), Int::from(1_usize))
            .map_err(|_overflow| MeasureError::Width)?;
        let answer =
            ByteSize(u64::try_from(usize::from(length)).map_err(|_width| MeasureError::Width)?);
        if let Some(largest) = proofs.get_mut(usize::from(object)) {
            *largest = (*largest).max(answer);
        }
    }
    let mut measured = Vec::new();
    let mut work = DecodeWork::new();
    let mut pending: Vec<NodeHash> = Vec::new();
    for ((object, table), proof) in schema
        .objects()
        .zip(committed.manifest().tables())
        .zip(proofs)
    {
        let root = size(blocks.load(table.root_node())?.bytes())?;
        let mut leaf = ByteSize::default();
        let mut children = RootChildren(0);
        pending.push(table.root_node());
        while let Some(node) = pending.pop() {
            let stored = blocks.load(node)?;
            match decode_node(stored.bytes(), &mut work)? {
                DecodedNode::Leaf(_) => leaf = leaf.max(size(stored.bytes())?),
                DecodedNode::Internal(internal) => {
                    if node == table.root_node() {
                        children = RootChildren(internal.children().len());
                    }
                    pending.extend(internal.children().iter().map(ChildRef::identity));
                },
            }
        }
        measured.push(Measurement {
            table: schema.object_name(object)?.clone(),
            records: table.records(),
            children,
            root,
            leaf,
            proof,
            levels: if children.0 != 0 && root >= leaf {
                Levels::Open
            }
            else {
                Levels::Closed
            },
        });
    }
    Ok(measured)
}
