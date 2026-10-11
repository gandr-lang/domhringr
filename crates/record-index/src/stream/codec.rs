//! The index protocol's byte language, without transport or trusted roots.

use gandr_storage_records::EncodedNode;
use gandr_storage_records::KeyBound;
use gandr_storage_records::KeyRange;
use gandr_storage_records::MembershipProof;
use gandr_storage_records::NonMembershipEvidence;
use gandr_storage_records::NonMembershipProof;
use gandr_storage_records::OwnedKeyBound;
use gandr_storage_records::OwnedKeyRange;
use gandr_storage_records::ProofEnvelope;
use gandr_storage_records::ProofKind;
use gandr_storage_records::ProofNode;
use gandr_storage_records::RangeProof;
use gandr_storage_records::Record;
use gandr_storage_records::hash_node;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use super::ANSWER_CAP;
use super::ByteSize;
use super::Request;
use super::StreamError;
use crate::IndexKind;
use crate::Manifest;
use crate::WireImage;
use crate::prove::Answer;
use crate::prove::Proof;
use crate::prove::ProveError;
use crate::prove::Query;
use crate::wire::Body;
use crate::wire::Cursor;
use crate::wire::Fixed;
use crate::wire::Length;
use crate::wire::WireError;

/// A wire discriminator, kept distinct from lengths and counts.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct Tag(u8);

/// Whether framing counts bytes or writes their bounded image.
enum Destination
{
    /// Measure without retaining any proof bytes.
    Count,
    /// Emit after the measured extent passed the cap.
    Image(WireImage),
}

/// One encoder for both size measurement and emitted framing.
struct Encoder
{
    /// Checked accumulated extent.
    size: ByteSize,
    /// The selected output mode.
    destination: Destination,
}

impl Encoder
{
    /// Account for bytes, copying them only when emitting a bounded image.
    ///
    /// # Specification
    /// - ensures: the extent advances by exactly the body's length.
    /// - fails: an unrepresentable total is refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WireError::Length`]: the total exceeds its wire width.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the holder reports the exact over-cap framing extent.
    /// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
    fn bytes(
        &mut self,
        body: Body<'_>,
    ) -> Result<(), WireError>
    {
        let length = u64::try_from(body.0.len()).map_err(|_width| WireError::Length)?;
        let size = arith::checked_add(Int::from(self.size.0), Int::from(length))
            .map_err(|_overflow| WireError::Length)?;
        self.size.0 = u64::from(size);
        if let Destination::Image(ref mut image) = self.destination {
            image.0.extend_from_slice(body.0);
        }
        Ok(())
    }

    /// Emit one discriminator.
    ///
    /// # Specification
    /// trivial.
    fn tag(
        &mut self,
        tag: Tag,
    ) -> Result<(), WireError>
    {
        self.bytes(Body(&[tag.0]))
    }

    /// Emit a four-byte count or extent.
    ///
    /// # Specification
    /// - ensures: the count is encoded little-endian in exactly four bytes.
    /// - fails: counts exceeding the wire width are refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WireError::Length`]: a count cannot be represented.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — framing size includes each length word.
    /// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
    fn count(
        &mut self,
        count: Length,
    ) -> Result<(), WireError>
    {
        let count = u32::try_from(count.0).map_err(|_width| WireError::Length)?;
        self.bytes(Body(&count.to_le_bytes()))
    }

    /// Emit a field's length before its exact bytes.
    ///
    /// # Specification
    /// trivial.
    fn framed(
        &mut self,
        body: Body<'_>,
    ) -> Result<(), WireError>
    {
        self.count(Length(body.0.len()))?;
        self.bytes(body)
    }

    /// Emit a record without carrying a trusted root.
    ///
    /// # Specification
    /// trivial.
    fn record(
        &mut self,
        record: &Record,
    ) -> Result<(), WireError>
    {
        self.framed(Body(record.key().as_ref()))?;
        self.framed(Body(record.value().as_ref()))
    }

    /// Emit the authenticated-node candidates in proof order.
    ///
    /// # Specification
    /// trivial.
    fn nodes(
        &mut self,
        nodes: &[ProofNode],
    ) -> Result<(), WireError>
    {
        self.count(Length(nodes.len()))?;
        for node in nodes {
            self.framed(Body(node.bytes().as_ref()))?;
        }
        Ok(())
    }

    /// Emit a bound using its protocol discriminator.
    ///
    /// # Specification
    /// trivial.
    fn bound(
        &mut self,
        bound: KeyBound<'_>,
    ) -> Result<(), WireError>
    {
        match bound {
            | KeyBound::Unbounded => self.tag(Tag(0)),
            | KeyBound::Included(key) => {
                self.tag(Tag(1))?;
                self.framed(Body(key.as_ref()))
            },
            | KeyBound::Excluded(key) => {
                self.tag(Tag(2))?;
                self.framed(Body(key.as_ref()))
            },
        }
    }
}

/// Frame a held answer identically for measurement and transmission.
///
/// # Specification
/// - ensures: no root is carried; the image carries manifest and proof parts.
/// - fails: a field or accumulated extent exceeds its wire width.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: manifest encoding or framing failed.
///
/// # Adequacy
/// - hypothesis: L3 — over-cap framing reports its size without any node bytes.
/// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
fn held(
    encoder: &mut Encoder,
    answer: &Answer,
) -> Result<(), StreamError>
{
    encoder.tag(Tag(1))?;
    let manifest = answer.manifest.encode()?;
    encoder.framed(Body(manifest.as_ref()))?;
    match &answer.proof {
        | &Proof::Present(ref proof) => {
            encoder.tag(Tag(1))?;
            encoder.framed(Body(proof.value().as_ref()))?;
            encoder.nodes(proof.nodes())?;
        },
        | &Proof::Absent(ref proof) => {
            encoder.tag(Tag(2))?;
            for neighbour in [proof.evidence().predecessor(), proof.evidence().successor()] {
                match neighbour {
                    | Some(record) => {
                        encoder.tag(Tag(1))?;
                        encoder.record(record)?;
                    },
                    | None => encoder.tag(Tag(0))?,
                }
            }
            encoder.nodes(proof.nodes())?;
        },
        | &Proof::Range(ref proof) => {
            encoder.tag(Tag(3))?;
            encoder.count(Length(proof.records().len()))?;
            for record in proof.records() {
                encoder.record(record)?;
            }
            encoder.nodes(proof.nodes())?;
        },
    }
    Ok(())
}

/// Measure the complete held-answer framing without allocating node copies.
///
/// # Specification
/// - ensures: the extent includes status, manifest, proof and every frame word.
/// - fails: an unrepresentable field or extent is refused.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: manifest or framing failure.
///
/// # Adequacy
/// - hypothesis: L2 — pinned sizes include complete answer framing.
/// - witness: `measure::tests::the_proof_sizes_are_pinned`
pub(super) fn size(answer: &Answer) -> Result<ByteSize, StreamError>
{
    let mut encoder = Encoder {
        size: ByteSize(0),
        destination: Destination::Count,
    };
    held(&mut encoder, answer)?;
    Ok(encoder.size)
}

/// Encode a bounded proof or its exact over-cap extent, never an oversized
/// body.
///
/// # Specification
/// - ensures: the image is at most the cap; an over-cap proof becomes tag two
///   and its eight-byte extent with no manifest or nodes.
/// - fails: unrepresentable framing or manifest encoding.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: manifest or framing failure.
///
/// # Adequacy
/// - hypothesis: L3 — over-cap answers are exactly nine bytes and carry the
///   size.
/// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
pub(super) fn encode(answer: &Answer) -> Result<WireImage, StreamError>
{
    let size = size(answer)?;
    if size > ANSWER_CAP {
        let mut bytes = vec![2];
        bytes.extend_from_slice(&size.0.to_le_bytes());
        return Ok(WireImage(bytes));
    }
    let capacity = usize::try_from(size.0).map_err(|_width| WireError::Length)?;
    let mut encoder = Encoder {
        size: ByteSize(0),
        destination: Destination::Image(WireImage(Vec::with_capacity(capacity))),
    };
    held(&mut encoder, answer)?;
    match encoder.destination {
        | Destination::Image(image) => Ok(image),
        | Destination::Count => Err(WireError::Tag.into()),
    }
}

/// Encode a request's digest and query without an answer root.
///
/// # Specification
/// trivial.
pub(super) fn request(request: &Request) -> Result<WireImage, StreamError>
{
    let mut encoder = Encoder {
        size: ByteSize(0),
        destination: Destination::Image(WireImage::default()),
    };
    encoder.bytes(Body(request.digest.as_ref()))?;
    match &request.query {
        | &Query::Key(ref key) => {
            encoder.tag(Tag(1))?;
            encoder.framed(Body(key.as_ref()))?;
        },
        | &Query::Range(ref range) => {
            encoder.tag(Tag(2))?;
            let range = range.as_range().map_err(ProveError::from)?;
            encoder.bound(range.start())?;
            encoder.bound(range.end())?;
        },
    }
    match encoder.destination {
        | Destination::Image(image) => Ok(image),
        | Destination::Count => Err(WireError::Tag.into()),
    }
}

/// Decode a range bound without allocating for an unbounded edge.
///
/// # Specification
/// trivial.
fn bound(cursor: &mut Cursor<'_>) -> Result<OwnedKeyBound, WireError>
{
    let Fixed([tag]) = cursor.fixed::<1>()?;
    match tag {
        | 0 => Ok(OwnedKeyBound::Unbounded),
        | 1 | 2 => {
            let body = cursor.framed()?;
            let key = body.0.into();
            Ok(if tag == 1 {
                OwnedKeyBound::Included(key)
            }
            else {
                OwnedKeyBound::Excluded(key)
            })
        },
        | _unknown => Err(WireError::Tag),
    }
}

/// Decode exactly one request, refusing trailing bytes and inverted bounds.
///
/// # Specification
/// - ensures: the returned digest, key and bounds preserve their wire bytes.
/// - fails: malformed framing, unknown tags or inverted bounds.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: the request is malformed.
///
/// # Adequacy
/// - hypothesis: L3 — holder responses name the requested unknown digest.
/// - witness: `stream::tests::an_unheld_digest_is_answered_unheld`
pub(super) fn read_request(image: &WireImage) -> Result<Request, StreamError>
{
    let mut cursor = Cursor::new(Body(image.as_ref()));
    let Fixed(digest) = cursor.fixed::<32>()?;
    let Fixed([tag]) = cursor.fixed::<1>()?;
    let query = match tag {
        | 1 => {
            let key = cursor.framed()?;
            Query::Key(key.0.into())
        },
        | 2 => {
            let start = bound(&mut cursor)?;
            let end = bound(&mut cursor)?;
            let range =
                KeyRange::new(start.as_bound(), end.as_bound()).map_err(ProveError::from)?;
            Query::Range(OwnedKeyRange::from_range(range))
        },
        | _unknown => return Err(WireError::Tag.into()),
    };
    cursor.finish()?;
    Ok(Request {
        digest: digest.into(),
        query,
    })
}

/// Decode a framed record's two fields.
///
/// # Specification
/// trivial.
fn record(cursor: &mut Cursor<'_>) -> Result<Record, WireError>
{
    let key = cursor.framed()?;
    let value = cursor.framed()?;
    Ok(Record::new(key.0, value.0))
}

/// An absent key's neighbour, before proof authentication.
enum Neighbour
{
    /// No record on this side of the query.
    None,
    /// The claimed nearest record on this side.
    Record(Record),
}

/// Decode one claimed neighbour without conferring trust.
///
/// # Specification
/// trivial.
fn neighbour(cursor: &mut Cursor<'_>) -> Result<Neighbour, WireError>
{
    let Fixed([tag]) = cursor.fixed::<1>()?;
    match tag {
        | 0 => Ok(Neighbour::None),
        | 1 => {
            let record = record(cursor)?;
            Ok(Neighbour::Record(record))
        },
        | _unknown => Err(WireError::Tag),
    }
}

/// Decode bounded node images and derive their identities from their bytes.
///
/// # Specification
/// - ensures: no identity is trusted from the wire; each node hash is computed.
/// - fails: truncated fields or an unknown node encoding during verification.
/// - panics: none.
///
/// # Errors
/// - [`WireError`]: a declared field is truncated.
///
/// # Adequacy
/// - hypothesis: L3 — forged node material fails against the selected root.
/// - witness: `prove::tests::a_forged_later_attempt_is_refused`
fn nodes(cursor: &mut Cursor<'_>) -> Result<Box<[ProofNode]>, WireError>
{
    let Fixed(count) = cursor.fixed::<4>()?;
    // The count is untrusted. Grow only for fields actually present in the
    // capped image, never reserve the advertised count before reading them.
    let mut nodes = Vec::new();
    for _node in 0 .. u32::from_le_bytes(count) {
        let body = cursor.framed()?;
        let hash = hash_node(EncodedNode::from(body.0));
        nodes.push(ProofNode::new(hash, body.0));
    }
    Ok(nodes.into_boxed_slice())
}

/// Decode a capped answer, checking its manifest before opening any proof node.
///
/// # Specification
/// - ensures: envelopes and root identities come only from the selected
///   manifest, never from the answer; all framing is consumed.
/// - fails: oversize, unheld, wrong manifest, question or malformed framing.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: answer refusal, identity or framing failure.
///
/// # Adequacy
/// - hypothesis: L3 — unheld names the digest, and one byte past the cap fails.
/// - witness: `stream::tests::an_unheld_digest_is_answered_unheld`
/// - witness: `stream::tests::an_answer_at_the_cap_is_read_and_one_byte_past_is_refused`
pub(super) fn decode(
    request: &Request,
    kind: IndexKind,
    image: &WireImage,
) -> Result<Answer, StreamError>
{
    let size = u64::try_from(image.0.len()).map_err(|_width| WireError::Length)?;
    if size > ANSWER_CAP.0 {
        return Err(StreamError::Oversize(ByteSize(size)));
    }
    let mut cursor = Cursor::new(Body(image.as_ref()));
    let Fixed([tag]) = cursor.fixed::<1>()?;
    match tag {
        | 0 => {
            cursor.finish()?;
            return Err(StreamError::Unheld(request.digest));
        },
        | 2 => {
            let Fixed(size) = cursor.fixed::<8>()?;
            cursor.finish()?;
            return Err(StreamError::Oversize(ByteSize(u64::from_le_bytes(size))));
        },
        | 1 => {},
        | _unknown => return Err(WireError::Tag.into()),
    }
    let image = cursor.framed()?;
    let manifest = Manifest::decode(&WireImage(image.0.to_vec()), kind)?;
    let digest = manifest.identity()?;
    if digest != request.digest {
        return Err(ProveError::Identity(request.digest).into());
    }
    let root = manifest.root().map_err(ProveError::from)?;
    let node = manifest.node();
    let Fixed([tag]) = cursor.fixed::<1>()?;
    let proof = match (tag, &request.query) {
        | (1, &Query::Key(ref key)) => {
            let value = cursor.framed()?;
            let nodes = nodes(&mut cursor)?;
            Proof::Present(MembershipProof::new(
                ProofEnvelope::new(root, ProofKind::Membership),
                node,
                key.as_borrowed(),
                value.0,
                nodes,
            ))
        },
        | (2, &Query::Key(ref key)) => {
            let predecessor = neighbour(&mut cursor)?;
            let successor = neighbour(&mut cursor)?;
            let nodes = nodes(&mut cursor)?;
            let predecessor = match predecessor {
                | Neighbour::None => None,
                | Neighbour::Record(record) => Some(record),
            };
            let successor = match successor {
                | Neighbour::None => None,
                | Neighbour::Record(record) => Some(record),
            };
            let evidence = NonMembershipEvidence::new(predecessor, successor);
            Proof::Absent(NonMembershipProof::new(
                ProofEnvelope::new(root, ProofKind::NonMembership),
                node,
                key.as_borrowed(),
                evidence,
                nodes,
            ))
        },
        | (3, &Query::Range(ref range)) => {
            let Fixed(count) = cursor.fixed::<4>()?;
            let mut records = Vec::new();
            for _record in 0 .. u32::from_le_bytes(count) {
                let record = record(&mut cursor)?;
                records.push(record);
            }
            let nodes = nodes(&mut cursor)?;
            Proof::Range(RangeProof::new(
                ProofEnvelope::new(root, ProofKind::Range),
                node,
                range.clone(),
                records,
                nodes,
            ))
        },
        | _different => return Err(ProveError::Question.into()),
    };
    cursor.finish()?;
    Ok(Answer { manifest, proof })
}
