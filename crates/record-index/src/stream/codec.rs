//! The index protocol's byte language, without transport or trusted roots.
//!
//! A request is a kind byte and the store root it is about:
//!
//! | Kind | Then |
//! | ---- | ---- |
//! | `1` question | the question's kind, `1` part, `2` arrow, `3` value, `4` preimage, `5` value preimage; its element's ordinal and its part as `u64le`, or for a value preimage a `u32le`-framed value |
//! | `2` manifest | nothing |
//! | `3` node | the node's 32-byte identity |
//!
//! An answer is `0` when the root isn't held, `2` and the `u64le` size of a
//! reply past the cap, or `1` and the reply: a proof image, a manifest image
//! or a node's bytes.

use anodized::spec;
use gandr_storage_records::NodeHash;
use gandr_storage_schema::ArrowId;
use gandr_storage_schema::AttributeId;
use gandr_storage_schema::AttributeValue;
use gandr_storage_schema::Ordinal;
use gandr_storage_schema::PartKey;
use gandr_storage_schema::Question;
use gandr_storage_schema::STORE_ROOT_LEN;
use gandr_storage_schema::StoreRoot;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use super::ANSWER_CAP;
use super::ByteSize;
use super::Request;
use super::StreamError;
use crate::WireImage;
use crate::keyed::Keyed;
use crate::wire::Body;
use crate::wire::Cursor;
use crate::wire::Fixed;
use crate::wire::WireError;

/// A wire discriminator, kept distinct from lengths and counts.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct Tag(u8);

/// Append a `u64le` field.
///
/// # Specification
/// trivial.
fn put_number(
    image: &mut WireImage,
    number: Fixed<8>,
)
{
    image.0.extend_from_slice(&number.0);
}

/// An element ordinal as its `u64le` field.
///
/// # Specification
/// - ensures: the field reads back as the ordinal.
/// - fails: an ordinal past 64 bits.
/// - panics: none.
/// - executable: none — the encoding is its own specification; the round-trip
///   witness reads every question back.
///
/// # Errors
/// - [`WireError::Length`]: past 64 bits.
///
/// # Adequacy
/// - hypothesis: L2 — every fixture question round-trips.
/// - witness: `stream::tests::every_question_round_trips_through_its_request`
fn ordinal(element: Ordinal) -> Result<Fixed<8>, WireError>
{
    let value = u64::try_from(element.0).map_err(|_width| WireError::Length)?;
    Ok(Fixed(value.to_le_bytes()))
}

/// Encode a request.
///
/// # Specification
/// - ensures: [`read_request`] reads it back as `request`.
/// - fails: an ordinal or a value too wide for its field.
/// - panics: none.
/// - executable: none — the encoding is its own specification; the round-trip
///   witness reads every kind back.
///
/// # Errors
/// - [`WireError`]: an unrepresentable field.
///
/// # Adequacy
/// - hypothesis: L2 — every question kind round-trips.
/// - witness: `stream::tests::every_question_round_trips_through_its_request`
pub(super) fn request(request: &Request) -> Result<WireImage, WireError>
{
    let mut image = WireImage(Vec::new());
    match *request {
        Request::Question { root, ref question } => {
            image.0.push(1);
            image.0.extend_from_slice(root.as_ref());
            let (kind, element, rest) = match *question {
                Question::Part { object, part } => (1, Ordinal(usize::from(object)), Some(part)),
                Question::Arrow { arrow, part } => (2, Ordinal(usize::from(arrow)), Some(part)),
                Question::Value { attribute, part } => {
                    (3, Ordinal(usize::from(attribute)), Some(part))
                },
                Question::Preimage { arrow, target } => {
                    (4, Ordinal(usize::from(arrow)), Some(target))
                },
                Question::ValuePreimage { attribute, .. } => {
                    (5, Ordinal(usize::from(attribute)), None)
                },
            };
            image.0.push(kind);
            put_number(&mut image, ordinal(element)?);
            match (rest, question) {
                (Some(part), _) => put_number(&mut image, Fixed(u64::from(part).to_le_bytes())),
                (None, &Question::ValuePreimage { ref value, .. }) => {
                    let length =
                        u32::try_from(value.as_ref().len()).map_err(|_width| WireError::Length)?;
                    image.0.extend_from_slice(&length.to_le_bytes());
                    image.0.extend_from_slice(value.as_ref());
                },
                (None, _) => return Err(WireError::Tag),
            }
        },
        Request::Manifest(root) => {
            image.0.push(2);
            image.0.extend_from_slice(root.as_ref());
        },
        Request::Node { root, node } => {
            image.0.push(3);
            image.0.extend_from_slice(root.as_ref());
            image.0.extend_from_slice(node.as_ref());
        },
    }
    Ok(image)
}

/// Read a request, resolving each element in the keyed schema.
///
/// # Specification
/// - ensures: the request [`request`] encoded.
/// - fails: an unknown kind, an ordinal outside the schema, truncation or
///   trailing bytes.
/// - panics: none.
/// - executable: none — the decoding is its own specification; the round-trip
///   witness reads every kind back.
///
/// # Errors
/// - [`WireError`]: malformed framing.
///
/// # Adequacy
/// - hypothesis: L2/L3 — every question kind round-trips; an ordinal past the
///   schema is refused.
/// - witness: `stream::tests::every_question_round_trips_through_its_request`
pub(super) fn read_request(
    image: &WireImage,
    keyed: &Keyed,
) -> Result<Request, WireError>
{
    let mut cursor = Cursor::new(Body(image.as_ref()));
    let Fixed([kind]) = cursor.fixed::<1>()?;
    let Fixed(root) = cursor.fixed::<STORE_ROOT_LEN>()?;
    let root = StoreRoot::from(root);
    let request = match Tag(kind) {
        Tag(1) => {
            let Fixed([question]) = cursor.fixed::<1>()?;
            let Fixed(element) = cursor.fixed::<8>()?;
            let element = Ordinal(
                usize::try_from(u64::from_le_bytes(element)).map_err(|_width| WireError::Length)?,
            );
            let question = match question {
                1 => Question::Part {
                    object: nth(keyed.schema.objects(), element)?,
                    part: part(&mut cursor)?,
                },
                2 => Question::Arrow {
                    arrow: nth::<ArrowId>(keyed.schema.arrows(), element)?,
                    part: part(&mut cursor)?,
                },
                3 => Question::Value {
                    attribute: nth::<AttributeId>(keyed.schema.attributes(), element)?,
                    part: part(&mut cursor)?,
                },
                4 => Question::Preimage {
                    arrow: nth::<ArrowId>(keyed.schema.arrows(), element)?,
                    target: part(&mut cursor)?,
                },
                5 => Question::ValuePreimage {
                    attribute: nth::<AttributeId>(keyed.schema.attributes(), element)?,
                    value: AttributeValue::from(cursor.framed()?.0),
                },
                _ => return Err(WireError::Tag),
            };
            Request::Question { root, question }
        },
        Tag(2) => Request::Manifest(root),
        Tag(3) => {
            let Fixed(node) = cursor.fixed::<32>()?;
            Request::Node {
                root,
                node: NodeHash::from(node),
            }
        },
        Tag(_) => return Err(WireError::Tag),
    };
    cursor.finish()?;
    Ok(request)
}

/// The element at an ordinal.
///
/// # Specification
/// trivial.
fn nth<T>(
    mut elements: impl Iterator<Item = T>,
    element: Ordinal,
) -> Result<T, WireError>
{
    elements.nth(element.0).ok_or(WireError::Tag)
}

/// Read a part key.
///
/// # Specification
/// trivial.
fn part(cursor: &mut Cursor<'_>) -> Result<PartKey, WireError>
{
    let Fixed(part) = cursor.fixed::<8>()?;
    Ok(PartKey::from(u64::from_le_bytes(part)))
}

/// Frame a reply, or its size alone when it would pass the cap.
///
/// # Specification
/// - ensures: tag one and the reply when the whole image is within the cap;
///   otherwise tag two and the size the image would have had.
/// - fails: an unrepresentable size.
/// - panics: none.
///
/// # Errors
/// - [`WireError::Length`]: the size exceeds 64 bits.
///
/// # Adequacy
/// - hypothesis: L3 — a reply one byte past the cap carries its size.
/// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |image|
    u64::try_from(image.0.len()).is_ok_and(|length| length <= ANSWER_CAP.0)))]
pub(super) fn reply(body: Body<'_>) -> Result<WireImage, WireError>
{
    let length = u64::try_from(body.0.len()).map_err(|_width| WireError::Length)?;
    let size = arith::checked_add(Int::from(length), Int::from(1_u64))
        .map_err(|_overflow| WireError::Length)?;
    if size > Int::from(ANSWER_CAP.0) {
        let mut image = WireImage(vec![2]);
        image.0.extend_from_slice(&u64::from(size).to_le_bytes());
        return Ok(image);
    }
    let mut image = WireImage(vec![1]);
    image.0.extend_from_slice(body.0);
    Ok(image)
}

/// Read a reply's body, refusing an unheld root or an over-cap size.
///
/// # Specification
/// - ensures: the body tag one carries.
/// - fails: tag zero as unheld `root`, tag two as its size, any other tag.
/// - panics: none.
/// - executable: none — the decoding is its own specification; the unheld and
///   over-cap witnesses read each tag.
///
/// # Errors
/// - [`StreamError`]: as above.
///
/// # Adequacy
/// - hypothesis: L3 — an unheld root and an over-cap reply are refused by name.
/// - witness: `stream::tests::an_unheld_root_is_answered_unheld`
/// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
pub(super) fn read_reply(
    image: &WireImage,
    root: StoreRoot,
) -> Result<Body<'_>, StreamError>
{
    match image.as_ref().split_first() {
        Some((&1, body)) => Ok(Body(body)),
        Some((&0, &[])) => Err(StreamError::Unheld(root)),
        Some((&2, size)) => {
            let mut cursor = Cursor::new(Body(size));
            let Fixed(size) = cursor.fixed::<8>()?;
            cursor.finish()?;
            Err(StreamError::Oversize(ByteSize(u64::from_le_bytes(size))))
        },
        Some(_) => Err(WireError::Tag.into()),
        None => Err(WireError::Truncated.into()),
    }
}

/// The holder's answer for an unheld root.
///
/// # Specification
/// trivial.
pub(super) fn unheld() -> WireImage
{
    WireImage(vec![0])
}
