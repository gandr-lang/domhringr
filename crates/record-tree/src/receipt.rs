//! Receipts: the payload every commit carries, and its encoding.
//!
//! A receipt is one byte of format version followed by its body: the tree,
//! the operation fence and the kind, in that order. A commit's blob is
//! exactly these bytes; its author is the commit's verified signer, never a
//! field.
//!
//! The body's codec is a stand-in, confined to [`Receipt::encode`] and
//! [`Receipt::decode`] until receipts encode through the value plane: the
//! postcard wire format of a private mirror of the receipt ([`Wire`]) —
//! fixed field order, the tree and peer keys as their raw 32 bytes, the
//! operation as its raw 16 bytes, the kind as a varint variant index, a
//! note's text as a varint length and its UTF-8 bytes, and no
//! self-describing framing.

use alloc::string::String;
use alloc::vec::Vec;

use sedimentree_core::blob::Blob;
use sedimentree_core::id::SedimentreeId;
use subduction_core::peer::id::PeerId;

use crate::id::PeerKey;
use crate::id::TreeId;

/// The receipt format this crate writes, and the only one it reads.
const VERSION: u8 = 1;

/// An operation's idempotency fence: sixteen bytes drawn at random when the
/// receipt is made. Two receipts carrying the same fence are one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Operation([u8; 16]);

impl Operation
{
    /// Draw a fresh fence from the operating system's random source.
    ///
    /// # Specification
    /// - ensures: the fence is sixteen bytes from the operating system's
    ///   cryptographically secure source, so two calls collide with negligible
    ///   probability.
    /// - fails: [`RandomError`] when the source cannot be read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two fences drawn in turn differ, which a constant or
    ///   an unfilled buffer would not.
    /// - witness: `receipt::tests::fences_are_drawn_fresh`
    #[inline]
    pub fn random() -> Result<Self, RandomError>
    {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(RandomError)?;
        Ok(Self(bytes))
    }
}

/// The transition a receipt records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind
{
    /// The tree's root; its author is the tree's owner.
    Open,
    /// The author delegates write authority to `to`.
    Grant
    {
        /// The peer granted write authority.
        to: PeerKey,
    },
    /// Content: the stand-in for every later receipt body.
    Note
    {
        /// The note's text.
        text: String,
    },
}

/// The payload of a commit: which tree it belongs to, the operation it is,
/// and the transition it records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt
{
    /// The tree this receipt belongs to.
    tree: TreeId,
    /// The idempotency fence.
    operation: Operation,
    /// The transition.
    kind: Kind,
}

/// The stand-in codec's view of a receipt body: postcard writes these fields
/// in this order. It borrows a note's text, so encoding copies nothing but
/// the fixed-size keys and decoding allocates only the text a receipt owns.
#[derive(serde::Serialize, serde::Deserialize)]
struct Wire<'text>
{
    /// The tree id's raw bytes.
    tree: [u8; 32],
    /// The fence's raw bytes.
    operation: [u8; 16],
    /// The transition, its text borrowed from the bytes it is read from.
    #[serde(borrow)]
    kind: WireKind<'text>,
}

/// The stand-in codec's view of a [`Kind`], variant for variant in the same
/// order.
#[derive(serde::Serialize, serde::Deserialize)]
enum WireKind<'text>
{
    /// [`Kind::Open`].
    Open,
    /// [`Kind::Grant`], the grantee's peer id as its raw bytes.
    Grant
    {
        /// The grantee's peer id.
        to: [u8; 32],
    },
    /// [`Kind::Note`], its text borrowed.
    Note
    {
        /// The note's text.
        text: &'text str,
    },
}

impl<'text> Wire<'text>
{
    /// The wire view of `receipt`, borrowing its text.
    ///
    /// # Specification
    /// trivial.
    fn of(receipt: &'text Receipt) -> Self
    {
        let kind = match receipt.kind {
            | Kind::Open => WireKind::Open,
            | Kind::Grant { to } => WireKind::Grant {
                to: *to.peer_id().as_bytes(),
            },
            | Kind::Note { ref text } => WireKind::Note { text },
        };
        Self {
            tree: *receipt.tree.sedimentree().as_bytes(),
            operation: receipt.operation.0,
            kind,
        }
    }

    /// The receipt this wire view spells, owning its text.
    ///
    /// # Specification
    /// trivial.
    fn into_receipt(self) -> Receipt
    {
        let kind = match self.kind {
            | WireKind::Open => Kind::Open,
            | WireKind::Grant { to } => Kind::Grant {
                to: PeerKey::new(PeerId::new(to)),
            },
            | WireKind::Note { text } => Kind::Note { text: text.into() },
        };
        Receipt::new(
            TreeId::from_sedimentree(SedimentreeId::new(self.tree)),
            Operation(self.operation),
            kind,
        )
    }
}

impl Receipt
{
    /// A receipt for `tree` carrying `operation` and recording `kind`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(
        tree: TreeId,
        operation: Operation,
        kind: Kind,
    ) -> Self
    {
        Self {
            tree,
            operation,
            kind,
        }
    }

    /// A fresh [`Kind::Open`] for `tree`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records an Open, and carries a
    ///   fresh fence ([`Operation::random`]).
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn open(tree: TreeId) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Open))
    }

    /// A fresh [`Kind::Grant`] of write authority on `tree` to `to`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records a grant to `to`, and
    ///   carries a fresh fence ([`Operation::random`]).
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn grant(
        tree: TreeId,
        to: PeerKey,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Grant { to }))
    }

    /// A fresh [`Kind::Note`] on `tree` carrying `text`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records a note of `text`, and
    ///   carries a fresh fence ([`Operation::random`]).
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn note(
        tree: TreeId,
        text: String,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Note { text }))
    }

    /// The tree the receipt names.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn tree(&self) -> TreeId
    {
        self.tree
    }

    /// The receipt's idempotency fence.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn operation(&self) -> Operation
    {
        self.operation
    }

    /// The transition the receipt records.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> &Kind
    {
        &self.kind
    }

    /// The receipt's tree, fence and kind, taken apart.
    ///
    /// # Specification
    /// trivial.
    pub(crate) fn into_parts(self) -> (TreeId, Operation, Kind)
    {
        (self.tree, self.operation, self.kind)
    }

    /// Encode the receipt into the blob a commit carries.
    ///
    /// # Specification
    /// - ensures: the blob is the version byte followed by the stand-in codec's
    ///   encoding of the tree, the fence and the kind, in that order;
    ///   [`Receipt::decode`] reads it back to an equal receipt, and equal
    ///   receipts encode to equal bytes.
    /// - fails: [`EncodeError`] when the codec refuses a value; no field of a
    ///   receipt is of a kind it refuses.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EncodeError`]: the codec refused to serialize.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every kind is encoded and decoded back equal, and one
    ///   encoding is compared byte for byte with independently written bytes,
    ///   which pins the field order and the absence of framing.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_note_encodes_to_its_fixed_layout`
    pub(crate) fn encode(&self) -> Result<Blob, EncodeError>
    {
        let wire = (VERSION, Wire::of(self));
        let size = postcard::experimental::serialized_size(&wire).map_err(EncodeError)?;
        let bytes = postcard::to_extend(&wire, Vec::with_capacity(size)).map_err(EncodeError)?;
        Ok(Blob::new(bytes))
    }

    /// Decode the receipt a commit's blob carries.
    ///
    /// # Specification
    /// - ensures: accepts exactly the blobs [`Receipt::encode`] produces: one
    ///   receipt has one encoding, so a blob padded with trailing bytes or
    ///   spelling a varint in more bytes than it needs is refused.
    /// - fails: [`DecodeError::Empty`] for an empty blob,
    ///   [`DecodeError::Version`] for any version byte but this format's,
    ///   [`DecodeError::Body`] for a body the codec cannot read (too short, an
    ///   unknown kind, text that is not UTF-8), [`DecodeError::Trailing`] for
    ///   bytes after the receipt, and [`DecodeError::NonCanonical`] for a body
    ///   longer than the receipt's own encoding.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`DecodeError::Empty`]: the blob is empty.
    /// - [`DecodeError::Version`]: the format version is not this one.
    /// - [`DecodeError::Body`]: the codec cannot read the body.
    /// - [`DecodeError::Trailing`]: bytes follow the receipt.
    /// - [`DecodeError::NonCanonical`]: the body is not the canonical encoding.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the empty blob, a foreign version, a truncated body,
    ///   an unknown kind, non-UTF-8 text, a trailing byte and an overlong
    ///   varint each meet their own refusal, beside the round trip of every
    ///   kind.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    pub(crate) fn decode(blob: &Blob) -> Result<Self, DecodeError>
    {
        let Some((&version, body)) = blob.as_slice().split_first()
        else {
            return Err(DecodeError::Empty);
        };
        if version != VERSION {
            return Err(DecodeError::Version { found: version });
        }
        let (wire, rest) = postcard::take_from_bytes::<Wire<'_>>(body)
            .map_err(|failure| DecodeError::Body(BodyError(failure)))?;
        if !rest.is_empty() {
            return Err(DecodeError::Trailing);
        }
        let canonical = postcard::experimental::serialized_size(&wire)
            .map_err(|failure| DecodeError::Body(BodyError(failure)))?;
        if canonical != body.len() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(wire.into_receipt())
    }
}

/// Why no operation fence could be drawn.
#[derive(Debug, thiserror::Error)]
#[error("cannot read the operating system's random source")]
#[repr(transparent)]
pub struct RandomError(#[source] getrandom::Error);

/// Why a receipt cannot be encoded.
#[derive(Debug, thiserror::Error)]
#[error("cannot encode the receipt")]
#[repr(transparent)]
pub struct EncodeError(#[source] postcard::Error);

/// Why the codec cannot read a receipt body; its source carries the codec's
/// own reason.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the codec cannot read the receipt body")]
#[repr(transparent)]
pub struct BodyError(#[source] postcard::Error);

/// Why a blob is not a receipt.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError
{
    /// The blob is empty.
    #[error("the blob is empty")]
    Empty,
    /// The format version is not the one this crate reads.
    #[error("receipt format version {found} is not version {VERSION}")]
    Version
    {
        /// The version byte the blob carries.
        found: u8,
    },
    /// The codec cannot read the body.
    #[error("the receipt body is malformed")]
    Body(#[source] BodyError),
    /// Bytes follow the receipt.
    #[error("bytes follow the receipt")]
    Trailing,
    /// The body is longer than the receipt's canonical encoding.
    #[error("the receipt is not canonically encoded")]
    NonCanonical,
}

#[cfg(test)]
mod tests
{
    use alloc::string::String;

    use sedimentree_core::blob::Blob;

    use super::BodyError;
    use super::DecodeError;
    use super::Kind;
    use super::Operation;
    use super::Receipt;
    use crate::id::PeerKey;
    use crate::id::TreeId;

    /// The tree the receipts name.
    const TREE: &str = "7265636569707472656365697074726563656970747265636569707472656365";

    /// A peer key a grant names.
    const PEER: &str = "7065657270656572706565727065657270656572706565727065657270656572";

    /// The tree the receipts name.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        TREE.parse().unwrap()
    }

    /// One receipt of every kind.
    ///
    /// # Specification
    /// trivial.
    fn every_kind() -> [Receipt; 3]
    {
        let peer = PEER.parse::<PeerKey>().unwrap();
        [
            Receipt::open(tree()).unwrap(),
            Receipt::grant(tree(), peer).unwrap(),
            Receipt::note(tree(), String::from("a note, with ünïcode")).unwrap(),
        ]
    }

    #[test]
    fn fences_are_drawn_fresh()
    {
        assert_ne!(
            Operation::random().unwrap(),
            Operation::random().unwrap(),
            "two fences drawn in turn differ"
        );
    }

    #[test]
    fn every_kind_round_trips()
    {
        for receipt in every_kind() {
            let blob = receipt.encode().unwrap();
            assert_eq!(
                Receipt::decode(&blob).unwrap(),
                receipt,
                "a receipt decodes to itself"
            );
            assert_eq!(receipt.encode().unwrap(), blob, "encoding is deterministic");
        }
    }

    #[test]
    fn a_note_encodes_to_its_fixed_layout()
    {
        let operation = Operation([0x0f; 16]);
        let receipt = Receipt::new(tree(), operation, Kind::Note {
            text: String::from("hi"),
        });
        let mut expected = vec![1_u8];
        expected.extend_from_slice(b"receiptreceiptreceiptreceiptrece");
        expected.extend_from_slice(&[0x0f; 16]);
        expected.extend_from_slice(&[2, 2, b'h', b'i']);
        assert_eq!(
            receipt.encode().unwrap().as_slice(),
            expected.as_slice(),
            "version, tree, fence, kind index, text length, text: nothing else"
        );
    }

    #[test]
    fn a_malformed_blob_is_refused_by_name()
    {
        let [open, _grant, note] = every_kind();
        let open = open.encode().unwrap().as_slice().to_vec();
        let note = note.encode().unwrap().as_slice().to_vec();
        let refused = |bytes: Vec<u8>| Receipt::decode(&Blob::new(bytes)).unwrap_err();

        assert_eq!(refused(Vec::new()), DecodeError::Empty);
        let mut version = open.clone();
        version[0] = 2;
        assert_eq!(refused(version), DecodeError::Version { found: 2 });
        let (_kind, truncated) = open.split_last().unwrap();
        assert!(
            matches!(
                refused(truncated.to_vec()),
                DecodeError::Body(BodyError(postcard::Error::DeserializeUnexpectedEnd))
            ),
            "a truncated body"
        );
        let mut kind = open.clone();
        *kind.last_mut().unwrap() = 3;
        assert!(
            matches!(refused(kind), DecodeError::Body(_)),
            "an unknown kind"
        );
        let mut text = note;
        *text.last_mut().unwrap() = 0xff;
        assert!(
            matches!(
                refused(text),
                DecodeError::Body(BodyError(postcard::Error::DeserializeBadUtf8))
            ),
            "text that is not UTF-8"
        );
        let mut trailing = open.clone();
        trailing.push(0);
        assert_eq!(refused(trailing), DecodeError::Trailing);
        let mut overlong = open;
        *overlong.last_mut().unwrap() = 0x80;
        overlong.push(0);
        assert_eq!(
            refused(overlong),
            DecodeError::NonCanonical,
            "the Open index spelled as a two-byte varint"
        );
    }
}
