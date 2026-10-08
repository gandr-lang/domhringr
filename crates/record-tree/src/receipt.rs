//! Receipts: the payload every commit carries, and its encoding.
//!
//! A receipt is the value plane's canonical value of a format version, the
//! tree it belongs to, the operation fence, and the kind, in that order. A
//! commit's blob is the receipt's flat form ([`gandr_storage_values`]'s
//! `encode_flat`): the token body a value-plane chunk frames, so a receipt
//! stored today commits through the value plane's chunk DAG later without
//! re-encoding. Its author is the commit's verified signer, never a field.
//!
//! In the value plane's token records (open, word, bytes, close), a receipt
//! is:
//!
//! ```text
//! receipt := open 0x01 · word 1 · bytes tree (32) · bytes operation (16) · kind · close
//! kind    := open 0x01 · close                          Open
//!          | open 0x02 · bytes grantee (32) · close     Grant
//!          | open 0x03 · bytes text (UTF-8) · close     Note
//! ```
//!
//! The decoder admits exactly what the encoder writes, so a receipt has one
//! blob. A constructor whose tag or payload it does not admit — another
//! receipt tag or version, an unknown kind, an id of the wrong length, text
//! that is not UTF-8 — is refused as that constructor
//! ([`ValueError::UnexpectedConstructor`] at its open record): the value
//! plane's refusals name token shapes, and this is the one that names the
//! constructor a codec turns away.

use alloc::string::String;

use gandr_storage_values::CanonicalValue;
use gandr_storage_values::CanonicalWord;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::TokenBody;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenOffset;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;
use gandr_storage_values::decode_flat;
use gandr_storage_values::encode_flat;
use sedimentree_core::blob::Blob;
use sedimentree_core::id::SedimentreeId;
use subduction_core::peer::id::PeerId;

use crate::id::PeerKey;
use crate::id::TreeId;

/// The receipt format this crate writes, and the only one it reads.
const VERSION: u64 = 1;

/// The receipt's constructor tag.
const RECEIPT: u8 = 0x01;

/// The constructor tag of [`Kind::Open`].
const OPEN: u8 = 0x01;

/// The constructor tag of [`Kind::Grant`].
const GRANT: u8 = 0x02;

/// The constructor tag of [`Kind::Note`].
const NOTE: u8 = 0x03;

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

    /// Encode the receipt into the blob a commit carries: its flat form.
    ///
    /// # Specification
    /// - ensures: the blob is the value plane's flat form of the receipt, the
    ///   records the module grammar lists; [`Receipt::decode`] reads it back to
    ///   an equal receipt, and equal receipts encode to equal bytes.
    /// - fails: the value plane's overflow refusal for a note too long for a
    ///   reader to address; a receipt embeds no committed pointer and always
    ///   emits one balanced value, so no other refusal arises.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the flat encoder refused the receipt.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every kind is encoded and decoded back equal, and one
    ///   encoding is compared byte for byte with independently written records,
    ///   which pins the grammar.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_note_encodes_to_its_fixed_layout`
    pub(crate) fn encode(&self) -> Result<Blob, ValueError>
    {
        let flat = encode_flat(self)?;
        Ok(Blob::new(flat.as_ref().to_vec()))
    }

    /// Decode the receipt a commit's blob carries.
    ///
    /// # Specification
    /// - ensures: accepts exactly the blobs [`Receipt::encode`] produces, so
    ///   one receipt has one blob.
    /// - fails: the value plane's refusals for a blob that is not one
    ///   well-formed value with nothing after it, and
    ///   [`ValueError::UnexpectedConstructor`] for a constructor the receipt
    ///   grammar does not admit.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the blob is not a receipt's flat form.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the empty blob, a foreign record kind, a truncated
    ///   receipt, a trailing record, a foreign receipt tag and version, short
    ///   ids, an unknown kind, non-UTF-8 text and an extra payload each meet
    ///   their own refusal, beside the round trip of every kind.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    pub(crate) fn decode(blob: &Blob) -> Result<Self, ValueError>
    {
        decode_flat(TokenBody::from(blob.as_slice()))
    }
}

impl CanonicalValue for Receipt
{
    /// Walk the receipt into `sink` in the module grammar's order.
    ///
    /// # Specification
    /// - ensures: on success `sink` received exactly one balanced value: the
    ///   receipt constructor holding the version word, the tree and fence
    ///   bytes, and the kind constructor with its payload.
    /// - fails: propagates the sink's refusal unchanged.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a record.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the flat form of a note is compared byte for byte
    ///   with records written independently, and every kind round-trips.
    /// - witness: `receipt::tests::a_note_encodes_to_its_fixed_layout`
    /// - witness: `receipt::tests::every_kind_round_trips`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        sink.open(ConstructorTag::from(RECEIPT))?;
        sink.word(CanonicalWord::from(VERSION))?;
        sink.bytes(TokenBytes::from(
            self.tree.sedimentree().as_bytes().as_slice(),
        ))?;
        sink.bytes(TokenBytes::from(self.operation.0.as_slice()))?;
        match self.kind {
            | Kind::Open => sink.open(ConstructorTag::from(OPEN))?,
            | Kind::Grant { to } => {
                sink.open(ConstructorTag::from(GRANT))?;
                sink.bytes(TokenBytes::from(to.peer_id().as_bytes().as_slice()))?;
            },
            | Kind::Note { ref text } => {
                sink.open(ConstructorTag::from(NOTE))?;
                sink.bytes(TokenBytes::from(text.as_bytes()))?;
            },
        }
        sink.close()?;
        sink.close()
    }

    /// Read one receipt from `reader`.
    ///
    /// # Specification
    /// - ensures: on success the receipt whose emission the records are, and
    ///   the reader stands after the receipt's close.
    /// - fails: [`ValueError::UnexpectedConstructor`] at the receipt's open
    ///   record for another receipt tag, another version, or a tree or fence of
    ///   the wrong length; at the kind's open record for an unknown kind, a
    ///   grantee of the wrong length, or text that is not UTF-8; and the
    ///   reader's own refusals for a record of the wrong kind, a truncated
    ///   stream or an exhausted budget.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — each refusal is met by a body built record by record,
    ///   and every kind round-trips.
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    /// - witness: `receipt::tests::every_kind_round_trips`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let receipt = Opened::read(reader)?;
        if u8::from(receipt.tag) != RECEIPT || u64::from(reader.read_word()?) != VERSION {
            return Err(receipt.refused());
        }
        let tree = <&[u8]>::from(reader.read_bytes()?);
        let tree = <[u8; 32]>::try_from(tree).map_err(|_wrong_length| receipt.refused())?;
        let operation = <&[u8]>::from(reader.read_bytes()?);
        let operation =
            <[u8; 16]>::try_from(operation).map_err(|_wrong_length| receipt.refused())?;
        let opened = Opened::read(reader)?;
        let kind = match u8::from(opened.tag) {
            | OPEN => Kind::Open,
            | GRANT => {
                let to = <&[u8]>::from(reader.read_bytes()?);
                let to = <[u8; 32]>::try_from(to).map_err(|_wrong_length| opened.refused())?;
                Kind::Grant {
                    to: PeerKey::new(PeerId::new(to)),
                }
            },
            | NOTE => {
                let text = <&[u8]>::from(reader.read_bytes()?);
                let text = core::str::from_utf8(text).map_err(|_not_utf8| opened.refused())?;
                Kind::Note { text: text.into() }
            },
            | _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        reader.read_close()?;
        let tree = TreeId::from_sedimentree(SedimentreeId::new(tree));
        Ok(Self::new(tree, Operation(operation), kind))
    }
}

/// A constructor's open record, as the receipt decoder read it.
#[derive(Clone, Copy, Debug)]
struct Opened
{
    /// The constructor's tag.
    tag: ConstructorTag,
    /// The open record's position.
    at: TokenOffset,
}

impl Opened
{
    /// Read the next record as an open record.
    ///
    /// # Specification
    /// - ensures: on success the tag read and the position of its record.
    /// - fails: the reader's refusals for any other record or none.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the next record is not an open record.
    fn read(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let at = reader.position();
        let tag = reader.read_tag()?;
        Ok(Self { tag, at })
    }

    /// The refusal of this constructor: its tag or its payload is not one the
    /// receipt grammar admits.
    ///
    /// # Specification
    /// trivial.
    const fn refused(self) -> ValueError
    {
        ValueError::UnexpectedConstructor {
            found: self.tag,
            position: self.at,
        }
    }
}

/// Why no operation fence could be drawn.
#[derive(Debug, thiserror::Error)]
#[error("cannot read the operating system's random source")]
#[repr(transparent)]
pub struct RandomError(#[source] getrandom::Error);

#[cfg(test)]
mod tests
{
    use alloc::string::String;
    use alloc::vec::Vec;

    use gandr_storage_values::ConstructorTag;
    use gandr_storage_values::TokenKind;
    use gandr_storage_values::TokenOffset;
    use gandr_storage_values::ValueError;
    use sedimentree_core::blob::Blob;

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
        let receipt = Receipt::new(tree(), Operation([0x0f; 16]), Kind::Note {
            text: String::from("hi"),
        });
        let mut expected = vec![0x01_u8, 0x01];
        expected.extend_from_slice(&[0x02, 1, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(&[0x03, 32, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(b"receiptreceiptreceiptreceiptrece");
        expected.extend_from_slice(&[0x03, 16, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(&[0x0f; 16]);
        expected.extend_from_slice(&[0x01, 0x03]);
        expected.extend_from_slice(&[0x03, 2, 0, 0, 0, 0, 0, 0, 0, b'h', b'i']);
        expected.extend_from_slice(&[0x05, 0x05]);
        assert_eq!(
            receipt.encode().unwrap().as_slice(),
            expected.as_slice(),
            "open receipt, version word, tree, fence, open note, text, two closes"
        );
    }

    #[test]
    fn a_malformed_blob_is_refused_by_name()
    {
        let open = |tag: u8| vec![0x01_u8, tag];
        let word = |value: u64| [&[0x02_u8][..], &value.to_le_bytes()].concat();
        let bytes = |payload: &[u8]| {
            let length = u64::try_from(payload.len()).unwrap().to_le_bytes();
            [&[0x03_u8][..], &length, payload].concat()
        };
        let close = || vec![0x05_u8];
        let refused = |records: &[Vec<u8>]| Receipt::decode(&Blob::new(records.concat()));
        let tree = [0x72_u8; 32];
        let fence = [0x0f_u8; 16];
        let at = TokenOffset::from;
        let constructor = |tag: u8, record: u32| ValueError::UnexpectedConstructor {
            found: ConstructorTag::from(tag),
            position: at(record),
        };
        let note = |text: &[u8]| {
            vec![
                open(1),
                word(1),
                bytes(&tree),
                bytes(&fence),
                open(3),
                bytes(text),
                close(),
                close(),
            ]
        };

        assert!(
            refused(&note(b"hi")).is_ok(),
            "the well-formed note decodes"
        );
        assert_eq!(
            refused(&[]),
            Err(ValueError::TruncatedStream { position: at(0) }),
            "an empty blob"
        );
        assert_eq!(
            refused(&[vec![0x6e]]),
            Err(ValueError::UnknownTokenKind { position: at(0) }),
            "a blob that is not token records"
        );
        let mut receipt = note(b"hi");
        receipt[0] = open(2);
        assert_eq!(
            refused(&receipt),
            Err(constructor(2, 0)),
            "a foreign receipt tag"
        );
        let mut receipt = note(b"hi");
        receipt[1] = word(2);
        assert_eq!(
            refused(&receipt),
            Err(constructor(1, 0)),
            "a foreign version"
        );
        let mut receipt = note(b"hi");
        receipt[2] = bytes(&[0x72; 31]);
        assert_eq!(refused(&receipt), Err(constructor(1, 0)), "a short tree id");
        let mut receipt = note(b"hi");
        receipt[3] = bytes(&[0x0f; 17]);
        assert_eq!(refused(&receipt), Err(constructor(1, 0)), "a long fence");
        let mut receipt = note(b"hi");
        receipt[4] = open(4);
        assert_eq!(refused(&receipt), Err(constructor(4, 4)), "an unknown kind");
        let mut receipt = note(b"hi");
        receipt[4] = open(2);
        receipt[5] = bytes(&[0x70; 31]);
        assert_eq!(refused(&receipt), Err(constructor(2, 4)), "a short grantee");
        assert_eq!(
            refused(&note(&[0x68, 0xff])),
            Err(constructor(3, 4)),
            "text that is not UTF-8"
        );
        let mut receipt = note(b"hi");
        receipt.insert(6, bytes(b"more"));
        assert_eq!(
            refused(&receipt),
            Err(ValueError::UnexpectedToken {
                expected: TokenKind::Close,
                found: TokenKind::Bytes,
                position: at(6),
            }),
            "a payload the kind does not carry"
        );
        let mut receipt = note(b"hi");
        receipt.pop();
        assert_eq!(
            refused(&receipt),
            Err(ValueError::TruncatedStream { position: at(7) }),
            "a receipt left open"
        );
        let mut receipt = note(b"hi");
        receipt.push(close());
        assert_eq!(
            refused(&receipt),
            Err(ValueError::TrailingTokens { position: at(8) }),
            "a record after the receipt"
        );
    }
}
