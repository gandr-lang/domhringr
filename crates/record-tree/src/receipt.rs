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
//! receipt   := open 0x01 · word 2 · bytes tree (32) · bytes operation (16) · kind · close
//! kind      := open 0x01 · bytes proof (64) · close                       Open
//!            | open 0x02 · bytes grantee (32) · close                     Grant
//!            | open 0x03 · bytes text (UTF-8) · close                     Note
//!            | open 0x04 · bytes path (UTF-8) · target · close            Bind
//!            | open 0x05 · bytes domain (ASCII) · close                   Claim
//!            | open 0x06 · bytes tree (32) · bytes label (UTF-8) · close  Introduce
//!            | open 0x07 · endpoint · bytes proof (64) · close            Present
//!            | open 0x08 · bytes peer (32) · close                        Withdraw
//! target    := open 0x01 · anchor · close                                 Anchor
//!            | open 0x02 · bytes endpoint (32) · close                    Endpoint
//!            | open 0x03 · bytes datum (UTF-8) · close                    Datum
//! anchor    := open 0x01 · authority · close                              Tree
//!            | open 0x02 · authority · bytes path (UTF-8) · close         Path
//!            | open 0x03 · authority · bytes commit (32) · close          Commit
//! authority := open 0x01 · bytes tree (32) · close                        Key
//!            | open 0x02 · bytes domain (ASCII) · close                   Domain
//!            | open 0x03 · bytes label (UTF-8) · close                    Label
//! endpoint  := open 0x01 · bytes id (32) · word count · address{count} · close
//! address   := open 0x01 · bytes ip (4 or 16) · word port · close         Direct
//!            | open 0x02 · bytes url (UTF-8) · close                      Relay
//! ```
//!
//! A tree, in the receipt's header, as an authority or as the tree
//! introduced, and an endpoint are ed25519 verifying keys; a grantee and a
//! withdrawn peer are 32-byte peer ids; a commit is its whole 32-byte id,
//! never a prefix; a path is its segments joined by `/`, none empty or
//! beginning with `.`; a domain is a DNS name as [`Domain`] admits it, and a
//! label one as [`Label`] admits it. An anchor is written as its typed parts,
//! so each part takes the record and the refusal it takes elsewhere in a
//! receipt. A presented endpoint lists its addresses in their order, each
//! once: direct addresses first, IPv4 before IPv6, by address and then port,
//! an IPv6 address without flow label or scope id; then relays by the URL's
//! text, each an `http` or `https` URL written as it parses back and holding
//! no `@`. A presence carries no time: its commit is when it holds since.
//!
//! The decoder admits exactly what the encoder writes, so a receipt has one
//! blob. A constructor whose tag or payload it does not admit — another
//! receipt tag or version, an unknown kind, target, anchor, authority or
//! address, an id of the wrong length (an abbreviated commit id among them), a
//! tree or endpoint that is not a verifying key, text that is not UTF-8, a
//! path with an empty or reserved segment, a malformed domain or label, an IP
//! address of another length, a port beyond 65535, a relay that is no
//! canonical `http` or `https` URL or holds `@`, addresses out of order or
//! repeated — is refused as that constructor
//! ([`ValueError::UnexpectedConstructor`] at its open record): the value
//! plane's refusals name token shapes, and this is the one that names the
//! constructor a codec turns away.

use alloc::collections::BTreeSet;
use alloc::string::String;
use core::net::IpAddr;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;

use gandr_storage_values::CanonicalValue;
use gandr_storage_values::CanonicalWord;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::TokenBody;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenOffset;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;
use gandr_storage_values::ValueQuantity;
use gandr_storage_values::decode_flat;
use gandr_storage_values::encode_flat;
use sedimentree_core::blob::Blob;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::peer::id::PeerId;

use crate::anchor::Anchor;
use crate::anchor::Authority;
use crate::anchor::Path;
use crate::anchor::Target;
use crate::id::Address;
use crate::id::Endpoint;
use crate::id::EndpointKey;
use crate::id::PeerKey;
use crate::id::TreeId;
use crate::identity::TreeKey;
use crate::name::Domain;
use crate::name::Label;

/// The receipt format this crate writes, and the only one it reads.
const VERSION: u64 = 2;

/// The receipt's constructor tag.
const RECEIPT: u8 = 0x01;

/// The constructor tag of [`Kind::Open`].
const OPEN: u8 = 0x01;

/// The constructor tag of [`Kind::Grant`].
const GRANT: u8 = 0x02;

/// The constructor tag of [`Kind::Note`].
const NOTE: u8 = 0x03;

/// The constructor tag of [`Kind::Bind`].
const BIND: u8 = 0x04;

/// The constructor tag of [`Kind::Claim`].
const CLAIM: u8 = 0x05;

/// The constructor tag of [`Kind::Introduce`].
const INTRODUCE: u8 = 0x06;

/// The constructor tag of [`Kind::Present`].
const PRESENT: u8 = 0x07;

/// The constructor tag of [`Kind::Withdraw`].
const WITHDRAW: u8 = 0x08;

/// The constructor tag of [`Target::Anchor`].
const ANCHOR: u8 = 0x01;

/// The constructor tag of [`Target::Endpoint`].
const ENDPOINT: u8 = 0x02;

/// The constructor tag of [`Target::Datum`].
const DATUM: u8 = 0x03;

/// The constructor tag of [`Anchor::Tree`].
const TREE: u8 = 0x01;

/// The constructor tag of [`Anchor::Path`].
const PATH: u8 = 0x02;

/// The constructor tag of [`Anchor::Commit`].
const COMMIT: u8 = 0x03;

/// The constructor tag of [`Authority::Key`].
const KEY: u8 = 0x01;

/// The constructor tag of [`Authority::Domain`].
const DOMAIN: u8 = 0x02;

/// The constructor tag of [`Authority::Label`].
const LABEL: u8 = 0x03;

/// The constructor tag of a presented [`Endpoint`] with its addresses.
const REACHED: u8 = 0x01;

/// The constructor tag of a direct [`Address`].
const DIRECT: u8 = 0x01;

/// The constructor tag of a relay [`Address`].
const RELAY: u8 = 0x02;

/// The domain an Open proof is signed under: the first of the two 32-byte
/// blocks of the message it signs, the owner's peer key the second.
const OPEN_PROOF_DOMAIN: [u8; 32] = *b"domhringr record tree open proof";

/// The domain an endpoint proof is signed under: the first of the two 32-byte
/// blocks of the message the endpoint key signs, the holder's peer key the
/// second.
const ENDPOINT_PROOF_DOMAIN: [u8; 32] = *b"domhringr record endpoint holder";

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

/// The proof an Open carries: the tree key's signature naming the tree's
/// owner, so a tree id names exactly the tree whose key signed its root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct OpenProof(iroh::Signature);

impl OpenProof
{
    /// Sign, under `key`, the message naming `owner`.
    ///
    /// # Specification
    /// - ensures: the message is [`OPEN_PROOF_DOMAIN`] followed by `owner`'s 32
    ///   bytes, so a proof names one owner and is no signature over any other
    ///   message this crate signs.
    /// - panics: none.
    pub(crate) fn sign(
        key: &iroh::SecretKey,
        owner: PeerKey,
    ) -> Self
    {
        let message = [OPEN_PROOF_DOMAIN, *owner.peer_id().as_bytes()];
        Self(key.sign(message.as_flattened()))
    }

    /// Check the proof names `owner` under `tree`'s key.
    ///
    /// # Specification
    /// - ensures: succeeds iff the proof is the strict ed25519 signature, under
    ///   `tree`'s verifying key, of the message [`OpenProof::sign`] signs for
    ///   `owner`.
    /// - fails: iroh's [`SignatureError`] otherwise.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SignatureError`]: the proof was made by another key, for another
    ///   owner, or is no signature.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a proof by the tree's key for the Open's author is
    ///   admitted; one by another key, and one by the tree's key for another
    ///   author, are each refused.
    /// - witness: `fold::tests::an_open_proved_by_another_key_is_refused`
    ///
    /// [`SignatureError`]: iroh::SignatureError
    pub(crate) fn verify(
        self,
        tree: TreeId,
        owner: PeerKey,
    ) -> Result<(), iroh::SignatureError>
    {
        let message = [OPEN_PROOF_DOMAIN, *owner.peer_id().as_bytes()];
        tree.key().verify(message.as_flattened(), &self.0)
    }
}

/// The proof a presence carries: the presented endpoint key's signature
/// naming the presence's author, so a presence names only an endpoint whose
/// key its author holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct EndpointProof(iroh::Signature);

impl EndpointProof
{
    /// Sign, under the endpoint key `key`, the message naming `holder`.
    ///
    /// # Specification
    /// - ensures: the message is [`ENDPOINT_PROOF_DOMAIN`] followed by
    ///   `holder`'s 32 bytes, so a proof names one holder and is no signature
    ///   over any other message this crate signs.
    /// - panics: none.
    pub(crate) fn sign(
        key: &iroh::SecretKey,
        holder: PeerKey,
    ) -> Self
    {
        let message = [ENDPOINT_PROOF_DOMAIN, *holder.peer_id().as_bytes()];
        Self(key.sign(message.as_flattened()))
    }

    /// Check the proof names `holder` under `endpoint`'s key.
    ///
    /// # Specification
    /// - ensures: succeeds iff the proof is the strict ed25519 signature, under
    ///   `endpoint`'s verifying key, of the message [`EndpointProof::sign`]
    ///   signs for `holder`.
    /// - fails: iroh's [`SignatureError`] otherwise.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SignatureError`]: the proof was made by another key, for another
    ///   holder, or is no signature.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a presence proved by the presented endpoint's key for
    ///   its author is admitted; one proved by another endpoint's key, and one
    ///   the presented endpoint's key made for another member, are each
    ///   refused.
    /// - witness: `fold::tests::a_presence_naming_another_members_endpoint_is_refused`
    ///
    /// [`SignatureError`]: iroh::SignatureError
    pub(crate) fn verify(
        self,
        endpoint: EndpointKey,
        holder: PeerKey,
    ) -> Result<(), iroh::SignatureError>
    {
        let message = [ENDPOINT_PROOF_DOMAIN, *holder.peer_id().as_bytes()];
        endpoint
            .endpoint_id()
            .verify(message.as_flattened(), &self.0)
    }
}

/// The transition a receipt records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind
{
    /// The tree's root; its author is the tree's owner, whom the proof names.
    Open
    {
        /// The tree key's proof naming the author the owner.
        proof: OpenProof,
    },
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
    /// The author binds `path` in the tree to `target`.
    Bind
    {
        /// The path bound.
        path: Path,
        /// What it is bound to.
        target: Target,
    },
    /// The author, the tree's owner, claims `domain` names the tree: with a
    /// witness naming the tree's key for the domain, the claim lets the domain
    /// stand for the key.
    Claim
    {
        /// The DNS name claimed.
        domain: Domain,
    },
    /// The author introduces `tree` by `label`, a petname that resolves in
    /// this tree alone.
    Introduce
    {
        /// The tree introduced.
        tree: TreeId,
        /// The petname it is introduced by.
        label: Label,
    },
    /// The author presents `endpoint` as where it is reached, from this
    /// receipt's commit until the record withdraws or supersedes it.
    Present
    {
        /// The endpoint presented, with its addresses.
        endpoint: Endpoint,
        /// The endpoint key's proof naming the author its holder.
        proof: EndpointProof,
    },
    /// The author withdraws the presence of `of`.
    Withdraw
    {
        /// The member whose presence is withdrawn.
        of: PeerKey,
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

    /// A fresh [`Kind::Open`] of `key`'s tree, naming `owner` its owner.
    ///
    /// # Specification
    /// - ensures: the receipt names `key`'s tree, records an Open whose proof
    ///   `key` made for `owner` ([`TreeKey::prove`]), and carries a fresh fence
    ///   ([`Operation::random`]); the fold admits it only when `owner` is the
    ///   author of the commit carrying it.
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn open(
        key: &TreeKey,
        owner: PeerKey,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        let proof = key.prove(owner);
        Ok(Self::new(key.tree(), operation, Kind::Open { proof }))
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

    /// A fresh [`Kind::Bind`] of `path` in `tree` to `target`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records a binding of `path` to
    ///   `target`, and carries a fresh fence ([`Operation::random`]).
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn bind(
        tree: TreeId,
        path: Path,
        target: Target,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Bind { path, target }))
    }

    /// A fresh [`Kind::Claim`] of `domain` for `tree`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records a claim of `domain`, and
    ///   carries a fresh fence ([`Operation::random`]); the fold admits it only
    ///   when the tree's owner is the author of the commit carrying it.
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn claim(
        tree: TreeId,
        domain: Domain,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Claim { domain }))
    }

    /// A fresh [`Kind::Introduce`] in `tree` of `introduced` by `label`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records the introduction of
    ///   `introduced` by `label`, and carries a fresh fence
    ///   ([`Operation::random`]).
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn introduce(
        tree: TreeId,
        label: Label,
        introduced: TreeId,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Introduce {
            tree: introduced,
            label,
        }))
    }

    /// A fresh [`Kind::Present`] in `tree` of `endpoint`, carrying `proof`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records the presence of `endpoint`
    ///   proved by `proof`, and carries a fresh fence ([`Operation::random`]);
    ///   the fold admits it only from a member whose key `proof` names under
    ///   the endpoint's key.
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    pub(crate) fn present(
        tree: TreeId,
        endpoint: Endpoint,
        proof: EndpointProof,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Present {
            endpoint,
            proof,
        }))
    }

    /// A fresh [`Kind::Withdraw`] in `tree` of the presence of `of`.
    ///
    /// # Specification
    /// - ensures: the receipt names `tree`, records the withdrawal of `of`'s
    ///   presence, and carries a fresh fence ([`Operation::random`]); the fold
    ///   admits it from the tree's owner, and from a member for its own
    ///   presence.
    /// - fails: [`RandomError`] when no fence can be drawn.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RandomError`]: the random source failed.
    #[inline]
    pub fn withdraw(
        tree: TreeId,
        of: PeerKey,
    ) -> Result<Self, RandomError>
    {
        let operation = Operation::random()?;
        Ok(Self::new(tree, operation, Kind::Withdraw { of }))
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
    ///   receipt, a trailing record, a foreign receipt tag and the previous
    ///   version, short ids, a tree that is not a key, an unknown kind, a short
    ///   proof, non-UTF-8 text, an empty, reserved or malformed path, an
    ///   unknown target, anchor and authority, an endpoint that is not a key,
    ///   an abbreviated commit id, a key authority that is not a key, a
    ///   malformed domain or label as authority and in a claim or an
    ///   introduction, an introduced tree that is not a key, a presented
    ///   endpoint that is not a key or has a short proof, an unknown address,
    ///   an IP address of another length, a port beyond 65535, a relay that is
    ///   not UTF-8, not canonical, of another scheme or holding `@`, addresses
    ///   out of order or repeated, a count above or below the addresses given,
    ///   a short withdrawn peer, and an extra payload each meet their own
    ///   refusal, beside the round trip of every kind, every target, every
    ///   anchor under every authority and a presence with every address form.
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
    /// - hypothesis: L3 — the flat forms of a note, a bind, a claim, an
    ///   introduction, a presence and a withdrawal are compared byte for byte
    ///   with records written independently, and every kind round-trips.
    /// - witness: `receipt::tests::a_note_encodes_to_its_fixed_layout`
    /// - witness: `receipt::tests::a_bind_encodes_to_its_fixed_layout`
    /// - witness: `receipt::tests::a_claim_and_an_introduction_encode_to_their_fixed_layouts`
    /// - witness: `receipt::tests::a_presence_and_a_withdrawal_encode_to_their_fixed_layouts`
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
        sink.bytes(TokenBytes::from(self.tree.key().as_bytes().as_slice()))?;
        sink.bytes(TokenBytes::from(self.operation.0.as_slice()))?;
        match self.kind {
            | Kind::Open { proof } => {
                sink.open(ConstructorTag::from(OPEN))?;
                sink.bytes(TokenBytes::from(proof.0.to_bytes().as_slice()))?;
            },
            | Kind::Grant { to } => {
                sink.open(ConstructorTag::from(GRANT))?;
                sink.bytes(TokenBytes::from(to.peer_id().as_bytes().as_slice()))?;
            },
            | Kind::Note { ref text } => {
                sink.open(ConstructorTag::from(NOTE))?;
                sink.bytes(TokenBytes::from(text.as_bytes()))?;
            },
            | Kind::Bind {
                ref path,
                ref target,
            } => {
                sink.open(ConstructorTag::from(BIND))?;
                let path: &str = path.as_ref();
                sink.bytes(TokenBytes::from(path.as_bytes()))?;
                target.emit_tokens(sink)?;
            },
            | Kind::Claim { ref domain } => {
                sink.open(ConstructorTag::from(CLAIM))?;
                let domain: &str = domain.as_ref();
                sink.bytes(TokenBytes::from(domain.as_bytes()))?;
            },
            | Kind::Introduce { tree, ref label } => {
                sink.open(ConstructorTag::from(INTRODUCE))?;
                sink.bytes(TokenBytes::from(tree.key().as_bytes().as_slice()))?;
                let label: &str = label.as_ref();
                sink.bytes(TokenBytes::from(label.as_bytes()))?;
            },
            | Kind::Present {
                ref endpoint,
                proof,
            } => {
                sink.open(ConstructorTag::from(PRESENT))?;
                endpoint.emit_tokens(sink)?;
                sink.bytes(TokenBytes::from(proof.0.to_bytes().as_slice()))?;
            },
            | Kind::Withdraw { of } => {
                sink.open(ConstructorTag::from(WITHDRAW))?;
                sink.bytes(TokenBytes::from(of.peer_id().as_bytes().as_slice()))?;
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
    ///   record for another receipt tag, another version, a tree of the wrong
    ///   length or that is not a verifying key, or a fence of the wrong length;
    ///   at the kind's open record for an unknown kind, a proof or grantee of
    ///   the wrong length, text that is not UTF-8, a path that is not UTF-8 or
    ///   has an empty or reserved segment, a domain that is not a DNS name
    ///   [`Domain`] admits, an introduced tree of the wrong length or that is
    ///   not a verifying key, a label that is not UTF-8 or not one [`Label`]
    ///   admits, a presence's proof or a withdrawn peer of the wrong length; as
    ///   [`Target`]'s decoder refuses for a bind's target and [`Endpoint`]'s
    ///   for a presented endpoint; and the reader's own refusals for a record
    ///   of the wrong kind, a truncated stream or an exhausted budget.
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
        let tree = receipt.key(reader)?;
        let operation = <&[u8]>::from(reader.read_bytes()?);
        let operation =
            <[u8; 16]>::try_from(operation).map_err(|_wrong_length| receipt.refused())?;
        let opened = Opened::read(reader)?;
        let kind = match u8::from(opened.tag) {
            | OPEN => {
                let proof = <&[u8]>::from(reader.read_bytes()?);
                let proof =
                    <[u8; 64]>::try_from(proof).map_err(|_wrong_length| opened.refused())?;
                Kind::Open {
                    proof: OpenProof(iroh::Signature::from_bytes(&proof)),
                }
            },
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
            | BIND => {
                let path = opened.path(reader)?;
                let target = Target::decode_tokens(reader)?;
                Kind::Bind { path, target }
            },
            | CLAIM => {
                let domain = opened.domain(reader)?;
                Kind::Claim { domain }
            },
            | INTRODUCE => {
                let tree = opened.key(reader)?;
                let label = opened.label(reader)?;
                Kind::Introduce {
                    tree: TreeId::new(tree),
                    label,
                }
            },
            | PRESENT => {
                let endpoint = Endpoint::decode_tokens(reader)?;
                let proof = <&[u8]>::from(reader.read_bytes()?);
                let proof =
                    <[u8; 64]>::try_from(proof).map_err(|_wrong_length| opened.refused())?;
                Kind::Present {
                    endpoint,
                    proof: EndpointProof(iroh::Signature::from_bytes(&proof)),
                }
            },
            | WITHDRAW => {
                let of = <&[u8]>::from(reader.read_bytes()?);
                let of = <[u8; 32]>::try_from(of).map_err(|_wrong_length| opened.refused())?;
                Kind::Withdraw {
                    of: PeerKey::new(PeerId::new(of)),
                }
            },
            | _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        reader.read_close()?;
        Ok(Self::new(TreeId::new(tree), Operation(operation), kind))
    }
}

impl CanonicalValue for Target
{
    /// Walk the target into `sink` in the module grammar's order.
    ///
    /// # Specification
    /// - ensures: on success `sink` received exactly one balanced value: the
    ///   target's constructor holding the anchor's value, or the endpoint's or
    ///   the datum's one bytes record.
    /// - fails: propagates the sink's refusal unchanged.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a record.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — binds to an anchor, an endpoint and a datum are
    ///   compared byte for byte with records written independently, and a bind
    ///   to every target round-trips.
    /// - witness: `receipt::tests::a_bind_encodes_to_its_fixed_layout`
    /// - witness: `receipt::tests::every_kind_round_trips`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            | Self::Anchor(ref anchor) => {
                sink.open(ConstructorTag::from(ANCHOR))?;
                anchor.emit_tokens(sink)?;
            },
            | Self::Endpoint(endpoint) => {
                sink.open(ConstructorTag::from(ENDPOINT))?;
                sink.bytes(TokenBytes::from(
                    endpoint.endpoint_id().as_bytes().as_slice(),
                ))?;
            },
            | Self::Datum(ref datum) => {
                sink.open(ConstructorTag::from(DATUM))?;
                sink.bytes(TokenBytes::from(datum.as_bytes()))?;
            },
        }
        sink.close()
    }

    /// Read one target from `reader`.
    ///
    /// # Specification
    /// - ensures: on success the target whose emission the records are, and the
    ///   reader stands after the target's close.
    /// - fails: [`ValueError::UnexpectedConstructor`] at the target's open
    ///   record for an unknown target, an endpoint of the wrong length or that
    ///   is not a verifying key, or a datum that is not UTF-8; as [`Anchor`]'s
    ///   decoder refuses for an anchor; and the reader's own refusals
    ///   otherwise.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the receipt decoder, which reads a
    ///   bind's target with it: every target round-trips and each refusal is
    ///   met by a body built record by record.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let target = match u8::from(opened.tag) {
            | ANCHOR => {
                let anchor = Anchor::decode_tokens(reader)?;
                Self::Anchor(anchor)
            },
            | ENDPOINT => {
                let key = opened.key(reader)?;
                Self::Endpoint(EndpointKey::new(key))
            },
            | DATUM => {
                let datum = <&[u8]>::from(reader.read_bytes()?);
                let datum = core::str::from_utf8(datum).map_err(|_not_utf8| opened.refused())?;
                Self::Datum(datum.into())
            },
            | _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(target)
    }
}

impl CanonicalValue for Anchor
{
    /// Walk the anchor into `sink` in the module grammar's order.
    ///
    /// # Specification
    /// - ensures: on success `sink` received exactly one balanced value: the
    ///   anchor's constructor holding its authority's value and, for a path or
    ///   a commit, the path's text or the commit id's 32 bytes.
    /// - fails: propagates the sink's refusal unchanged.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a record.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — binds to a commit, a path and a bare tree anchor are
    ///   compared byte for byte with records written independently, and a bind
    ///   to each anchor form under each authority form round-trips.
    /// - witness: `receipt::tests::a_bind_encodes_to_its_fixed_layout`
    /// - witness: `receipt::tests::every_kind_round_trips`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            | Self::Tree(ref authority) => {
                sink.open(ConstructorTag::from(TREE))?;
                authority.emit_tokens(sink)?;
            },
            | Self::Path {
                ref authority,
                ref path,
            } => {
                sink.open(ConstructorTag::from(PATH))?;
                authority.emit_tokens(sink)?;
                let path: &str = path.as_ref();
                sink.bytes(TokenBytes::from(path.as_bytes()))?;
            },
            | Self::Commit {
                ref authority,
                commit,
            } => {
                sink.open(ConstructorTag::from(COMMIT))?;
                authority.emit_tokens(sink)?;
                sink.bytes(TokenBytes::from(commit.as_bytes().as_slice()))?;
            },
        }
        sink.close()
    }

    /// Read one anchor from `reader`.
    ///
    /// # Specification
    /// - ensures: on success the anchor whose emission the records are, and the
    ///   reader stands after the anchor's close.
    /// - fails: [`ValueError::UnexpectedConstructor`] at the anchor's open
    ///   record for an unknown anchor, a path that is not UTF-8 or has an empty
    ///   or reserved segment, or a commit id of any length but 32 bytes, an
    ///   abbreviated one among them; as [`Authority`]'s decoder refuses for the
    ///   authority; and the reader's own refusals otherwise.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the receipt decoder, which reads a
    ///   bind's anchor target with it: every anchor form round-trips under
    ///   every authority, and an unknown anchor, an abbreviated, a short and a
    ///   long commit id, a reserved and an empty path segment, and a tree
    ///   anchor carrying a payload each meet their own refusal.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let anchor = match u8::from(opened.tag) {
            | TREE => {
                let authority = Authority::decode_tokens(reader)?;
                Self::Tree(authority)
            },
            | PATH => {
                let authority = Authority::decode_tokens(reader)?;
                let path = opened.path(reader)?;
                Self::Path { authority, path }
            },
            | COMMIT => {
                let authority = Authority::decode_tokens(reader)?;
                let commit = opened.commit(reader)?;
                Self::Commit { authority, commit }
            },
            | _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(anchor)
    }
}

impl CanonicalValue for Authority
{
    /// Walk the authority into `sink` in the module grammar's order.
    ///
    /// # Specification
    /// - ensures: on success `sink` received exactly one balanced value: the
    ///   authority's constructor holding its one bytes record, the tree key's
    ///   32 bytes or the DNS name's or the label's text.
    /// - fails: propagates the sink's refusal unchanged.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a record.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — anchors under a key, a DNS name and a label are
    ///   compared byte for byte with records written independently, and every
    ///   anchor form under each authority round-trips.
    /// - witness: `receipt::tests::a_bind_encodes_to_its_fixed_layout`
    /// - witness: `receipt::tests::every_kind_round_trips`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            | Self::Key(tree) => {
                sink.open(ConstructorTag::from(KEY))?;
                sink.bytes(TokenBytes::from(tree.key().as_bytes().as_slice()))?;
            },
            | Self::Domain(ref domain) => {
                sink.open(ConstructorTag::from(DOMAIN))?;
                let domain: &str = domain.as_ref();
                sink.bytes(TokenBytes::from(domain.as_bytes()))?;
            },
            | Self::Label(ref label) => {
                sink.open(ConstructorTag::from(LABEL))?;
                let label: &str = label.as_ref();
                sink.bytes(TokenBytes::from(label.as_bytes()))?;
            },
        }
        sink.close()
    }

    /// Read one authority from `reader`.
    ///
    /// # Specification
    /// - ensures: on success the authority whose emission the records are, and
    ///   the reader stands after the authority's close.
    /// - fails: [`ValueError::UnexpectedConstructor`] at the authority's open
    ///   record for an unknown authority, a key of the wrong length or that is
    ///   not a verifying key, a DNS name [`Domain`] does not admit, or a label
    ///   [`Label`] does not admit; and the reader's own refusals otherwise.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the receipt decoder: each authority
    ///   form round-trips, and an unknown authority, a short key, a key that is
    ///   not a verifying key, an undotted DNS name, and a label spelled as a
    ///   tree id, holding a dot or empty each meet their own refusal.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let authority = match u8::from(opened.tag) {
            | KEY => {
                let key = opened.key(reader)?;
                Self::Key(TreeId::new(key))
            },
            | DOMAIN => {
                let domain = opened.domain(reader)?;
                Self::Domain(domain)
            },
            | LABEL => {
                let label = opened.label(reader)?;
                Self::Label(label)
            },
            | _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(authority)
    }
}

impl CanonicalValue for Endpoint
{
    /// Walk the presented endpoint into `sink` in the module grammar's order.
    ///
    /// # Specification
    /// - ensures: on success `sink` received exactly one balanced value: the
    ///   endpoint's constructor holding its id's 32 bytes, the count of its
    ///   addresses, and each address's value in order.
    /// - fails: propagates the sink's refusal unchanged, and the value plane's
    ///   overflow refusal for more addresses than a word counts.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a record.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a presence of an endpoint at an IPv4, an IPv6 and a
    ///   relay address is compared byte for byte with records written
    ///   independently, and presences with no address and with every address
    ///   form round-trip.
    /// - witness: `receipt::tests::a_presence_and_a_withdrawal_encode_to_their_fixed_layouts`
    /// - witness: `receipt::tests::every_kind_round_trips`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        sink.open(ConstructorTag::from(REACHED))?;
        sink.bytes(TokenBytes::from(
            self.key().endpoint_id().as_bytes().as_slice(),
        ))?;
        let count = u64::try_from(self.addresses().len()).map_err(|_too_many| {
            ValueError::ArithmeticOverflow {
                quantity: ValueQuantity::TokenCount,
            }
        })?;
        sink.word(CanonicalWord::from(count))?;
        for address in self.addresses() {
            address.emit_tokens(sink)?;
        }
        sink.close()
    }

    /// Read one presented endpoint from `reader`.
    ///
    /// # Specification
    /// - ensures: on success the endpoint whose emission the records are, and
    ///   the reader stands after the endpoint's close.
    /// - fails: [`ValueError::UnexpectedConstructor`] at the endpoint's open
    ///   record for another tag, an id of the wrong length or that is not a
    ///   verifying key, or an address not after the one before it in order —
    ///   out of order or repeated; as [`Address`]'s decoder refuses for an
    ///   address; and the reader's own refusals for fewer addresses than the
    ///   count, more, or any other record.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the receipt decoder: presences with
    ///   no address and with every address form round-trip, and an unknown
    ///   endpoint tag, an id that is not a key, two addresses out of order, a
    ///   repeated address, a count above and one below the addresses given each
    ///   meet their own refusal.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        if u8::from(opened.tag) != REACHED {
            return Err(opened.refused());
        }
        let key = opened.key(reader)?;
        let count = u64::from(reader.read_word()?);
        let mut addresses = BTreeSet::new();
        for _place in 0 .. count {
            let address = Address::decode_tokens(reader)?;
            if addresses.last().is_some_and(|last| *last >= address) {
                return Err(opened.refused());
            }
            let _was_held = addresses.insert(address);
        }
        reader.read_close()?;
        Ok(Self::from_parts(EndpointKey::new(key), addresses))
    }
}

impl CanonicalValue for Address
{
    /// Walk the address into `sink` in the module grammar's order.
    ///
    /// # Specification
    /// - ensures: on success `sink` received exactly one balanced value: a
    ///   direct address's constructor holding the IP address's 4 or 16 bytes
    ///   and the port's word, or a relay's holding the URL's text.
    /// - fails: propagates the sink's refusal unchanged.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a record.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an IPv4, an IPv6 and a relay address are compared
    ///   byte for byte with records written independently.
    /// - witness: `receipt::tests::a_presence_and_a_withdrawal_encode_to_their_fixed_layouts`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            | Self::Direct(direct) => {
                sink.open(ConstructorTag::from(DIRECT))?;
                match direct.ip() {
                    | IpAddr::V4(ip) => sink.bytes(TokenBytes::from(ip.octets().as_slice()))?,
                    | IpAddr::V6(ip) => sink.bytes(TokenBytes::from(ip.octets().as_slice()))?,
                }
                sink.word(CanonicalWord::from(u64::from(direct.port())))?;
            },
            | Self::Relay(ref url) => {
                sink.open(ConstructorTag::from(RELAY))?;
                sink.bytes(TokenBytes::from(url.as_str().as_bytes()))?;
            },
        }
        sink.close()
    }

    /// Read one address from `reader`.
    ///
    /// # Specification
    /// - ensures: on success the address whose emission the records are, and
    ///   the reader stands after the address's close.
    /// - fails: [`ValueError::UnexpectedConstructor`] at the address's open
    ///   record for an unknown address, an IP address of any length but 4 or 16
    ///   bytes, a port beyond 65535, or a relay that is not UTF-8, not a URL
    ///   written as it parses back, or one [`Address::relay`] refuses; and the
    ///   reader's own refusals otherwise.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the receipt decoder: every address
    ///   form round-trips, and an unknown address, a 5-byte IP address, port
    ///   65536, and a relay that is not UTF-8, not canonical, of the `ftp`
    ///   scheme or holding `@` each meet their own refusal.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let address = match u8::from(opened.tag) {
            | DIRECT => {
                let ip = <&[u8]>::from(reader.read_bytes()?);
                let ip = if let Ok(v4) = <[u8; 4]>::try_from(ip) {
                    IpAddr::V4(Ipv4Addr::from(v4))
                }
                else {
                    let v6 = <[u8; 16]>::try_from(ip).map_err(|_wrong_length| opened.refused())?;
                    IpAddr::V6(Ipv6Addr::from(v6))
                };
                let port = u64::from(reader.read_word()?);
                let port = u16::try_from(port).map_err(|_beyond_a_port| opened.refused())?;
                Self::Direct(SocketAddr::new(ip, port))
            },
            | RELAY => {
                let text = <&[u8]>::from(reader.read_bytes()?);
                let text = core::str::from_utf8(text).map_err(|_not_utf8| opened.refused())?;
                let url = text
                    .parse::<iroh::RelayUrl>()
                    .map_err(|_not_a_url| opened.refused())?;
                if url.as_str() != text {
                    return Err(opened.refused());
                }
                Self::relay(url).map_err(|_not_a_relay| opened.refused())?
            },
            | _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(address)
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

    /// Read the next record as the 32 bytes of an ed25519 verifying key in
    /// this constructor.
    ///
    /// # Specification
    /// - ensures: on success the key the bytes record spells.
    /// - fails: this constructor's refusal ([`Opened::refused`]) for bytes of
    ///   another length or that are not a verifying key, and the reader's
    ///   refusals for any other record or none.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    fn key(
        self,
        reader: &mut TokenReader<'_>,
    ) -> Result<iroh::PublicKey, ValueError>
    {
        let key = <&[u8]>::from(reader.read_bytes()?);
        let key = <[u8; 32]>::try_from(key).map_err(|_wrong_length| self.refused())?;
        iroh::PublicKey::from_bytes(&key).map_err(|_not_a_key| self.refused())
    }

    /// Read the next record as a commit id in this constructor: its whole 32
    /// bytes.
    ///
    /// # Specification
    /// - ensures: on success the commit id the bytes record spells.
    /// - fails: this constructor's refusal ([`Opened::refused`]) for bytes of
    ///   another length, an abbreviated id among them, and the reader's
    ///   refusals for any other record or none.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    fn commit(
        self,
        reader: &mut TokenReader<'_>,
    ) -> Result<CommitId, ValueError>
    {
        let commit = <&[u8]>::from(reader.read_bytes()?);
        let commit = <[u8; 32]>::try_from(commit).map_err(|_wrong_length| self.refused())?;
        Ok(CommitId::new(commit))
    }

    /// Read the next record as a path in this constructor.
    ///
    /// # Specification
    /// - ensures: on success the path the bytes record spells.
    /// - fails: this constructor's refusal ([`Opened::refused`]) for bytes that
    ///   are not UTF-8 or not a path [`Path`] admits — one with an empty or a
    ///   reserved segment — and the reader's refusals for any other record or
    ///   none.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    fn path(
        self,
        reader: &mut TokenReader<'_>,
    ) -> Result<Path, ValueError>
    {
        let path = <&[u8]>::from(reader.read_bytes()?);
        let path = core::str::from_utf8(path).map_err(|_not_utf8| self.refused())?;
        path.parse::<Path>().map_err(|_not_a_path| self.refused())
    }

    /// Read the next record as a DNS name in this constructor.
    ///
    /// # Specification
    /// - ensures: on success the DNS name the bytes record spells.
    /// - fails: this constructor's refusal ([`Opened::refused`]) for bytes that
    ///   are not UTF-8 or not a DNS name [`Domain`] admits, and the reader's
    ///   refusals for any other record or none.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    fn domain(
        self,
        reader: &mut TokenReader<'_>,
    ) -> Result<Domain, ValueError>
    {
        let domain = <&[u8]>::from(reader.read_bytes()?);
        let domain = core::str::from_utf8(domain).map_err(|_not_ascii| self.refused())?;
        domain
            .parse::<Domain>()
            .map_err(|_not_a_domain| self.refused())
    }

    /// Read the next record as a label in this constructor.
    ///
    /// # Specification
    /// - ensures: on success the label the bytes record spells.
    /// - fails: this constructor's refusal ([`Opened::refused`]) for bytes that
    ///   are not UTF-8 or not a label [`Label`] admits, and the reader's
    ///   refusals for any other record or none.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    fn label(
        self,
        reader: &mut TokenReader<'_>,
    ) -> Result<Label, ValueError>
    {
        let label = <&[u8]>::from(reader.read_bytes()?);
        let label = core::str::from_utf8(label).map_err(|_not_utf8| self.refused())?;
        label
            .parse::<Label>()
            .map_err(|_not_a_label| self.refused())
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
    use core::net::Ipv4Addr;
    use core::net::Ipv6Addr;
    use core::net::SocketAddr;

    use gandr_storage_values::ConstructorTag;
    use gandr_storage_values::TokenKind;
    use gandr_storage_values::TokenOffset;
    use gandr_storage_values::ValueError;
    use sedimentree_core::blob::Blob;
    use sedimentree_core::loose_commit::id::CommitId;

    use super::EndpointProof;
    use super::Kind;
    use super::Operation;
    use super::Receipt;
    use crate::anchor::Anchor;
    use crate::anchor::Authority;
    use crate::anchor::Target;
    use crate::id::Endpoint;
    use crate::id::EndpointKey;
    use crate::id::PeerKey;
    use crate::id::TreeId;
    use crate::testing::elsewhere_key;
    use crate::testing::tree_key;

    /// A peer key a grant names.
    const PEER: &str = "7065657270656572706565727065657270656572706565727065657270656572";

    /// The z-base-32 spelling of the all-zero key, which no label may be.
    const ZERO: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    /// The tree the receipts name.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        tree_key().tree()
    }

    /// One receipt of every kind, and a bind to every target.
    ///
    /// # Specification
    /// trivial.
    fn every_kind() -> Vec<Receipt>
    {
        let peer = PEER.parse::<PeerKey>().unwrap();
        let endpoint = EndpointKey::new(iroh::SecretKey::from_bytes(&[7; 32]).public());
        let mut targets = vec![
            Target::Endpoint(endpoint),
            Target::Datum(String::from("vault/page.md at 3f2a, ünïcode")),
        ];
        for authority in [
            Authority::Key(elsewhere_key().tree()),
            Authority::Domain("gandr-lang.example.org".parse().unwrap()),
            Authority::Label("my friend, größer".parse().unwrap()),
        ] {
            targets.push(Target::Anchor(Anchor::Tree(authority.clone())));
            targets.push(Target::Anchor(Anchor::Path {
                authority: authority.clone(),
                path: "concept/größe".parse().unwrap(),
            }));
            targets.push(Target::Anchor(Anchor::Commit {
                authority,
                commit: CommitId::new([9; 32]),
            }));
        }
        let mut receipts = vec![
            Receipt::open(&tree_key(), peer).unwrap(),
            Receipt::grant(tree(), peer).unwrap(),
            Receipt::note(tree(), String::from("a note, with ünïcode")).unwrap(),
            Receipt::claim(tree(), "gandr-lang.example.org".parse().unwrap()).unwrap(),
            Receipt::introduce(
                tree(),
                "my friend, größer".parse().unwrap(),
                elsewhere_key().tree(),
            )
            .unwrap(),
            Receipt::withdraw(tree(), peer).unwrap(),
        ];
        let secret = iroh::SecretKey::from_bytes(&[7; 32]);
        let proof = EndpointProof::sign(&secret, peer);
        for presented in [
            Endpoint::new(endpoint),
            Endpoint::new(endpoint)
                .with_direct(SocketAddr::from((Ipv4Addr::LOCALHOST, 5)))
                .with_direct(SocketAddr::from((Ipv6Addr::LOCALHOST, 9))),
            format!("{endpoint}@https://relay.example.org@[2001:db8::1]:65535")
                .parse()
                .unwrap(),
        ] {
            receipts.push(Receipt::present(tree(), presented, proof).unwrap());
        }
        for target in targets {
            let path = "concept/sub concept/größe".parse().unwrap();
            receipts.push(Receipt::bind(tree(), path, target).unwrap());
        }
        receipts
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
        expected.extend_from_slice(&[0x02, 2, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(&[0x03, 32, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(tree().key().as_bytes());
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
    fn a_bind_encodes_to_its_fixed_layout()
    {
        let bytes = |payload: &[u8]| {
            let length = u64::try_from(payload.len()).unwrap().to_le_bytes();
            [&[0x03_u8][..], &length, payload].concat()
        };
        let elsewhere = elsewhere_key().tree();
        let endpoint = EndpointKey::new(iroh::SecretKey::from_bytes(&[7; 32]).public());
        let layouts = [
            (
                Target::Anchor(Anchor::commit(elsewhere, CommitId::new([0x09; 32]))),
                [
                    vec![0x01, 0x01, 0x01, 0x03, 0x01, 0x01],
                    bytes(elsewhere.key().as_bytes()),
                    vec![0x05],
                    bytes(&[0x09; 32]),
                    vec![0x05, 0x05],
                ]
                .concat(),
                "open anchor, open commit, open key, tree, close, commit, two closes",
            ),
            (
                Target::Anchor(Anchor::Path {
                    authority: Authority::Domain("a.bc".parse().unwrap()),
                    path: "x".parse().unwrap(),
                }),
                [
                    vec![0x01, 0x01, 0x01, 0x02, 0x01, 0x02],
                    bytes(b"a.bc"),
                    vec![0x05],
                    bytes(b"x"),
                    vec![0x05, 0x05],
                ]
                .concat(),
                "open anchor, open path, open domain, domain, close, path, two closes",
            ),
            (
                Target::Anchor(Anchor::Tree(Authority::Label("b".parse().unwrap()))),
                [vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x03], bytes(b"b"), vec![
                    0x05, 0x05, 0x05,
                ]]
                .concat(),
                "open anchor, open tree, open label, label, three closes",
            ),
            (
                Target::Endpoint(endpoint),
                [
                    vec![0x01, 0x02],
                    bytes(endpoint.endpoint_id().as_bytes()),
                    vec![0x05],
                ]
                .concat(),
                "open endpoint, endpoint, close",
            ),
            (
                Target::Datum(String::from("d")),
                [vec![0x01, 0x03], bytes(b"d"), vec![0x05]].concat(),
                "open datum, datum, close",
            ),
        ];
        for (target, records, layout) in layouts {
            let receipt = Receipt::new(tree(), Operation([0x0f; 16]), Kind::Bind {
                path: "a/b".parse().unwrap(),
                target,
            });
            let mut expected = vec![0x01_u8, 0x01];
            expected.extend_from_slice(&[0x02, 2, 0, 0, 0, 0, 0, 0, 0]);
            expected.extend(bytes(tree().key().as_bytes()));
            expected.extend(bytes(&[0x0f; 16]));
            expected.extend_from_slice(&[0x01, 0x04]);
            expected.extend(bytes(b"a/b"));
            expected.extend(records);
            expected.extend_from_slice(&[0x05, 0x05]);
            assert_eq!(
                receipt.encode().unwrap().as_slice(),
                expected.as_slice(),
                "open receipt, version word, tree, fence, open bind, path, {layout}, two closes"
            );
        }
    }

    #[test]
    fn a_claim_and_an_introduction_encode_to_their_fixed_layouts()
    {
        let header = || {
            let mut header = vec![0x01_u8, 0x01];
            header.extend_from_slice(&[0x02, 2, 0, 0, 0, 0, 0, 0, 0]);
            header.extend_from_slice(&[0x03, 32, 0, 0, 0, 0, 0, 0, 0]);
            header.extend_from_slice(tree().key().as_bytes());
            header.extend_from_slice(&[0x03, 16, 0, 0, 0, 0, 0, 0, 0]);
            header.extend_from_slice(&[0x0f; 16]);
            header
        };
        let claim = Receipt::new(tree(), Operation([0x0f; 16]), Kind::Claim {
            domain: "a.bc".parse().unwrap(),
        });
        let mut expected = header();
        expected.extend_from_slice(&[0x01, 0x05]);
        expected.extend_from_slice(&[0x03, 4, 0, 0, 0, 0, 0, 0, 0, b'a', b'.', b'b', b'c']);
        expected.extend_from_slice(&[0x05, 0x05]);
        assert_eq!(
            claim.encode().unwrap().as_slice(),
            expected.as_slice(),
            "open receipt, version word, tree, fence, open claim, domain, two closes"
        );
        let introduced = elsewhere_key().tree();
        let introduction = Receipt::new(tree(), Operation([0x0f; 16]), Kind::Introduce {
            tree: introduced,
            label: "b".parse().unwrap(),
        });
        let mut expected = header();
        expected.extend_from_slice(&[0x01, 0x06]);
        expected.extend_from_slice(&[0x03, 32, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(introduced.key().as_bytes());
        expected.extend_from_slice(&[0x03, 1, 0, 0, 0, 0, 0, 0, 0, b'b']);
        expected.extend_from_slice(&[0x05, 0x05]);
        assert_eq!(
            introduction.encode().unwrap().as_slice(),
            expected.as_slice(),
            "open receipt, version word, tree, fence, open introduce, tree, label, two closes"
        );
    }

    #[test]
    fn a_presence_and_a_withdrawal_encode_to_their_fixed_layouts()
    {
        let bytes = |payload: &[u8]| {
            let length = u64::try_from(payload.len()).unwrap().to_le_bytes();
            [&[0x03_u8][..], &length, payload].concat()
        };
        let word = |value: u64| [&[0x02_u8][..], &value.to_le_bytes()].concat();
        let header = || {
            let mut header = vec![0x01_u8, 0x01];
            header.extend(word(2));
            header.extend(bytes(tree().key().as_bytes()));
            header.extend(bytes(&[0x0f; 16]));
            header
        };
        let key = EndpointKey::new(iroh::SecretKey::from_bytes(&[7; 32]).public());
        let endpoint = format!("{key}@https://relay.example.org/@[::1]:9@127.0.0.1:5")
            .parse::<Endpoint>()
            .unwrap();
        let presence = Receipt::new(tree(), Operation([0x0f; 16]), Kind::Present {
            endpoint,
            proof: EndpointProof(iroh::Signature::from_bytes(&[0x70; 64])),
        });
        let expected = [
            header(),
            vec![0x01, 0x07, 0x01, 0x01],
            bytes(key.endpoint_id().as_bytes()),
            word(3),
            vec![0x01, 0x01],
            bytes(&[127, 0, 0, 1]),
            word(5),
            vec![0x05, 0x01, 0x01],
            bytes(&Ipv6Addr::LOCALHOST.octets()),
            word(9),
            vec![0x05, 0x01, 0x02],
            bytes(b"https://relay.example.org/"),
            vec![0x05, 0x05],
            bytes(&[0x70; 64]),
            vec![0x05, 0x05],
        ]
        .concat();
        assert_eq!(
            presence.encode().unwrap().as_slice(),
            expected.as_slice(),
            "open receipt, version word, tree, fence, open present, open endpoint, id, count, \
             the IPv4, the IPv6 and the relay address each opened and closed in order, close, \
             proof, two closes"
        );
        let peer = PEER.parse::<PeerKey>().unwrap();
        let withdrawal = Receipt::new(tree(), Operation([0x0f; 16]), Kind::Withdraw { of: peer });
        let expected = [
            header(),
            vec![0x01, 0x08],
            bytes(peer.peer_id().as_bytes()),
            vec![0x05, 0x05],
        ]
        .concat();
        assert_eq!(
            withdrawal.encode().unwrap().as_slice(),
            expected.as_slice(),
            "open receipt, version word, tree, fence, open withdraw, peer, two closes"
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
        let tree = *tree().key().as_bytes();
        let not_a_key = (0_u8 ..= 255)
            .map(|byte| [byte; 32])
            .find(|bytes| iroh::PublicKey::from_bytes(bytes).is_err())
            .unwrap();
        let fence = [0x0f_u8; 16];
        let at = TokenOffset::from;
        let constructor = |tag: u8, record: u32| ValueError::UnexpectedConstructor {
            found: ConstructorTag::from(tag),
            position: at(record),
        };
        let note = |text: &[u8]| {
            vec![
                open(1),
                word(2),
                bytes(&tree),
                bytes(&fence),
                open(3),
                bytes(text),
                close(),
                close(),
            ]
        };
        let bind = |path: &[u8], target: Vec<Vec<u8>>| {
            let mut records = vec![
                open(1),
                word(2),
                bytes(&tree),
                bytes(&fence),
                open(4),
                bytes(path),
            ];
            records.extend(target);
            records.extend([close(), close()]);
            records
        };
        let target = |tag: u8, payload: &[u8]| vec![open(tag), bytes(payload), close()];
        let anchor = |form: u8, authority: u8, named: &[u8], carried: Vec<Vec<u8>>| {
            let mut records = vec![open(1), open(form), open(authority), bytes(named), close()];
            records.extend(carried);
            records.extend([close(), close()]);
            records
        };
        let commit = |id: &[u8]| anchor(3, 1, &tree, vec![bytes(id)]);
        let claim = |domain: &[u8]| {
            vec![
                open(1),
                word(2),
                bytes(&tree),
                bytes(&fence),
                open(5),
                bytes(domain),
                close(),
                close(),
            ]
        };
        let introduce = |introduced: &[u8], label: &[u8]| {
            vec![
                open(1),
                word(2),
                bytes(&tree),
                bytes(&fence),
                open(6),
                bytes(introduced),
                bytes(label),
                close(),
                close(),
            ]
        };

        assert!(
            refused(&note(b"hi")).is_ok(),
            "the well-formed note decodes"
        );
        assert!(
            refused(&bind(b"a/b", commit(&[9; 32]))).is_ok(),
            "the well-formed bind to a commit decodes"
        );
        assert!(
            refused(&bind(
                b"a/b",
                anchor(2, 2, b"example.test", vec![bytes(b"x")])
            ))
            .is_ok(),
            "the well-formed bind to a path under a DNS name decodes"
        );
        assert!(
            refused(&bind(b"a/b", anchor(1, 3, b"b", vec![]))).is_ok(),
            "the well-formed bind to a tree by its label decodes"
        );
        assert!(
            refused(&claim(b"example.test")).is_ok(),
            "the well-formed claim decodes"
        );
        assert!(
            refused(&introduce(&tree, b"b")).is_ok(),
            "the well-formed introduction decodes"
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
        receipt[1] = word(1);
        assert_eq!(
            refused(&receipt),
            Err(constructor(1, 0)),
            "the previous version"
        );
        let mut receipt = note(b"hi");
        receipt[2] = bytes(&tree[.. 31]);
        assert_eq!(refused(&receipt), Err(constructor(1, 0)), "a short tree id");
        let mut receipt = note(b"hi");
        receipt[2] = bytes(&not_a_key);
        assert_eq!(
            refused(&receipt),
            Err(constructor(1, 0)),
            "a tree id that is not a verifying key"
        );
        let mut receipt = note(b"hi");
        receipt[3] = bytes(&[0x0f; 17]);
        assert_eq!(refused(&receipt), Err(constructor(1, 0)), "a long fence");
        let mut receipt = note(b"hi");
        receipt[4] = open(9);
        assert_eq!(refused(&receipt), Err(constructor(9, 4)), "an unknown kind");
        let mut receipt = note(b"hi");
        receipt[4] = open(1);
        receipt[5] = bytes(&[0x70; 63]);
        assert_eq!(refused(&receipt), Err(constructor(1, 4)), "a short proof");
        let mut receipt = note(b"hi");
        receipt[4] = open(2);
        receipt[5] = bytes(&[0x70; 31]);
        assert_eq!(refused(&receipt), Err(constructor(2, 4)), "a short grantee");
        assert_eq!(
            refused(&note(&[0x68, 0xff])),
            Err(constructor(3, 4)),
            "text that is not UTF-8"
        );
        for path in [
            &b""[..],
            b"/a",
            b"a/",
            b"a//b",
            b"/",
            &[0x61, 0xff],
            b".a",
            b"a/.b",
            b".",
            b"..",
        ] {
            assert_eq!(
                refused(&bind(path, commit(&[9; 32]))),
                Err(constructor(4, 4)),
                "the path {path:?} is empty, has an empty or a reserved segment, or is not UTF-8"
            );
        }
        assert_eq!(
            refused(&bind(b"a", target(4, &[9; 32]))),
            Err(constructor(4, 6)),
            "an unknown target"
        );
        for endpoint in [&[9_u8; 31][..], &not_a_key] {
            assert_eq!(
                refused(&bind(b"a", target(2, endpoint))),
                Err(constructor(2, 6)),
                "an endpoint that is short or not a verifying key"
            );
        }
        assert_eq!(
            refused(&bind(b"a", target(3, &[0x68, 0xff]))),
            Err(constructor(3, 6)),
            "a datum that is not UTF-8"
        );
        assert_eq!(
            refused(&bind(b"a", anchor(4, 1, &tree, vec![]))),
            Err(constructor(4, 7)),
            "an unknown anchor"
        );
        for id in [&[9_u8; 4][..], &[9_u8; 31], &[9_u8; 33]] {
            assert_eq!(
                refused(&bind(b"a", commit(id))),
                Err(constructor(3, 7)),
                "the commit id {id:?} is abbreviated to eight hex digits, short or long"
            );
        }
        for path in [&b""[..], b".x", b"x/.commit", b"x//y", &[0xff]] {
            assert_eq!(
                refused(&bind(b"a", anchor(2, 1, &tree, vec![bytes(path)]))),
                Err(constructor(2, 7)),
                "the anchor's path {path:?} is empty, has an empty or a reserved segment, or is \
                 not UTF-8"
            );
        }
        assert_eq!(
            refused(&bind(b"a", anchor(1, 4, &tree, vec![]))),
            Err(constructor(4, 8)),
            "an unknown authority"
        );
        for key in [&tree[.. 31], &not_a_key] {
            assert_eq!(
                refused(&bind(b"a", anchor(1, 1, key, vec![]))),
                Err(constructor(1, 8)),
                "a key authority that is short or not a verifying key"
            );
        }
        assert_eq!(
            refused(&bind(b"a", anchor(1, 2, b"nodot", vec![]))),
            Err(constructor(2, 8)),
            "a DNS authority that is no DNS name"
        );
        for label in [&b""[..], b"a.b", ZERO.as_bytes()] {
            assert_eq!(
                refused(&bind(b"a", anchor(1, 3, label, vec![]))),
                Err(constructor(3, 8)),
                "the label authority {label:?} is empty, holds a dot, or is a tree id"
            );
        }
        assert_eq!(
            refused(&bind(b"a", anchor(1, 1, &tree, vec![bytes(b"x")]))),
            Err(ValueError::UnexpectedToken {
                expected: TokenKind::Close,
                found: TokenKind::Bytes,
                position: at(11),
            }),
            "a payload a tree anchor does not carry"
        );
        for domain in [
            &b"Example.test"[..],
            b"localhost",
            b"",
            b"example..test",
            b"example.test.",
            b"exa_mple.test",
            &[0x61, 0x2e, 0xff],
        ] {
            assert_eq!(
                refused(&claim(domain)),
                Err(constructor(5, 4)),
                "the domain {domain:?} is uppercase, undotted, empty, malformed or not ASCII"
            );
        }
        for label in [&b""[..], b"a/b", b"a.b", &[0x61, 0xff], ZERO.as_bytes()] {
            assert_eq!(
                refused(&introduce(&tree, label)),
                Err(constructor(6, 4)),
                "the label {label:?} is empty, holds a slash or a dot, is not UTF-8, or is a tree \
                 id"
            );
        }
        for introduced in [&tree[.. 31], &not_a_key] {
            assert_eq!(
                refused(&introduce(introduced, b"b")),
                Err(constructor(6, 4)),
                "an introduced tree that is short or not a verifying key"
            );
        }
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
        let endpoint = *iroh::SecretKey::from_bytes(&[7; 32]).public().as_bytes();
        let reached = |id: &[u8], count: u64, addresses: Vec<Vec<u8>>| {
            let mut records = vec![open(1), bytes(id), word(count)];
            records.extend(addresses);
            records.push(close());
            records
        };
        let present = |presented: Vec<Vec<u8>>, proof: &[u8]| {
            let mut records = vec![open(1), word(2), bytes(&tree), bytes(&fence), open(7)];
            records.extend(presented);
            records.extend([bytes(proof), close(), close()]);
            records
        };
        let direct = |ip: &[u8], port: u64| vec![open(1), bytes(ip), word(port), close()];
        let relay = |url: &[u8]| vec![open(2), bytes(url), close()];
        let at_one = |address: Vec<Vec<u8>>| present(reached(&endpoint, 1, address), &[0x70; 64]);
        assert!(
            refused(&present(
                reached(
                    &endpoint,
                    2,
                    [direct(&[127, 0, 0, 1], 5), relay(b"https://a.example/")].concat()
                ),
                &[0x70; 64]
            ))
            .is_ok(),
            "the well-formed presence decodes"
        );
        assert_eq!(
            refused(&present(
                [vec![open(2)], reached(&endpoint, 0, vec![]).split_off(1)].concat(),
                &[0x70; 64]
            )),
            Err(constructor(2, 5)),
            "an unknown endpoint"
        );
        for id in [&endpoint[.. 31], &not_a_key] {
            assert_eq!(
                refused(&present(reached(id, 0, vec![]), &[0x70; 64])),
                Err(constructor(1, 5)),
                "a presented endpoint that is short or not a verifying key"
            );
        }
        assert_eq!(
            refused(&present(reached(&endpoint, 0, vec![]), &[0x70; 63])),
            Err(constructor(7, 4)),
            "a short endpoint proof"
        );
        assert_eq!(
            refused(&at_one(vec![open(3), bytes(b"x"), close()])),
            Err(constructor(3, 8)),
            "an unknown address"
        );
        // One past the largest port, 65535.
        let beyond = 0x0001_0000_u64;
        for (ip, port) in [(&[127_u8, 0, 0, 1, 0][..], 5), (&[127, 0, 0, 1], beyond)] {
            assert_eq!(
                refused(&at_one(direct(ip, port))),
                Err(constructor(1, 8)),
                "the IP address {ip:?} is of another length or the port {port} beyond a port"
            );
        }
        for url in [
            &[0x68, 0xff][..],
            b"https://a.example",
            b"ftp://a.example/",
            b"https://user@a.example/",
            b"nowhere",
        ] {
            assert_eq!(
                refused(&at_one(relay(url))),
                Err(constructor(2, 8)),
                "the relay {url:?} is not UTF-8, not canonical, of another scheme, holds @ or is \
                 no URL"
            );
        }
        let first = direct(&[127, 0, 0, 1], 5);
        for (addresses, case) in [
            (
                [relay(b"https://a.example/"), first.clone()].concat(),
                "out of order",
            ),
            ([first.clone(), first.clone()].concat(), "repeated"),
        ] {
            assert_eq!(
                refused(&present(reached(&endpoint, 2, addresses), &[0x70; 64])),
                Err(constructor(1, 5)),
                "addresses {case}"
            );
        }
        assert!(
            matches!(
                refused(&present(reached(&endpoint, 2, first.clone()), &[0x70; 64])),
                Err(ValueError::UnexpectedToken {
                    found: TokenKind::Close,
                    position,
                    ..
                }) if position == at(12)
            ),
            "a count above the addresses given"
        );
        assert_eq!(
            refused(&present(reached(&endpoint, 0, first), &[0x70; 64])),
            Err(ValueError::UnexpectedToken {
                expected: TokenKind::Close,
                found: TokenKind::Open,
                position: at(8),
            }),
            "a count below the addresses given"
        );
        assert_eq!(
            refused(&[
                open(1),
                word(2),
                bytes(&tree),
                bytes(&fence),
                open(8),
                bytes(&[0x70; 31]),
                close(),
                close(),
            ]),
            Err(constructor(8, 4)),
            "a short withdrawn peer"
        );
    }
}
