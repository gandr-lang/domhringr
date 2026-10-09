//! The identifiers a tree is named by, a commit is located by and a peer is
//! addressed by: a tree id in the z-base-32 form an anchor's authority
//! carries, a commit id in the lowercase hex an anchor's commit form carries,
//! whole or abbreviated by hand to a prefix, the peer and endpoint keys in the
//! hex form the peer binary reads and prints, and an endpoint with the
//! addresses it is reached at.

use alloc::collections::BTreeSet;
use alloc::string::String;
use core::fmt;
use core::net::SocketAddr;
use core::net::SocketAddrV6;
use core::ops::RangeInclusive;
use core::str::FromStr;

use sedimentree_core::id::SedimentreeId;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::peer::id::PeerId;

/// Hex digits in the text form of a 32-byte id.
const HEX_DIGITS: usize = 64;

/// Hex digits in the shortest prefix a commit id is abbreviated to.
const COMMIT_PREFIX_DIGITS: usize = 8;

/// Characters in the text form of a tree id.
pub const TREE_CHARACTERS: usize = 52;

/// The z-base-32 alphabet: the symbols iroh writes a key in for a DNS label,
/// in value order.
const Z_BASE_32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// A tree's id: the ed25519 verifying key of the key that opened it, whose
/// 32 bytes are also the sedimentree's id. Written as 52 z-base-32
/// characters, the form iroh writes an endpoint id in a DNS label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TreeId(iroh::PublicKey);

impl TreeId
{
    /// The tree id `key` is the verifying key of.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn new(key: iroh::PublicKey) -> Self
    {
        Self(key)
    }

    /// The verifying key a proof for the tree is checked under.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn key(self) -> iroh::PublicKey
    {
        self.0
    }

    /// The sedimentree id subduction knows the tree by: the key's bytes.
    ///
    /// # Specification
    /// trivial.
    pub(crate) fn sedimentree(self) -> SedimentreeId
    {
        SedimentreeId::new(*self.0.as_bytes())
    }
}

impl FromStr for TreeId
{
    type Err = ParseIdError;

    /// Read a tree id from its z-base-32 text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the 52-character z-base-32 texts that spell
    ///   an ed25519 verifying key canonically (the last character's four unused
    ///   bits zero), and yields the tree id whose key they spell; [`Display`]
    ///   writes that same text back.
    /// - fails: [`ParseIdError::TreeLength`] for text of any other byte length,
    ///   [`ParseIdError::TreeAlphabet`] for a byte outside the z-base-32
    ///   alphabet (an uppercase letter among them), and
    ///   [`ParseIdError::TreeKey`] for a text that is not a key's canonical
    ///   spelling.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::TreeLength`]: the text is not 52 bytes long.
    /// - [`ParseIdError::TreeAlphabet`]: a byte is not a z-base-32 symbol.
    /// - [`ParseIdError::TreeKey`]: the text spells no verifying key, or not
    ///   canonically.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the all-zero key's spelling (52 `y`s) and a generated
    ///   key round-trip, the length boundary (51, 52, 53 characters) and a
    ///   non-alphabet character separate acceptance from the first two
    ///   refusals, and a non-canonical last character meets the third.
    /// - witness: `id::tests::a_tree_id_round_trips_through_its_anchor_text`
    /// - witness: `id::tests::a_tree_id_is_exactly_fifty_two_z_base_32_characters`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.len() != TREE_CHARACTERS {
            return Err(ParseIdError::TreeLength);
        }
        if !text.bytes().all(|byte| Z_BASE_32.contains(&byte)) {
            return Err(ParseIdError::TreeAlphabet);
        }
        iroh::PublicKey::from_z32(text)
            .map(Self)
            .map_err(ParseIdError::TreeKey)
    }
}

impl fmt::Display for TreeId
{
    /// Write the tree id as its 52 z-base-32 characters.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        // economy: iroh's encoder returns a fresh `String`; writing the
        // characters in place needs a z-base-32 codec this crate does not carry.
        f.write_str(&self.0.to_z32())
    }
}

/// A subduction peer id: the public half of the key a peer signs its
/// handshakes and commits with, written as 64 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PeerKey(PeerId);

impl PeerKey
{
    /// Take a subduction peer id as a peer key.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn new(peer: PeerId) -> Self
    {
        Self(peer)
    }

    /// The subduction peer id this key spells.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn peer_id(self) -> PeerId
    {
        self.0
    }
}

impl FromStr for PeerKey
{
    type Err = ParseIdError;

    /// Read a subduction peer id from its hex text.
    ///
    /// # Specification
    /// - ensures: accepts exactly 64 hex digits, either case, and yields the
    ///   peer id whose bytes they spell.
    /// - fails: [`ParseIdError::Length`] for text of any other byte length,
    ///   [`ParseIdError::Digit`] for a non-hex character.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::Length`]: the text is not 64 bytes long.
    /// - [`ParseIdError::Digit`]: a character is not a hex digit.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a round trip through `Display`, mixed case, the
    ///   length boundary (63, 64, 65 digits), a non-hex character and a sign
    ///   separate acceptance from each refusal and pin the decoded bytes.
    /// - witness: `id::tests::a_peer_key_round_trips_through_its_hex_text`
    /// - witness: `id::tests::a_peer_key_is_exactly_sixty_four_hex_digits`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let bytes = text.parse::<HexBytes>()?;
        Ok(Self(PeerId::new(bytes.0)))
    }
}

impl fmt::Display for PeerKey
{
    /// Write the peer id as 64 lowercase hex digits.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Display::fmt(&self.0, f)
    }
}

/// An iroh endpoint id: the public half of the key a peer's QUIC endpoint is
/// dialed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EndpointKey(iroh::EndpointId);

impl EndpointKey
{
    /// Take an iroh endpoint id as an endpoint key.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn new(endpoint: iroh::EndpointId) -> Self
    {
        Self(endpoint)
    }

    /// The iroh endpoint id this key spells.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn endpoint_id(self) -> iroh::EndpointId
    {
        self.0
    }
}

impl FromStr for EndpointKey
{
    type Err = ParseIdError;

    /// Read an iroh endpoint id from its text form.
    ///
    /// # Specification
    /// - ensures: accepts what iroh's own parser accepts (the hex form this
    ///   crate prints, or iroh's base32 form) when it names a valid ed25519
    ///   public key.
    /// - fails: [`ParseIdError::Endpoint`] otherwise, carrying iroh's reason.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::Endpoint`]: the text is not an endpoint id.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a round trip through `Display` and a non-key text
    ///   separate acceptance from refusal.
    /// - witness: `id::tests::an_endpoint_key_round_trips_through_its_hex_text`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        text.parse::<iroh::EndpointId>()
            .map(Self)
            .map_err(ParseIdError::Endpoint)
    }
}

impl fmt::Display for EndpointKey
{
    /// Write the endpoint id as 64 lowercase hex digits.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A commit id abbreviated by hand to a prefix of its lowercase hex digits.
///
/// It holds at least 8 digits and fewer than 64, and names the one commit in a
/// tree whose id begins with it; it is neither self-verifying nor stable as the
/// tree grows, so a receipt never carries one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitPrefix
{
    /// The digits, as written.
    digits: String,
    /// The smallest commit id the digits begin: the digits padded with `0`s.
    first: CommitId,
    /// The largest commit id the digits begin: the digits padded with `f`s.
    last: CommitId,
}

impl CommitPrefix
{
    /// The commit ids the prefix abbreviates, in id order.
    ///
    /// # Specification
    /// - ensures: a commit id lies in the range iff its lowercase hex begins
    ///   with the prefix's digits: the range runs from the digits padded with
    ///   `0`s to the digits padded with `f`s, and lowercase hex of equal length
    ///   sorts as the bytes it spells.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an 8-digit prefix's range is compared with the ids
    ///   its two paddings spell, and the ids one below and one above it fall
    ///   outside; through resolution, prefixes matching one, two and no commit
    ///   of a tree are read to that commit, to an ambiguity and to unknown.
    /// - witness: `id::tests::a_prefix_spans_the_ids_it_begins`
    /// - witness: `store::tests::a_commit_resolves_by_its_anchor_to_its_verdict`
    /// - witness: `store::tests::an_ambiguous_prefix_is_refused_naming_it`
    pub(crate) const fn span(&self) -> RangeInclusive<CommitId>
    {
        RangeInclusive::new(self.first, self.last)
    }
}

impl fmt::Display for CommitPrefix
{
    /// Write the digits as written.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(&self.digits)
    }
}

/// A commit id as the last segment of an anchor's commit form spells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitDigits
{
    /// All 64 digits: the commit id itself.
    Full(CommitId),
    /// 8 to 63 digits: a prefix of the id.
    Abbreviated(CommitPrefix),
}

impl FromStr for CommitDigits
{
    type Err = ParseIdError;

    /// Read a commit id, whole or abbreviated, from its lowercase hex digits.
    ///
    /// # Specification
    /// - ensures: 64 lowercase hex digits read as the commit id they spell
    ///   ([`CommitDigits::Full`]), whose `Display` writes the same digits back;
    ///   8 to 63 read as a prefix ([`CommitDigits::Abbreviated`]) keeping the
    ///   digits as written.
    /// - fails: [`ParseIdError::CommitShort`] for fewer than 8 bytes,
    ///   [`ParseIdError::CommitLong`] for more than 64, and
    ///   [`ParseIdError::CommitDigit`] for a byte that is not a lowercase hex
    ///   digit, an uppercase one among them, in that order.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::CommitShort`]: fewer than 8 digits.
    /// - [`ParseIdError::CommitLong`]: more than 64 digits.
    /// - [`ParseIdError::CommitDigit`]: a byte is not a lowercase hex digit.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the anchor parser: 64 digits
    ///   round-trip as a commit anchor, 8 and 63 read as a prefix, and 7, 65,
    ///   an uppercase and a non-hex digit each meet their own refusal.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_commit_reference_may_abbreviate_its_id`
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.len() < COMMIT_PREFIX_DIGITS {
            return Err(ParseIdError::CommitShort);
        }
        if text.len() > HEX_DIGITS {
            return Err(ParseIdError::CommitLong);
        }
        let (mut first, mut last) = ([b'0'; HEX_DIGITS], [b'f'; HEX_DIGITS]);
        for ((low, high), digit) in first.iter_mut().zip(last.iter_mut()).zip(text.bytes()) {
            *low = digit;
            *high = digit;
        }
        let spell = |digits: [u8; HEX_DIGITS]| -> Result<CommitId, ParseIdError> {
            let mut bytes = [0_u8; 32];
            data_encoding::HEXLOWER
                .decode_mut(&digits, &mut bytes)
                .map_err(|partial| ParseIdError::CommitDigit(partial.error))?;
            Ok(CommitId::new(bytes))
        };
        let first = spell(first)?;
        let last = spell(last)?;
        if text.len() == HEX_DIGITS {
            return Ok(Self::Full(first));
        }
        Ok(Self::Abbreviated(CommitPrefix {
            digits: text.into(),
            first,
            last,
        }))
    }
}

/// Where an iroh endpoint is reached: a direct UDP address, or the relay
/// server it is connected to.
///
/// The derived order places every direct address before every relay, IPv4
/// before IPv6, then by address and port, and relays by their URL's text: the
/// order an endpoint's text form and its receipt encoding list them in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address
{
    /// A direct UDP address. An IPv6 address carries no flow label and no
    /// scope id: both are local to the host that names them.
    Direct(SocketAddr),
    /// A relay server: an `http` or `https` URL whose text holds no `@`, the
    /// character an endpoint's text form separates its addresses by.
    Relay(iroh::RelayUrl),
}

impl Address
{
    /// `address` as a direct address: an IPv6 address without its flow label
    /// and scope id.
    ///
    /// # Specification
    /// - ensures: an IPv4 address is kept as given; an IPv6 address keeps its
    ///   address and port, with the flow label and the scope id zero.
    /// - panics: none.
    pub(crate) fn direct(address: SocketAddr) -> Self
    {
        match address {
            | SocketAddr::V4(_) => Self::Direct(address),
            | SocketAddr::V6(v6) => {
                Self::Direct(SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), 0, 0)))
            },
        }
    }

    /// `url` as a relay address, when an endpoint can hold it.
    ///
    /// # Specification
    /// - ensures: an `http` or `https` URL whose text holds no `@` is a relay
    ///   address.
    /// - fails: [`ParseIdError::Relay`], carrying the URL's text, for any other
    ///   scheme or for a text holding `@`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::Relay`]: the URL is no relay an endpoint holds.
    pub(crate) fn relay(url: iroh::RelayUrl) -> Result<Self, ParseIdError>
    {
        if !matches!(url.scheme(), "http" | "https") || url.as_str().contains('@') {
            return Err(ParseIdError::Relay(url.as_str().into()));
        }
        Ok(Self::Relay(url))
    }
}

impl FromStr for Address
{
    type Err = ParseIdError;

    /// Read one address of an endpoint's text form.
    ///
    /// # Specification
    /// - ensures: an IP address and port reads as a direct address, as
    ///   [`Address::direct`] keeps it; any other text reads as a relay URL, as
    ///   [`Address::relay`] admits it.
    /// - fails: [`ParseIdError::Address`], carrying the text, for text that is
    ///   neither an IP address and port nor a URL, and as [`Address::relay`]
    ///   for a URL no endpoint holds.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::Address`]: the text is no address.
    /// - [`ParseIdError::Relay`]: the URL is no relay an endpoint holds.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the endpoint's text form: an IPv4,
    ///   an IPv6 with a scope id and a relay read back, and an empty address, a
    ///   word and a relay of another scheme each meet their own refusal.
    /// - witness: `id::tests::an_endpoint_round_trips_through_its_text`
    /// - witness: `id::tests::a_malformed_endpoint_text_is_refused`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if let Ok(direct) = text.parse::<SocketAddr>() {
            return Ok(Self::direct(direct));
        }
        let url = text
            .parse::<iroh::RelayUrl>()
            .map_err(|_not_a_url| ParseIdError::Address(text.into()))?;
        Self::relay(url)
    }
}

impl fmt::Display for Address
{
    /// Write a direct address as its IP address and port, an IPv6 address in
    /// brackets, and a relay as its URL.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Direct(address) => fmt::Display::fmt(&address, f),
            | Self::Relay(ref url) => f.write_str(url.as_str()),
        }
    }
}

/// An iroh endpoint as a dialer reaches it: its id, and the addresses it is
/// reached at.
///
/// An endpoint with no address is reached by its id alone, through iroh's
/// address lookups. Written `<endpoint-id>`, then `@<address>` for each
/// address in order: a direct address as its IP address and port, an IPv6
/// address in brackets, and a relay as its URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint
{
    /// The endpoint's id.
    key: EndpointKey,
    /// The addresses it is reached at.
    addresses: BTreeSet<Address>,
}

impl Endpoint
{
    /// The endpoint `key`, at no address: reached through iroh's lookups.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(key: EndpointKey) -> Self
    {
        Self {
            key,
            addresses: BTreeSet::new(),
        }
    }

    /// The endpoint with `direct` among its addresses.
    ///
    /// # Specification
    /// - ensures: the address is held as [`Address::direct`] keeps it: an IPv6
    ///   address without its flow label and scope id.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an IPv6 address given with a scope id reads back
    ///   without it through the text form.
    /// - witness: `id::tests::an_endpoint_round_trips_through_its_text`
    #[inline]
    #[must_use]
    pub fn with_direct(
        mut self,
        direct: SocketAddr,
    ) -> Self
    {
        let _was_held = self.addresses.insert(Address::direct(direct));
        self
    }

    /// An endpoint from its id and addresses, as a decoder read them.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn from_parts(
        key: EndpointKey,
        addresses: BTreeSet<Address>,
    ) -> Self
    {
        Self { key, addresses }
    }

    /// The endpoint iroh names by `addr`: its id, its direct addresses and its
    /// relays.
    ///
    /// # Specification
    /// - ensures: each IP address is held as [`Address::direct`] keeps it and
    ///   each relay [`Address::relay`] admits is held; a relay it refuses, and
    ///   an address of a transport beyond IP and relays, is left out.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an address with an IPv4, an IPv6 with a scope id, a
    ///   relay, a relay holding `@` and one of another scheme is taken to the
    ///   first three alone, the IPv6 without its scope id.
    /// - witness: `id::tests::an_endpoint_keeps_the_addresses_it_can_hold`
    pub(crate) fn of(addr: &iroh::EndpointAddr) -> Self
    {
        let addresses = addr
            .addrs
            .iter()
            .filter_map(|transport| match *transport {
                | iroh::TransportAddr::Ip(direct) => Some(Address::direct(direct)),
                // A relay the record cannot hold is not presented.
                | iroh::TransportAddr::Relay(ref url) => Address::relay(url.clone()).ok(),
                | _ => None,
            })
            .collect();
        Self {
            key: EndpointKey::new(addr.id),
            addresses,
        }
    }

    /// The endpoint's id.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn key(&self) -> EndpointKey
    {
        self.key
    }

    /// The addresses the endpoint is reached at, in order.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn addresses(&self) -> &BTreeSet<Address>
    {
        &self.addresses
    }

    /// The endpoint as iroh dials it: its id and every address.
    ///
    /// # Specification
    /// trivial.
    pub(crate) fn addr(&self) -> iroh::EndpointAddr
    {
        iroh::EndpointAddr::from_parts(
            self.key.endpoint_id(),
            self.addresses.iter().map(|address| match *address {
                | Address::Direct(direct) => iroh::TransportAddr::Ip(direct),
                | Address::Relay(ref url) => iroh::TransportAddr::Relay(url.clone()),
            }),
        )
    }
}

impl FromStr for Endpoint
{
    type Err = ParseIdError;

    /// Read an endpoint from its text form.
    ///
    /// # Specification
    /// - ensures: accepts an endpoint id as [`EndpointKey`] reads it, followed
    ///   by any number of addresses each preceded by `@`, in any order and with
    ///   repetition, each read as [`Address`] reads it; [`Display`] writes the
    ///   addresses back in order, each once.
    /// - fails: as [`EndpointKey`]'s parser for the id, and as [`Address`]'s
    ///   for an address, an empty one among them.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::Endpoint`]: the id is not an endpoint id.
    /// - [`ParseIdError::Address`]: an address is neither an IP address and
    ///   port nor a URL.
    /// - [`ParseIdError::Relay`]: a URL is no relay an endpoint holds.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an endpoint alone, one at an IPv4 address, and one at
    ///   an IPv6 address, a repeated IPv4 address and a relay given out of
    ///   order read back to their display; a malformed id, a trailing `@`, a
    ///   word and an `ftp` URL each meet their own refusal.
    /// - witness: `id::tests::an_endpoint_round_trips_through_its_text`
    /// - witness: `id::tests::a_malformed_endpoint_text_is_refused`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut parts = text.split('@');
        let key = parts.next().unwrap_or_default().parse::<EndpointKey>()?;
        let addresses = parts
            .map(str::parse::<Address>)
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self { key, addresses })
    }
}

impl fmt::Display for Endpoint
{
    /// Write the endpoint id, then `@` and each address in order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        write!(f, "{}", self.key)?;
        for address in &self.addresses {
            write!(f, "@{address}")?;
        }
        Ok(())
    }
}

/// A remote peer as a dialer names it: the endpoint to reach, at the
/// addresses it names, and the subduction identity that endpoint must prove
/// it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePeer
{
    /// The iroh endpoint dialed.
    endpoint: Endpoint,
    /// The subduction identity the handshake must authenticate.
    peer: PeerKey,
}

impl RemotePeer
{
    /// Name a remote peer by its endpoint and its subduction peer id.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(
        endpoint: Endpoint,
        peer: PeerKey,
    ) -> Self
    {
        Self { endpoint, peer }
    }

    /// The endpoint dialed.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint
    {
        &self.endpoint
    }

    /// The peer id the remote must authenticate as.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn peer(&self) -> PeerKey
    {
        self.peer
    }
}

/// Why a text is not an id.
#[derive(Debug, thiserror::Error)]
pub enum ParseIdError
{
    /// The text is not 64 bytes long.
    #[error("an id is {HEX_DIGITS} hex digits")]
    Length,
    /// A character is not a hex digit.
    #[error("an id is written in hex digits")]
    Digit(#[source] data_encoding::DecodeError),
    /// The text is not an iroh endpoint id.
    #[error("not an iroh endpoint id")]
    Endpoint(#[source] iroh::KeyParsingError),
    /// The text is not 52 bytes long.
    #[error("a tree id is {TREE_CHARACTERS} z-base-32 characters")]
    TreeLength,
    /// A byte is not a z-base-32 symbol.
    #[error("a tree id is written in the z-base-32 symbols ybndrfg8ejkmcpqxot1uwisza345h769")]
    TreeAlphabet,
    /// The text spells no ed25519 verifying key, or not canonically.
    #[error("not a tree id: no ed25519 verifying key is spelled so")]
    TreeKey(#[source] iroh::KeyParsingError),
    /// The commit id is abbreviated to fewer than 8 hex digits.
    #[error("a commit id is abbreviated to {COMMIT_PREFIX_DIGITS} hex digits at the fewest")]
    CommitShort,
    /// The commit id has more than 64 hex digits.
    #[error("a commit id is {HEX_DIGITS} hex digits at most")]
    CommitLong,
    /// A byte of the commit id is not a lowercase hex digit.
    #[error("a commit id is written in lowercase hex digits")]
    CommitDigit(#[source] data_encoding::DecodeError),
    /// An endpoint's address is neither an IP address and port nor a URL.
    #[error("an address is an IP address and port or a relay URL: {0:?}")]
    Address(String),
    /// A URL is no relay an endpoint holds.
    #[error("a relay is an http or https URL holding no @: {0:?}")]
    Relay(String),
}

/// Thirty-two bytes decoded from hex text.
#[repr(transparent)]
struct HexBytes([u8; 32]);

impl FromStr for HexBytes
{
    type Err = ParseIdError;

    /// Decode exactly 64 hex digits into 32 bytes.
    ///
    /// # Specification
    /// - ensures: accepts exactly 64 hex digits, either case.
    /// - fails: [`ParseIdError::Length`] for text of any other byte length,
    ///   [`ParseIdError::Digit`] for a non-hex character.
    /// - panics: none; the output buffer is sized to the decoded length the
    ///   length check has just established.
    ///
    /// # Errors
    /// - [`ParseIdError::Length`]: the text is not 64 bytes long.
    /// - [`ParseIdError::Digit`]: a character is not a hex digit.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the peer key, whose parser is this
    ///   one plus a constructor.
    /// - witness: `id::tests::a_peer_key_is_exactly_sixty_four_hex_digits`
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.len() != HEX_DIGITS {
            return Err(ParseIdError::Length);
        }
        let mut bytes = [0_u8; 32];
        data_encoding::HEXLOWER_PERMISSIVE
            .decode_mut(text.as_bytes(), &mut bytes)
            .map_err(|partial| ParseIdError::Digit(partial.error))?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests
{
    use core::net::Ipv4Addr;
    use core::net::Ipv6Addr;
    use core::net::SocketAddr;
    use core::net::SocketAddrV6;

    use super::Address;
    use super::CommitDigits;
    use super::Endpoint;
    use super::EndpointKey;
    use super::ParseIdError;
    use super::PeerKey;
    use super::TreeId;

    /// A fixed 64-digit id whose bytes are all distinct.
    const ID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// The z-base-32 spelling of the all-zero key: the symbol for zero is `y`.
    const ZERO: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    #[test]
    fn a_tree_id_round_trips_through_its_anchor_text()
    {
        let zero = ZERO.parse::<TreeId>().unwrap();
        assert_eq!(
            zero.sedimentree().as_bytes(),
            &[0; 32],
            "52 `y`s spell the all-zero key"
        );
        assert_eq!(zero.to_string(), ZERO, "display is the z-base-32 text");
        let generated = TreeId::new(iroh::SecretKey::from_bytes(&[3; 32]).public());
        let text = generated.to_string();
        assert_eq!(text.len(), 52, "a tree id is 52 characters: {text}");
        assert_eq!(
            text.parse::<TreeId>().unwrap(),
            generated,
            "a generated key's text reads back to it"
        );
    }

    #[test]
    fn a_tree_id_is_exactly_fifty_two_z_base_32_characters()
    {
        let (short, _last) = ZERO.split_at(51);
        let long = format!("{ZERO}y");
        assert!(
            matches!(short.parse::<TreeId>(), Err(ParseIdError::TreeLength)),
            "51 characters are refused for their length"
        );
        assert!(
            matches!(long.parse::<TreeId>(), Err(ParseIdError::TreeLength)),
            "53 characters are refused for their length"
        );
        for outside in ['0', 'l', 'v', '2', 'Y', '/'] {
            let text = format!("{outside}{short}");
            assert!(
                matches!(text.parse::<TreeId>(), Err(ParseIdError::TreeAlphabet)),
                "{outside:?} is not a z-base-32 symbol"
            );
        }
        let non_canonical = format!("{short}b");
        assert!(
            matches!(
                non_canonical.parse::<TreeId>(),
                Err(ParseIdError::TreeKey(_))
            ),
            "a last character with an unused bit set spells no key canonically"
        );
    }

    #[test]
    fn a_peer_key_round_trips_through_its_hex_text()
    {
        let peer = ID.parse::<PeerKey>().unwrap();
        assert_eq!(
            peer.0.as_bytes()[31],
            0x1f,
            "the last digit pair is the last byte"
        );
        assert_eq!(peer.to_string(), ID, "display is the lowercase hex text");
        let upper = ID.to_uppercase().parse::<PeerKey>().unwrap();
        assert_eq!(upper, peer, "uppercase digits spell the same id");
    }

    #[test]
    fn a_peer_key_is_exactly_sixty_four_hex_digits()
    {
        let (short, _last) = ID.split_at(63);
        let long = format!("{ID}0");
        assert!(
            matches!(short.parse::<PeerKey>(), Err(ParseIdError::Length)),
            "63 digits are refused for their length"
        );
        assert!(
            matches!(long.parse::<PeerKey>(), Err(ParseIdError::Length)),
            "65 digits are refused for their length"
        );
        let not_hex = format!("{short}g");
        assert!(
            matches!(not_hex.parse::<PeerKey>(), Err(ParseIdError::Digit(_))),
            "a non-hex character is refused as a digit"
        );
        let signed = format!("+{short}");
        assert!(
            matches!(signed.parse::<PeerKey>(), Err(ParseIdError::Digit(_))),
            "a sign is not a digit"
        );
    }

    #[test]
    fn a_prefix_spans_the_ids_it_begins()
    {
        let Ok(CommitDigits::Abbreviated(prefix)) = "0123abcd".parse::<CommitDigits>()
        else {
            panic!("eight digits are a prefix");
        };
        assert_eq!(
            prefix.to_string(),
            "0123abcd",
            "a prefix displays as written"
        );
        let whole = |text: String| match text.parse::<CommitDigits>() {
            | Ok(CommitDigits::Full(commit)) => commit,
            | other => panic!("not a whole commit id: {text}: {other:?}"),
        };
        let (zeros, fs) = ("0".repeat(56), "f".repeat(56));
        let span = prefix.span();
        assert_eq!(
            *span.start(),
            whole(format!("0123abcd{zeros}")),
            "the span begins at the digits padded with zeros"
        );
        assert_eq!(
            *span.end(),
            whole(format!("0123abcd{fs}")),
            "and ends at the digits padded with fs"
        );
        assert!(
            !span.contains(&whole(format!("0123abcc{fs}"))),
            "the id just below lies outside"
        );
        assert!(
            !span.contains(&whole(format!("0123abce{zeros}"))),
            "the id just above lies outside"
        );
    }

    #[test]
    fn an_endpoint_key_round_trips_through_its_hex_text()
    {
        let endpoint = EndpointKey(iroh::SecretKey::from_bytes(&[7; 32]).public());
        let text = endpoint.to_string();
        assert_eq!(
            text.parse::<EndpointKey>().unwrap(),
            endpoint,
            "display parses back"
        );
        assert!(
            matches!(
                "not a key".parse::<EndpointKey>(),
                Err(ParseIdError::Endpoint(_))
            ),
            "a non-key text is refused"
        );
    }

    /// A fixed endpoint id.
    ///
    /// # Specification
    /// trivial.
    fn endpoint_key() -> EndpointKey
    {
        EndpointKey(iroh::SecretKey::from_bytes(&[7; 32]).public())
    }

    #[test]
    fn an_endpoint_round_trips_through_its_text()
    {
        let key = endpoint_key();
        assert_eq!(
            key.to_string().parse::<Endpoint>().unwrap(),
            Endpoint::new(key),
            "an endpoint id alone is an endpoint at no address"
        );
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9, 7, 3));
        let endpoint = Endpoint::new(key)
            .with_direct(scoped)
            .with_direct(SocketAddr::from((Ipv4Addr::LOCALHOST, 5)));
        assert_eq!(
            endpoint.to_string(),
            format!("{key}@127.0.0.1:5@[::1]:9"),
            "IPv4 before IPv6, the IPv6 address without its flow label and scope id"
        );
        let given = format!("{key}@https://relay.example.org@[::1]:9@127.0.0.1:5@127.0.0.1:5");
        let read = given.parse::<Endpoint>().unwrap();
        assert_eq!(
            read.to_string(),
            format!("{key}@127.0.0.1:5@[::1]:9@https://relay.example.org/"),
            "addresses read in any order and with repetition display in order, each once, \
             the relay as its URL parses back"
        );
        assert_eq!(
            read.to_string().parse::<Endpoint>().unwrap(),
            read,
            "the display parses back"
        );
    }

    #[test]
    fn a_malformed_endpoint_text_is_refused()
    {
        let key = endpoint_key();
        assert!(
            matches!(
                "nothex@127.0.0.1:5".parse::<Endpoint>(),
                Err(ParseIdError::Endpoint(_))
            ),
            "a malformed id is refused"
        );
        for address in ["", "nowhere", "127.0.0.1"] {
            assert!(
                matches!(
                    format!("{key}@{address}").parse::<Endpoint>(),
                    Err(ParseIdError::Address(ref text)) if text == address
                ),
                "{address:?} is no address"
            );
        }
        for relay in [
            "ftp://relay.example.org/",
            "https://user@relay.example.org/",
        ] {
            assert!(
                matches!(relay.parse::<Address>(), Err(ParseIdError::Relay(_))),
                "{relay:?} is no relay an endpoint holds"
            );
        }
    }

    #[test]
    fn an_endpoint_keeps_the_addresses_it_can_hold()
    {
        let key = endpoint_key();
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9, 7, 3));
        let held: iroh::RelayUrl = "https://relay.example.org/".parse().unwrap();
        let addr = iroh::EndpointAddr::from_parts(key.endpoint_id(), [
            iroh::TransportAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 5))),
            iroh::TransportAddr::Ip(scoped),
            iroh::TransportAddr::Relay(held),
            iroh::TransportAddr::Relay("https://user@relay.example.org/".parse().unwrap()),
            iroh::TransportAddr::Relay("ftp://relay.example.org/".parse().unwrap()),
        ]);
        let endpoint = Endpoint::of(&addr);
        assert_eq!(
            endpoint.to_string(),
            format!("{key}@127.0.0.1:5@[::1]:9@https://relay.example.org/"),
            "the direct addresses and the http relay are held, the IPv6 address unscoped"
        );
        assert_eq!(
            endpoint.addr().addrs.len(),
            3,
            "the dial names exactly the addresses held"
        );
    }
}
