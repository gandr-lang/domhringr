//! The identifiers a peer is addressed by and a tree is named by, in the hex
//! text form the peer binary reads and prints.

use core::fmt;
use core::str::FromStr;

use sedimentree_core::id::SedimentreeId;
use subduction_core::peer::id::PeerId;

/// Hex digits in the text form of a 32-byte id.
const HEX_DIGITS: usize = 64;

/// A sedimentree's id, written as 64 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TreeId(SedimentreeId);

impl TreeId
{
    /// The sedimentree id subduction knows the tree by.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn sedimentree(self) -> SedimentreeId
    {
        self.0
    }
}

impl FromStr for TreeId
{
    type Err = ParseIdError;

    /// Read a tree id from its hex text.
    ///
    /// # Specification
    /// - ensures: accepts exactly 64 hex digits, either case, and yields the
    ///   tree id whose bytes they spell.
    /// - fails: [`ParseIdError::Length`] for text of any other byte length,
    ///   [`ParseIdError::Digit`] for a non-hex character.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseIdError::Length`]: the text is not 64 bytes long.
    /// - [`ParseIdError::Digit`]: a character is not a hex digit.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the length boundary (63, 64, 65 digits), a non-hex
    ///   character, mixed case, and a round trip through `Display` separate
    ///   acceptance from each refusal and pin the decoded bytes.
    /// - witness: `id::tests::a_tree_id_round_trips_through_its_hex_text`
    /// - witness: `id::tests::a_tree_id_is_exactly_sixty_four_hex_digits`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let bytes = text.parse::<HexBytes>()?;
        Ok(Self(SedimentreeId::new(bytes.0)))
    }
}

impl fmt::Display for TreeId
{
    /// Write the tree id as 64 lowercase hex digits.
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
    /// - hypothesis: L3 — the peer id shares the tree id's decoder; a round
    ///   trip through `Display` pins that the peer id carries the decoded bytes
    ///   unchanged.
    /// - witness: `id::tests::a_peer_key_round_trips_through_its_hex_text`
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

/// A remote peer as a dialer names it: the endpoint to reach and the
/// subduction identity that endpoint must prove it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemotePeer
{
    /// The iroh endpoint dialed, by id alone.
    endpoint: EndpointKey,
    /// The subduction identity the handshake must authenticate.
    peer: PeerKey,
}

impl RemotePeer
{
    /// Name a remote peer by its endpoint id and its subduction peer id.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(
        endpoint: EndpointKey,
        peer: PeerKey,
    ) -> Self
    {
        Self { endpoint, peer }
    }

    /// The endpoint id dialed.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn endpoint(&self) -> EndpointKey
    {
        self.endpoint
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
    /// - hypothesis: L3 — witnessed through the tree id, whose parser is this
    ///   one plus a constructor.
    /// - witness: `id::tests::a_tree_id_is_exactly_sixty_four_hex_digits`
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
    use super::EndpointKey;
    use super::ParseIdError;
    use super::PeerKey;
    use super::TreeId;

    /// A fixed 64-digit id whose bytes are all distinct.
    const ID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn a_tree_id_round_trips_through_its_hex_text()
    {
        let tree = ID.parse::<TreeId>().unwrap();
        assert_eq!(
            tree.0.as_bytes()[31],
            0x1f,
            "the last digit pair is the last byte"
        );
        assert_eq!(tree.to_string(), ID, "display is the lowercase hex text");
        let upper = ID.to_uppercase().parse::<TreeId>().unwrap();
        assert_eq!(upper, tree, "uppercase digits spell the same id");
    }

    #[test]
    fn a_tree_id_is_exactly_sixty_four_hex_digits()
    {
        let (short, _last) = ID.split_at(63);
        let long = format!("{ID}0");
        assert!(
            matches!(short.parse::<TreeId>(), Err(ParseIdError::Length)),
            "63 digits are refused for their length"
        );
        assert!(
            matches!(long.parse::<TreeId>(), Err(ParseIdError::Length)),
            "65 digits are refused for their length"
        );
        let not_hex = format!("{short}g");
        assert!(
            matches!(not_hex.parse::<TreeId>(), Err(ParseIdError::Digit(_))),
            "a non-hex character is refused as a digit"
        );
        let signed = format!("+{short}");
        assert!(
            matches!(signed.parse::<TreeId>(), Err(ParseIdError::Digit(_))),
            "a sign is not a digit"
        );
    }

    #[test]
    fn a_peer_key_round_trips_through_its_hex_text()
    {
        let peer = ID.parse::<PeerKey>().unwrap();
        assert_eq!(
            peer.0.as_bytes()[0],
            0x00,
            "the first digit pair is the first byte"
        );
        assert_eq!(peer.to_string(), ID, "display is the lowercase hex text");
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
}
