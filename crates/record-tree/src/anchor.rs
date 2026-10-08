//! Anchors: the `domhringr://` names a tree and the paths in it go by, what a
//! path is bound to, and what resolving a path answers.
//!
//! An anchor's authority is the tree id, the tree's own verifying key, so the
//! name certifies itself; its path is bound in the tree by a `Bind` receipt
//! the fold admits ([`Kind::Bind`]), and a path nothing binds resolves to
//! [`Resolution::Unbound`], never to a default.
//!
//! [`Kind::Bind`]: crate::receipt::Kind::Bind

use alloc::string::String;
use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;

use sedimentree_core::loose_commit::id::CommitId;

use crate::id::EndpointKey;
use crate::id::ParseIdError;
use crate::id::PeerKey;
use crate::id::TreeId;
use crate::line::Field;
use crate::line::OneLine;

/// The text every anchor begins with: the scheme and its separators.
const SCHEME: &str = "domhringr://";

/// A path in a tree: one or more segments, each non-empty UTF-8 without `/`,
/// written joined by `/`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Path(String);

impl FromStr for Path
{
    type Err = ParseAnchorError;

    /// Read a path from its segments joined by `/`.
    ///
    /// # Specification
    /// - ensures: accepts exactly the texts whose `/`-separated segments are
    ///   all non-empty, and keeps the text as written, so [`Display`] writes it
    ///   back.
    /// - fails: [`ParseAnchorError::EmptySegment`] for the empty text, a
    ///   leading or trailing `/`, or two `/` in a row.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseAnchorError::EmptySegment`]: a segment is empty.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — one- and two-segment paths round-trip through an
    ///   anchor, and the empty path, a leading, a trailing and a doubled `/`
    ///   are each refused.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_malformed_anchor_is_refused_by_name`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.split('/').any(str::is_empty) {
            return Err(ParseAnchorError::EmptySegment);
        }
        Ok(Self(text.into()))
    }
}

impl fmt::Display for Path
{
    /// Write the segments joined by `/`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Path
{
    /// The segments joined by `/`, as written.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &str
    {
        &self.0
    }
}

/// A `domhringr://` name: a tree, or a path in a tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor
{
    /// `domhringr://<tree>/`: the tree itself.
    Tree(TreeId),
    /// `domhringr://<tree>/<segment>/…/<segment>`: a path in the tree.
    Path
    {
        /// The tree the path is in.
        tree: TreeId,
        /// The path.
        path: Path,
    },
}

impl Anchor
{
    /// The tree the anchor names or names a path in.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn tree(&self) -> TreeId
    {
        match *self {
            | Self::Tree(tree) | Self::Path { tree, .. } => tree,
        }
    }
}

impl FromStr for Anchor
{
    type Err = ParseAnchorError;

    /// Read an anchor from its text.
    ///
    /// # Specification
    /// - ensures: accepts `domhringr://<tree>/` as [`Anchor::Tree`] and
    ///   `domhringr://<tree>/<path>` as [`Anchor::Path`], where `<tree>` is a
    ///   tree id's text and `<path>` a path's; [`Display`] writes the same text
    ///   back, so an anchor has one text.
    /// - fails: [`ParseAnchorError::Scheme`] for text not beginning
    ///   `domhringr://`; [`ParseAnchorError::DnsName`] for an authority
    ///   containing a dot, the form reserved for a DNS name; then
    ///   [`ParseAnchorError::Unterminated`] for an authority with no `/` after
    ///   it, [`ParseAnchorError::Authority`] for an authority that is not a
    ///   tree id, carrying why, and [`ParseAnchorError::EmptySegment`] for a
    ///   path with an empty segment, in that order.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseAnchorError::Scheme`]: the scheme is not `domhringr://`.
    /// - [`ParseAnchorError::DnsName`]: the authority is a DNS name.
    /// - [`ParseAnchorError::Unterminated`]: no `/` follows the authority.
    /// - [`ParseAnchorError::Authority`]: the authority is not a tree id.
    /// - [`ParseAnchorError::EmptySegment`]: a path segment is empty.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a bare tree, a one-segment and a multi-segment path
    ///   with a space and non-ASCII round-trip; each refusal is met by a text
    ///   that differs from an accepted one in the one place it names: the
    ///   scheme, a dotted authority with and without a path, a missing `/`, an
    ///   authority of 51 and 53 characters or with a foreign symbol, and an
    ///   empty, leading, trailing or doubled segment.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_malformed_anchor_is_refused_by_name`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let rest = text.strip_prefix(SCHEME).ok_or(ParseAnchorError::Scheme)?;
        let split = rest.split_once('/');
        let authority = split.map_or(rest, |(authority, _path)| authority);
        if authority.contains('.') {
            return Err(ParseAnchorError::DnsName);
        }
        let Some((authority, path)) = split
        else {
            return Err(ParseAnchorError::Unterminated);
        };
        let tree = authority
            .parse::<TreeId>()
            .map_err(ParseAnchorError::Authority)?;
        if path.is_empty() {
            return Ok(Self::Tree(tree));
        }
        let path = path.parse::<Path>()?;
        Ok(Self::Path { tree, path })
    }
}

impl fmt::Display for Anchor
{
    /// Write the anchor as `domhringr://<tree>/`, followed by the path for a
    /// path anchor.
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
            | Self::Tree(tree) => write!(f, "{SCHEME}{tree}/"),
            | Self::Path { tree, ref path } => write!(f, "{SCHEME}{tree}/{path}"),
        }
    }
}

/// Why a text is not an anchor.
#[derive(Debug, thiserror::Error)]
pub enum ParseAnchorError
{
    /// The text does not begin with the scheme.
    #[error("an anchor begins with {SCHEME}")]
    Scheme,
    /// The authority contains a dot: the form reserved for a DNS name, which
    /// resolves to a tree key only through a witness.
    #[error("an anchor naming its tree by DNS name is reserved; name the tree by its key")]
    DnsName,
    /// No `/` follows the authority.
    #[error("an anchor's tree is followed by /")]
    Unterminated,
    /// The authority is not a tree id.
    #[error("cannot read the anchor's tree")]
    Authority(#[source] ParseIdError),
    /// A path segment is empty.
    #[error("an anchor's path has an empty segment")]
    EmptySegment,
}

/// What a path is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target
{
    /// A commit, by id.
    Commit(CommitId),
    /// Another tree.
    Tree(TreeId),
    /// An iroh endpoint.
    Endpoint(EndpointKey),
    /// An opaque private datum: a vault path at a revision, a tracker id.
    Datum(String),
}

impl fmt::Display for Target
{
    /// Write the target as `commit <hex>`, `tree domhringr://<tree>/`,
    /// `endpoint <hex>` or `datum <text>`.
    ///
    /// # Specification
    /// - ensures: one line with no newline: a datum's backslashes and control
    ///   characters are escaped as a note's are.
    /// - panics: none.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Commit(commit) => write!(f, "commit {commit}"),
            | Self::Tree(tree) => write!(f, "tree {}", Anchor::Tree(tree)),
            | Self::Endpoint(endpoint) => write!(f, "endpoint {endpoint}"),
            | Self::Datum(ref datum) => {
                f.write_str("datum ")?;
                OneLine::new(f, Field::Last).write_str(datum)
            },
        }
    }
}

/// What a path resolves to in a tree's view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution
{
    /// The binding the fold admitted last in canonical order: its author and
    /// its target.
    Bound(PeerKey, Target),
    /// No admitted binding names the path.
    Unbound,
}

impl fmt::Display for Resolution
{
    /// Write the target of a binding, or `unbound`.
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
            | Self::Bound(_author, ref target) => fmt::Display::fmt(target, f),
            | Self::Unbound => f.write_str("unbound"),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::Anchor;
    use super::ParseAnchorError;
    use crate::id::ParseIdError;
    use crate::id::TreeId;

    /// The z-base-32 spelling of the all-zero key.
    const ZERO: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    /// The tree the all-zero key names.
    ///
    /// # Specification
    /// trivial.
    fn zero() -> TreeId
    {
        ZERO.parse().unwrap()
    }

    #[test]
    fn an_anchor_round_trips_through_its_text()
    {
        let bare = format!("domhringr://{ZERO}/");
        assert_eq!(
            bare.parse::<Anchor>().unwrap(),
            Anchor::Tree(zero()),
            "a bare anchor names the tree"
        );
        for path in ["x", "concept/sub concept/größe"] {
            let text = format!("domhringr://{ZERO}/{path}");
            let anchor = text.parse::<Anchor>().unwrap();
            assert_eq!(
                anchor,
                Anchor::Path {
                    tree: zero(),
                    path: path.parse().unwrap(),
                },
                "{text}"
            );
            assert_eq!(anchor.tree(), zero(), "{text} is in the tree");
            assert_eq!(anchor.to_string(), text, "{text} displays back");
        }
        assert_eq!(
            Anchor::Tree(zero()).to_string(),
            bare,
            "a bare anchor displays with its slash"
        );
    }

    #[test]
    fn a_malformed_anchor_is_refused_by_name()
    {
        let refused = |text: String| text.parse::<Anchor>().unwrap_err();
        let (short, _last) = ZERO.split_at(51);
        assert!(matches!(
            refused(format!("domhring://{ZERO}/x")),
            ParseAnchorError::Scheme
        ));
        assert!(matches!(
            refused(format!("DOMHRINGR://{ZERO}/x")),
            ParseAnchorError::Scheme
        ));
        assert!(matches!(refused(ZERO.into()), ParseAnchorError::Scheme));
        for dns in [
            "domhringr://gandr.dev/x",
            "domhringr://gandr.dev/",
            "domhringr://gandr.dev",
        ] {
            assert!(
                matches!(refused(dns.into()), ParseAnchorError::DnsName),
                "{dns} is a DNS name"
            );
        }
        assert!(matches!(
            refused(format!("domhringr://{ZERO}")),
            ParseAnchorError::Unterminated
        ));
        assert!(matches!(
            refused(format!("domhringr://{short}/x")),
            ParseAnchorError::Authority(ParseIdError::TreeLength)
        ));
        assert!(matches!(
            refused(format!("domhringr://{ZERO}y/x")),
            ParseAnchorError::Authority(ParseIdError::TreeLength)
        ));
        assert!(matches!(
            refused(format!("domhringr://{short}0/x")),
            ParseAnchorError::Authority(ParseIdError::TreeAlphabet)
        ));
        assert!(matches!(
            refused("domhringr:///x".into()),
            ParseAnchorError::Authority(ParseIdError::TreeLength)
        ));
        for path in ["/x", "x/", "x//y", "/"] {
            let text = format!("domhringr://{ZERO}/{path}");
            assert!(
                matches!(refused(text.clone()), ParseAnchorError::EmptySegment),
                "{text} has an empty segment"
            );
        }
    }
}
