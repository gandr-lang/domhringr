//! Anchors: the `domhringr://` names a tree and the paths in it go by, what a
//! path is bound to, and what resolving an anchor answers.
//!
//! An anchor's authority names its tree in one of three forms. The key form,
//! the tree id itself, certifies itself and is canonical. A DNS name is sugar
//! for a key that two sides verify: a witness names candidate keys, and the
//! one tree among them whose fold admits its owner's claim of the name is the
//! tree ([`Kind::Claim`]). A label is a petname: an introduction in the tree it
//! is read in names the tree ([`Kind::Introduce`]), and it resolves nowhere
//! else. A path is bound in the tree by a `Bind` receipt the fold admits
//! ([`Kind::Bind`]), and a path nothing binds resolves to
//! [`Resolution::Unbound`], never to a default.
//!
//! [`Kind::Bind`]: crate::receipt::Kind::Bind
//! [`Kind::Claim`]: crate::receipt::Kind::Claim
//! [`Kind::Introduce`]: crate::receipt::Kind::Introduce

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
use crate::name::Domain;
use crate::name::Label;
use crate::name::ParseDomainError;
use crate::name::ParseLabelError;

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

/// What an anchor names its tree by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority
{
    /// The tree id: the canonical form, which certifies itself.
    Key(TreeId),
    /// A DNS name: the tree is the one tree among those a witness names whose
    /// fold admits its owner's claim of the name.
    Domain(Domain),
    /// A label: the tree an introduction names in the tree the label is read
    /// in.
    Label(Label),
}

impl FromStr for Authority
{
    type Err = ParseAnchorError;

    /// Read an anchor's authority from its text.
    ///
    /// # Specification
    /// - ensures: text holding a dot is read as a DNS name
    ///   ([`Authority::Domain`]), 52 z-base-32 characters as a tree id
    ///   ([`Authority::Key`]), and any other text as a label
    ///   ([`Authority::Label`]), so each text has one form; [`Display`] writes
    ///   the text back.
    /// - fails: [`ParseAnchorError::Domain`] for a dotted text that is no DNS
    ///   name, [`ParseAnchorError::Authority`] for 52 z-base-32 characters that
    ///   spell no key, and [`ParseAnchorError::Label`] for the empty text, each
    ///   carrying why.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseAnchorError::Domain`]: the dotted authority is no DNS name.
    /// - [`ParseAnchorError::Authority`]: the key-shaped authority spells no
    ///   key.
    /// - [`ParseAnchorError::Label`]: the authority is empty.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the anchor parser: each form is
    ///   read from texts on either side of the boundaries that separate them (a
    ///   dot, 51, 52 and 53 z-base-32 characters, an uppercase spelling), and
    ///   each refusal is met by its own text.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_malformed_anchor_is_refused_by_name`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.contains('.') {
            let domain = text.parse::<Domain>().map_err(ParseAnchorError::Domain)?;
            return Ok(Self::Domain(domain));
        }
        match text.parse::<TreeId>() {
            | Ok(tree) => Ok(Self::Key(tree)),
            | Err(ParseIdError::TreeLength | ParseIdError::TreeAlphabet) => {
                let label = text.parse::<Label>().map_err(ParseAnchorError::Label)?;
                Ok(Self::Label(label))
            },
            | Err(failure) => Err(ParseAnchorError::Authority(failure)),
        }
    }
}

impl fmt::Display for Authority
{
    /// Write the tree id, the DNS name or the label.
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
            | Self::Key(tree) => fmt::Display::fmt(&tree, f),
            | Self::Domain(ref domain) => fmt::Display::fmt(domain, f),
            | Self::Label(ref label) => fmt::Display::fmt(label, f),
        }
    }
}

/// A `domhringr://` name: a tree, or a path in a tree, the tree named by its
/// key, a DNS name or a label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor
{
    /// `domhringr://<authority>/`: the tree itself.
    Tree(Authority),
    /// `domhringr://<authority>/<segment>/…/<segment>`: a path in the tree.
    Path
    {
        /// What names the tree the path is in.
        authority: Authority,
        /// The path.
        path: Path,
    },
}

impl Anchor
{
    /// The key form of `tree` itself: `domhringr://<tree>/`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn key(tree: TreeId) -> Self
    {
        Self::Tree(Authority::Key(tree))
    }

    /// What names the tree the anchor names or names a path in.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn authority(&self) -> &Authority
    {
        match *self {
            | Self::Tree(ref authority) | Self::Path { ref authority, .. } => authority,
        }
    }
}

impl FromStr for Anchor
{
    type Err = ParseAnchorError;

    /// Read an anchor from its text.
    ///
    /// # Specification
    /// - ensures: accepts `domhringr://<authority>/` as [`Anchor::Tree`] and
    ///   `domhringr://<authority>/<path>` as [`Anchor::Path`], where
    ///   `<authority>` is read as [`Authority`]'s parser reads it — a DNS name
    ///   when it holds a dot, a tree id when it is 52 z-base-32 characters, a
    ///   label otherwise — and `<path>` as a path; [`Display`] writes the same
    ///   text back, so an anchor has one text.
    /// - fails: [`ParseAnchorError::Scheme`] for text not beginning
    ///   `domhringr://`, [`ParseAnchorError::Unterminated`] for an authority
    ///   with no `/` after it, the authority's refusal
    ///   ([`ParseAnchorError::Domain`], [`ParseAnchorError::Authority`] or
    ///   [`ParseAnchorError::Label`]), and [`ParseAnchorError::EmptySegment`]
    ///   for a path with an empty segment, in that order.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseAnchorError::Scheme`]: the scheme is not `domhringr://`.
    /// - [`ParseAnchorError::Unterminated`]: no `/` follows the authority.
    /// - [`ParseAnchorError::Domain`]: the dotted authority is no DNS name.
    /// - [`ParseAnchorError::Authority`]: the key-shaped authority spells no
    ///   key.
    /// - [`ParseAnchorError::Label`]: the authority is empty.
    /// - [`ParseAnchorError::EmptySegment`]: a path segment is empty.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a bare tree and one- and multi-segment paths with a
    ///   space and non-ASCII round-trip under each of the three authority
    ///   forms, among them a 51- and a 53-character z-base-32 label and an
    ///   uppercase spelling of a tree id; each refusal is met by a text that
    ///   differs from an accepted one in the one place it names: the scheme, a
    ///   missing `/`, a malformed DNS name, a key-shaped text spelling no key,
    ///   an empty authority, and an empty, leading, trailing or doubled
    ///   segment.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_malformed_anchor_is_refused_by_name`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let rest = text.strip_prefix(SCHEME).ok_or(ParseAnchorError::Scheme)?;
        let Some((authority, path)) = rest.split_once('/')
        else {
            return Err(ParseAnchorError::Unterminated);
        };
        let authority = authority.parse::<Authority>()?;
        if path.is_empty() {
            return Ok(Self::Tree(authority));
        }
        let path = path.parse::<Path>()?;
        Ok(Self::Path { authority, path })
    }
}

impl fmt::Display for Anchor
{
    /// Write the anchor as `domhringr://<authority>/`, followed by the path
    /// for a path anchor.
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
            | Self::Tree(ref authority) => write!(f, "{SCHEME}{authority}/"),
            | Self::Path {
                ref authority,
                ref path,
            } => write!(f, "{SCHEME}{authority}/{path}"),
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
    /// No `/` follows the authority.
    #[error("an anchor's tree is followed by /")]
    Unterminated,
    /// The authority holds a dot but is no DNS name.
    #[error("cannot read the anchor's DNS name")]
    Domain(#[source] ParseDomainError),
    /// The authority is spelled as a tree id but is none.
    #[error("cannot read the anchor's tree")]
    Authority(#[source] ParseIdError),
    /// The authority is read as a label but is none.
    #[error("cannot read the anchor's label")]
    Label(#[source] ParseLabelError),
    /// A path segment is empty.
    #[error("an anchor's path has an empty segment")]
    EmptySegment,
}

/// The tree a label anchor is read in: a label resolves through the
/// introductions of that one tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope
{
    /// Labels are read in this tree.
    In(TreeId),
    /// No tree is named, so a label has nowhere to be read.
    Unscoped,
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
            | Self::Tree(tree) => write!(f, "tree {}", Anchor::key(tree)),
            | Self::Endpoint(endpoint) => write!(f, "endpoint {endpoint}"),
            | Self::Datum(ref datum) => {
                f.write_str("datum ")?;
                OneLine::new(f, Field::Last).write_str(datum)
            },
        }
    }
}

/// What an anchor resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution
{
    /// A binding, its author and its target: for a path, the bind the fold
    /// admitted last in canonical order; for a tree named by a DNS name or a
    /// label, the claim or introduction that names it, to that tree.
    Bound(PeerKey, Target),
    /// No admitted binding names the path, or a tree named by its key, which
    /// nothing binds.
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
    use super::Authority;
    use super::ParseAnchorError;
    use crate::id::ParseIdError;
    use crate::id::TreeId;
    use crate::name::ParseDomainError;
    use crate::name::ParseLabelError;

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
        let (short, _last) = ZERO.split_at(51);
        let long = format!("{ZERO}y");
        let upper = ZERO.to_uppercase();
        let authorities = [
            (String::from(ZERO), Authority::Key(zero())),
            (
                String::from("example.test"),
                Authority::Domain("example.test".parse().unwrap()),
            ),
            (String::from("b"), Authority::Label("b".parse().unwrap())),
            (
                String::from(short),
                Authority::Label(short.parse().unwrap()),
            ),
            (long.clone(), Authority::Label(long.parse().unwrap())),
            (upper.clone(), Authority::Label(upper.parse().unwrap())),
            (
                String::from("my friend"),
                Authority::Label("my friend".parse().unwrap()),
            ),
        ];
        for (written, authority) in authorities {
            let bare = format!("domhringr://{written}/");
            let anchor = bare.parse::<Anchor>().unwrap();
            assert_eq!(
                anchor,
                Anchor::Tree(authority.clone()),
                "{bare} names the tree"
            );
            assert_eq!(anchor.authority(), &authority, "{bare}'s authority");
            assert_eq!(anchor.to_string(), bare, "{bare} displays with its slash");
            for path in ["x", "concept/sub concept/größe"] {
                let text = format!("domhringr://{written}/{path}");
                let anchor = text.parse::<Anchor>().unwrap();
                assert_eq!(
                    anchor,
                    Anchor::Path {
                        authority: authority.clone(),
                        path: path.parse().unwrap(),
                    },
                    "{text}"
                );
                assert_eq!(anchor.authority(), &authority, "{text} is in the tree");
                assert_eq!(anchor.to_string(), text, "{text} displays back");
            }
        }
        assert_eq!(
            Anchor::key(zero()).to_string(),
            format!("domhringr://{ZERO}/"),
            "a tree's key form"
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
        for unterminated in [
            format!("domhringr://{ZERO}"),
            String::from("domhringr://example.test"),
            String::from("domhringr://b"),
        ] {
            assert!(
                matches!(
                    refused(unterminated.clone()),
                    ParseAnchorError::Unterminated
                ),
                "{unterminated} has no / after its authority"
            );
        }
        assert!(matches!(
            refused("domhringr://Example.test/x".into()),
            ParseAnchorError::Domain(ParseDomainError::Uppercase)
        ));
        assert!(matches!(
            refused("domhringr://example..test/x".into()),
            ParseAnchorError::Domain(ParseDomainError::EmptyLabel)
        ));
        assert!(matches!(
            refused("domhringr://.x/".into()),
            ParseAnchorError::Domain(ParseDomainError::EmptyLabel)
        ));
        assert!(matches!(
            refused(format!("domhringr://{short}b/x")),
            ParseAnchorError::Authority(ParseIdError::TreeKey(_))
        ));
        assert!(matches!(
            refused("domhringr:///x".into()),
            ParseAnchorError::Label(ParseLabelError::Empty)
        ));
        for path in ["/x", "x/", "x//y", "/"] {
            for authority in [ZERO, "example.test", "b"] {
                let text = format!("domhringr://{authority}/{path}");
                assert!(
                    matches!(refused(text.clone()), ParseAnchorError::EmptySegment),
                    "{text} has an empty segment"
                );
            }
        }
    }
}
