//! Anchors: the `domhringr://` names a tree, the paths in it and its commits
//! go by, what a path is bound to, and what resolving one answers.
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
//! Segments beginning with `.` are reserved: no path holds one. The reserved
//! form `domhringr://<authority>/.commit/<commit id>` names a commit by locus
//! and content at once, so it needs no binding: it resolves to the commit with
//! the fold's verdict on it when the tree holds it, and to
//! [`Resolution::Unknown`] otherwise. An anchor carries the whole commit id; a
//! [`Reference`] typed by hand may abbreviate it to a prefix of 8 hex digits or
//! more, which resolves to the one commit of the tree whose id begins with it.
//!
//! [`Kind::Bind`]: crate::receipt::Kind::Bind
//! [`Kind::Claim`]: crate::receipt::Kind::Claim
//! [`Kind::Introduce`]: crate::receipt::Kind::Introduce

use alloc::string::String;
use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;

use sedimentree_core::loose_commit::id::CommitId;

use crate::fold::Verdict;
use crate::id::CommitDigits;
use crate::id::CommitPrefix;
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

/// The reserved segment a commit anchor's commit id follows.
const COMMIT: &str = ".commit";

/// A path in a tree: one or more segments, each non-empty UTF-8 without `/`
/// that does not begin with `.`, written joined by `/`.
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
    ///   all non-empty and none of which begins with `.`, and keeps the text as
    ///   written, so [`Display`] writes it back.
    /// - fails: [`ParseAnchorError::EmptySegment`] for the empty text, a
    ///   leading or trailing `/`, or two `/` in a row; then
    ///   [`ParseAnchorError::Reserved`] for a segment beginning with `.`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseAnchorError::EmptySegment`]: a segment is empty.
    /// - [`ParseAnchorError::Reserved`]: a segment begins with `.`.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — one- and two-segment paths round-trip through an
    ///   anchor; the empty path, a leading, a trailing and a doubled `/` are
    ///   each refused as empty; a first, a later, a lone `.` and a `..` segment
    ///   are each refused as reserved, read alone, through an anchor and
    ///   through the receipt decoder.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_malformed_anchor_is_refused_by_name`
    /// - witness: `anchor::tests::a_reserved_segment_is_refused_by_name`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.split('/').any(str::is_empty) {
            return Err(ParseAnchorError::EmptySegment);
        }
        if text.split('/').any(|segment| segment.starts_with('.')) {
            return Err(ParseAnchorError::Reserved);
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

/// A `domhringr://` name: a tree, a path in a tree, or a commit in a tree, the
/// tree named by its key, a DNS name or a label.
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
    /// `domhringr://<authority>/.commit/<commit id>`: a commit in the tree, by
    /// its whole id.
    Commit
    {
        /// What names the tree the commit is in.
        authority: Authority,
        /// The commit's id.
        commit: CommitId,
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

    /// The key form of the commit `commit` in `tree`:
    /// `domhringr://<tree>/.commit/<commit id>`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn commit(
        tree: TreeId,
        commit: CommitId,
    ) -> Self
    {
        Self::Commit {
            authority: Authority::Key(tree),
            commit,
        }
    }

    /// What names the tree the anchor names or names something in.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn authority(&self) -> &Authority
    {
        match *self {
            | Self::Tree(ref authority)
            | Self::Path { ref authority, .. }
            | Self::Commit { ref authority, .. } => authority,
        }
    }
}

impl FromStr for Anchor
{
    type Err = ParseAnchorError;

    /// Read an anchor from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the texts [`Reference`]'s parser reads as a
    ///   [`Reference::Anchor`] — a bare tree, a path, or a commit by its whole
    ///   id, under any of the three authority forms — and yields that anchor;
    ///   [`Display`] writes the same text back, so an anchor has one text.
    /// - fails: as [`Reference`]'s parser, and
    ///   [`ParseAnchorError::Abbreviated`] for a commit form whose commit id is
    ///   a prefix.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseAnchorError::Abbreviated`]: the commit id is abbreviated.
    /// - every other [`ParseAnchorError`]: as [`Reference`]'s parser.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a bare tree, paths and a commit by its whole id
    ///   round-trip under each authority form, and the commit form with 8 and
    ///   63 digits is refused as abbreviated; every other refusal is the
    ///   reference parser's, witnessed there.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_commit_reference_may_abbreviate_its_id`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let reference = text.parse::<Reference>()?;
        match reference {
            | Reference::Anchor(anchor) => Ok(anchor),
            | Reference::Abbreviated { .. } => Err(ParseAnchorError::Abbreviated),
        }
    }
}

impl fmt::Display for Anchor
{
    /// Write the anchor as `domhringr://<authority>/`, followed by the path
    /// for a path anchor, and by `.commit/` and the commit id's 64 lowercase
    /// hex digits for a commit anchor.
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
            | Self::Commit {
                ref authority,
                commit,
            } => write!(f, "{SCHEME}{authority}/{COMMIT}/{commit}"),
        }
    }
}

/// A `domhringr://` name as typed by hand: an anchor, or the commit form with
/// its commit id abbreviated to a prefix, which a receipt never carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference
{
    /// An anchor, a commit in it named by its whole id.
    Anchor(Anchor),
    /// `domhringr://<authority>/.commit/<prefix>`: the one commit in the tree
    /// whose id begins with the prefix.
    Abbreviated
    {
        /// What names the tree the commit is in.
        authority: Authority,
        /// The prefix of the commit's id.
        prefix: CommitPrefix,
    },
}

impl Reference
{
    /// What names the tree the reference names or names something in.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn authority(&self) -> &Authority
    {
        match *self {
            | Self::Anchor(ref anchor) => anchor.authority(),
            | Self::Abbreviated { ref authority, .. } => authority,
        }
    }

    /// What the reference names in the tree its authority names.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn locus(&self) -> Locus<'_>
    {
        match *self {
            | Self::Anchor(Anchor::Tree(_)) => Locus::Tree,
            | Self::Anchor(Anchor::Path { ref path, .. }) => Locus::Within(Within::Path(path)),
            | Self::Anchor(Anchor::Commit { commit, .. }) => Locus::Within(Within::Commit(commit)),
            | Self::Abbreviated { ref prefix, .. } => Locus::Within(Within::Prefix(prefix)),
        }
    }
}

impl From<Anchor> for Reference
{
    /// The anchor, as a reference.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(anchor: Anchor) -> Self
    {
        Self::Anchor(anchor)
    }
}

impl FromStr for Reference
{
    type Err = ParseAnchorError;

    /// Read a reference from its text.
    ///
    /// # Specification
    /// - ensures: accepts `domhringr://<authority>/` as [`Anchor::Tree`];
    ///   `domhringr://<authority>/.commit/<commit id>` as [`Anchor::Commit`]
    ///   for 64 lowercase hex digits and as [`Reference::Abbreviated`] for 8 to
    ///   63; and `domhringr://<authority>/<path>` as [`Anchor::Path`]
    ///   otherwise. `<authority>` is read as [`Authority`]'s parser reads it —
    ///   a DNS name when it holds a dot, a tree id when it is 52 z-base-32
    ///   characters, a label otherwise — and `<path>` as a path.
    /// - fails: [`ParseAnchorError::Scheme`] for text not beginning
    ///   `domhringr://`, [`ParseAnchorError::Unterminated`] for an authority
    ///   with no `/` after it, the authority's refusal
    ///   ([`ParseAnchorError::Domain`], [`ParseAnchorError::Authority`] or
    ///   [`ParseAnchorError::Label`]); then, when the first segment is
    ///   `.commit`, [`ParseAnchorError::CommitForm`] unless exactly one segment
    ///   follows it and [`ParseAnchorError::Commit`] when that segment is no
    ///   commit id; otherwise the path's refusal
    ///   ([`ParseAnchorError::EmptySegment`] or
    ///   [`ParseAnchorError::Reserved`]), in that order.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseAnchorError::Scheme`]: the scheme is not `domhringr://`.
    /// - [`ParseAnchorError::Unterminated`]: no `/` follows the authority.
    /// - [`ParseAnchorError::Domain`]: the dotted authority is no DNS name.
    /// - [`ParseAnchorError::Authority`]: the key-shaped authority spells no
    ///   key.
    /// - [`ParseAnchorError::Label`]: the authority is empty.
    /// - [`ParseAnchorError::CommitForm`]: `.commit` is not followed by exactly
    ///   one segment.
    /// - [`ParseAnchorError::Commit`]: the commit id is fewer than 8 or more
    ///   than 64 lowercase hex digits.
    /// - [`ParseAnchorError::EmptySegment`]: a path segment is empty.
    /// - [`ParseAnchorError::Reserved`]: a path segment begins with `.`.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a bare tree, one- and multi-segment paths with a
    ///   space and non-ASCII, and a commit by its whole id round-trip under
    ///   each of the three authority forms, among them a 51- and a 53-character
    ///   z-base-32 label and an uppercase spelling of a tree id; 8 and 63
    ///   digits read as a prefix under each form; each refusal is met by a text
    ///   that differs from an accepted one in the one place it names: the
    ///   scheme, a missing `/`, a malformed DNS name, a key-shaped text
    ///   spelling no key, an empty authority, an empty, leading, trailing or
    ///   doubled segment, a reserved segment first, later, alone and doubled, a
    ///   `.commit` followed by no segment or by two, and a commit id of 0, 7
    ///   and 65 digits, in uppercase, or holding a non-hex digit.
    /// - witness: `anchor::tests::an_anchor_round_trips_through_its_text`
    /// - witness: `anchor::tests::a_malformed_anchor_is_refused_by_name`
    /// - witness: `anchor::tests::a_reserved_segment_is_refused_by_name`
    /// - witness: `anchor::tests::a_commit_reference_may_abbreviate_its_id`
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
            return Ok(Self::Anchor(Anchor::Tree(authority)));
        }
        let mut segments = path.split('/');
        if segments.next() == Some(COMMIT) {
            let (Some(digits), None) = (segments.next(), segments.next())
            else {
                return Err(ParseAnchorError::CommitForm);
            };
            let digits = digits
                .parse::<CommitDigits>()
                .map_err(ParseAnchorError::Commit)?;
            return Ok(match digits {
                | CommitDigits::Full(commit) => Self::Anchor(Anchor::Commit { authority, commit }),
                | CommitDigits::Abbreviated(prefix) => Self::Abbreviated { authority, prefix },
            });
        }
        let path = path.parse::<Path>()?;
        Ok(Self::Anchor(Anchor::Path { authority, path }))
    }
}

/// What a reference names in the tree its authority names.
#[derive(Clone, Copy, Debug)]
pub enum Locus<'reference>
{
    /// The tree itself.
    Tree,
    /// Something in the tree.
    Within(Within<'reference>),
}

/// Something a reference names in its tree.
#[derive(Clone, Copy, Debug)]
pub enum Within<'reference>
{
    /// A path.
    Path(&'reference Path),
    /// A commit, by its whole id.
    Commit(CommitId),
    /// A commit, by a prefix of its id.
    Prefix(&'reference CommitPrefix),
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
    /// A path segment begins with `.`: such segments are reserved.
    #[error("a path segment beginning with . is reserved")]
    Reserved,
    /// `.commit` is not followed by exactly one segment, the commit id.
    #[error("a commit anchor is domhringr://<tree>/.commit/<commit id>")]
    CommitForm,
    /// The segment after `.commit` is no commit id.
    #[error("cannot read the anchor's commit id")]
    Commit(#[source] ParseIdError),
    /// The commit id is abbreviated where an anchor carries it whole.
    #[error("an anchor carries the whole commit id: 64 hex digits")]
    Abbreviated,
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
    /// A tree, a path in a tree, or a commit in a tree, by its anchor.
    Anchor(Anchor),
    /// An iroh endpoint.
    Endpoint(EndpointKey),
    /// An opaque private datum: a vault path at a revision, a tracker id.
    Datum(String),
}

impl fmt::Display for Target
{
    /// Write the target as `anchor <anchor>`, `endpoint <hex>` or `datum
    /// <text>`.
    ///
    /// # Specification
    /// - ensures: one line with no newline: an anchor's or a datum's
    ///   backslashes and control characters are escaped as a note's are.
    /// - panics: none.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Anchor(ref anchor) => {
                f.write_str("anchor ")?;
                write!(OneLine::new(f, Field::Last), "{anchor}")
            },
            | Self::Endpoint(endpoint) => write!(f, "endpoint {endpoint}"),
            | Self::Datum(ref datum) => {
                f.write_str("datum ")?;
                OneLine::new(f, Field::Last).write_str(datum)
            },
        }
    }
}

/// What a reference resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution
{
    /// A binding, its author and its target: for a path, the bind the fold
    /// admitted last in canonical order; for a tree named by a DNS name or a
    /// label, the claim or introduction that names it, to that tree's anchor.
    Bound(PeerKey, Target),
    /// No admitted binding names the path, or a tree named by its key, which
    /// nothing binds.
    Unbound,
    /// A commit the tree holds, and the fold's verdict on it.
    Commit
    {
        /// The commit's whole id.
        id: CommitId,
        /// Whether the fold admitted the commit, or why it refused it.
        verdict: Verdict,
    },
    /// No commit the tree holds has the id named, or an id beginning with the
    /// prefix named.
    Unknown,
}

impl fmt::Display for Resolution
{
    /// Write the target of a binding, `unbound`, `commit <hex>` followed by
    /// the verdict, or `unknown`.
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
            | Self::Commit { id, ref verdict } => write!(f, "commit {id} {verdict}"),
            | Self::Unknown => f.write_str("unknown"),
        }
    }
}

#[cfg(test)]
mod tests
{
    use sedimentree_core::loose_commit::id::CommitId;

    use super::Anchor;
    use super::Authority;
    use super::ParseAnchorError;
    use super::Path;
    use super::Reference;
    use crate::id::ParseIdError;
    use crate::id::TreeId;
    use crate::name::ParseDomainError;
    use crate::name::ParseLabelError;

    /// The z-base-32 spelling of the all-zero key.
    const ZERO: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    /// A whole commit id whose bytes are all distinct, in hex.
    const HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// The tree the all-zero key names.
    ///
    /// # Specification
    /// trivial.
    fn zero() -> TreeId
    {
        ZERO.parse().unwrap()
    }

    /// The commit id [`HEX`] spells.
    ///
    /// # Specification
    /// trivial.
    fn whole() -> CommitId
    {
        CommitId::new(core::array::from_fn(|index| u8::try_from(index).unwrap()))
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
            let text = format!("domhringr://{written}/.commit/{HEX}");
            let anchor = text.parse::<Anchor>().unwrap();
            assert_eq!(
                anchor,
                Anchor::Commit {
                    authority: authority.clone(),
                    commit: whole(),
                },
                "{text} names the commit"
            );
            assert_eq!(anchor.authority(), &authority, "{text} is in the tree");
            assert_eq!(
                anchor.to_string(),
                text,
                "{text} displays back with its whole id"
            );
            assert_eq!(
                text.parse::<Reference>().unwrap(),
                Reference::Anchor(anchor),
                "{text} typed by hand reads as the same anchor"
            );
        }
        assert_eq!(
            Anchor::key(zero()).to_string(),
            format!("domhringr://{ZERO}/"),
            "a tree's key form"
        );
        assert_eq!(
            Anchor::commit(zero(), whole()).to_string(),
            format!("domhringr://{ZERO}/.commit/{HEX}"),
            "a commit's key form"
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

    #[test]
    fn a_reserved_segment_is_refused_by_name()
    {
        let refused = |text: String| text.parse::<Reference>().unwrap_err();
        for path in [".x", "x/.y", ".", "..", ".peer/k", ".heads", "x/.commit/y"] {
            for authority in [ZERO, "example.test", "b"] {
                let text = format!("domhringr://{authority}/{path}");
                assert!(
                    matches!(refused(text.clone()), ParseAnchorError::Reserved),
                    "{text} holds a reserved segment"
                );
            }
            assert!(
                matches!(path.parse::<Path>(), Err(ParseAnchorError::Reserved)),
                "{path} is no path"
            );
        }
        for form in [".commit", ".commit/x/y", ".commit//"] {
            let text = format!("domhringr://{ZERO}/{form}");
            assert!(
                matches!(refused(text.clone()), ParseAnchorError::CommitForm),
                "{text} names no one commit id"
            );
        }
    }

    #[test]
    fn a_commit_reference_may_abbreviate_its_id()
    {
        for written in [ZERO, "example.test", "b"] {
            let authority = written.parse::<Authority>().unwrap();
            for digits in [8, 63] {
                let (prefix, _rest) = HEX.split_at(digits);
                let text = format!("domhringr://{written}/.commit/{prefix}");
                match text.parse::<Reference>() {
                    | Ok(Reference::Abbreviated {
                        authority: read,
                        prefix: abbreviated,
                    }) => {
                        assert_eq!(read, authority, "{text}'s authority");
                        assert_eq!(abbreviated.to_string(), prefix, "{text} keeps its digits");
                    },
                    | other => panic!("{text} is an abbreviated reference: {other:?}"),
                }
                assert!(
                    matches!(text.parse::<Anchor>(), Err(ParseAnchorError::Abbreviated)),
                    "{text} is no anchor, which carries the whole id"
                );
            }
        }
        let refused = |digits: &str| {
            format!("domhringr://{ZERO}/.commit/{digits}")
                .parse::<Reference>()
                .unwrap_err()
        };
        let (seven, _rest) = HEX.split_at(7);
        for (digits, case) in [(seven, "seven digits"), ("", "no digits")] {
            assert!(
                matches!(
                    refused(digits),
                    ParseAnchorError::Commit(ParseIdError::CommitShort)
                ),
                "{case} are too few"
            );
        }
        assert!(
            matches!(
                refused(&format!("{HEX}0")),
                ParseAnchorError::Commit(ParseIdError::CommitLong)
            ),
            "65 digits are too many"
        );
        for (digits, case) in [
            (HEX.to_uppercase(), "uppercase digits"),
            (String::from("0123456g"), "a non-hex digit"),
        ] {
            assert!(
                matches!(
                    refused(&digits),
                    ParseAnchorError::Commit(ParseIdError::CommitDigit(_))
                ),
                "{case} spell no commit id"
            );
        }
    }
}
