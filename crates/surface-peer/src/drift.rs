//! The drift check: a concepts tree's bindings held against the anchors a
//! public checkout cites and the pages a vault checkout holds.
//!
//! A concepts tree binds each concept, a path in it, to a datum
//! `vault:<path>@<commit>` ([`Page`]): the vault page its public derivative
//! was written or last confirmed against, and the vault commit it was
//! confirmed at. A public checkout cites a concept by its anchor in the key
//! form, `domhringr://<tree-id>/<concept>`, in its tracked text
//! ([`Citations`]). [`check`] scans the public checkout, asks the vault
//! checkout for each bound page's blob at `HEAD` and at its commit, and
//! reports in anchor order ([`Report`]) every disagreement it finds
//! ([`State`]). Both checkouts are read by the `git` binary, run as a
//! subprocess whose output is read whole, each as the repository at its own
//! path.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use core::fmt;
use core::fmt::Write as _;
use core::num::NonZeroU64;
use core::str::FromStr;
use std::io::Write as _;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Output;
use std::process::Stdio;

use domhringr_record_tree::Anchor;
use domhringr_record_tree::Authority;
use domhringr_record_tree::Path;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Target;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;

/// What a page datum begins with.
const VAULT: &str = "vault:";

/// How many hex digits a bound commit id has: a SHA-1 object name.
const COMMIT_DIGITS: usize = 40;

/// The characters besides whitespace and control characters that end a
/// citation in running text: the quotes, brackets and separators that prose
/// and markup put around an anchor.
const DELIMITERS: [char; 13] = [
    '`', '"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', '|', '\\',
];

/// The sentence punctuation a citation never ends with: a sentence that ends
/// on an anchor puts it there, so it is dropped from the end of a hit.
const TRAILING: [char; 6] = ['.', ',', ':', ';', '!', '?'];

/// The variables that name a repository to git, as `git rev-parse
/// --local-env-vars` lists them, less the two that carry `-c` configuration:
/// git clears exactly these before it runs a command in another repository,
/// and the check clears them so that a checkout is read as the repository at
/// its path even inside another repository's hook.
const REPOSITORY_VARIABLES: [&str; 13] = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
];

/// Which checkout the check reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checkout
{
    /// The public checkout, whose tracked text cites the concepts.
    Public,
    /// The vault checkout, which holds the pages the concepts are bound to.
    Vault,
}

impl fmt::Display for Checkout
{
    /// Write the checkout's name, which is also its option's.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Public => "public",
            | Self::Vault => "vault",
        })
    }
}

/// Why the check could not read a checkout.
#[derive(Debug, thiserror::Error)]
pub enum CheckError
{
    /// git cannot be started in the checkout, or its input or its output
    /// cannot be passed.
    #[error("cannot run git in the {checkout} checkout")]
    Run
    {
        /// The checkout git was run in.
        checkout: Checkout,
        /// Why it cannot run.
        #[source]
        source: std::io::Error,
    },
    /// git ran and failed, as in a directory that is no git checkout.
    #[error("git failed in the {checkout} checkout with {status}: {diagnostic}")]
    Git
    {
        /// The checkout git was run in.
        checkout: Checkout,
        /// How git exited.
        status: ExitStatus,
        /// What git wrote to standard error.
        diagnostic: Diagnostic,
    },
    /// git's output is not in the form the check asked for.
    #[error("cannot read git's output in the {0} checkout")]
    Unreadable(Checkout),
}

impl CheckError
{
    /// The failure of the git run in `checkout` that produced `output`.
    ///
    /// # Specification
    /// trivial.
    fn failed(
        checkout: Checkout,
        output: &Output,
    ) -> Self
    {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        Self::Git {
            checkout,
            status: output.status,
            diagnostic: Diagnostic(diagnostic.trim_end().into()),
        }
    }
}

/// What git wrote to standard error, with its trailing whitespace removed.
#[derive(Debug)]
#[repr(transparent)]
pub struct Diagnostic(String);

impl fmt::Display for Diagnostic
{
    /// Write the diagnostic on one line, its newlines escaped.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Display::fmt(
            &Escaped {
                text: &self.0,
                field: Field::Last,
            },
            f,
        )
    }
}

/// Where a field stands on a report line, which decides what its escape
/// covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field
{
    /// The line's last field: a space is part of it.
    Last,
    /// A field another follows: a space would end it, so it is escaped too.
    Inner,
}

/// Text written so that it stays in its field of one report line, escaped as
/// `view` escapes a path or a datum.
struct Escaped<'text>
{
    /// The text.
    text: &'text str,
    /// Where it stands.
    field: Field,
}

impl fmt::Display for Escaped<'_>
{
    /// Write the text, escaping a backslash as `\\`, a control character as
    /// its Rust escape (`\n`, `\u{7}`), and in an inner field a space as
    /// `\u{20}`.
    ///
    /// # Specification
    /// - ensures: the output holds no control character, and in an inner field
    ///   no space; distinct texts write distinct outputs, since every escape
    ///   begins with the backslash a literal backslash is escaped to.
    /// - fails: the formatter's own error.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`fmt::Error`]: the formatter refused a write.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a binding's anchor holding a space and a file name
    ///   holding a newline and a backslash are printed in a report and compared
    ///   with their escaped lines.
    /// - witness: `drift::tests::findings_are_reported_in_anchor_order`
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        for character in self.text.chars() {
            if character == '\\' || character.is_control() {
                write!(f, "{}", character.escape_default())?;
            }
            else if character == ' ' && self.field == Field::Inner {
                write!(f, "{}", character.escape_unicode())?;
            }
            else {
                f.write_char(character)?;
            }
        }
        Ok(())
    }
}

/// A file in the vault, by its path from the repository's top: segments
/// joined by `/`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct PagePath(String);

/// A commit in the vault, by its 40 lowercase hex digits.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct Revision(String);

/// A vault page at a revision: what a binding's datum names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Page
{
    /// The page's path in the vault.
    path: PagePath,
    /// The vault commit the binding was written or confirmed at.
    revision: Revision,
}

impl FromStr for Page
{
    type Err = ParseDatumError;

    /// Read a page from a binding's datum, `vault:<path>@<commit>`.
    ///
    /// # Specification
    /// - ensures: accepts exactly the texts that begin with `vault:` and end
    ///   with `@` and 40 lowercase hex digits, the commit, where what stands
    ///   between them, the path, is one or more `/`-separated non-empty
    ///   segments, none of them `.` or `..`, holding no control character. The
    ///   path is split from the commit at the last `@`, so a path may hold one.
    /// - fails: [`ParseDatumError::Scheme`] for a text not beginning `vault:`,
    ///   then [`ParseDatumError::Separator`] when no `@` follows it,
    ///   [`ParseDatumError::Commit`] when the commit is not 40 lowercase hex
    ///   digits, [`ParseDatumError::Control`] for a path holding a control
    ///   character, [`ParseDatumError::EmptySegment`] for an empty path or one
    ///   with a leading, a trailing or a doubled `/`, and
    ///   [`ParseDatumError::Relative`] for a `.` or `..` segment, in that
    ///   order.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseDatumError::Scheme`]: the datum does not begin `vault:`.
    /// - [`ParseDatumError::Separator`]: no `@` names the commit.
    /// - [`ParseDatumError::Commit`]: the commit is not 40 lowercase hex
    ///   digits.
    /// - [`ParseDatumError::Control`]: the path holds a control character.
    /// - [`ParseDatumError::EmptySegment`]: a path segment is empty.
    /// - [`ParseDatumError::Relative`]: a path segment is `.` or `..`.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a one-segment path, a nested path with spaces, a path
    ///   holding `@` and a path with a dot-leading segment are read to their
    ///   path and commit; each refusal is met by a datum that differs from an
    ///   accepted one in the one place it names: the scheme's case, a missing
    ///   `@`, a commit of 39 and 41 digits, in uppercase and with a non-hex
    ///   digit, a newline in the path, an empty path, a leading, a trailing and
    ///   a doubled `/`, and a `.` and a `..` segment.
    /// - witness: `drift::tests::a_page_datum_reads_its_path_and_commit`
    /// - witness: `drift::tests::a_malformed_page_datum_is_refused_by_name`
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let rest = text.strip_prefix(VAULT).ok_or(ParseDatumError::Scheme)?;
        let (path, commit) = rest.rsplit_once('@').ok_or(ParseDatumError::Separator)?;
        let hex = commit
            .bytes()
            .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'));
        if commit.len() != COMMIT_DIGITS || !hex {
            return Err(ParseDatumError::Commit);
        }
        if path.chars().any(char::is_control) {
            return Err(ParseDatumError::Control);
        }
        if path.split('/').any(str::is_empty) {
            return Err(ParseDatumError::EmptySegment);
        }
        if path.split('/').any(|segment| matches!(segment, "." | "..")) {
            return Err(ParseDatumError::Relative);
        }
        Ok(Self {
            path: PagePath(path.into()),
            revision: Revision(commit.into()),
        })
    }
}

impl fmt::Display for Page
{
    /// Write the page as a report names it, `<path>@<commit>`, the path
    /// escaped as a line's last field.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        let path = Escaped {
            text: &self.path.0,
            field: Field::Last,
        };
        write!(f, "{path}@{}", self.revision.0)
    }
}

/// Why a binding's datum names no vault page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum ParseDatumError
{
    /// The datum does not begin `vault:`.
    #[error("a page datum begins with vault:")]
    Scheme,
    /// No `@` separates the page's path from its commit.
    #[error("a page datum is vault:<path>@<commit>")]
    Separator,
    /// The commit is not 40 lowercase hex digits.
    #[error("a page's commit is 40 lowercase hex digits")]
    Commit,
    /// The path holds a control character.
    #[error("a page's path holds a control character")]
    Control,
    /// A path segment is empty: the path is empty, or has a leading, a
    /// trailing or a doubled `/`.
    #[error("a page's path has an empty segment")]
    EmptySegment,
    /// A path segment is `.` or `..`.
    #[error("a page's path names . or ..")]
    Relative,
}

/// A file in the public checkout, by its path from the repository's top as
/// git prints it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct FileName(String);

/// A line's number in its file, counted from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct LineNumber(NonZeroU64);

/// A line of a file in the public checkout.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Line
{
    /// The file.
    file: FileName,
    /// The line's number in it.
    number: LineNumber,
}

impl fmt::Display for Line
{
    /// Write the line as `<file>:<number>`, the file escaped as a line's last
    /// field.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        let file = Escaped {
            text: &self.file.0,
            field: Field::Last,
        };
        write!(f, "{file}:{}", self.number.0)
    }
}

/// A hit that reads as no anchor: its text, which begins with the tree's
/// anchor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct Hit(String);

/// What a git command wrote to standard output, read as UTF-8 with
/// replacement characters.
#[derive(Debug)]
#[repr(transparent)]
struct GitOutput(String);

/// What the public checkout cites under the concepts tree.
#[derive(Debug, Default, PartialEq, Eq)]
struct Citations
{
    /// Each concept cited, with every line that cites it.
    cited: BTreeMap<Path, BTreeSet<Line>>,
    /// Each hit that reads as no anchor, with every line it stands on.
    unreadable: BTreeMap<Hit, BTreeSet<Line>>,
}

impl Citations
{
    /// Read the citations of concepts in `tree` from `listing`, what `git grep
    /// --null --line-number` printed for the tree's anchor.
    ///
    /// # Specification
    /// - requires: `listing` is a sequence of matching lines, each its file's
    ///   name, a NUL, its number, a NUL, its text and a newline, the last
    ///   newline optional.
    /// - ensures: every occurrence of the tree's anchor, `domhringr://<tree
    ///   id>/`, in a line's text begins a hit, which runs to the first
    ///   whitespace, control character, or one of `` ` `` `"` `'` `<` `>` `(`
    ///   `)` `[` `]` `{` `}` `|` `\`, or to the end of the text, less any `.`
    ///   `,` `:` `;` `!` `?` that ends it; the next hit is sought after it. A
    ///   hit that reads as a path anchor cites that path on the line; a hit
    ///   that reads as the bare tree or a commit in it cites no concept and is
    ///   not kept; a hit that reads as no anchor is kept as unreadable on the
    ///   line. A line citing a concept, or holding an unreadable hit, twice is
    ///   kept once.
    /// - fails: [`CheckError::Unreadable`] naming the public checkout when a
    ///   line lacks either NUL or its number is not a positive decimal.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`CheckError::Unreadable`]: the listing is not in the form asked for.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — one listing holds citations in backticks, angle
    ///   brackets, a link's parentheses, before a comma and at a sentence's
    ///   end, two on one line, one twice on one line, a nested path, the bare
    ///   tree and a commit in it, an anchor of another tree, and hits with an
    ///   empty segment, a reserved segment and an abbreviated commit, in a file
    ///   whose name holds a colon and a newline, with line numbers 9 and 10,
    ///   and the last line without its newline; the citations it reads are
    ///   compared exactly. A line without its second NUL and a line numbered 0
    ///   are each refused.
    /// - witness: `drift::tests::a_scan_reads_each_citation_with_its_file_and_line`
    fn read(
        listing: &GitOutput,
        tree: TreeId,
    ) -> Result<Self, CheckError>
    {
        let prefix = Anchor::key(tree).to_string();
        let unreadable = || CheckError::Unreadable(Checkout::Public);
        let ends = |character: char| {
            character.is_whitespace() || character.is_control() || DELIMITERS.contains(&character)
        };
        let mut citations = Self::default();
        let mut rest = listing.0.as_str();
        while !rest.is_empty() {
            let (file, after) = rest.split_once('\0').ok_or_else(unreadable)?;
            let (number, after) = after.split_once('\0').ok_or_else(unreadable)?;
            let (mut text, after) = after.split_once('\n').unwrap_or((after, ""));
            rest = after;
            let number = number
                .parse::<NonZeroU64>()
                .map_err(|_number| unreadable())?;
            let line = Line {
                file: FileName(file.into()),
                number: LineNumber(number),
            };
            while let Some(start) = text.find(prefix.as_str()) {
                // `find` yields character boundaries, so neither split fails.
                let Some((_before, from)) = text.split_at_checked(start)
                else {
                    break;
                };
                let end = from.find(ends).unwrap_or(from.len());
                let Some((hit, after)) = from.split_at_checked(end)
                else {
                    break;
                };
                text = after;
                let hit = hit.trim_end_matches(TRAILING);
                match hit.parse::<Anchor>() {
                    | Ok(Anchor::Path { path, .. }) => {
                        let _first = citations
                            .cited
                            .entry(path)
                            .or_default()
                            .insert(line.clone());
                    },
                    | Ok(Anchor::Tree(_) | Anchor::Commit { .. }) => {},
                    | Err(_reason) => {
                        let _first = citations
                            .unreadable
                            .entry(Hit(hit.into()))
                            .or_default()
                            .insert(line.clone());
                    },
                }
            }
        }
        Ok(citations)
    }
}

/// An object name `git cat-file` is asked about: `<revision>:<path>`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct Query(String);

impl Query
{
    /// The page's path at the vault's `HEAD`.
    ///
    /// # Specification
    /// trivial.
    fn head(page: &Page) -> Self
    {
        Self(format!("HEAD:{}", page.path.0))
    }

    /// The page's path at the commit it is bound at.
    ///
    /// # Specification
    /// trivial.
    fn bound(page: &Page) -> Self
    {
        Self(format!("{}:{}", page.revision.0, page.path.0))
    }
}

/// A git object name, in hex.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct ObjectName(String);

/// What the vault holds at a page's path at one revision.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Held
{
    /// A blob: the page.
    Blob(ObjectName),
    /// No page: nothing at the path, an object that is no blob there, or a
    /// revision the vault does not hold.
    Absent,
}

impl Held
{
    /// Read the answer to each of `queries` from `answers`, what `git cat-file
    /// --batch-check='%(objectname) %(objecttype)'` printed for them.
    ///
    /// # Specification
    /// - requires: no query holds a newline.
    /// - ensures: one value per query, in order: [`Held::Blob`] with the object
    ///   name for an answer `<name> blob`, and [`Held::Absent`] for an answer
    ///   `<name> tree`, `<name> commit`, `<name> tag` or `<query> missing`.
    /// - fails: [`CheckError::Unreadable`] naming the vault checkout when an
    ///   answer has no such form, a name holds a non-hex digit, or there are
    ///   fewer or more answers than queries.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`CheckError::Unreadable`]: the answers are not in the form asked for.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — answers naming a blob, a tree and a commit, and a
    ///   missing answer for a path with a space, are read to their values; one
    ///   answer short, one answer over, an unknown object type and a missing
    ///   answer echoing another query are each refused.
    /// - witness: `drift::tests::the_vault_answers_each_query_with_a_blob_or_an_absence`
    fn answers(
        answers: &GitOutput,
        queries: &[Query],
    ) -> Result<Vec<Self>, CheckError>
    {
        let unreadable = || CheckError::Unreadable(Checkout::Vault);
        let mut lines = answers.0.split_terminator('\n');
        let mut held = Vec::with_capacity(queries.len());
        for query in queries {
            let answer = lines.next().ok_or_else(unreadable)?;
            let named = answer.split_once(' ').filter(|&(name, _kind)| {
                !name.is_empty() && name.bytes().all(|digit| digit.is_ascii_hexdigit())
            });
            held.push(match named {
                | Some((name, "blob")) => Self::Blob(ObjectName(name.into())),
                | Some((_name, "tree" | "commit" | "tag")) => Self::Absent,
                | Some(_) | None if answer.strip_suffix(" missing") == Some(query.0.as_str()) => {
                    Self::Absent
                },
                | Some(_) | None => return Err(unreadable()),
            });
        }
        match lines.next() {
            | Some(_) => Err(unreadable()),
            | None => Ok(held),
        }
    }
}

/// Where a well-formed binding's page stands against the vault's `HEAD`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing
{
    /// The page's blob at `HEAD` is its blob at the bound commit.
    Consistent,
    /// The page is at `HEAD`, but its blob there is not its blob at the
    /// bound commit, or the bound commit holds no such page.
    Drifted,
    /// The page is not at `HEAD`.
    Missing,
}

impl Standing
{
    /// Where a page stands, from what the vault holds at its path at `HEAD`
    /// and at its bound commit.
    ///
    /// # Specification
    /// - ensures: [`Standing::Missing`] when `head` is absent, whatever `bound`
    ///   is; [`Standing::Consistent`] when both are the same blob; and
    ///   [`Standing::Drifted`] when `head` is a blob and `bound` another or
    ///   absent.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the same blob at both, two blobs, a blob at `HEAD`
    ///   only, and an absence at `HEAD` against a blob and against an absence
    ///   are each located to their standing.
    /// - witness: `drift::tests::a_page_stands_by_its_blobs_at_head_and_at_its_commit`
    fn of(
        head: &Held,
        bound: &Held,
    ) -> Self
    {
        match (head, bound) {
            | (&Held::Absent, _) => Self::Missing,
            | (&Held::Blob(ref now), &Held::Blob(ref then)) if now == then => Self::Consistent,
            | (&Held::Blob(_), &Held::Blob(_) | &Held::Absent) => Self::Drifted,
        }
    }
}

/// A binding's target as the target of a report line: the page its datum
/// names, or the target as `view` writes it when it names none.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct Rendered(String);

/// A binding's target, read by the datum grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Datum
{
    /// A datum naming a vault page.
    Page(Page),
    /// Any other target: an anchor, an endpoint, or a datum the grammar
    /// refuses.
    Unreadable(Rendered),
}

impl Datum
{
    /// Read `target` as a page datum.
    ///
    /// # Specification
    /// - ensures: [`Datum::Page`] for a datum [`Page`]'s parser accepts;
    ///   [`Datum::Unreadable`] with the target as `view` writes it for any
    ///   other datum, an anchor and an endpoint.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a page datum reads to its page, and a datum the
    ///   grammar refuses (holding a newline), an anchor and an endpoint are
    ///   each kept as `view` writes them, one line; the grammar's own refusals
    ///   are witnessed on [`Page`]'s parser.
    /// - witness: `drift::tests::a_target_that_names_no_page_is_kept_as_view_writes_it`
    fn read(target: &Target) -> Self
    {
        let unreadable = || Self::Unreadable(Rendered(target.to_string()));
        match *target {
            | Target::Datum(ref text) => match text.parse::<Page>() {
                | Ok(page) => Self::Page(page),
                | Err(_reason) => unreadable(),
            },
            | Target::Anchor(_) | Target::Endpoint(_) => unreadable(),
        }
    }
}

/// A binding, judged against the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reading
{
    /// The binding names a page, which stands so.
    Page(Page, Standing),
    /// The binding names no page.
    Unreadable(Rendered),
}

/// What the check finds of an anchor, as the report names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum State
{
    /// A cited anchor no binding names.
    Unbound,
    /// A binding whose page's blob at the vault's `HEAD` is not its blob at
    /// the bound commit.
    Drifted,
    /// A binding whose page is not at the vault's `HEAD`.
    Missing,
    /// A binding whose anchor nothing in the public checkout cites.
    Orphaned,
    /// A binding whose target the datum grammar refuses, or a hit in the
    /// public checkout that reads as no anchor.
    Malformed,
}

impl fmt::Display for State
{
    /// Write the state's name: `unbound`, `drifted`, `missing`, `orphaned`
    /// or `malformed`.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Unbound => "unbound",
            | Self::Drifted => "drifted",
            | Self::Missing => "missing",
            | Self::Orphaned => "orphaned",
            | Self::Malformed => "malformed",
        })
    }
}

/// An anchor's text as a report names it: a bound or cited anchor, or an
/// unreadable hit.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct Named(String);

/// Where a finding stands.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Place
{
    /// A line of the public checkout: where an anchor is cited.
    Cited(Line),
    /// The page a binding names.
    Page(Page),
    /// The target of a binding that names no page.
    Target(Rendered),
}

impl fmt::Display for Place
{
    /// Write `<file>:<line>`, `<vault path>@<commit>`, or the target as
    /// `view` writes it.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Cited(ref line) => fmt::Display::fmt(line, f),
            | Self::Page(ref page) => fmt::Display::fmt(page, f),
            | Self::Target(ref target) => f.write_str(&target.0),
        }
    }
}

/// One line of a report: what the check finds of an anchor, and where.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding
{
    /// The anchor.
    anchor: Named,
    /// What is found of it.
    state: State,
    /// Where.
    place: Place,
}

impl fmt::Display for Finding
{
    /// Write `<state> <anchor> <place>`, the anchor escaped as an inner
    /// field.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        let anchor = Escaped {
            text: &self.anchor.0,
            field: Field::Inner,
        };
        write!(f, "{} {anchor} {}", self.state, self.place)
    }
}

/// The check's findings, in anchor order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Report(Vec<Finding>);

impl Report
{
    /// The report of `findings`.
    ///
    /// # Specification
    /// - ensures: the findings are ordered by anchor text, then by state in the
    ///   order unbound, drifted, missing, orphaned, malformed, then by place: a
    ///   cited line by file name and then by line number, before a page by path
    ///   and then by commit, before a target by its text.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — findings given out of order, among them one anchor
    ///   both drifted and orphaned, one cited unbound on lines 10 and 9 of one
    ///   file and line 1 of another, and anchors whose order is neither their
    ///   states' nor their places', print in the specified order.
    /// - witness: `drift::tests::findings_are_reported_in_anchor_order`
    fn new(mut findings: Vec<Finding>) -> Self
    {
        findings.sort();
        Self(findings)
    }

    /// The findings, in anchor order.
    ///
    /// # Specification
    /// trivial.
    pub fn findings(&self) -> &[Finding]
    {
        &self.0
    }
}

impl fmt::Display for Report
{
    /// Write one line per finding, each ending in a newline; nothing for no
    /// findings.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        for finding in &self.0 {
            writeln!(f, "{finding}")?;
        }
        Ok(())
    }
}

/// Check `tree`'s bindings in `view` against the public checkout at `public`
/// and the vault checkout at `vault`.
///
/// # Specification
/// - requires: `view` is `tree`'s view.
/// - ensures: the report holds, for each anchor in `tree` that the public
///   checkout's tracked files cite ([`Citations::read`]) and no binding names,
///   one `unbound` finding per line citing it; for each binding whose target is
///   no page datum, a `malformed` finding at the target; for each binding whose
///   page is not at the vault's `HEAD`, a `missing` finding at the page; for
///   each binding whose page is at `HEAD` with a blob other than the one at its
///   bound commit, or that commit holds none, a `drifted` finding at the page;
///   for each binding no line cites, an `orphaned` finding at its page or
///   target; and for each hit that reads as no anchor, one `malformed` finding
///   per line holding it. It holds nothing else, so a consistent pair yields an
///   empty report.
/// - ensures: each checkout is read as the repository at its path whatever
///   repository the environment names: the public checkout's tracked files,
///   named from its top, with `git grep`, skipping binary files, and the
///   vault's objects with one `git cat-file --batch-check`.
/// - fails: [`CheckError::Run`] when git cannot be started in a checkout or its
///   input or output cannot be passed, [`CheckError::Git`] when git fails
///   there, as in a directory that is no checkout, and
///   [`CheckError::Unreadable`] when its output is not in the form asked for.
/// - panics: none.
///
/// # Errors
/// - [`CheckError::Run`]: git cannot run in a checkout.
/// - [`CheckError::Git`]: git failed in a checkout.
/// - [`CheckError::Unreadable`]: git's output cannot be read.
///
/// # Adequacy
/// - hypothesis: L3 — over a fixture pair of git repositories and one tree, a
///   consistent, a rewritten, a deleted and an uncited page's bindings and an
///   unbound citation report exactly their four lines in anchor order, alike
///   when the environment names the vault as the repository; once the pair
///   agrees the report is empty. The unit tests pin the parts no git reaches:
///   the grammar, the scan, the answers and the judgement.
/// - witness: `drift::tests::drift_names_each_finding_and_is_silent_on_a_consistent_pair`
/// - witness: `drift::tests::findings_are_reported_in_anchor_order`
pub fn check(
    tree: TreeId,
    view: &View,
    public: &std::path::Path,
    vault: &std::path::Path,
) -> Result<Report, CheckError>
{
    let citations = scan(public, tree)?;
    let readings = stand(vault, view.bindings())?;
    Ok(judge(tree, &readings, &citations))
}

/// Scan the public checkout at `public` for citations of concepts in `tree`.
///
/// # Specification
/// - ensures: runs `git grep` for the tree's anchor as a fixed string over
///   every tracked file of the repository at `public`, binary files skipped,
///   names printed from the repository's top, and reads its listing as
///   [`Citations::read`] does; no match is no citation.
/// - fails: as [`run`]; [`CheckError::Git`] when git exits other than 0, or
///   than 1 with nothing written; and as [`Citations::read`].
/// - panics: none.
///
/// # Errors
/// - [`CheckError::Run`]: git cannot run in the checkout.
/// - [`CheckError::Git`]: git failed in the checkout.
/// - [`CheckError::Unreadable`]: the listing cannot be read.
///
/// # Adequacy
/// - hypothesis: L3 — the process test's public checkout cites four concepts in
///   two files, then five; each citation's file and line is printed or cleared
///   as the bindings change, and alike with the vault named by the environment.
/// - witness: `drift::tests::drift_names_each_finding_and_is_silent_on_a_consistent_pair`
fn scan(
    public: &std::path::Path,
    tree: TreeId,
) -> Result<Citations, CheckError>
{
    let anchor = Anchor::key(tree).to_string();
    let mut command = git(public);
    command
        .args([
            "grep",
            "-I",
            "--line-number",
            "--null",
            "--no-color",
            "--no-column",
            "--full-name",
            "--fixed-strings",
            "-e",
        ])
        .arg(&anchor)
        .args(["--", ":/"]);
    let output = run(&mut command, Checkout::Public, &Input::default())?;
    let nothing =
        output.status.code() == Some(1_i32) && output.stdout.is_empty() && output.stderr.is_empty();
    if nothing {
        return Ok(Citations::default());
    }
    if !output.status.success() {
        return Err(CheckError::failed(Checkout::Public, &output));
    }
    let listing = GitOutput(String::from_utf8_lossy(&output.stdout).into_owned());
    Citations::read(&listing, tree)
}

/// Judge each of `bindings` against the vault checkout at `vault`.
///
/// # Specification
/// - ensures: one reading per binding, by path: [`Reading::Page`] with the
///   page's standing ([`Standing::of`] of its blobs at `HEAD` and at its bound
///   commit) for a target [`Datum::read`] reads as a page, and
///   [`Reading::Unreadable`] for any other. git is run once, with two queries
///   per page, even when no binding names one, so a vault checkout that is no
///   repository fails the check.
/// - fails: as [`run`]; [`CheckError::Git`] when git exits other than 0; and as
///   [`Held::answers`].
/// - panics: none.
///
/// # Errors
/// - [`CheckError::Run`]: git cannot run in the checkout.
/// - [`CheckError::Git`]: git failed in the checkout.
/// - [`CheckError::Unreadable`]: the answers cannot be read.
///
/// # Adequacy
/// - hypothesis: L3 — the process test binds a consistent, a rewritten, a
///   deleted and an uncited page, rebinds the rewritten one at `HEAD` and
///   restores the deleted one; each is printed or cleared by its standing.
/// - witness: `drift::tests::drift_names_each_finding_and_is_silent_on_a_consistent_pair`
fn stand<'view>(
    vault: &std::path::Path,
    bindings: &'view BTreeMap<Path, (PeerKey, Target)>,
) -> Result<BTreeMap<&'view Path, Reading>, CheckError>
{
    let datums: Vec<(&Path, Datum)> = bindings
        .iter()
        .map(|(path, &(_author, ref target))| (path, Datum::read(target)))
        .collect();
    let mut queries = Vec::new();
    for &(_path, ref datum) in &datums {
        if let Datum::Page(ref page) = *datum {
            queries.extend([Query::head(page), Query::bound(page)]);
        }
    }
    let input = queries.iter().fold(String::new(), |mut input, query| {
        input.push_str(&query.0);
        input.push('\n');
        input
    });
    let mut command = git(vault);
    command.args([
        "cat-file",
        "--batch-check=%(objectname) %(objecttype)",
        "--buffer",
    ]);
    let output = run(&mut command, Checkout::Vault, &Input(input))?;
    if !output.status.success() {
        return Err(CheckError::failed(Checkout::Vault, &output));
    }
    let answers = GitOutput(String::from_utf8_lossy(&output.stdout).into_owned());
    let mut held = Held::answers(&answers, &queries)?.into_iter();
    let mut readings = BTreeMap::new();
    for (path, datum) in datums {
        let reading = match datum {
            | Datum::Page(page) => {
                let (Some(head), Some(bound)) = (held.next(), held.next())
                else {
                    return Err(CheckError::Unreadable(Checkout::Vault));
                };
                Reading::Page(page, Standing::of(&head, &bound))
            },
            | Datum::Unreadable(target) => Reading::Unreadable(target),
        };
        let _first = readings.insert(path, reading);
    }
    Ok(readings)
}

/// The findings of `tree`'s bindings, judged as `readings`, against
/// `citations`.
///
/// # Specification
/// - ensures: the report [`check`] specifies, from the bindings' readings and
///   the public checkout's citations alone: `unbound` per line citing a concept
///   no reading names; `malformed` per line holding an unreadable hit;
///   `drifted`, `missing` or `malformed` at a reading's page or target as its
///   standing or its datum says, nothing for a consistent page; and `orphaned`
///   at it when no line cites its concept. A binding's anchor is the key form
///   of its path in `tree`.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — readings of a consistent, a drifted, a missing and a
///   malformed binding, one of them uncited, and citations of an unbound
///   concept on three lines and an unreadable hit yield exactly their findings;
///   a consistent cited binding yields none.
/// - witness: `drift::tests::findings_are_reported_in_anchor_order`
fn judge(
    tree: TreeId,
    readings: &BTreeMap<&Path, Reading>,
    citations: &Citations,
) -> Report
{
    let named = |path: &Path| {
        let anchor = Anchor::Path {
            authority: Authority::Key(tree),
            path: path.clone(),
        };
        Named(anchor.to_string())
    };
    let mut findings = Vec::new();
    for (path, lines) in &citations.cited {
        if !readings.contains_key(path) {
            findings.extend(lines.iter().map(|line| Finding {
                anchor: named(path),
                state: State::Unbound,
                place: Place::Cited(line.clone()),
            }));
        }
    }
    for (hit, lines) in &citations.unreadable {
        findings.extend(lines.iter().map(|line| Finding {
            anchor: Named(hit.0.clone()),
            state: State::Malformed,
            place: Place::Cited(line.clone()),
        }));
    }
    for (&path, reading) in readings {
        let place = match *reading {
            | Reading::Page(ref page, _) => Place::Page(page.clone()),
            | Reading::Unreadable(ref target) => Place::Target(target.clone()),
        };
        let mut find = |state| {
            findings.push(Finding {
                anchor: named(path),
                state,
                place: place.clone(),
            });
        };
        match *reading {
            | Reading::Page(_, Standing::Consistent) => {},
            | Reading::Page(_, Standing::Drifted) => find(State::Drifted),
            | Reading::Page(_, Standing::Missing) => find(State::Missing),
            | Reading::Unreadable(_) => find(State::Malformed),
        }
        if !citations.cited.contains_key(path) {
            find(State::Orphaned);
        }
    }
    Report::new(findings)
}

/// What a git command reads on standard input.
#[derive(Debug, Default)]
#[repr(transparent)]
struct Input(String);

/// git, to run in the checkout at `directory` as the repository there.
///
/// # Specification
/// - ensures: the command runs the `git` found on the path, in `directory`,
///   with every variable of [`REPOSITORY_VARIABLES`] removed from its
///   environment.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — the process test runs the check with `GIT_DIR`,
///   `GIT_WORK_TREE` and `GIT_INDEX_FILE` naming the vault and reads the same
///   report.
/// - witness: `drift::tests::drift_names_each_finding_and_is_silent_on_a_consistent_pair`
fn git(directory: &std::path::Path) -> Command
{
    let mut command = Command::new("git");
    command.current_dir(directory);
    for variable in REPOSITORY_VARIABLES {
        command.env_remove(variable);
    }
    command
}

/// Run `command` in `checkout`, writing `input` to its standard input while
/// its output is read whole.
///
/// # Specification
/// - ensures: returns how the command exited and everything it wrote to
///   standard output and standard error; the input is written from a second
///   thread, so a command answering line by line never blocks on a full pipe.
/// - fails: [`CheckError::Run`] when the command cannot start or its output
///   cannot be read, and when its input cannot be written to a command that
///   then exits 0; a command that fails before reading its input is reported by
///   its exit status.
/// - panics: none.
///
/// # Errors
/// - [`CheckError::Run`]: the command cannot start, or its input or output
///   cannot be passed.
///
/// # Adequacy
/// - hypothesis: L3 — the process test runs both checkouts' commands through
///   this function and reads their output.
/// - witness: `drift::tests::drift_names_each_finding_and_is_silent_on_a_consistent_pair`
fn run(
    command: &mut Command,
    checkout: Checkout,
    input: &Input,
) -> Result<Output, CheckError>
{
    let failed = |source| CheckError::Run { checkout, source };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failed)?;
    let stdin = child.stdin.take();
    let (output, written) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || match stdin {
            | Some(mut stdin) => stdin.write_all(input.0.as_bytes()),
            | None => Ok(()),
        });
        (child.wait_with_output(), writer.join())
    });
    let output = output.map_err(failed)?;
    match written {
        | Ok(Err(source)) if output.status.success() => Err(failed(source)),
        | Ok(Ok(()) | Err(_)) => Ok(output),
        | Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeMap;
    use alloc::collections::BTreeSet;
    use core::num::NonZeroU64;

    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::Path;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::Target;
    use domhringr_record_tree::TreeId;

    use super::CheckError;
    use super::Checkout;
    use super::Citations;
    use super::Datum;
    use super::FileName;
    use super::GitOutput;
    use super::Held;
    use super::Hit;
    use super::Line;
    use super::LineNumber;
    use super::ObjectName;
    use super::Page;
    use super::PagePath;
    use super::ParseDatumError;
    use super::Query;
    use super::Reading;
    use super::Rendered;
    use super::Revision;
    use super::Standing;
    use super::judge;

    /// The tree the tests cite and bind in: the all-zero key's.
    const TREE: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/";

    /// A vault commit: 40 hex digits.
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// One digit short of a commit.
    const SHORT: &str = "0123456789abcdef0123456789abcdef0123456";

    /// One digit over a commit.
    const LONG: &str = "0123456789abcdef0123456789abcdef012345678";

    /// The tree [`TREE`] names.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        match TREE.parse::<Anchor>().unwrap() {
            | Anchor::Tree(domhringr_record_tree::Authority::Key(tree)) => tree,
            | other => panic!("not a tree: {other:?}"),
        }
    }

    #[test]
    fn a_page_datum_reads_its_path_and_commit()
    {
        let page = |path: &str| Page {
            path: PagePath(path.into()),
            revision: Revision(COMMIT.into()),
        };
        for path in [
            "index.md",
            "pages/A page.md",
            "people/a@b.md",
            ".obsidian/workspace.json",
        ] {
            let datum = format!("vault:{path}@{COMMIT}");
            assert_eq!(
                datum.parse::<Page>().unwrap(),
                page(path),
                "{datum} reads to its path and commit"
            );
        }
        assert_eq!(
            page("pages/A page.md").to_string(),
            format!("pages/A page.md@{COMMIT}"),
            "a page reads as a report names it"
        );
    }

    #[test]
    fn a_malformed_page_datum_is_refused_by_name()
    {
        let cases = [
            (format!("Vault:a.md@{COMMIT}"), ParseDatumError::Scheme),
            (format!("a.md@{COMMIT}"), ParseDatumError::Scheme),
            (String::from("vault:a.md"), ParseDatumError::Separator),
            (format!("vault:a.md@{SHORT}"), ParseDatumError::Commit),
            (format!("vault:a.md@{LONG}"), ParseDatumError::Commit),
            (
                format!("vault:a.md@{}", COMMIT.to_uppercase()),
                ParseDatumError::Commit,
            ),
            (format!("vault:a.md@{SHORT}g"), ParseDatumError::Commit),
            (format!("vault:a.md@{COMMIT}@HEAD"), ParseDatumError::Commit),
            (format!("vault:a\nb.md@{COMMIT}"), ParseDatumError::Control),
            (format!("vault:@{COMMIT}"), ParseDatumError::EmptySegment),
            (
                format!("vault:/a.md@{COMMIT}"),
                ParseDatumError::EmptySegment,
            ),
            (format!("vault:a/@{COMMIT}"), ParseDatumError::EmptySegment),
            (
                format!("vault:a//b.md@{COMMIT}"),
                ParseDatumError::EmptySegment,
            ),
            (format!("vault:./a.md@{COMMIT}"), ParseDatumError::Relative),
            (
                format!("vault:a/../b.md@{COMMIT}"),
                ParseDatumError::Relative,
            ),
        ];
        for (datum, reason) in cases {
            assert_eq!(
                datum.parse::<Page>(),
                Err(reason),
                "{datum:?} is refused as {reason:?}"
            );
        }
    }

    #[test]
    fn a_target_that_names_no_page_is_kept_as_view_writes_it()
    {
        let datum = format!("vault:pages/A page.md@{COMMIT}");
        assert_eq!(
            Datum::read(&Target::Datum(datum.clone())),
            Datum::Page(datum.parse().unwrap()),
            "a page datum reads as its page"
        );
        let state = tempfile::tempdir().unwrap();
        let identity =
            Identity::load_or_create(&StateDir::from(state.path().to_path_buf())).unwrap();
        let endpoint = identity.endpoint_key();
        let cases = [
            (
                Target::Datum(String::from("vault:a\nb.md@HEAD")),
                String::from(r"datum vault:a\nb.md@HEAD"),
            ),
            (
                Target::Anchor(Anchor::key(tree())),
                format!("anchor {TREE}"),
            ),
            (Target::Endpoint(endpoint), format!("endpoint {endpoint}")),
        ];
        for (target, written) in cases {
            assert_eq!(
                Datum::read(&target),
                Datum::Unreadable(Rendered(written)),
                "{target:?} names no page"
            );
        }
    }

    #[test]
    fn a_scan_reads_each_citation_with_its_file_and_line()
    {
        let tree = tree();
        let commit = "07".repeat(32);
        let listing = [
            format!("README.md\x009\x00See `{TREE}alpha` and <{TREE}beta>, then {TREE}alpha again.\n"),
            format!(
                "README.md\x0010\x00Read [it]({TREE}gamma/delta), or {TREE}epsilon, or {TREE}zeta.\n"
            ),
            format!(
                "docs/a:b\nc.md\x001\x00The tree {TREE} and {TREE}.commit/{commit} cite nothing; nor does domhringr://example.test/alpha.\n"
            ),
            format!("docs/a:b\nc.md\x002\x00Broken: {TREE}a//b {TREE}.hidden {TREE}.commit/0123abcd"),
        ]
        .concat();
        let line = |file: &str, number: u64| Line {
            file: FileName(file.into()),
            number: LineNumber(NonZeroU64::new(number).unwrap()),
        };
        let lines = |file: &str, number: u64| BTreeSet::from([line(file, number)]);
        let expected = Citations {
            cited: BTreeMap::from(
                [
                    ("alpha", lines("README.md", 9)),
                    ("beta", lines("README.md", 9)),
                    ("gamma/delta", lines("README.md", 10)),
                    ("epsilon", lines("README.md", 10)),
                    ("zeta", lines("README.md", 10)),
                ]
                .map(|(path, lines)| (path.parse::<Path>().unwrap(), lines)),
            ),
            unreadable: BTreeMap::from(
                ["a//b", ".hidden", ".commit/0123abcd"]
                    .map(|rest| (Hit(format!("{TREE}{rest}")), lines("docs/a:b\nc.md", 2))),
            ),
        };
        assert_eq!(
            Citations::read(&GitOutput(listing), tree).unwrap(),
            expected,
            "every citation is read with its file and line, and nothing else"
        );
        for (listing, case) in [
            (
                "README.md\x00no second NUL\n",
                "a line without its second NUL",
            ),
            ("README.md\x000\x00text\n", "a line numbered 0"),
        ] {
            assert!(
                matches!(
                    Citations::read(&GitOutput(listing.into()), tree),
                    Err(CheckError::Unreadable(Checkout::Public))
                ),
                "{case} is refused"
            );
        }
    }

    #[test]
    fn the_vault_answers_each_query_with_a_blob_or_an_absence()
    {
        let queries = [
            "HEAD:a.md",
            "0123456789abcdef0123456789abcdef01234567:a.md",
            "HEAD:pages/A page.md",
            "HEAD:pages",
            "HEAD:vendor",
        ]
        .map(|query| Query(query.into()));
        let (blob, other) = ("a".repeat(40), "b".repeat(40));
        let answers = format!(
            "{blob} blob\n{other} blob\nHEAD:pages/A page.md missing\n{blob} tree\n{other} commit\n"
        );
        assert_eq!(
            Held::answers(&GitOutput(answers.clone()), &queries).unwrap(),
            vec![
                Held::Blob(ObjectName(blob.clone())),
                Held::Blob(ObjectName(other)),
                Held::Absent,
                Held::Absent,
                Held::Absent,
            ],
            "a blob is the page; a missing path, a tree and a commit are none"
        );
        let short = answers.trim_end().rsplit_once('\n').unwrap().0.to_owned();
        for (answers, case) in [
            (short, "one answer short"),
            (format!("{answers}{blob} blob\n"), "one answer over"),
            (
                answers.replacen(" tree", " trees", 1),
                "an unknown object type",
            ),
            (
                answers.replacen("HEAD:pages/A page.md missing", "HEAD:b.md missing", 1),
                "a missing answer echoing another query",
            ),
        ] {
            assert!(
                matches!(
                    Held::answers(&GitOutput(answers), &queries),
                    Err(CheckError::Unreadable(Checkout::Vault))
                ),
                "{case} is refused"
            );
        }
    }

    #[test]
    fn a_page_stands_by_its_blobs_at_head_and_at_its_commit()
    {
        let blob = |name: &str| Held::Blob(ObjectName(name.repeat(40)));
        let cases = [
            (blob("a"), blob("a"), Standing::Consistent),
            (blob("a"), blob("b"), Standing::Drifted),
            (blob("a"), Held::Absent, Standing::Drifted),
            (Held::Absent, blob("a"), Standing::Missing),
            (Held::Absent, Held::Absent, Standing::Missing),
        ];
        for (head, bound, standing) in cases {
            assert_eq!(
                Standing::of(&head, &bound),
                standing,
                "{head:?} at HEAD against {bound:?} at the bound commit"
            );
        }
    }

    #[test]
    fn findings_are_reported_in_anchor_order()
    {
        let tree = tree();
        let page = |path: &str| Page {
            path: PagePath(path.into()),
            revision: Revision(COMMIT.into()),
        };
        let line = |file: &str, number: u64| Line {
            file: FileName(file.into()),
            number: LineNumber(NonZeroU64::new(number).unwrap()),
        };
        let paths = ["consistent", "drifted", "missing", "odd one", "unbound"]
            .map(|path| path.parse::<Path>().unwrap());
        let [consistent, drifted, missing, odd, unbound] = paths.each_ref();
        let readings = BTreeMap::from([
            (
                consistent,
                Reading::Page(page("a.md"), Standing::Consistent),
            ),
            (
                drifted,
                Reading::Page(page("pages/Drifted page.md"), Standing::Drifted),
            ),
            (missing, Reading::Page(page("m.md"), Standing::Missing)),
            (
                odd,
                Reading::Unreadable(Rendered(String::from("datum vault:x"))),
            ),
        ]);
        let citations = Citations {
            cited: BTreeMap::from([
                (consistent.clone(), BTreeSet::from([line("README.md", 1)])),
                (missing.clone(), BTreeSet::from([line("README.md", 2)])),
                (
                    unbound.clone(),
                    BTreeSet::from([
                        line("docs/b.md", 10),
                        line("docs/b.md", 9),
                        line("docs/a\\b\nc.md", 1),
                    ]),
                ),
            ]),
            unreadable: BTreeMap::from([(
                Hit(format!("{TREE}a//b")),
                BTreeSet::from([line("README.md", 3)]),
            )]),
        };
        let report = judge(tree, &readings, &citations);
        let expected = [
            format!("malformed {TREE}a//b README.md:3"),
            format!("drifted {TREE}drifted pages/Drifted page.md@{COMMIT}"),
            format!("orphaned {TREE}drifted pages/Drifted page.md@{COMMIT}"),
            format!("missing {TREE}missing m.md@{COMMIT}"),
            format!(r"orphaned {TREE}odd\u{{20}}one datum vault:x"),
            format!(r"malformed {TREE}odd\u{{20}}one datum vault:x"),
            format!(r"unbound {TREE}unbound docs/a\\b\nc.md:1"),
            format!("unbound {TREE}unbound docs/b.md:9"),
            format!("unbound {TREE}unbound docs/b.md:10"),
        ]
        .map(|line| format!("{line}\n"))
        .concat();
        assert_eq!(
            report.to_string(),
            expected,
            "one line per finding, by anchor, then state, then place"
        );
        assert_eq!(
            report.findings().len(),
            9,
            "nothing beyond the lines printed is found"
        );
        let agreed = BTreeMap::from([(
            consistent,
            Reading::Page(page("a.md"), Standing::Consistent),
        )]);
        let cited = Citations {
            cited: BTreeMap::from([(consistent.clone(), BTreeSet::from([line("README.md", 1)]))]),
            unreadable: BTreeMap::new(),
        };
        let report = judge(tree, &agreed, &cited);
        assert!(
            report.findings().is_empty() && report.to_string().is_empty(),
            "a consistent pair reports nothing"
        );
    }
}
