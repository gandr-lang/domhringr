//! `domhringr-peer`: one record-plane peer over a state directory. It opens a
//! sedimentree under a key of the tree's own, grants write authority on it,
//! writes notes to it, binds paths in it, claims DNS names for it, introduces
//! other trees in it by label, resolves an anchor or a commit to what it
//! names, prints the view every peer holding the same commits folds them to,
//! reads the tree's heads, and syncs the tree with another peer over iroh.
//!
//! ```text
//! domhringr-peer --state <dir> id
//! domhringr-peer --state <dir> serve [--port <port>]
//! domhringr-peer --state <dir> open
//! domhringr-peer --state <dir> grant <tree> <peer-id>
//! domhringr-peer --state <dir> note <tree> <text>
//! domhringr-peer --state <dir> bind <anchor> <target>
//! domhringr-peer --state <dir> claim <tree> <domain>
//! domhringr-peer --state <dir> introduce <tree> <label> <tree>
//! domhringr-peer --state <dir> whence <name> [--witness <domain>=<tree-id>]... [--in <tree>]
//! domhringr-peer --state <dir> view <tree>
//! domhringr-peer --state <dir> heads <tree>
//! domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree> [--at <ip:port>]
//! ```
//!
//! A tree is named by its anchor, `domhringr://<tree-id>/`, whose tree id is
//! the tree key's 52 z-base-32 characters; a path in the tree by
//! `domhringr://<tree-id>/<segment>/…/<segment>`; and a commit in it by
//! `domhringr://<tree-id>/.commit/<commit-id>`. A segment beginning with `.`
//! is reserved for forms the scheme names, so no path holds one. `whence`
//! reads each in three forms: the key form above; the DNS form,
//! `domhringr://<domain>/…`, whose DNS name contains a dot and resolves to the
//! one tree that both its witness names and whose root claims it — the
//! `_domhringr.<domain>` TXT records, or the trees `--witness` names in their
//! place; and the label form, `domhringr://<label>/…`, whose label has no dot
//! and resolves through the introductions of the `--in` tree alone. `whence`
//! also reads a commit id abbreviated to a prefix of at least 8 of its hex
//! digits that no other commit of the tree begins with, and prints a commit as
//! `commit <commit-id> admitted`, `commit <commit-id> refused <reason>`, or
//! `unknown` when the tree holds no such commit. A target is `anchor
//! <anchor>`, a tree, a path or a commit in any of the three forms with the
//! commit id whole, `endpoint <endpoint-id>` or `datum <text>`. Peer, endpoint
//! and commit ids are 64 hex digits.
//!
//! The state directory holds the peer's two keys, the key of each tree it
//! opened, and its tree store, all created on first use. A command holds the
//! store exclusively while it runs, so every command but `id` fails while
//! `serve` runs on the same directory; `id` reads only the keys and runs beside
//! it.
//!
//! The exit status is 0 on success, 1 when the command fails, and 2 for a
//! command line that cannot be run; diagnostics go to standard error.

// The opt-in quenchant lints: absence named by `Maybe` in signatures and in
// fields outside wire form, arithmetic on nominal types. Selected here because
// Dylint's `-D` cannot reach rustc through `cargo dylint`; see
// `.config/mise/tasks/mise-tasks-check.toml`.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]

use core::error::Error;
use core::fmt;
use core::net::AddrParseError;
use core::net::SocketAddr;
use core::str::FromStr;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use domhringr_record_tree::AcceptError;
use domhringr_record_tree::Address;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::Authority;
use domhringr_record_tree::BindError;
use domhringr_record_tree::BindPort;
use domhringr_record_tree::CommitError;
use domhringr_record_tree::Dns;
use domhringr_record_tree::Domain;
use domhringr_record_tree::HeadsError;
use domhringr_record_tree::Identity;
use domhringr_record_tree::IdentityError;
use domhringr_record_tree::Label;
use domhringr_record_tree::OpenError;
use domhringr_record_tree::ParseAnchorError;
use domhringr_record_tree::ParseDomainError;
use domhringr_record_tree::ParseIdError;
use domhringr_record_tree::ParseLabelError;
use domhringr_record_tree::ParsePortError;
use domhringr_record_tree::Path;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::RandomError;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Reference;
use domhringr_record_tree::RemotePeer;
use domhringr_record_tree::Scope;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::Static;
use domhringr_record_tree::SyncError;
use domhringr_record_tree::Target;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::TreeKey;
use domhringr_record_tree::UdpPort;
use domhringr_record_tree::ViewError;
use domhringr_record_tree::WhenceError;

/// The synopsis written after a usage error.
const USAGE: &str = "\
usage: domhringr-peer --state <dir> id
       domhringr-peer --state <dir> serve [--port <port>]
       domhringr-peer --state <dir> open
       domhringr-peer --state <dir> grant <tree> <peer-id>
       domhringr-peer --state <dir> note <tree> <text>
       domhringr-peer --state <dir> bind <anchor> <target>
       domhringr-peer --state <dir> claim <tree> <domain>
       domhringr-peer --state <dir> introduce <tree> <label> <tree>
       domhringr-peer --state <dir> whence <name> [--witness <domain>=<tree-id>]... [--in <tree>]
       domhringr-peer --state <dir> view <tree>
       domhringr-peer --state <dir> heads <tree>
       domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree> [--at <ip:port>]
where  <tree>   is domhringr://<tree-id>/
       <anchor> is domhringr://<tree-id>/<segment>/.../<segment>
       <commit> is domhringr://<tree-id>/.commit/<commit-id>, the id whole, or for whence
                a prefix of at least 8 hex digits no other commit of the tree begins with
       <name>   is a <tree>, an <anchor> or a <commit> in one of three forms: by key, as
                above; by DNS name, <domain> in place of <tree-id>: a name with a dot,
                resolved through its witness and the tree's claim; or by label, <label>
                in place of <tree-id>: a name without a dot, resolved in the --in tree
       <target> is anchor <name> | endpoint <endpoint-id> | datum <text>
A segment beginning with . is reserved for the forms above: no path holds one.
";

/// The exit status of a command line that cannot be run.
const USAGE_STATUS: u8 = 2;

/// The command a command line names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verb
{
    /// Print the peer's ids.
    Id,
    /// Accept peers until killed.
    Serve,
    /// Open a tree.
    Open,
    /// Grant a peer write authority on a tree.
    Grant,
    /// Write a note to a tree.
    Note,
    /// Bind a path in a tree to a target.
    Bind,
    /// Claim a DNS name for a tree.
    Claim,
    /// Introduce a tree by a label in another.
    Introduce,
    /// Print what an anchor or a commit resolves to.
    Whence,
    /// Print a tree's view.
    View,
    /// Print a tree's heads.
    Heads,
    /// Sync a tree with a remote peer.
    Sync,
}

impl fmt::Display for Verb
{
    /// Write the verb followed by the operands it takes.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Id => "id",
            | Self::Serve => "serve [--port <port>]",
            | Self::Open => "open",
            | Self::Grant => "grant <tree> <peer-id>",
            | Self::Note => "note <tree> <text>",
            | Self::Bind => "bind <anchor> anchor|endpoint|datum <target>",
            | Self::Claim => "claim <tree> <domain>",
            | Self::Introduce => "introduce <tree> <label> <tree>",
            | Self::Whence => "whence <name> [--witness <domain>=<tree-id>]... [--in <tree>]",
            | Self::View => "view <tree>",
            | Self::Heads => "heads <tree>",
            | Self::Sync => "sync <endpoint-id> <peer-id> <tree> [--at <ip:port>]",
        })
    }
}

/// The operand an id or anchor is read for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operand
{
    /// The tree to grant on, write to, claim for, introduce in, read, sync,
    /// or read a label in, or the tree introduced.
    Tree,
    /// The anchor to bind or resolve.
    Anchor,
    /// A bind's target anchor.
    Target,
    /// The remote's iroh endpoint id, or a bind's target endpoint.
    Endpoint,
    /// The remote's or the grantee's subduction peer id.
    Peer,
    /// The tree a witness supplied by hand names.
    Witness,
}

impl fmt::Display for Operand
{
    /// Write the operand's name as a diagnostic reads it.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Tree => "tree anchor",
            | Self::Anchor => "anchor",
            | Self::Target => "target anchor",
            | Self::Endpoint => "endpoint id",
            | Self::Peer => "peer id",
            | Self::Witness => "witness's tree id",
        })
    }
}

/// A command with its operands read.
#[derive(Debug, PartialEq, Eq)]
enum Command
{
    /// Print the endpoint id, then the peer id.
    Id,
    /// Bind on `port`, print the ids and `listening`, then accept peers until
    /// killed.
    Serve
    {
        /// The UDP port the endpoint binds.
        port: BindPort,
    },
    /// Mint a tree key, commit the tree's Open proved by it, and print the
    /// tree's anchor.
    Open,
    /// Commit a grant on `tree` to `to` and print the commit id.
    Grant
    {
        /// The tree granted on.
        tree: TreeId,
        /// The peer granted write authority.
        to: PeerKey,
    },
    /// Commit a note of `text` to `tree` and print the commit id.
    Note
    {
        /// The tree written to.
        tree: TreeId,
        /// The note's text.
        text: String,
    },
    /// Commit a bind of `path` in `tree` to `target` and print the commit id.
    Bind
    {
        /// The tree the path is in.
        tree: TreeId,
        /// The path bound.
        path: Path,
        /// What the path is bound to.
        target: Target,
    },
    /// Commit a claim of `domain` for `tree` and print the commit id.
    Claim
    {
        /// The tree the name is claimed for.
        tree: TreeId,
        /// The DNS name claimed.
        domain: Domain,
    },
    /// Commit an introduction of `introduced` by `label` in `tree` and print
    /// the commit id.
    Introduce
    {
        /// The tree the introduction is made in.
        tree: TreeId,
        /// The label introduced.
        label: Label,
        /// The tree the label names.
        introduced: TreeId,
    },
    /// Print what `reference` resolves to, asking `witnessing` for a DNS name's
    /// candidates and reading a label in `scope`.
    Whence
    {
        /// The anchor or the commit resolved.
        reference: Reference,
        /// What names a DNS name's candidate trees.
        witnessing: Witnessing,
        /// The tree a label is read in.
        scope: Scope,
    },
    /// Print `tree`'s view.
    View
    {
        /// The tree folded.
        tree: TreeId,
    },
    /// Print `tree`'s heads.
    Heads
    {
        /// The tree read.
        tree: TreeId,
    },
    /// Sync `tree` with `remote` and print the heads after it, then the path.
    Sync
    {
        /// The peer dialed.
        remote: RemotePeer,
        /// The tree synced.
        tree: TreeId,
    },
}

/// What names a DNS name's candidate trees for one `whence`.
#[derive(Debug, PartialEq, Eq)]
enum Witnessing
{
    /// The `_domhringr.<domain>` TXT records.
    Dns,
    /// The trees `--witness` named, in place of DNS.
    ByHand(Static),
}

/// A command line, read.
#[derive(Debug, PartialEq, Eq)]
struct Invocation
{
    /// The peer's state directory.
    state: StateDir,
    /// What to do with it.
    command: Command,
}

/// Why a command line cannot be run.
#[derive(Debug, thiserror::Error)]
enum UsageError
{
    /// An option other than `--state`, or `--state` without its value.
    #[error(transparent)]
    Arguments(#[from] lexopt::Error),
    /// No command follows the options.
    #[error("no command given")]
    NoCommand,
    /// The command is not one this binary has.
    #[error("unknown command {0:?}")]
    Command(OsString),
    /// `--state` is absent.
    #[error("no state directory given: --state <dir>")]
    State,
    /// The command has too few or too many operands.
    #[error("expected: {0}")]
    Operands(Verb),
    /// An operand is not the id it stands for.
    #[error("cannot read the {operand}")]
    Operand
    {
        /// The operand.
        operand: Operand,
        /// Why it is not an id.
        #[source]
        source: ParseIdError,
    },
    /// An operand is not an anchor.
    #[error("cannot read the {operand}")]
    Anchor
    {
        /// The operand.
        operand: Operand,
        /// Why it is not an anchor.
        #[source]
        source: ParseAnchorError,
    },
    /// A tree operand is an anchor naming a path or a commit.
    #[error("the tree anchor names a path or a commit: expected domhringr://<tree-id>/")]
    NotTree,
    /// A tree operand names its tree by a DNS name or a label where only the
    /// key form is read.
    #[error("the tree is named by its key here: expected domhringr://<tree-id>/")]
    NotKey,
    /// The anchor to bind names no path: it is bare or names a commit.
    #[error("the anchor names no path to bind: expected domhringr://<tree-id>/<path>")]
    NoPath,
    /// A DNS name operand is not a DNS name.
    #[error("cannot read the DNS name")]
    Domain(#[source] ParseDomainError),
    /// A label operand is not a label.
    #[error("cannot read the label")]
    Label(#[source] ParseLabelError),
    /// A `--witness` value has no `=` between its DNS name and its tree id.
    #[error("a witness is <domain>=<tree-id>")]
    Witness,
    /// A bind's target kind is not one this binary has.
    #[error("unknown target kind {0:?}: expected anchor, endpoint or datum")]
    Target(OsString),
    /// A note's text, a datum, a DNS name or a label is not UTF-8.
    #[error("the text is not UTF-8: {0:?}")]
    Text(OsString),
    /// `--port`'s value is not a UDP port.
    #[error("cannot read the port")]
    Port(#[source] ParsePortError),
    /// `--at`'s value is not an IP address and port.
    #[error("cannot read the address")]
    At(#[source] AddrParseError),
}

/// Why a command failed once its command line was read.
#[derive(Debug, thiserror::Error)]
enum RunError
{
    /// The async runtime cannot start.
    #[error("cannot start the async runtime")]
    Runtime(#[source] std::io::Error),
    /// The identity cannot be read or created.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The tree store cannot be opened.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// The endpoint cannot bind.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// The endpoint closed while serving.
    #[error("the endpoint closed while serving")]
    Closed,
    /// No operation fence can be drawn for a receipt.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// The commit cannot be appended.
    #[error(transparent)]
    Commit(#[from] CommitError),
    /// The view cannot be folded.
    #[error(transparent)]
    View(#[from] ViewError),
    /// The anchor does not resolve.
    #[error(transparent)]
    Whence(#[from] WhenceError),
    /// The heads cannot be read.
    #[error(transparent)]
    Heads(#[from] HeadsError),
    /// The sync failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// Standard output cannot be written.
    #[error("cannot write to standard output")]
    Output(#[source] std::io::Error),
    /// Standard error cannot be written.
    #[error("cannot write to standard error")]
    Diagnostics(#[source] std::io::Error),
}

/// Read the command line that follows the program name.
///
/// # Specification
/// - ensures: accepts `--state <dir>` (or `--state=<dir>`; the last one given
///   wins) followed by a verb and exactly the operands that verb takes, or, for
///   `serve`, the options [`serve_port`] reads, or, for `sync` and `whence`,
///   what [`sync_command`] and [`whence_command`] read. Other verbs' operands
///   are taken verbatim, so a note's text or a datum beginning with `-` is a
///   text, not an option. A tree operand is a bare anchor in the key form,
///   `bind`'s anchor names a path in the key form, `claim`'s DNS name and
///   `introduce`'s label are read as [`read_name`] reads them, and `bind`'s
///   target is read as [`read_target`] reads it.
/// - fails: [`UsageError::Arguments`] for any option but `--state` or for
///   `--state` without a value, [`UsageError::NoCommand`] when no verb follows
///   the options, [`UsageError::Command`] for an unknown verb,
///   [`UsageError::State`] when `--state` is absent, [`UsageError::Operands`]
///   for too few or too many operands, checked before any operand is read,
///   [`UsageError::Operand`] for an id that does not parse,
///   [`UsageError::Anchor`] for an anchor that does not parse,
///   [`UsageError::NotTree`] for a tree operand naming a path or a commit,
///   [`UsageError::NotKey`] for a tree operand or an anchor to bind naming its
///   tree by a DNS name or a label, [`UsageError::NoPath`] for an anchor to
///   bind that is bare or names a commit, [`UsageError::Text`] for a note's
///   text, a DNS name or a label that is not UTF-8, [`UsageError::Domain`] and
///   [`UsageError::Label`] for a DNS name or a label that does not parse, as
///   [`read_target`] for `bind`'s target, as [`serve_port`] for `serve`, and as
///   [`sync_command`] and [`whence_command`] for `sync` and `whence`.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or `--state` lacks a value.
/// - [`UsageError::NoCommand`]: no verb follows the options.
/// - [`UsageError::Command`]: the verb is unknown.
/// - [`UsageError::State`]: `--state` is absent.
/// - [`UsageError::Operands`]: the verb's operand count is wrong.
/// - [`UsageError::Operand`]: an operand is not an id.
/// - [`UsageError::Anchor`]: an operand is not an anchor.
/// - [`UsageError::NotTree`]: a tree operand names a path or a commit.
/// - [`UsageError::NotKey`]: a tree operand or the anchor to bind is not in the
///   key form.
/// - [`UsageError::NoPath`]: the anchor to bind names no path.
/// - [`UsageError::Domain`]: the DNS name to claim does not parse.
/// - [`UsageError::Label`]: the label to introduce does not parse.
/// - [`UsageError::Witness`]: a `--witness` value has no `=`.
/// - [`UsageError::Target`]: the bind's target kind is unknown.
/// - [`UsageError::Text`]: the note's text, a datum, a DNS name or a label is
///   not UTF-8.
/// - [`UsageError::Port`]: `serve`'s port is not a UDP port.
/// - [`UsageError::At`]: `sync`'s address is not an IP address and port.
///
/// # Adequacy
/// - hypothesis: L3 — each verb with its operands, every bind target kind, a
///   bare, a path and a commit anchor to resolve in each of the three forms and
///   an abbreviated commit, both `--state` spellings, `serve` with and without
///   a port, `sync` with and without an address, `whence` with and without
///   witnesses and a scope, and a dash-leading note and datum separate the
///   accepted lines, and one line per refusal pins which refusal each
///   malformation gets, including an arity error that wins over a malformed
///   operand.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn parse(mut arguments: lexopt::Parser) -> Result<Invocation, UsageError>
{
    let mut state = None;
    let word = loop {
        match arguments.next()? {
            | Some(lexopt::Arg::Long("state")) => state = Some(arguments.value()?),
            | Some(lexopt::Arg::Value(word)) => break word,
            | Some(other) => return Err(UsageError::from(other.unexpected())),
            | None => return Err(UsageError::NoCommand),
        }
    };
    let verb = verb(word)?;
    let state = StateDir::from(PathBuf::from(state.ok_or(UsageError::State)?));
    if verb == Verb::Serve {
        let port = serve_port(&mut arguments)?;
        let command = Command::Serve { port };
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Sync {
        let command = sync_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Whence {
        let command = whence_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    let mut raw = arguments.raw_args()?;
    // One more operand than any verb takes is read, so that a surplus is seen.
    let operands = (raw.next(), raw.next(), raw.next(), raw.next());
    let command = match (verb, operands) {
        | (Verb::Id, (None, None, None, None)) => Command::Id,
        | (Verb::Open, (None, None, None, None)) => Command::Open,
        | (Verb::Grant, (Some(tree), Some(to), None, None)) => {
            let tree = read_tree(&tree)?;
            Command::Grant {
                tree,
                to: read_id(&to, Operand::Peer)?,
            }
        },
        | (Verb::Note, (Some(tree), Some(text), None, None)) => Command::Note {
            tree: read_tree(&tree)?,
            text: text.into_string().map_err(UsageError::Text)?,
        },
        | (Verb::Bind, (Some(anchor), Some(kind), Some(value), None)) => {
            let anchor = read_anchor::<Anchor>(&anchor, Operand::Anchor)?;
            let Anchor::Path { authority, path } = anchor
            else {
                return Err(UsageError::NoPath);
            };
            let Authority::Key(tree) = authority
            else {
                return Err(UsageError::NotKey);
            };
            let target = read_target(&kind, value)?;
            Command::Bind { tree, path, target }
        },
        | (Verb::Claim, (Some(tree), Some(domain), None, None)) => Command::Claim {
            tree: read_tree(&tree)?,
            domain: read_name(domain, UsageError::Domain)?,
        },
        | (Verb::Introduce, (Some(tree), Some(label), Some(introduced), None)) => {
            Command::Introduce {
                tree: read_tree(&tree)?,
                label: read_name(label, UsageError::Label)?,
                introduced: read_tree(&introduced)?,
            }
        },
        | (Verb::View, (Some(tree), None, None, None)) => Command::View {
            tree: read_tree(&tree)?,
        },
        | (Verb::Heads, (Some(tree), None, None, None)) => Command::Heads {
            tree: read_tree(&tree)?,
        },
        | (verb, _) => return Err(UsageError::Operands(verb)),
    };
    Ok(Invocation { state, command })
}

/// Read `sync`'s operands and options from what follows the verb.
///
/// # Specification
/// - ensures: accepts the endpoint id, the peer id and the tree anchor, in that
///   order, with `--at <ip:port>` (or `--at=<ip:port>`; the last one given
///   wins) anywhere among them, which names the remote's direct address; with
///   no `--at` the remote is looked up by its endpoint id.
/// - fails: [`UsageError::Arguments`] for any other option or for `--at`
///   without a value, [`UsageError::At`] for a value that is not an IP address
///   and port, [`UsageError::Operands`] for other than three operands, checked
///   before any operand is read, and [`UsageError::Operand`],
///   [`UsageError::Anchor`] and [`UsageError::NotTree`] for an operand that is
///   not what it stands for.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or `--at` lacks a value.
/// - [`UsageError::At`]: the address is not an IP address and port.
/// - [`UsageError::Operands`]: there are not three operands.
/// - [`UsageError::Operand`]: the endpoint id or the peer id does not parse.
/// - [`UsageError::Anchor`]: the tree anchor does not parse.
/// - [`UsageError::NotTree`]: the tree anchor names a path.
///
/// # Adequacy
/// - hypothesis: L3 — no option, both `--at` spellings and an `--at` before the
///   operands are read to their addresses, and a malformed address, a missing
///   value, a surplus operand and each malformed operand meet their own
///   refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn sync_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut address = Address::Lookup;
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("at") => {
                let value = arguments.value()?;
                let direct = value.to_string_lossy().parse::<SocketAddr>();
                address = Address::Direct(direct.map_err(UsageError::At)?);
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let mut operands = operands.into_iter();
    match (
        operands.next(),
        operands.next(),
        operands.next(),
        operands.next(),
    ) {
        | (Some(endpoint), Some(peer), Some(tree), None) => {
            let endpoint = read_id(&endpoint, Operand::Endpoint)?;
            let peer = read_id(&peer, Operand::Peer)?;
            Ok(Command::Sync {
                remote: RemotePeer::new(endpoint, peer, address),
                tree: read_tree(&tree)?,
            })
        },
        | _ => Err(UsageError::Operands(Verb::Sync)),
    }
}

/// Read `whence`'s operand and options from what follows the verb.
///
/// # Specification
/// - ensures: accepts one reference, an anchor or a commit in any of the three
///   forms, the commit's id whole or abbreviated, with any number of `--witness
///   <domain>=<tree-id>` and at most one effective `--in <tree>` (or
///   `--in=<tree>`; the last one given wins) anywhere around it. With no
///   `--witness`, a DNS name's candidates are its `_domhringr.<domain>` TXT
///   records; with any, they are the trees the `--witness` values name for it,
///   and DNS is not asked. With no `--in`, a label is read in no tree.
/// - fails: [`UsageError::Arguments`] for any other option or for an option
///   without a value, [`UsageError::Witness`], [`UsageError::Text`],
///   [`UsageError::Domain`] and [`UsageError::Operand`] as [`read_witness`] for
///   a malformed witness, [`UsageError::Anchor`], [`UsageError::NotTree`] and
///   [`UsageError::NotKey`] as [`read_tree`] for a malformed `--in`,
///   [`UsageError::Operands`] for other than one operand, checked before the
///   operand is read, and [`UsageError::Anchor`] for an operand that is not a
///   reference.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or an option lacks a value.
/// - [`UsageError::Witness`], [`UsageError::Text`], [`UsageError::Domain`],
///   [`UsageError::Operand`]: as [`read_witness`].
/// - [`UsageError::NotTree`], [`UsageError::NotKey`]: as [`read_tree`] for
///   `--in`.
/// - [`UsageError::Operands`]: there is not one operand.
/// - [`UsageError::Anchor`]: the reference or `--in`'s tree does not parse.
///
/// # Adequacy
/// - hypothesis: L3 — a key, a DNS and a label anchor, a commit whole and
///   abbreviated, two witnesses for one name and a repeated `--in` are read to
///   their command, and a witness without `=`, with a malformed name or tree
///   id, an `--in` naming a path, a reserved segment, a commit id too short to
///   read, a missing operand and a surplus one each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn whence_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut scope = Scope::Unscoped;
    let mut witnessed = Vec::new();
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("witness") => {
                let value = arguments.value()?;
                witnessed.push(read_witness(value)?);
            },
            | lexopt::Arg::Long("in") => {
                let value = arguments.value()?;
                scope = Scope::In(read_tree(&value)?);
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let witnessing = if witnessed.is_empty() {
        Witnessing::Dns
    }
    else {
        Witnessing::ByHand(witnessed.into_iter().collect())
    };
    let mut operands = operands.into_iter();
    match (operands.next(), operands.next()) {
        | (Some(reference), None) => Ok(Command::Whence {
            reference: read_anchor(&reference, Operand::Anchor)?,
            witnessing,
            scope,
        }),
        | _ => Err(UsageError::Operands(Verb::Whence)),
    }
}

/// Read the DNS name and the tree a `--witness` value pairs.
///
/// # Specification
/// - ensures: splits `value` at its first `=`, reads the DNS name before it as
///   [`read_name`] does and the tree id after it as [`read_id`] does, and
///   yields both.
/// - fails: [`UsageError::Text`] for a value that is not UTF-8,
///   [`UsageError::Witness`] for one without `=`, [`UsageError::Domain`] for a
///   DNS name that does not parse, and [`UsageError::Operand`] naming the
///   witness's tree id for a tree id that does not parse.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Text`]: the value is not UTF-8.
/// - [`UsageError::Witness`]: the value has no `=`.
/// - [`UsageError::Domain`]: the DNS name does not parse.
/// - [`UsageError::Operand`]: the tree id does not parse.
///
/// # Adequacy
/// - hypothesis: L3 — a well-formed pair is read to its name and tree, and a
///   value without `=`, with an undotted name and with a short tree id each
///   meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_witness(value: OsString) -> Result<(Domain, TreeId), UsageError>
{
    let text = value.into_string().map_err(UsageError::Text)?;
    let (domain, tree) = text.split_once('=').ok_or(UsageError::Witness)?;
    let domain = domain.parse().map_err(UsageError::Domain)?;
    let tree = read_id(OsStr::new(tree), Operand::Witness)?;
    Ok((domain, tree))
}

/// Read `serve`'s options from what follows the verb.
///
/// # Specification
/// - ensures: accepts nothing, which leaves the port ephemeral, or `--port
///   <port>` (or `--port=<port>`; the last one given wins), which fixes it.
/// - fails: [`UsageError::Arguments`] for any other option or for `--port`
///   without a value, [`UsageError::Operands`] for an operand, and
///   [`UsageError::Port`] for a value that is not a port from 1 through 65535.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or `--port` lacks a value.
/// - [`UsageError::Operands`]: an operand follows `serve`.
/// - [`UsageError::Port`]: the value is not a UDP port.
///
/// # Adequacy
/// - hypothesis: L3 — no option, both `--port` spellings and a repeated
///   `--port` are read to their ports, and a stray operand, an unknown option,
///   a missing value and port 0 each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn serve_port(arguments: &mut lexopt::Parser) -> Result<BindPort, UsageError>
{
    let mut port = BindPort::Ephemeral;
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("port") => {
                let value = arguments.value()?;
                let fixed = value.to_string_lossy().parse::<UdpPort>();
                port = BindPort::Fixed(fixed.map_err(UsageError::Port)?);
            },
            | lexopt::Arg::Value(_) => return Err(UsageError::Operands(Verb::Serve)),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    Ok(port)
}

/// Name the verb `word` spells.
///
/// # Specification
/// - ensures: `id`, `serve`, `open`, `grant`, `note`, `bind`, `claim`,
///   `introduce`, `whence`, `view`, `heads` and `sync` name their verbs.
/// - fails: [`UsageError::Command`] for any other word, carrying it.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Command`]: the word is not a verb.
///
/// # Adequacy
/// - hypothesis: L3 — every verb is read by name and an unknown word, among
///   them the retired `commit`, is refused with the word kept.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn verb(word: OsString) -> Result<Verb, UsageError>
{
    match word.to_str() {
        | Some("id") => Ok(Verb::Id),
        | Some("serve") => Ok(Verb::Serve),
        | Some("open") => Ok(Verb::Open),
        | Some("grant") => Ok(Verb::Grant),
        | Some("note") => Ok(Verb::Note),
        | Some("bind") => Ok(Verb::Bind),
        | Some("claim") => Ok(Verb::Claim),
        | Some("introduce") => Ok(Verb::Introduce),
        | Some("whence") => Ok(Verb::Whence),
        | Some("view") => Ok(Verb::View),
        | Some("heads") => Ok(Verb::Heads),
        | Some("sync") => Ok(Verb::Sync),
        | Some(_) | None => Err(UsageError::Command(word)),
    }
}

/// Read the id `text` spells, for the operand `operand`.
///
/// # Specification
/// - ensures: yields the id `T`'s parser reads from `text`; text that is not
///   UTF-8 is read with replacement characters, which no id parser accepts.
/// - fails: [`UsageError::Operand`] naming `operand` and carrying the parser's
///   reason.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Operand`]: the text is not an id.
///
/// # Adequacy
/// - hypothesis: L3 — a malformed peer id and endpoint id are refused under
///   their own operand names.
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_id<T>(
    text: &OsStr,
    operand: Operand,
) -> Result<T, UsageError>
where
    T: FromStr<Err = ParseIdError>,
{
    text.to_string_lossy()
        .parse::<T>()
        .map_err(|source| UsageError::Operand { operand, source })
}

/// Read the anchor or the reference `text` spells, for the operand `operand`.
///
/// # Specification
/// - ensures: yields what `T`'s parser reads from `text`: for an [`Anchor`], a
///   tree, a path or a commit by its whole id, and for a [`Reference`] also a
///   commit by a prefix of its id, in any of the three forms; text that is not
///   UTF-8 is read with replacement characters, which no anchor's authority
///   accepts.
/// - fails: [`UsageError::Anchor`] naming `operand` and carrying the parser's
///   reason.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Anchor`]: the text is not what `T` reads.
///
/// # Adequacy
/// - hypothesis: L3 — a hex tree id where a tree anchor stands, an empty and a
///   reserved segment and a commit id too short to read in a reference to
///   resolve, and an abbreviated commit id in a target anchor are refused under
///   their own operand names, each with the parser's reason.
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_anchor<T>(
    text: &OsStr,
    operand: Operand,
) -> Result<T, UsageError>
where
    T: FromStr<Err = ParseAnchorError>,
{
    text.to_string_lossy()
        .parse::<T>()
        .map_err(|source| UsageError::Anchor { operand, source })
}

/// Read the tree a bare anchor `text` names by its key.
///
/// # Specification
/// - ensures: yields the tree of the bare anchor `domhringr://<tree-id>/`.
/// - fails: as [`read_anchor`] for the tree operand, [`UsageError::NotTree`]
///   for an anchor naming a path or a commit, and [`UsageError::NotKey`] for a
///   bare anchor naming its tree by a DNS name or a label.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Anchor`]: the text is not an anchor.
/// - [`UsageError::NotTree`]: the anchor names a path or a commit.
/// - [`UsageError::NotKey`]: the anchor is not in the key form.
///
/// # Adequacy
/// - hypothesis: L3 — a bare anchor is read to its tree wherever a tree stands,
///   a path or a commit anchor in its place is refused as no tree, and a bare
///   DNS or label anchor as no key.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_tree(text: &OsStr) -> Result<TreeId, UsageError>
{
    let anchor = read_anchor::<Anchor>(text, Operand::Tree)?;
    match anchor {
        | Anchor::Tree(Authority::Key(tree)) => Ok(tree),
        | Anchor::Tree(Authority::Domain(_) | Authority::Label(_)) => Err(UsageError::NotKey),
        | Anchor::Path { .. } | Anchor::Commit { .. } => Err(UsageError::NotTree),
    }
}

/// Read the name `text` spells: a DNS name to claim or a label to introduce.
///
/// # Specification
/// - ensures: yields the name `T`'s parser reads from `text`.
/// - fails: [`UsageError::Text`] for text that is not UTF-8, carrying it, and
///   `refused` of the parser's reason for text `T` does not read.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Text`]: the text is not UTF-8.
/// - `refused`'s error: the text is not a `T`.
///
/// # Adequacy
/// - hypothesis: L3 — a DNS name and a label are read wherever they stand, and
///   an undotted DNS name and a dotted label are refused under their own
///   refusals.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_name<T>(
    text: OsString,
    refused: fn(T::Err) -> UsageError,
) -> Result<T, UsageError>
where
    T: FromStr,
{
    let text = text.into_string().map_err(UsageError::Text)?;
    text.parse().map_err(refused)
}

/// Read a bind's target from its kind and its value.
///
/// # Specification
/// - ensures: `anchor` reads the value as an anchor — a tree, a path or a
///   commit by its whole id, in any of the three forms — `endpoint` as an
///   endpoint id, and `datum` takes it verbatim.
/// - fails: [`UsageError::Target`] for any other kind, carrying it,
///   [`UsageError::Anchor`] naming the target anchor for an anchor that does
///   not parse or abbreviates its commit id, [`UsageError::Operand`] for an
///   endpoint id that does not parse, and [`UsageError::Text`] for a datum that
///   is not UTF-8.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Target`]: the kind is unknown.
/// - [`UsageError::Anchor`]: the anchor does not parse.
/// - [`UsageError::Operand`]: the endpoint id does not parse.
/// - [`UsageError::Text`]: the datum is not UTF-8.
///
/// # Adequacy
/// - hypothesis: L3 — each kind is read to its target, an anchor in each of its
///   forms and a dash-leading datum among them, and an unknown kind, among them
///   the names of an anchor's forms, an abbreviated commit, and a datum that is
///   not UTF-8 each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_target(
    kind: &OsStr,
    value: OsString,
) -> Result<Target, UsageError>
{
    match kind.to_str() {
        | Some("anchor") => read_anchor(&value, Operand::Target).map(Target::Anchor),
        | Some("endpoint") => read_id(&value, Operand::Endpoint).map(Target::Endpoint),
        | Some("datum") => value
            .into_string()
            .map(Target::Datum)
            .map_err(UsageError::Text),
        | Some(_) | None => Err(UsageError::Target(kind.to_os_string())),
    }
}

/// Run `invocation` to completion on a fresh multi-threaded runtime.
///
/// # Specification
/// - ensures: the command runs as [`execute`] specifies; the runtime, and every
///   task the command left running on it, is gone on return.
/// - fails: [`RunError::Runtime`] when the runtime cannot start, otherwise as
///   [`execute`].
/// - panics: none.
///
/// # Errors
/// - [`RunError::Runtime`]: the runtime cannot start.
/// - every other [`RunError`]: as [`execute`].
///
/// # Adequacy
/// - hypothesis: L3 — the process test runs every command through this function
///   and observes its output.
/// - witness: `sync::tests::two_peers_fold_one_tree_to_identical_views`
fn run(invocation: Invocation) -> Result<(), RunError>
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(RunError::Runtime)?;
    runtime.block_on(execute(invocation))
}

/// Carry out one command against its state directory.
///
/// # Specification
/// - requires: called within a Tokio runtime.
/// - ensures: the identity exists beneath the state directory. `id` writes the
///   endpoint id line, then the peer id line, and opens no store. `open` opens
///   the store, mints a tree key beneath the state directory, commits the
///   tree's Open proved by that key for this peer, and writes the tree's anchor
///   line. `grant`, `note`, `bind`, `claim` and `introduce` commit their
///   receipt, under a fresh operation fence, and write the new commit's id
///   line. `whence` writes what the reference resolves to in the local views
///   ([`Peer::whence`]), asking DNS for a DNS name's candidate trees unless
///   `--witness` named them: for a path the target bound to it (`anchor
///   <anchor>`, `endpoint <endpoint-id>` or `datum <text>`) or `unbound`; for a
///   bare DNS or label anchor the anchor of the tree it names by key; for a
///   commit `commit <commit-id> admitted`, `commit <commit-id> refused
///   <reason>`, or `unknown` when the tree holds none. `view` writes the tree's
///   view, one line per fact ([`domhringr_record_tree::View`]'s display).
///   `heads` writes the tree's heads, one sorted hex line each. `sync` dials
///   the remote, at its direct address when `--at` named one, writes the heads
///   after the sync the same way, then `path <peer-id> <path>` for the path the
///   connection took, having closed its endpoint. `serve` runs as [`serve`]
///   specifies.
/// - fails: [`RunError::Identity`], [`RunError::Open`], [`RunError::Bind`],
///   [`RunError::Random`], [`RunError::Commit`], [`RunError::View`],
///   [`RunError::Whence`], [`RunError::Heads`] and [`RunError::Sync`] as the
///   record library reports them, and [`RunError::Output`] when standard output
///   cannot be written. A failed sync still closes the endpoint.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Identity`]: the identity cannot be read or created, or a tree
///   key cannot be minted.
/// - [`RunError::Open`]: the store cannot be opened, as when `serve` holds it.
/// - [`RunError::Bind`]: the endpoint cannot bind.
/// - [`RunError::Random`]: no operation fence can be drawn.
/// - [`RunError::Commit`]: the commit cannot be appended.
/// - [`RunError::View`]: the tree is unopened or its commits cannot be read.
/// - [`RunError::Whence`]: the reference does not resolve, as when its DNS name
///   is unclaimed, its label unintroduced or its commit prefix ambiguous.
/// - [`RunError::Heads`]: the heads cannot be read.
/// - [`RunError::Sync`]: the sync failed.
/// - [`RunError::Output`]: standard output cannot be written.
/// - [`RunError::Closed`], [`RunError::Diagnostics`]: as [`serve`].
///
/// # Adequacy
/// - hypothesis: L3 — two processes exchange ids, open a tree and parse its
///   anchor, grant, write notes, bind paths, claim a DNS name, introduce a tree
///   by a label, resolve anchors in all three forms and commits whole and
///   abbreviated, read heads and views, and sync at each other's direct address
///   in both directions; views are compared byte for byte across processes and
///   with the expected facts, resolutions with the commit bound, across forms
///   and with each commit's verdict, refusals by their diagnostic, and each
///   sync's path line is parsed.
/// - witness: `sync::tests::two_peers_fold_one_tree_to_identical_views`
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
/// - witness: `sync::tests::an_anchor_resolves_alike_on_both_peers`
/// - witness: `sync::tests::a_named_anchor_resolves_through_its_claim_or_introduction`
/// - witness: `sync::tests::a_commit_resolves_to_its_verdict_on_both_peers`
async fn execute(invocation: Invocation) -> Result<(), RunError>
{
    let Invocation { state, command } = invocation;
    let identity = Identity::load_or_create(&state)?;
    match command {
        | Command::Id => emit(&format_args!(
            "{}\n{}\n",
            identity.endpoint_key(),
            identity.peer_key()
        )),
        | Command::Serve { port } => serve(Peer::open(&state, identity)?, port).await,
        | Command::Open => {
            let owner = identity.peer_key();
            let peer = Peer::open(&state, identity)?;
            let key = TreeKey::mint(&state)?;
            peer.commit(key.tree(), Receipt::open(&key, owner)?).await?;
            drop(peer);
            emit(&format_args!("{}\n", Anchor::key(key.tree())))
        },
        | Command::Grant { tree, to } => {
            let peer = Peer::open(&state, identity)?;
            record(&peer, tree, Receipt::grant(tree, to)?).await
        },
        | Command::Note { tree, text } => {
            let peer = Peer::open(&state, identity)?;
            record(&peer, tree, Receipt::note(tree, text)?).await
        },
        | Command::Bind { tree, path, target } => {
            let peer = Peer::open(&state, identity)?;
            record(&peer, tree, Receipt::bind(tree, path, target)?).await
        },
        | Command::Claim { tree, domain } => {
            let peer = Peer::open(&state, identity)?;
            record(&peer, tree, Receipt::claim(tree, domain)?).await
        },
        | Command::Introduce {
            tree,
            label,
            introduced,
        } => {
            let peer = Peer::open(&state, identity)?;
            record(&peer, tree, Receipt::introduce(tree, label, introduced)?).await
        },
        | Command::Whence {
            reference,
            witnessing,
            scope,
        } => {
            let peer = Peer::open(&state, identity)?;
            let resolution = match witnessing {
                | Witnessing::Dns => peer.whence(&reference, &Dns::system(), scope).await?,
                | Witnessing::ByHand(witness) => peer.whence(&reference, &witness, scope).await?,
            };
            drop(peer);
            emit(&format_args!("{resolution}\n"))
        },
        | Command::View { tree } => {
            let view = Peer::open(&state, identity)?.view(tree).await?;
            emit(&view)
        },
        | Command::Heads { tree } => {
            let heads = Peer::open(&state, identity)?.heads(tree).await?;
            emit(&heads)
        },
        | Command::Sync { remote, tree } => {
            let node = Peer::open(&state, identity)?
                .bind(BindPort::Ephemeral)
                .await?;
            let synced = node.sync(&remote, tree).await;
            node.close().await;
            drop(node);
            let synced = synced?;
            emit(&format_args!(
                "{}path {} {}\n",
                synced.heads(),
                remote.peer(),
                synced.path()
            ))
        },
    }
}

/// Commit `receipt` to `tree` on `peer` and write the commit id line.
///
/// # Specification
/// - ensures: on success the commit is durable and its id line written.
/// - fails: [`RunError::Commit`] when the commit cannot be appended,
///   [`RunError::Output`] when standard output cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Commit`]: the commit cannot be appended.
/// - [`RunError::Output`]: standard output cannot be written.
///
/// # Adequacy
/// - hypothesis: L3 — the process test commits every kind and reads each
///   printed commit id back among the tree's heads.
/// - witness: `sync::tests::two_peers_fold_one_tree_to_identical_views`
async fn record(
    peer: &Peer,
    tree: TreeId,
    receipt: Receipt,
) -> Result<(), RunError>
{
    let id = peer.commit(tree, receipt).await?;
    emit(&format_args!("{id}\n"))
}

/// Bind `peer` on `port`, announce it, and accept peers until the process is
/// killed.
///
/// # Specification
/// - ensures: once the endpoint is bound, writes the endpoint id line, the peer
///   id line and `listening`; then, for each peer admitted, writes `accepted
///   <peer-id>` and `path <peer-id> <path>` for the path its connection took
///   when admitted. A connection that fails its handshake is reported on
///   standard error and serving continues.
/// - fails: [`RunError::Bind`] when the endpoint cannot bind,
///   [`RunError::Closed`] if the endpoint closes, [`RunError::Output`] and
///   [`RunError::Diagnostics`] when standard output or standard error cannot be
///   written. It does not return otherwise.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Bind`]: the endpoint cannot bind, as when `port` is taken.
/// - [`RunError::Closed`]: the endpoint closed.
/// - [`RunError::Output`]: standard output cannot be written.
/// - [`RunError::Diagnostics`]: standard error cannot be written.
///
/// # Adequacy
/// - hypothesis: L3 — the process test serves on a fixed port, reads the
///   announced ids and `listening`, syncs against the server repeatedly, and
///   reads an `accepted` line and a parseable `path` line per sync.
/// - witness: `sync::tests::two_peers_fold_one_tree_to_identical_views`
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
async fn serve(
    peer: Peer,
    port: BindPort,
) -> Result<(), RunError>
{
    let node = peer.bind(port).await?;
    emit(&format_args!(
        "{}\n{}\nlistening\n",
        node.endpoint_key(),
        node.peer().identity().peer_key()
    ))?;
    loop {
        match node.accept().await {
            | Ok(accepted) => emit(&format_args!(
                "accepted {peer}\npath {peer} {path}\n",
                peer = accepted.peer(),
                path = accepted.path()
            ))?,
            | Err(AcceptError::Closed) => return Err(RunError::Closed),
            | Err(failure) => report(&failure).map_err(RunError::Diagnostics)?,
        }
    }
}

/// Write `lines` to standard output and flush it.
///
/// # Specification
/// - ensures: on success the text is written and flushed, so a reader on a pipe
///   sees it at once.
/// - fails: [`RunError::Output`] when standard output cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Output`]: the write or the flush fails.
fn emit(lines: &dyn fmt::Display) -> Result<(), RunError>
{
    let mut stdout = std::io::stdout().lock();
    write!(stdout, "{lines}").map_err(RunError::Output)?;
    stdout.flush().map_err(RunError::Output)
}

/// Write `error` and its causes to standard error as one line.
///
/// # Specification
/// - ensures: writes `domhringr-peer: `, the error, each of its sources in
///   order each preceded by `: `, and a newline.
/// - fails: the write's own error when standard error cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`std::io::Error`]: standard error cannot be written.
fn report(error: &dyn Error) -> std::io::Result<()>
{
    let mut stderr = std::io::stderr().lock();
    write!(stderr, "domhringr-peer: {error}")?;
    for cause in core::iter::successors(error.source(), |&cause| cause.source()) {
        write!(stderr, ": {cause}")?;
    }
    writeln!(stderr)
}

/// Entry point.
///
/// # Specification
/// - ensures: runs the command line as [`run`] specifies and exits 0.
/// - fails: exits 2 after writing the reason and the synopsis to standard error
///   when the command line cannot be run ([`parse`]), and exits 1 after writing
///   the reason when the command fails. When standard error cannot be written
///   the exit status is the only report.
/// - panics: none.
fn main() -> ExitCode
{
    let invocation = match parse(lexopt::Parser::from_env()) {
        | Ok(invocation) => invocation,
        | Err(error) => {
            let reported =
                report(&error).and_then(|()| std::io::stderr().lock().write_all(USAGE.as_bytes()));
            return match reported {
                | Ok(()) | Err(_) => ExitCode::from(USAGE_STATUS),
            };
        },
    };
    match run(invocation) {
        | Ok(()) => ExitCode::SUCCESS,
        | Err(error) => match report(&error) {
            | Ok(()) | Err(_) => ExitCode::FAILURE,
        },
    }
}

#[cfg(test)]
mod tests
{
    use core::net::Ipv4Addr;
    use core::net::SocketAddr;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use domhringr_record_tree::Address;
    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::Authority;
    use domhringr_record_tree::BindPort;
    use domhringr_record_tree::Domain;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::Label;
    use domhringr_record_tree::ParseAnchorError;
    use domhringr_record_tree::ParseDomainError;
    use domhringr_record_tree::ParseIdError;
    use domhringr_record_tree::ParseLabelError;
    use domhringr_record_tree::Path;
    use domhringr_record_tree::Reference;
    use domhringr_record_tree::RemotePeer;
    use domhringr_record_tree::Scope;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::Static;
    use domhringr_record_tree::Target;
    use domhringr_record_tree::TreeId;
    use domhringr_record_tree::TreeKey;
    use domhringr_record_tree::UdpPort;

    use super::Command;
    use super::Invocation;
    use super::Operand;
    use super::UsageError;
    use super::Verb;
    use super::Witnessing;
    use super::parse;

    /// The id of the tree the command lines name: the all-zero key's.
    const TREE_ID: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    /// That tree's anchor.
    const TREE: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/";

    /// A path in that tree.
    const PATH: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/a/b";

    /// A commit id: 64 hex digits, which no anchor reads where a tree stands.
    const COMMIT: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    /// The DNS name the command lines claim and witness.
    ///
    /// # Specification
    /// trivial.
    fn example() -> Domain
    {
        "example.test".parse().unwrap()
    }

    /// A second tree, minted for the test.
    ///
    /// # Specification
    /// trivial.
    fn minted() -> TreeId
    {
        let root = tempfile::tempdir().unwrap();
        TreeKey::mint(&StateDir::from(root.path().to_path_buf()))
            .unwrap()
            .tree()
    }

    /// A real endpoint id and peer id, from an identity made for the test,
    /// looked up by endpoint id.
    ///
    /// # Specification
    /// trivial.
    fn remote() -> RemotePeer
    {
        let root = tempfile::tempdir().unwrap();
        let identity =
            Identity::load_or_create(&StateDir::from(root.path().to_path_buf())).unwrap();
        RemotePeer::new(
            identity.endpoint_key(),
            identity.peer_key(),
            Address::Lookup,
        )
    }

    #[test]
    fn every_verb_reads_its_operands()
    {
        let tree = TREE_ID.parse::<TreeId>().unwrap();
        let other = minted();
        let other_anchor = Anchor::key(other).to_string();
        let b = "b".parse::<Label>().unwrap();
        let (witnessed, witnessed_other, scoped) = (
            format!("example.test={TREE_ID}"),
            format!("--witness=example.test={other}"),
            format!("--in={other_anchor}"),
        );
        let whence = |anchor: Anchor| Command::Whence {
            reference: Reference::from(anchor),
            witnessing: Witnessing::Dns,
            scope: Scope::Unscoped,
        };
        let (anchor, path) = (
            PATH.parse::<Anchor>().unwrap(),
            "a/b".parse::<Path>().unwrap(),
        );
        let commit_text = format!("{TREE}.commit/{COMMIT}");
        let commit = commit_text.parse::<Anchor>().unwrap();
        let state = StateDir::from(PathBuf::from("dir"));
        let remote = remote();
        let (endpoint, peer) = (remote.endpoint().to_string(), remote.peer().to_string());
        let direct = RemotePeer::new(
            remote.endpoint(),
            remote.peer(),
            Address::Direct(SocketAddr::from((Ipv4Addr::LOCALHOST, 49731))),
        );
        let port = |text: &str| BindPort::Fixed(text.parse::<UdpPort>().unwrap());
        let bind = |target: Target| Command::Bind {
            tree,
            path: path.clone(),
            target,
        };
        let lines = [
            (vec!["--state", "dir", "id"], Command::Id),
            (vec!["--state=dir", "serve"], Command::Serve {
                port: BindPort::Ephemeral,
            }),
            (
                vec!["--state", "dir", "serve", "--port", "49731"],
                Command::Serve {
                    port: port("49731"),
                },
            ),
            (
                vec!["--state", "dir", "serve", "--port=1", "--port=65535"],
                Command::Serve {
                    port: port("65535"),
                },
            ),
            (vec!["--state", "dir", "open"], Command::Open),
            (
                vec!["--state", "dir", "grant", TREE, &peer],
                Command::Grant {
                    tree,
                    to: remote.peer(),
                },
            ),
            (
                vec!["--state", "dir", "note", TREE, "--not-an-option"],
                Command::Note {
                    tree,
                    text: String::from("--not-an-option"),
                },
            ),
            (
                vec!["--state", "dir", "bind", PATH, "anchor", &commit_text],
                bind(Target::Anchor(commit.clone())),
            ),
            (
                vec!["--state", "dir", "bind", PATH, "anchor", TREE],
                bind(Target::Anchor(Anchor::key(tree))),
            ),
            (
                vec!["--state", "dir", "bind", PATH, "anchor", "domhringr://b/x"],
                bind(Target::Anchor(Anchor::Path {
                    authority: Authority::Label(b.clone()),
                    path: "x".parse().unwrap(),
                })),
            ),
            (
                vec!["--state", "dir", "bind", PATH, "endpoint", &endpoint],
                bind(Target::Endpoint(remote.endpoint())),
            ),
            (
                vec!["--state", "dir", "bind", PATH, "datum", "--not an option"],
                bind(Target::Datum(String::from("--not an option"))),
            ),
            (
                vec!["--state", "dir", "claim", TREE, "example.test"],
                Command::Claim {
                    tree,
                    domain: example(),
                },
            ),
            (
                vec!["--state", "dir", "introduce", TREE, "b", &other_anchor],
                Command::Introduce {
                    tree,
                    label: b.clone(),
                    introduced: other,
                },
            ),
            (vec!["--state", "dir", "whence", PATH], whence(anchor)),
            (
                vec!["--state", "dir", "whence", TREE],
                whence(Anchor::key(tree)),
            ),
            (
                vec!["--state", "dir", "whence", &commit_text],
                whence(commit),
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "whence",
                    "--witness",
                    &witnessed,
                    "domhringr://example.test/a/b",
                    &witnessed_other,
                ],
                Command::Whence {
                    reference: Reference::from(Anchor::Path {
                        authority: Authority::Domain(example()),
                        path: path.clone(),
                    }),
                    witnessing: Witnessing::ByHand(
                        [(example(), tree), (example(), other)]
                            .into_iter()
                            .collect::<Static>(),
                    ),
                    scope: Scope::Unscoped,
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "whence",
                    "--in",
                    TREE,
                    "domhringr://b/",
                    &scoped,
                ],
                Command::Whence {
                    reference: Reference::from(Anchor::Tree(Authority::Label(b))),
                    witnessing: Witnessing::Dns,
                    scope: Scope::In(other),
                },
            ),
            (vec!["--state", "dir", "view", TREE], Command::View { tree }),
            (
                vec!["--state", "elsewhere", "--state", "dir", "heads", TREE],
                Command::Heads { tree },
            ),
            (
                vec!["--state", "dir", "sync", &endpoint, &peer, TREE],
                Command::Sync { remote, tree },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "sync",
                    "--at",
                    "127.0.0.1:49731",
                    &endpoint,
                    &peer,
                    TREE,
                ],
                Command::Sync {
                    remote: direct,
                    tree,
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "sync",
                    &endpoint,
                    &peer,
                    TREE,
                    "--at=[::1]:1",
                    "--at=127.0.0.1:49731",
                ],
                Command::Sync {
                    remote: direct,
                    tree,
                },
            ),
        ];
        for (line, command) in lines {
            let invocation = parse(lexopt::Parser::from_args(line.clone())).unwrap();
            assert_eq!(
                invocation,
                Invocation {
                    state: state.clone(),
                    command
                },
                "{line:?}"
            );
        }
        let prefix = format!("{TREE}.commit/07070707");
        let abbreviated = parse(lexopt::Parser::from_args(vec![
            "--state",
            "dir",
            "whence",
            prefix.as_str(),
        ]))
        .unwrap();
        assert!(
            matches!(
                abbreviated.command,
                Command::Whence {
                    reference: Reference::Abbreviated {
                        authority: Authority::Key(read),
                        ref prefix,
                    },
                    witnessing: Witnessing::Dns,
                    scope: Scope::Unscoped,
                } if read == tree && prefix.to_string() == "07070707"
            ),
            "whence reads a commit id abbreviated to eight digits as a prefix"
        );
    }

    #[test]
    fn a_malformed_command_line_is_refused()
    {
        let remote = remote();
        let (endpoint, peer) = (remote.endpoint().to_string(), remote.peer().to_string());
        let refused = |line: Vec<OsString>| parse(lexopt::Parser::from_args(line)).unwrap_err();
        let line = |words: &[&str]| words.iter().map(OsString::from).collect::<Vec<_>>();
        let commit_text = format!("{TREE}.commit/{COMMIT}");
        assert!(matches!(refused(line(&[])), UsageError::NoCommand));
        assert!(matches!(
            refused(line(&["--state"])),
            UsageError::Arguments(_)
        ));
        assert!(matches!(
            refused(line(&["--verbose", "id"])),
            UsageError::Arguments(_)
        ));
        assert!(matches!(refused(line(&["id"])), UsageError::State));
        assert!(
            matches!(refused(line(&["--state", "dir", "tail"])), UsageError::Command(word) if word == "tail")
        );
        assert!(matches!(
            refused(line(&["--state", "dir", "id", "extra"])),
            UsageError::Operands(Verb::Id)
        ));
        assert!(
            matches!(
                refused(line(&["--state", "dir", "open", TREE])),
                UsageError::Operands(Verb::Open)
            ),
            "`open` mints its tree and names none"
        );
        assert!(matches!(
            refused(line(&["--state", "dir", "heads"])),
            UsageError::Operands(Verb::Heads)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "heads", "nothex", "extra"])),
            UsageError::Operands(Verb::Heads)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "heads", "nothex"])),
            UsageError::Anchor {
                operand: Operand::Tree,
                source: ParseAnchorError::Scheme,
            }
        ));
        assert!(
            matches!(
                refused(line(&["--state", "dir", "heads", COMMIT])),
                UsageError::Anchor {
                    operand: Operand::Tree,
                    source: ParseAnchorError::Scheme,
                }
            ),
            "a hex id is no tree anchor"
        );
        assert!(matches!(
            refused(line(&["--state", "dir", "view", PATH])),
            UsageError::NotTree
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "grant", PATH, &peer])),
            UsageError::NotTree
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", &endpoint, "nothex", TREE])),
            UsageError::Operand {
                operand: Operand::Peer,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", "nothex", "nothex", TREE])),
            UsageError::Operand {
                operand: Operand::Endpoint,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", &endpoint, &peer, PATH])),
            UsageError::NotTree
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", "nothex", &peer])),
            UsageError::Operands(Verb::Sync)
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "sync", &endpoint, &peer, TREE, "x"
            ])),
            UsageError::Operands(Verb::Sync)
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "sync", &endpoint, &peer, TREE, "--at", "nowhere"
            ])),
            UsageError::At(_)
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "sync", &endpoint, &peer, TREE, "--at"
            ])),
            UsageError::Arguments(_)
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "sync", &endpoint, &peer, TREE, "-v"
            ])),
            UsageError::Arguments(_)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "grant", TREE])),
            UsageError::Operands(Verb::Grant)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "grant", TREE, "nothex"])),
            UsageError::Operand {
                operand: Operand::Peer,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "bind", PATH, "anchor"])),
            UsageError::Operands(Verb::Bind)
        ));
        for bound in [TREE, commit_text.as_str()] {
            assert!(
                matches!(
                    refused(line(&["--state", "dir", "bind", bound, "anchor", TREE])),
                    UsageError::NoPath
                ),
                "{bound} names no path to bind"
            );
        }
        for kind in ["commit", "tree", "tag"] {
            assert!(
                matches!(refused(line(&["--state", "dir", "bind", PATH, kind, TREE])), UsageError::Target(read) if read == kind),
                "{kind} is no target kind"
            );
        }
        let abbreviated = format!("{TREE}.commit/07070707");
        assert!(
            matches!(
                refused(line(&[
                    "--state",
                    "dir",
                    "bind",
                    PATH,
                    "anchor",
                    &abbreviated
                ])),
                UsageError::Anchor {
                    operand: Operand::Target,
                    source: ParseAnchorError::Abbreviated,
                }
            ),
            "a target anchor carries its commit id whole"
        );
        assert!(matches!(
            refused(line(&["--state", "dir", "bind", PATH, "anchor", COMMIT])),
            UsageError::Anchor {
                operand: Operand::Target,
                source: ParseAnchorError::Scheme,
            }
        ));
        assert!(matches!(
            refused(line(&[
                "--state",
                "dir",
                "bind",
                "domhringr://example.test/x",
                "anchor",
                TREE
            ])),
            UsageError::NotKey
        ));
        assert!(
            matches!(
                refused(line(&["--state", "dir", "view", &commit_text])),
                UsageError::NotTree
            ),
            "a commit anchor names no tree"
        );
        for (reference, reason) in [
            (format!("{TREE}.x"), "a reserved first segment"),
            (format!("{TREE}a/.commit"), "a reserved later segment"),
        ] {
            assert!(
                matches!(
                    refused(line(&["--state", "dir", "whence", &reference])),
                    UsageError::Anchor {
                        operand: Operand::Anchor,
                        source: ParseAnchorError::Reserved,
                    }
                ),
                "{reason}"
            );
        }
        let trailing = format!("{commit_text}/x");
        assert!(
            matches!(
                refused(line(&["--state", "dir", "whence", &trailing])),
                UsageError::Anchor {
                    operand: Operand::Anchor,
                    source: ParseAnchorError::CommitForm,
                }
            ),
            "a commit form with a path after its id"
        );
        let short = format!("{TREE}.commit/0707070");
        assert!(
            matches!(
                refused(line(&["--state", "dir", "whence", &short])),
                UsageError::Anchor {
                    operand: Operand::Anchor,
                    source: ParseAnchorError::Commit(ParseIdError::CommitShort),
                }
            ),
            "seven digits are too few to abbreviate a commit id"
        );
        assert!(matches!(
            refused(line(&[
                "--state",
                "dir",
                "whence",
                "domhringr://example.test/a//b"
            ])),
            UsageError::Anchor {
                operand: Operand::Anchor,
                source: ParseAnchorError::EmptySegment,
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "whence"])),
            UsageError::Operands(Verb::Whence)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "whence", PATH, "extra"])),
            UsageError::Operands(Verb::Whence)
        ));
        let bad_witness = format!("nodot={TREE_ID}");
        let witnesses = [
            (
                vec!["--witness", "example.test"],
                "a witness without = pairs nothing",
            ),
            (vec!["--witness", &bad_witness], "an undotted DNS name"),
            (vec!["--witness", "example.test=short"], "a short tree id"),
            (vec!["--in", PATH], "a scope naming a path"),
            (vec!["--in", "domhringr://b/"], "a scope naming a label"),
            (vec!["--witness"], "a witness without a value"),
            (vec!["-v"], "an unknown option"),
        ];
        let [
            no_equals,
            undotted,
            short,
            scope_path,
            scope_label,
            no_value,
            unknown,
        ] = witnesses.map(|(options, case)| {
            let mut words = vec!["--state", "dir", "whence", PATH];
            words.extend(options);
            (refused(line(&words)), case)
        });
        assert!(
            matches!(no_equals.0, UsageError::Witness),
            "{}",
            no_equals.1
        );
        assert!(
            matches!(undotted.0, UsageError::Domain(ParseDomainError::Undotted)),
            "{}",
            undotted.1
        );
        assert!(
            matches!(short.0, UsageError::Operand {
                operand: Operand::Witness,
                ..
            }),
            "{}",
            short.1
        );
        assert!(
            matches!(scope_path.0, UsageError::NotTree),
            "{}",
            scope_path.1
        );
        assert!(
            matches!(scope_label.0, UsageError::NotKey),
            "{}",
            scope_label.1
        );
        assert!(
            matches!(no_value.0, UsageError::Arguments(_)),
            "{}",
            no_value.1
        );
        assert!(
            matches!(unknown.0, UsageError::Arguments(_)),
            "{}",
            unknown.1
        );
        assert!(matches!(
            refused(line(&["--state", "dir", "claim", TREE])),
            UsageError::Operands(Verb::Claim)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "claim", TREE, "nodot"])),
            UsageError::Domain(ParseDomainError::Undotted)
        ));
        assert!(matches!(
            refused(line(&[
                "--state",
                "dir",
                "claim",
                "domhringr://example.test/",
                "example.test"
            ])),
            UsageError::NotKey
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "introduce", TREE, "b"])),
            UsageError::Operands(Verb::Introduce)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "introduce", TREE, "a.b", TREE])),
            UsageError::Label(ParseLabelError::Dot)
        ));
        assert!(matches!(
            refused(line(&[
                "--state",
                "dir",
                "introduce",
                TREE,
                "b",
                "domhringr://b/"
            ])),
            UsageError::NotKey
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "introduce", TREE, "b", PATH])),
            UsageError::NotTree
        ));
        assert!(
            matches!(refused(line(&["--state", "dir", "commit", TREE, "text"])), UsageError::Command(word) if word == "commit"),
            "`note` replaced `commit`"
        );
        assert!(matches!(
            refused(line(&["--state", "dir", "serve", "extra"])),
            UsageError::Operands(Verb::Serve)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "serve", "--verbose"])),
            UsageError::Arguments(_)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "serve", "--port"])),
            UsageError::Arguments(_)
        ));
        for port in ["0", "65536", "port"] {
            assert!(
                matches!(
                    refused(line(&["--state", "dir", "serve", "--port", port])),
                    UsageError::Port(_)
                ),
                "{port:?} is not a port"
            );
        }
        let not_utf8 = || std::os::unix::ffi::OsStringExt::from_vec(vec![0xff]);
        let mut invalid = line(&["--state", "dir", "note", TREE]);
        invalid.push(not_utf8());
        assert!(matches!(refused(invalid), UsageError::Text(_)));
        let mut invalid = line(&["--state", "dir", "bind", PATH, "datum"]);
        invalid.push(not_utf8());
        assert!(matches!(refused(invalid), UsageError::Text(_)));
        let mut invalid = line(&["--state", "dir", "claim", TREE]);
        invalid.push(not_utf8());
        assert!(matches!(refused(invalid), UsageError::Text(_)));
        let mut invalid = line(&["--state", "dir", "introduce", TREE]);
        invalid.extend([not_utf8(), OsString::from(TREE)]);
        assert!(matches!(refused(invalid), UsageError::Text(_)));
        let mut invalid = line(&["--state", "dir", "whence", PATH, "--witness"]);
        invalid.push(not_utf8());
        assert!(matches!(refused(invalid), UsageError::Text(_)));
    }
}
