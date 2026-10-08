//! `domhringr-peer`: one record-plane peer over a state directory. It opens a
//! sedimentree under a key of the tree's own, grants write authority on it,
//! writes notes to it, binds paths in it, resolves an anchor to what its path
//! is bound to, prints the view every peer holding the same commits folds them
//! to, reads the tree's heads, and syncs the tree with another peer over iroh.
//!
//! ```text
//! domhringr-peer --state <dir> id
//! domhringr-peer --state <dir> serve [--port <port>]
//! domhringr-peer --state <dir> open
//! domhringr-peer --state <dir> grant <tree> <peer-id>
//! domhringr-peer --state <dir> note <tree> <text>
//! domhringr-peer --state <dir> bind <anchor> <target>
//! domhringr-peer --state <dir> whence <anchor>
//! domhringr-peer --state <dir> view <tree>
//! domhringr-peer --state <dir> heads <tree>
//! domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree> [--at <ip:port>]
//! ```
//!
//! A tree is named by its anchor, `domhringr://<tree-id>/`, whose tree id is
//! the tree key's 52 z-base-32 characters; a path in the tree by
//! `domhringr://<tree-id>/<segment>/…/<segment>`. A target is `commit
//! <commit-id>`, `tree <tree>`, `endpoint <endpoint-id>` or `datum <text>`.
//! Peer, endpoint and commit ids are 64 hex digits.
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
use domhringr_record_tree::BindError;
use domhringr_record_tree::BindPort;
use domhringr_record_tree::CommitError;
use domhringr_record_tree::CommitHex;
use domhringr_record_tree::HeadsError;
use domhringr_record_tree::Identity;
use domhringr_record_tree::IdentityError;
use domhringr_record_tree::OpenError;
use domhringr_record_tree::ParseAnchorError;
use domhringr_record_tree::ParseIdError;
use domhringr_record_tree::ParsePortError;
use domhringr_record_tree::Path;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::RandomError;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::RemotePeer;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::SyncError;
use domhringr_record_tree::Target;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::TreeKey;
use domhringr_record_tree::UdpPort;
use domhringr_record_tree::ViewError;

/// The synopsis written after a usage error.
const USAGE: &str = "\
usage: domhringr-peer --state <dir> id
       domhringr-peer --state <dir> serve [--port <port>]
       domhringr-peer --state <dir> open
       domhringr-peer --state <dir> grant <tree> <peer-id>
       domhringr-peer --state <dir> note <tree> <text>
       domhringr-peer --state <dir> bind <anchor> <target>
       domhringr-peer --state <dir> whence <anchor>
       domhringr-peer --state <dir> view <tree>
       domhringr-peer --state <dir> heads <tree>
       domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree> [--at <ip:port>]
where  <tree>   is domhringr://<tree-id>/
       <anchor> is domhringr://<tree-id>/<segment>/.../<segment>, or for whence a <tree>
       <target> is commit <commit-id> | tree <tree> | endpoint <endpoint-id> | datum <text>
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
    /// Print what an anchor resolves to.
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
            | Self::Bind => "bind <anchor> commit|tree|endpoint|datum <target>",
            | Self::Whence => "whence <anchor>",
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
    /// The tree to grant on, write to, read, or sync, or a bind's target tree.
    Tree,
    /// The anchor to bind or resolve.
    Anchor,
    /// The remote's iroh endpoint id, or a bind's target endpoint.
    Endpoint,
    /// The remote's or the grantee's subduction peer id.
    Peer,
    /// A bind's target commit.
    Commit,
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
            | Self::Endpoint => "endpoint id",
            | Self::Peer => "peer id",
            | Self::Commit => "commit id",
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
    /// Print what `anchor` resolves to in its tree's view.
    Whence
    {
        /// The anchor resolved.
        anchor: Anchor,
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
    /// A tree operand is an anchor naming a path.
    #[error("the tree anchor names a path: expected domhringr://<tree-id>/")]
    NotTree,
    /// The anchor to bind names no path.
    #[error("the anchor names no path to bind: expected domhringr://<tree-id>/<path>")]
    NoPath,
    /// A bind's target kind is not one this binary has.
    #[error("unknown target kind {0:?}: expected commit, tree, endpoint or datum")]
    Target(OsString),
    /// A note's text or a datum is not UTF-8.
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
///   `serve`, the options [`serve_port`] reads, or, for `sync`, what
///   [`sync_command`] reads. Other verbs' operands are taken verbatim, so a
///   note's text or a datum beginning with `-` is a text, not an option. A tree
///   operand is a bare anchor, `bind`'s anchor names a path, `whence`'s is
///   either, and `bind`'s target is read as [`read_target`] reads it.
/// - fails: [`UsageError::Arguments`] for any option but `--state` or for
///   `--state` without a value, [`UsageError::NoCommand`] when no verb follows
///   the options, [`UsageError::Command`] for an unknown verb,
///   [`UsageError::State`] when `--state` is absent, [`UsageError::Operands`]
///   for too few or too many operands, checked before any operand is read,
///   [`UsageError::Operand`] for an id that does not parse,
///   [`UsageError::Anchor`] for an anchor that does not parse,
///   [`UsageError::NotTree`] for a tree operand naming a path,
///   [`UsageError::NoPath`] for a bare anchor to bind, [`UsageError::Text`] for
///   a note's text that is not UTF-8, as [`read_target`] for `bind`'s target,
///   as [`serve_port`] for `serve`, and as [`sync_command`] for `sync`.
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
/// - [`UsageError::NotTree`]: a tree operand names a path.
/// - [`UsageError::NoPath`]: the anchor to bind names no path.
/// - [`UsageError::Target`]: the bind's target kind is unknown.
/// - [`UsageError::Text`]: the note's text or a datum is not UTF-8.
/// - [`UsageError::Port`]: `serve`'s port is not a UDP port.
/// - [`UsageError::At`]: `sync`'s address is not an IP address and port.
///
/// # Adequacy
/// - hypothesis: L3 — each verb with its operands, every bind target kind, a
///   bare and a path anchor to resolve, both `--state` spellings, `serve` with
///   and without a port, `sync` with and without an address, and a dash-leading
///   note and datum separate the accepted lines, and one line per refusal pins
///   which refusal each malformation gets, including an arity error that wins
///   over a malformed operand.
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
            let anchor = read_anchor(&anchor, Operand::Anchor)?;
            let Anchor::Path { tree, path } = anchor
            else {
                return Err(UsageError::NoPath);
            };
            let target = read_target(&kind, value)?;
            Command::Bind { tree, path, target }
        },
        | (Verb::Whence, (Some(anchor), None, None, None)) => Command::Whence {
            anchor: read_anchor(&anchor, Operand::Anchor)?,
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
/// - ensures: `id`, `serve`, `open`, `grant`, `note`, `bind`, `whence`, `view`,
///   `heads` and `sync` name their verbs.
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
/// - hypothesis: L3 — a malformed peer id, endpoint id and commit id are
///   refused under their own operand names.
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

/// Read the anchor `text` spells, for the operand `operand`.
///
/// # Specification
/// - ensures: yields the anchor [`Anchor`]'s parser reads from `text`, bare or
///   naming a path; text that is not UTF-8 is read with replacement characters,
///   which no anchor's tree accepts.
/// - fails: [`UsageError::Anchor`] naming `operand` and carrying the parser's
///   reason.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Anchor`]: the text is not an anchor.
///
/// # Adequacy
/// - hypothesis: L3 — a hex tree id where a tree anchor stands and a DNS-named
///   anchor where an anchor to resolve stands are refused under their own
///   operand names, the latter with the parser's reserved reason.
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_anchor(
    text: &OsStr,
    operand: Operand,
) -> Result<Anchor, UsageError>
{
    text.to_string_lossy()
        .parse::<Anchor>()
        .map_err(|source| UsageError::Anchor { operand, source })
}

/// Read the tree a bare anchor `text` names.
///
/// # Specification
/// - ensures: yields the tree of the bare anchor `domhringr://<tree-id>/`.
/// - fails: as [`read_anchor`] for the tree operand, and
///   [`UsageError::NotTree`] for an anchor naming a path.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Anchor`]: the text is not an anchor.
/// - [`UsageError::NotTree`]: the anchor names a path.
///
/// # Adequacy
/// - hypothesis: L3 — a bare anchor is read to its tree wherever a tree stands,
///   and a path anchor in its place is refused as no tree.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_tree(text: &OsStr) -> Result<TreeId, UsageError>
{
    let anchor = read_anchor(text, Operand::Tree)?;
    match anchor {
        | Anchor::Tree(tree) => Ok(tree),
        | Anchor::Path { .. } => Err(UsageError::NotTree),
    }
}

/// Read a bind's target from its kind and its value.
///
/// # Specification
/// - ensures: `commit` reads the value as a commit id, `tree` as a bare tree
///   anchor, `endpoint` as an endpoint id, and `datum` takes it verbatim.
/// - fails: [`UsageError::Target`] for any other kind, carrying it,
///   [`UsageError::Operand`] for a commit or endpoint id that does not parse,
///   as [`read_tree`] for a tree, and [`UsageError::Text`] for a datum that is
///   not UTF-8.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Target`]: the kind is unknown.
/// - [`UsageError::Operand`]: the commit or endpoint id does not parse.
/// - [`UsageError::Anchor`], [`UsageError::NotTree`]: as [`read_tree`].
/// - [`UsageError::Text`]: the datum is not UTF-8.
///
/// # Adequacy
/// - hypothesis: L3 — each kind is read to its target, a dash-leading datum
///   among them, and an unknown kind, a malformed commit id and a datum that is
///   not UTF-8 each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_target(
    kind: &OsStr,
    value: OsString,
) -> Result<Target, UsageError>
{
    match kind.to_str() {
        | Some("commit") => {
            let commit = read_id::<CommitHex>(&value, Operand::Commit)?;
            Ok(Target::Commit(commit.id()))
        },
        | Some("tree") => read_tree(&value).map(Target::Tree),
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
///   line. `grant`, `note` and `bind` commit their receipt, under a fresh
///   operation fence, and write the new commit's id line. `whence` writes what
///   the anchor resolves to in its tree's local view ([`Peer::whence`]): the
///   target, or `unbound`. `view` writes the tree's view, one line per fact
///   ([`domhringr_record_tree::View`]'s display). `heads` writes the tree's
///   heads, one sorted hex line each. `sync` dials the remote, at its direct
///   address when `--at` named one, writes the heads after the sync the same
///   way, then `path <peer-id> <path>` for the path the connection took, having
///   closed its endpoint. `serve` runs as [`serve`] specifies.
/// - fails: [`RunError::Identity`], [`RunError::Open`], [`RunError::Bind`],
///   [`RunError::Random`], [`RunError::Commit`], [`RunError::View`],
///   [`RunError::Heads`] and [`RunError::Sync`] as the record library reports
///   them, and [`RunError::Output`] when standard output cannot be written. A
///   failed sync still closes the endpoint.
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
/// - [`RunError::Heads`]: the heads cannot be read.
/// - [`RunError::Sync`]: the sync failed.
/// - [`RunError::Output`]: standard output cannot be written.
/// - [`RunError::Closed`], [`RunError::Diagnostics`]: as [`serve`].
///
/// # Adequacy
/// - hypothesis: L3 — two processes exchange ids, open a tree and parse its
///   anchor, grant, write notes, bind paths, resolve them, read heads and
///   views, and sync at each other's direct address in both directions; views
///   are compared byte for byte across processes and with the expected facts,
///   resolutions with the commit bound, and each sync's path line is parsed.
/// - witness: `sync::tests::two_peers_fold_one_tree_to_identical_views`
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
/// - witness: `sync::tests::an_anchor_resolves_alike_on_both_peers`
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
            emit(&format_args!("{}\n", Anchor::Tree(key.tree())))
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
        | Command::Whence { anchor } => {
            let resolution = Peer::open(&state, identity)?.whence(&anchor).await?;
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
    use domhringr_record_tree::BindPort;
    use domhringr_record_tree::CommitHex;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::ParseAnchorError;
    use domhringr_record_tree::Path;
    use domhringr_record_tree::RemotePeer;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::Target;
    use domhringr_record_tree::UdpPort;

    use super::Command;
    use super::Invocation;
    use super::Operand;
    use super::UsageError;
    use super::Verb;
    use super::parse;

    /// The tree the command lines name: the all-zero key's anchor.
    const TREE: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/";

    /// A path in that tree.
    const PATH: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/a/b";

    /// A commit id, which is also the form a tree id took before anchors.
    const COMMIT: &str = "0707070707070707070707070707070707070707070707070707070707070707";

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
        let tree = TREE.parse::<Anchor>().unwrap().tree();
        let (anchor, path) = (
            PATH.parse::<Anchor>().unwrap(),
            "a/b".parse::<Path>().unwrap(),
        );
        let commit = COMMIT.parse::<CommitHex>().unwrap().id();
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
                vec!["--state", "dir", "bind", PATH, "commit", COMMIT],
                bind(Target::Commit(commit)),
            ),
            (
                vec!["--state", "dir", "bind", PATH, "tree", TREE],
                bind(Target::Tree(tree)),
            ),
            (
                vec!["--state", "dir", "bind", PATH, "endpoint", &endpoint],
                bind(Target::Endpoint(remote.endpoint())),
            ),
            (
                vec!["--state", "dir", "bind", PATH, "datum", "--not an option"],
                bind(Target::Datum(String::from("--not an option"))),
            ),
            (vec!["--state", "dir", "whence", PATH], Command::Whence {
                anchor,
            }),
            (vec!["--state", "dir", "whence", TREE], Command::Whence {
                anchor: Anchor::Tree(tree),
            }),
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
    }

    #[test]
    fn a_malformed_command_line_is_refused()
    {
        let remote = remote();
        let (endpoint, peer) = (remote.endpoint().to_string(), remote.peer().to_string());
        let refused = |line: Vec<OsString>| parse(lexopt::Parser::from_args(line)).unwrap_err();
        let line = |words: &[&str]| words.iter().map(OsString::from).collect::<Vec<_>>();
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
            "a hex tree id is no longer read"
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
            refused(line(&["--state", "dir", "bind", PATH, "commit"])),
            UsageError::Operands(Verb::Bind)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "bind", TREE, "commit", COMMIT])),
            UsageError::NoPath
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "bind", PATH, "commit", "nothex"])),
            UsageError::Operand {
                operand: Operand::Commit,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "bind", PATH, "tree", PATH])),
            UsageError::NotTree
        ));
        assert!(
            matches!(refused(line(&["--state", "dir", "bind", PATH, "tag", "x"])), UsageError::Target(kind) if kind == "tag")
        );
        assert!(matches!(
            refused(line(&[
                "--state",
                "dir",
                "whence",
                "domhringr://example.org/x"
            ])),
            UsageError::Anchor {
                operand: Operand::Anchor,
                source: ParseAnchorError::DnsName,
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "whence", PATH, "extra"])),
            UsageError::Operands(Verb::Whence)
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
    }
}
