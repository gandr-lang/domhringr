//! `domhringr-peer`: one record-plane peer over a state directory. It commits
//! to a sedimentree, reads the tree's heads, and syncs the tree with another
//! peer over iroh.
//!
//! ```text
//! domhringr-peer --state <dir> id
//! domhringr-peer --state <dir> serve
//! domhringr-peer --state <dir> commit <tree-id> <text>
//! domhringr-peer --state <dir> heads <tree-id>
//! domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree-id>
//! ```
//!
//! The state directory holds the peer's two keys and its tree store, both
//! created on first use. A command holds the store exclusively while it runs,
//! so `commit`, `heads` and `sync` fail while `serve` runs on the same
//! directory; `id` reads only the keys and runs beside it.
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
use core::str::FromStr;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use domhringr_record_tree::AcceptError;
use domhringr_record_tree::BindError;
use domhringr_record_tree::CommitError;
use domhringr_record_tree::Content;
use domhringr_record_tree::HeadsError;
use domhringr_record_tree::Identity;
use domhringr_record_tree::IdentityError;
use domhringr_record_tree::OpenError;
use domhringr_record_tree::ParseIdError;
use domhringr_record_tree::Peer;
use domhringr_record_tree::RemotePeer;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::SyncError;
use domhringr_record_tree::TreeId;

/// The synopsis written after a usage error.
const USAGE: &str = "\
usage: domhringr-peer --state <dir> id
       domhringr-peer --state <dir> serve
       domhringr-peer --state <dir> commit <tree-id> <text>
       domhringr-peer --state <dir> heads <tree-id>
       domhringr-peer --state <dir> sync <endpoint-id> <peer-id> <tree-id>
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
    /// Append a commit to a tree.
    Commit,
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
            | Self::Serve => "serve",
            | Self::Commit => "commit <tree-id> <text>",
            | Self::Heads => "heads <tree-id>",
            | Self::Sync => "sync <endpoint-id> <peer-id> <tree-id>",
        })
    }
}

/// The operand an id is read for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operand
{
    /// The tree to commit to, read, or sync.
    Tree,
    /// The remote's iroh endpoint id.
    Endpoint,
    /// The remote's subduction peer id.
    Peer,
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
            | Self::Tree => "tree id",
            | Self::Endpoint => "endpoint id",
            | Self::Peer => "peer id",
        })
    }
}

/// A command with its operands read.
#[derive(Debug, PartialEq, Eq)]
enum Command
{
    /// Print the endpoint id, then the peer id.
    Id,
    /// Bind, print the ids and `listening`, then accept peers until killed.
    Serve,
    /// Append `content` to `tree` and print the commit id.
    Commit
    {
        /// The tree appended to.
        tree: TreeId,
        /// The commit's bytes.
        content: Content,
    },
    /// Print `tree`'s heads.
    Heads
    {
        /// The tree read.
        tree: TreeId,
    },
    /// Sync `tree` with `remote` and print the heads after it.
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
    /// The text to commit is not UTF-8.
    #[error("the text to commit is not UTF-8: {0:?}")]
    Text(OsString),
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
    /// The commit cannot be appended.
    #[error(transparent)]
    Commit(#[from] CommitError),
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
///   wins) followed by a verb and exactly the operands that verb takes. The
///   operands are taken verbatim, so a text beginning with `-` is a text, not
///   an option.
/// - fails: [`UsageError::Arguments`] for any option but `--state` or for
///   `--state` without a value, [`UsageError::NoCommand`] when no verb follows
///   the options, [`UsageError::Command`] for an unknown verb,
///   [`UsageError::State`] when `--state` is absent, [`UsageError::Operands`]
///   for too few or too many operands, checked before any operand is read,
///   [`UsageError::Operand`] for an id that does not parse, and
///   [`UsageError::Text`] for a text that is not UTF-8.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or `--state` lacks a value.
/// - [`UsageError::NoCommand`]: no verb follows the options.
/// - [`UsageError::Command`]: the verb is unknown.
/// - [`UsageError::State`]: `--state` is absent.
/// - [`UsageError::Operands`]: the verb's operand count is wrong.
/// - [`UsageError::Operand`]: an operand is not an id.
/// - [`UsageError::Text`]: the text is not UTF-8.
///
/// # Adequacy
/// - hypothesis: L3 — each verb with its operands, both `--state` spellings,
///   and a dash-leading text separate the accepted lines, and one line per
///   refusal pins which refusal each malformation gets, including an arity
///   error that wins over a malformed operand.
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
    let mut raw = arguments.raw_args()?;
    // One more operand than any verb takes is read, so that a surplus is seen.
    let operands = (raw.next(), raw.next(), raw.next(), raw.next());
    let command = match (verb, operands) {
        | (Verb::Id, (None, None, None, None)) => Command::Id,
        | (Verb::Serve, (None, None, None, None)) => Command::Serve,
        | (Verb::Commit, (Some(tree), Some(text), None, None)) => Command::Commit {
            tree: read_id(&tree, Operand::Tree)?,
            content: content(text)?,
        },
        | (Verb::Heads, (Some(tree), None, None, None)) => Command::Heads {
            tree: read_id(&tree, Operand::Tree)?,
        },
        | (Verb::Sync, (Some(endpoint), Some(peer), Some(tree), None)) => {
            let endpoint = read_id(&endpoint, Operand::Endpoint)?;
            let peer = read_id(&peer, Operand::Peer)?;
            Command::Sync {
                remote: RemotePeer::new(endpoint, peer),
                tree: read_id(&tree, Operand::Tree)?,
            }
        },
        | (verb, _) => return Err(UsageError::Operands(verb)),
    };
    Ok(Invocation { state, command })
}

/// Name the verb `word` spells.
///
/// # Specification
/// - ensures: `id`, `serve`, `commit`, `heads` and `sync` name their verbs.
/// - fails: [`UsageError::Command`] for any other word, carrying it.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Command`]: the word is not a verb.
///
/// # Adequacy
/// - hypothesis: L3 — every verb is read by name and an unknown word is refused
///   with the word kept.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn verb(word: OsString) -> Result<Verb, UsageError>
{
    match word.to_str() {
        | Some("id") => Ok(Verb::Id),
        | Some("serve") => Ok(Verb::Serve),
        | Some("commit") => Ok(Verb::Commit),
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
/// - hypothesis: L3 — a malformed tree id and a malformed endpoint id are
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

/// Take `text` as commit content.
///
/// # Specification
/// - ensures: the content is the text's UTF-8 bytes.
/// - fails: [`UsageError::Text`] for text that is not UTF-8, carrying it.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Text`]: the text is not UTF-8.
///
/// # Adequacy
/// - hypothesis: L3 — a dash-leading text becomes its bytes and an invalid byte
///   sequence is refused.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn content(text: OsString) -> Result<Content, UsageError>
{
    text.into_string()
        .map(|text| Content::from(text.into_bytes()))
        .map_err(UsageError::Text)
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
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
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
///   endpoint id line, then the peer id line, and opens no store. `commit`
///   writes the new commit's id line. `heads` writes the tree's heads, one
///   sorted hex line each. `sync` writes the heads after the sync the same way,
///   having closed its endpoint. `serve` runs as [`serve`] specifies.
/// - fails: [`RunError::Identity`], [`RunError::Open`], [`RunError::Bind`],
///   [`RunError::Commit`], [`RunError::Heads`] and [`RunError::Sync`] as the
///   record library reports them, and [`RunError::Output`] when standard output
///   cannot be written. A failed sync still closes the endpoint.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Identity`]: the identity cannot be read or created.
/// - [`RunError::Open`]: the store cannot be opened, as when `serve` holds it.
/// - [`RunError::Bind`]: the endpoint cannot bind.
/// - [`RunError::Commit`]: the commit cannot be appended.
/// - [`RunError::Heads`]: the heads cannot be read.
/// - [`RunError::Sync`]: the sync failed.
/// - [`RunError::Output`]: standard output cannot be written.
/// - [`RunError::Closed`], [`RunError::Diagnostics`]: as [`serve`].
///
/// # Adequacy
/// - hypothesis: L3 — two processes exchange ids, commit, read heads, and sync
///   before and after one restarts; each output line is compared exactly with
///   another process's output.
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
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
        | Command::Serve => serve(Peer::open(&state, identity)?).await,
        | Command::Commit { tree, content } => {
            let id = Peer::open(&state, identity)?.commit(tree, content).await?;
            emit(&format_args!("{id}\n"))
        },
        | Command::Heads { tree } => {
            let heads = Peer::open(&state, identity)?.heads(tree).await?;
            emit(&heads)
        },
        | Command::Sync { remote, tree } => {
            let node = Peer::open(&state, identity)?.bind().await?;
            let synced = node.sync(&remote, tree).await;
            node.close().await;
            drop(node);
            emit(&synced?)
        },
    }
}

/// Bind `peer`, announce it, and accept peers until the process is killed.
///
/// # Specification
/// - ensures: once the endpoint is bound, writes the endpoint id line, the peer
///   id line and `listening`; then writes `accepted <peer-id>` for each peer
///   admitted. A connection that fails its handshake is reported on standard
///   error and serving continues.
/// - fails: [`RunError::Bind`] when the endpoint cannot bind,
///   [`RunError::Closed`] if the endpoint closes, [`RunError::Output`] and
///   [`RunError::Diagnostics`] when standard output or standard error cannot be
///   written. It does not return otherwise.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Bind`]: the endpoint cannot bind.
/// - [`RunError::Closed`]: the endpoint closed.
/// - [`RunError::Output`]: standard output cannot be written.
/// - [`RunError::Diagnostics`]: standard error cannot be written.
///
/// # Adequacy
/// - hypothesis: L3 — the process test reads the announced ids and `listening`,
///   syncs against the server before and after a restart, and reads one
///   `accepted` line per sync.
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
async fn serve(peer: Peer) -> Result<(), RunError>
{
    let node = peer.bind().await?;
    emit(&format_args!(
        "{}\n{}\nlistening\n",
        node.endpoint_key(),
        node.peer().identity().peer_key()
    ))?;
    loop {
        match node.accept().await {
            | Ok(remote) => emit(&format_args!("accepted {remote}\n"))?,
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
    use std::ffi::OsString;
    use std::path::PathBuf;

    use domhringr_record_tree::Content;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::RemotePeer;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::TreeId;

    use super::Command;
    use super::Invocation;
    use super::Operand;
    use super::UsageError;
    use super::Verb;
    use super::parse;

    /// The tree the command lines name.
    const TREE: &str = "6c696e656c696e656c696e656c696e656c696e656c696e656c696e656c696e65";

    /// A real endpoint id and peer id, from an identity made for the test.
    ///
    /// # Specification
    /// trivial.
    fn remote() -> RemotePeer
    {
        let root = tempfile::tempdir().unwrap();
        let identity =
            Identity::load_or_create(&StateDir::from(root.path().to_path_buf())).unwrap();
        RemotePeer::new(identity.endpoint_key(), identity.peer_key())
    }

    #[test]
    fn every_verb_reads_its_operands()
    {
        let tree = TREE.parse::<TreeId>().unwrap();
        let state = StateDir::from(PathBuf::from("dir"));
        let remote = remote();
        let (endpoint, peer) = (remote.endpoint().to_string(), remote.peer().to_string());
        let lines = [
            (vec!["--state", "dir", "id"], Command::Id),
            (vec!["--state=dir", "serve"], Command::Serve),
            (
                vec!["--state", "dir", "commit", TREE, "--not-an-option"],
                Command::Commit {
                    tree,
                    content: Content::from(b"--not-an-option".to_vec()),
                },
            ),
            (
                vec!["--state", "elsewhere", "--state", "dir", "heads", TREE],
                Command::Heads { tree },
            ),
            (
                vec!["--state", "dir", "sync", &endpoint, &peer, TREE],
                Command::Sync { remote, tree },
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
        let endpoint = remote().endpoint().to_string();
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
            UsageError::Operand {
                operand: Operand::Tree,
                ..
            }
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
        let mut invalid = line(&["--state", "dir", "commit", TREE]);
        invalid.push(std::os::unix::ffi::OsStringExt::from_vec(vec![0xff]));
        assert!(matches!(refused(invalid), UsageError::Text(_)));
    }
}
