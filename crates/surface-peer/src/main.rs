//! `domhringr-peer`: one record-plane peer over a state directory. It opens a
//! sedimentree under a key of the tree's own, grants write authority on it,
//! writes notes to it, binds paths in it, claims DNS names for it, introduces
//! other trees in it by label, presents and withdraws the endpoint it is
//! reached at, resolves an anchor or a commit to what it names, prints the
//! view every peer holding the same commits folds them to and the book of
//! who is reachable where, reads the tree's heads, syncs the tree with
//! another peer over iroh, dispatches a seat to a tree read as a task and
//! wakes it, reports on, hands off or retires from the dispatch it holds,
//! replays the task, fetches the evidence its receipts name, judges a
//! transcript of the task into a verdict on its dispatch, reads playbooks and
//! rubrics and runs them on the task, and checks a concepts tree's bindings
//! against a public and a vault checkout.
//!
//! ```text
//! domhringr-peer --state <dir> id
//! domhringr-peer --state <dir> serve [--port <port>] [--surface <program>]
//! domhringr-peer --state <dir> open
//! domhringr-peer --state <dir> grant <tree> <peer-id>
//! domhringr-peer --state <dir> note <tree> <text>
//! domhringr-peer --state <dir> bind <anchor> <target>
//! domhringr-peer --state <dir> claim <tree> <domain>
//! domhringr-peer --state <dir> introduce <tree> <label> <tree>
//! domhringr-peer --state <dir> present <tree> [--port <port>]
//! domhringr-peer --state <dir> withdraw <tree> [<peer-id>]
//! domhringr-peer --state <dir> book <tree>
//! domhringr-peer --state <dir> whence <name> [--witness <domain>=<tree-id>]... [--in <tree>]
//!                [--peer <peer-id>] [--at <endpoint>] [--local]
//! domhringr-peer --state <dir> view <tree>
//! domhringr-peer --state <dir> heads <tree>
//! domhringr-peer --state <dir> sync <tree> [--peer <peer-id>] [--at <endpoint>]
//! domhringr-peer --state <dir> dispatch <tree> <peer-id> <brief> [--at <endpoint>]
//! domhringr-peer --state <dir> report <tree> <file> <summary>
//! domhringr-peer --state <dir> handoff <tree> <peer-id>
//! domhringr-peer --state <dir> retire <tree>
//! domhringr-peer --state <dir> replay <tree> [--peer <peer-id>] [--at <endpoint>] [--local]
//! domhringr-peer --state <dir> evidence <tree> <digest> [--peer <peer-id>] [--at <endpoint>]
//!                [--local]
//! domhringr-peer --state <dir> drift --public <checkout> --vault <checkout> <tree>
//! domhringr-peer --state <dir> judge ask --question <text> --option <text>...
//!                (--transcript <digest> | --transcript-file <file>) [--static <file>]
//! domhringr-peer --state <dir> judge verdict <tree> --rubric <content-hash>
//!                (--transcript <digest> | --transcript-file <file>)
//!                (--question <text> --option <text>...)... [--static <file>]
//! domhringr-peer --state <dir> playbook validate <file>
//! domhringr-peer --state <dir> playbook run <file> <tree> [--task-state <dir>] [--static <file>]
//! domhringr-peer --state <dir> rubric validate <file>
//! domhringr-peer --state <dir> rubric grade <file> <tree> [--task-state <dir>] [--static <file>]
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
//! and commit ids are 64 hex digits. An endpoint is an endpoint id followed by
//! any number of `@<address>`, each an IP address and port (an IPv6 address
//! in brackets) or a relay URL: `<endpoint-id>@192.0.2.7:4433`.
//!
//! `present` binds the endpoint at `--port`, the port `serve` binds after it,
//! and commits a presence of it at the addresses iroh names for it: who the
//! peer is reached at, for every peer that syncs the tree. `withdraw` commits
//! the withdrawal of a presence, this peer's own unless a peer id is named.
//! `book` prints each present peer as `<peer-id> <endpoint> <commit-id>`, the
//! commit the one that presented the endpoint. The book is the record's, so
//! a peer is reached where it last said it is, until it or the owner
//! withdraws that.
//!
//! `sync` dials the peer `--peer` names, or the tree's owner, at the endpoint
//! `--at` names, or else at that peer's presence in the tree's book, and
//! prints `source <tree> book <commit-id>` or `source <tree> at <endpoint>`
//! first: where the endpoint came from. `whence` reaches the same way, before
//! resolving, each tree the resolution reads that the peer aimed at is not
//! this peer — the key's tree, every tree the DNS name's witness names, or the
//! label's `--in` tree and then the tree it introduces — printing a `source`
//! line for each; `--local` resolves from the local store alone. A peer with no
//! presence in the book and no `--at` is unreachable; first contact names the
//! endpoint by hand, and one sync carries the book.
//!
//! A tree is also a task. `dispatch` puts the seat its peer id names in the
//! task's slot to work from a brief — `anchor <anchor>`, or `content
//! <content-hash>`, 64 hex digits of BLAKE3 — and wakes it: it commits the
//! dispatch, or re-sends the current one when it already puts that seat to
//! that brief, prints the dispatch's commit id at once, then reaches the seat
//! at `--at` or at its presence in the task's book, names the dispatch on the
//! seat protocol's one stream, and prints the `source` line and `woken` when
//! the seat holds the slot. `serve` answers such wakes: it pulls the task from
//! the operator, presents itself in the task's book when the book lacks it,
//! prints `woken <tree> <dispatch-id>`, and acts through `--surface`: it runs
//! the program with `anchor <anchor>` or `content <hash>` as its arguments and
//! the task's and the dispatch's anchors in `DOMHRINGR_TASK` and
//! `DOMHRINGR_DISPATCH`, and when the program exits 0 keeps its standard
//! output as evidence and commits a report — the output named by its value
//! manifest, and its first line as the summary — and prints `reported <tree>
//! <commit-id>`; a program that fails prints `unreported <tree>
//! <dispatch-id>` and the slot stays held. A seat serving without `--surface`
//! holds its slots and never reports; on start it acts on every dispatch it
//! holds unreported. `serve` also answers fetches of the evidence its store
//! holds, printing `served <digest>` for each one it sent and `unserved
//! <digest>` with the cause on standard error for one it does not hold.
//! `report` keeps the content of `<file>` as evidence and commits a
//! report naming it; `report`, `handoff` and `retire` commit their receipt on
//! the task's current dispatch from the store alone, the summary taken
//! verbatim. `replay` reaches the current attempt's seat, or `--peer`, as
//! `sync` does — the task's owner when no dispatch is admitted — syncs the
//! task, fetches from that peer each evidence the admitted receipts name that
//! the local store lacks, and prints the `source` line, one line per seat
//! receipt the fold admitted and where the task stands: `undispatched`; the
//! furthest of a verification, a grading, a decision and a landing on the
//! current dispatch, `verified <dispatch-id> <verification-id>`, `graded
//! <dispatch-id> <grading-id> <composed>`, `decided <dispatch-id>
//! <decision-id> <decision>` or `landed <dispatch-id> <landing-id>
//! <revision>`; otherwise `dispatched <dispatch-id> <holder>`, `reported
//! <dispatch-id> <report-id>`, or `stalled <dispatch-id> <retirement-id>`;
//! then `evidence <digest> held` or `evidence <digest> unheld` per evidence
//! in the order first named, the cause of an unheld one on standard error.
//! `--local` prints the local store's task and evidence alone.
//!
//! Evidence — a report's content, a verifier's output, a judge's transcript —
//! lives in the evidence store as a value of the value plane, and a receipt
//! names it by its manifest digest, 64 hex digits. `evidence` writes the
//! content `<digest>` names to standard output, byte for byte, from the local
//! store, or else fetched from the peer whose receipt in the task names it,
//! or `--peer`, at `--at` or at its presence in the book, and kept. A fetched
//! value is checked whole — its manifest's identity and profile, every chunk
//! against its digest, the closure complete — before any byte is written: a
//! value the holder cannot send whole is refused naming the first chunk
//! neither side holds, and nothing reaches standard output.
//!
//! A judge rules on a task's current dispatch. `judge ask` asks one question
//! about a transcript — the content at `--transcript-file`, or the evidence
//! `--transcript` names by its digest, held in the local store — and prints
//! `transcript <digest>` and `ruling <question-hash> <ruling>`; `judge
//! verdict` asks each question in turn, prints the same lines, keeps the
//! transcript as evidence, commits a verdict on the task's current dispatch
//! naming this peer the judge, the `--rubric` the questions come from, the
//! transcript by its digest and each question by its hash with each ruling,
//! and prints the commit id. A question is a `--question` and the `--option`s
//! after it, two to twenty-six, lettered `A`, `B`, … in order; its hash is
//! the BLAKE3 of its canonical form. A ruling is `read <letter> A=<p> B=<p> …
//! outside=<p>` — the answer letter, each option's probability renormalised
//! over the option letters, and the mass outside them — or `unread
//! <reason>`, the reason `no letter`, `outside`, `tied`, `endpoint` or
//! `malformed` and its cause written to standard error, the command still
//! succeeding: an unread question is recorded, never a default letter. The
//! judge asks the OpenAI-compatible endpoint the environment names —
//! `DOMHRINGR_JUDGE_ENDPOINT` its base URL, `DOMHRINGR_JUDGE_MODEL`, and
//! optionally `DOMHRINGR_JUDGE_KEY`, a bearer key, and
//! `DOMHRINGR_JUDGE_CEILING`, the most outside mass it admits — or, with
//! `--static`, answers from a table file of `<question-hash>
//! <transcript-digest> <ruling>` lines. `replay` prints a verdict as `verdict
//! <commit-id> <dispatch-id> <judge> <rubric> <transcript>` and one `ruling
//! <commit-id> <question> <ruling>` line per question.
//!
//! A playbook and a rubric are TOML documents (`domhringr-strategy-document`
//! states their shapes). `playbook validate` reads a playbook and each rubric
//! its steps name, relative to its own directory, and prints `playbook <hash>
//! <name>` and per step `step <id> verifier` or `step <id> question
//! <rubric-hash> <question> <question-hash>`; `rubric validate` prints
//! `rubric <hash> <name>` and per question `question <name> <hash>`, the
//! hashes a `--static` table names. A document that does not read fails
//! naming its file, the field at fault and why: `<file>: steps[1].why:
//! missing field`. `playbook run` names the task's current dispatch, prints
//! the `playbook` line, runs each verifier step in turn in `--task-state`
//! (the working directory by default) with its output and error as one
//! stream, keeps the output as evidence, commits a verification naming this
//! peer the runner, and prints `verified <commit-id> <step> <output-digest>
//! <status>`, the status `exit <code>` or `signal <number>`; then for each
//! rubric its steps name it prints the `rubric` line, reads the rubric's
//! state files into the transcript, keeps it as evidence, asks the questions
//! the steps name as `judge verdict` asks
//! them, commits the verdict, prints `verdict <commit-id>` and `grade
//! <question-hash> <grade>` per question — `met`, `unmet`, `undecided` or
//! `refused` against the rubric's band — commits the grading of the verdict
//! and prints `graded <commit-id> <composed>`. `rubric grade` grades every
//! question of one rubric the same way. A failing verifier or an unmet grade
//! is recorded, and the command still succeeds. `replay` prints a
//! verification as `verified <commit-id> <dispatch-id> <runner> <playbook>
//! <step> <output> <status>`, and a grading as `graded <commit-id>
//! <dispatch-id> <verdict-id> <rubric> <composed>` and one `grade <commit-id>
//! <question> <grade>` line per question.
//!
//! The state directory holds the peer's two keys, the key of each tree it
//! opened, its tree store and its evidence store, all created on first use.
//! A command holds the tree store exclusively while it runs, so every command
//! but `id` fails while `serve` runs on the same directory; `id` reads only
//! the keys and runs beside it.
//!
//! `drift` folds a concepts tree, whose paths are bound to data
//! `vault:<path>@<commit>`, and reads two git checkouts with the `git`
//! binary: the public one, whose tracked text cites the tree's paths by
//! their key-form anchors, and the vault, which holds the pages. It prints one
//! line per finding in anchor order — `unbound`, `drifted`, `missing`,
//! `orphaned` or `malformed`, the anchor, and the citing `<file>:<line>` or
//! the bound `<vault path>@<commit>` — and prints nothing for a consistent
//! pair. It syncs nothing and dials no one.
//!
//! The exit status is 0 on success, 1 when the command fails, 2 for a
//! command line that cannot be run, and 3 when `drift` reports a finding;
//! diagnostics go to standard error.

// The opt-in quenchant lints: absence named by `Maybe` in signatures and in
// fields outside wire form, arithmetic on nominal types. Selected here because
// Dylint's `-D` cannot reach rustc through `cargo dylint`; see
// `.config/mise/tasks/mise-tasks-check.toml`.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]

extern crate alloc;

mod drift;
mod strategy;

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use core::error::Error;
use core::fmt;
use core::slice;
use core::str::FromStr;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use domhringr_judge_oracle::Backend;
use domhringr_judge_oracle::ChatCompletions;
use domhringr_judge_oracle::Config;
use domhringr_judge_oracle::ConfigError;
use domhringr_judge_oracle::EndpointError;
use domhringr_judge_oracle::ParseTableError;
use domhringr_judge_oracle::Question;
use domhringr_judge_oracle::QuestionError;
use domhringr_judge_oracle::Transcript;
use domhringr_record_evidence::Evidence;
use domhringr_record_evidence::EvidenceError;
use domhringr_record_evidence::FetchError;
use domhringr_record_evidence::ParseDigestError;
use domhringr_record_evidence::ParsedDigest;
use domhringr_record_evidence::Served;
use domhringr_record_tree::Aim;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::At;
use domhringr_record_tree::Authority;
use domhringr_record_tree::BindError;
use domhringr_record_tree::BindPort;
use domhringr_record_tree::Brief;
use domhringr_record_tree::CommitError;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Content;
use domhringr_record_tree::ContentHash;
use domhringr_record_tree::Current;
use domhringr_record_tree::Dns;
use domhringr_record_tree::Domain;
use domhringr_record_tree::Endpoint;
use domhringr_record_tree::HeadsError;
use domhringr_record_tree::Identity;
use domhringr_record_tree::IdentityError;
use domhringr_record_tree::Label;
use domhringr_record_tree::Node;
use domhringr_record_tree::OpenError;
use domhringr_record_tree::ParseAnchorError;
use domhringr_record_tree::ParseDomainError;
use domhringr_record_tree::ParseIdError;
use domhringr_record_tree::ParseLabelError;
use domhringr_record_tree::ParsePortError;
use domhringr_record_tree::ParseSummaryError;
use domhringr_record_tree::Path;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::PresentError;
use domhringr_record_tree::RandomError;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Reference;
use domhringr_record_tree::Resolution;
use domhringr_record_tree::Route;
use domhringr_record_tree::RouteError;
use domhringr_record_tree::Ruling;
use domhringr_record_tree::Scope;
use domhringr_record_tree::Slot;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::Static;
use domhringr_record_tree::Summary;
use domhringr_record_tree::SyncError;
use domhringr_record_tree::Target;
use domhringr_record_tree::Task;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::TreeKey;
use domhringr_record_tree::UdpPort;
use domhringr_record_tree::ViewError;
use domhringr_record_tree::WhenceError;
use domhringr_record_tree::Witness;
use domhringr_seat_slot::Event;
use domhringr_seat_slot::Surface;
use domhringr_seat_slot::Wake;
use domhringr_seat_slot::WakeError;
use gandr_storage_values::ManifestDigest;

/// The synopsis written after a usage error.
const USAGE: &str = "\
usage: domhringr-peer --state <dir> id
       domhringr-peer --state <dir> serve [--port <port>] [--surface <program>]
       domhringr-peer --state <dir> open
       domhringr-peer --state <dir> grant <tree> <peer-id>
       domhringr-peer --state <dir> note <tree> <text>
       domhringr-peer --state <dir> bind <anchor> <target>
       domhringr-peer --state <dir> claim <tree> <domain>
       domhringr-peer --state <dir> introduce <tree> <label> <tree>
       domhringr-peer --state <dir> present <tree> [--port <port>]
       domhringr-peer --state <dir> withdraw <tree> [<peer-id>]
       domhringr-peer --state <dir> book <tree>
       domhringr-peer --state <dir> whence <name> [--witness <domain>=<tree-id>]... [--in <tree>]
                      [--peer <peer-id>] [--at <endpoint>] [--local]
       domhringr-peer --state <dir> view <tree>
       domhringr-peer --state <dir> heads <tree>
       domhringr-peer --state <dir> sync <tree> [--peer <peer-id>] [--at <endpoint>]
       domhringr-peer --state <dir> dispatch <tree> <peer-id> <brief> [--at <endpoint>]
       domhringr-peer --state <dir> report <tree> <file> <summary>
       domhringr-peer --state <dir> handoff <tree> <peer-id>
       domhringr-peer --state <dir> retire <tree>
       domhringr-peer --state <dir> pause <tree>
       domhringr-peer --state <dir> replay <tree> [--peer <peer-id>] [--at <endpoint>] [--local]
                      [--base]
       domhringr-peer --state <dir> evidence <tree> <digest> [--peer <peer-id>] [--at <endpoint>]
                      [--local]
       domhringr-peer --state <dir> drift --public <checkout> --vault <checkout> <tree>
       domhringr-peer --state <dir> judge ask <question> <transcript> [--static <file>]
       domhringr-peer --state <dir> judge verdict <tree> --rubric <content-hash> <transcript>
                      <question>... [--static <file>]
       domhringr-peer --state <dir> playbook validate <file>
       domhringr-peer --state <dir> playbook run <file> <tree> [--task-state <dir>]
                      [--static <file>]
       domhringr-peer --state <dir> rubric validate <file>
       domhringr-peer --state <dir> rubric grade <file> <tree> [--task-state <dir>]
                      [--static <file>]
where  <tree>   is domhringr://<tree-id>/
       <anchor> is domhringr://<tree-id>/<segment>/.../<segment>
       <commit> is domhringr://<tree-id>/.commit/<commit-id>, the id whole, or for whence
                a prefix of at least 8 hex digits no other commit of the tree begins with
       <name>   is a <tree>, an <anchor> or a <commit> in one of three forms: by key, as
                above; by DNS name, <domain> in place of <tree-id>: a name with a dot,
                resolved through its witness and the tree's claim; or by label, <label>
                in place of <tree-id>: a name without a dot, resolved in the --in tree
       <target> is anchor <name> | endpoint <endpoint-id> | datum <text>
       <brief>  is anchor <anchor> | content <content-hash>, 64 hex digits of BLAKE3
       <digest> is evidence's manifest digest, 64 hex digits
       <endpoint> is <endpoint-id>, then @<ip:port> or @<relay-url> for each address
                it is reached at; sync and whence reach the tree's owner, or --peer,
                dispatch the seat, replay the current dispatch's seat and evidence the
                peer whose receipt names it, at --at, or else at its presence in the
                tree's book
       <program> runs as <program> anchor <anchor> | content <hash>; exiting 0, its
                standard output is the report, kept as evidence, its first line the summary
       <checkout> is a directory in a git working tree, read as its whole repository
       <question> is --question <text> --option <text>..., two to twenty-six options
       <transcript> is --transcript <digest> | --transcript-file <file>
       <file>   for report holds the report's content; for --static it holds
                <question-hash> <transcript-digest> <ruling> lines; without
                it the judge asks the endpoint DOMHRINGR_JUDGE_ENDPOINT and
                DOMHRINGR_JUDGE_MODEL name; for validate, run and grade it is a playbook
                or a rubric in TOML
       <dir>    for --task-state is the task's state, where verifiers run and a rubric's
                state files are read; the working directory by default
A segment beginning with . is reserved for the forms above: no path holds one.
";

/// The exit status of a command line that cannot be run.
const USAGE_STATUS: u8 = 2;

/// The exit status of a `drift` that reported a finding.
const DRIFT_STATUS: u8 = 3;

/// The command a command line names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verb
{
    /// Print the peer's ids.
    Id,
    /// Accept peers and answer wakes until killed.
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
    /// Present this peer's endpoint in a tree.
    Present,
    /// Withdraw a presence from a tree.
    Withdraw,
    /// Print a tree's book.
    Book,
    /// Print what an anchor or a commit resolves to.
    Whence,
    /// Print a tree's view.
    View,
    /// Print a tree's heads.
    Heads,
    /// Sync a tree with a remote peer.
    Sync,
    /// Dispatch a seat to a brief in a task and wake it.
    Dispatch,
    /// Report on the task's current dispatch.
    Report,
    /// Hand the task's current slot to another seat.
    Handoff,
    /// Retire from the task's current slot.
    Retire,
    /// Pause work while retaining the slot.
    Pause,
    /// Print a task's seat receipts and where it stands.
    Replay,
    /// Print the content of an evidence a task names, fetching it when the
    /// local store lacks it.
    Evidence,
    /// Check a concepts tree against a public and a vault checkout.
    Drift,
    /// Ask a question about a transcript, or rule on a task: `judge` without
    /// `ask` or `verdict` after it.
    Judge,
    /// Ask a question about a transcript and print the ruling.
    Ask,
    /// Ask questions about a task's transcript and commit the rulings as a
    /// verdict on its current dispatch.
    Verdict,
    /// Read a playbook, or run one on a task: `playbook` without `validate`
    /// or `run` after it.
    Playbook,
    /// Read a playbook and the rubrics it names, and print them.
    ValidatePlaybook,
    /// Run a playbook's checks on a task's current dispatch and commit them.
    RunPlaybook,
    /// Read a rubric, or grade one on a task: `rubric` without `validate` or
    /// `grade` after it.
    Rubric,
    /// Read a rubric and print it.
    ValidateRubric,
    /// Grade a rubric's questions on a task's current dispatch and commit
    /// them.
    GradeRubric,
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
            | Self::Serve => "serve [--port <port>] [--surface <program>]",
            | Self::Open => "open",
            | Self::Grant => "grant <tree> <peer-id>",
            | Self::Note => "note <tree> <text>",
            | Self::Bind => "bind <anchor> anchor|endpoint|datum <target>",
            | Self::Claim => "claim <tree> <domain>",
            | Self::Introduce => "introduce <tree> <label> <tree>",
            | Self::Present => "present <tree> [--port <port>]",
            | Self::Withdraw => "withdraw <tree> [<peer-id>]",
            | Self::Book => "book <tree>",
            | Self::Whence => {
                "whence <name> [--witness <domain>=<tree-id>]... [--in <tree>] [--peer \
                 <peer-id>] [--at <endpoint>] [--local]"
            },
            | Self::View => "view <tree>",
            | Self::Heads => "heads <tree>",
            | Self::Sync => "sync <tree> [--peer <peer-id>] [--at <endpoint>]",
            | Self::Dispatch => {
                "dispatch <tree> <peer-id> anchor|content <brief> [--at <endpoint>]"
            },
            | Self::Report => "report <tree> <file> <summary>",
            | Self::Handoff => "handoff <tree> <peer-id>",
            | Self::Retire => "retire <tree>",
            | Self::Pause => "pause <tree>",
            | Self::Replay => {
                "replay <tree> [--peer <peer-id>] [--at <endpoint>] [--local] [--base]"
            },
            | Self::Evidence => {
                "evidence <tree> <digest> [--peer <peer-id>] [--at <endpoint>] [--local]"
            },
            | Self::Drift => "drift --public <checkout> --vault <checkout> <tree>",
            | Self::Judge => "judge ask|verdict",
            | Self::Ask => {
                "judge ask --question <text> --option <text>... --transcript <digest> | \
                 --transcript-file <file> [--static <file>]"
            },
            | Self::Verdict => {
                "judge verdict <tree> --rubric <content-hash> --transcript <digest> | \
                 --transcript-file <file> (--question <text> --option <text>...)... [--static \
                 <file>]"
            },
            | Self::Playbook => "playbook validate|run",
            | Self::ValidatePlaybook => "playbook validate <file>",
            | Self::RunPlaybook => {
                "playbook run <file> <tree> [--task-state <dir>] [--static <file>]"
            },
            | Self::Rubric => "rubric validate|grade",
            | Self::ValidateRubric => "rubric validate <file>",
            | Self::GradeRubric => {
                "rubric grade <file> <tree> [--task-state <dir>] [--static <file>]"
            },
        })
    }
}

/// The operand an id or anchor is read for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operand
{
    /// The tree to grant on, write to, claim for, introduce in, present in,
    /// withdraw from, read, sync, dispatch in, report on, rule on, fetch
    /// evidence for, or read a label in, or the tree introduced.
    Tree,
    /// The anchor to bind or resolve.
    Anchor,
    /// A bind's target anchor.
    Target,
    /// A bind's target endpoint.
    Endpoint,
    /// The endpoint `--at` names: the remote's endpoint id and addresses.
    At,
    /// The grantee's, the remote's, the withdrawn presence's, the seat's or
    /// the handoff's recipient's subduction peer id.
    Peer,
    /// The tree a witness supplied by hand names.
    Witness,
    /// A dispatch's brief anchor.
    Brief,
    /// A brief's content hash.
    Content,
    /// The evidence `evidence` prints, by its manifest digest.
    Evidence,
    /// A judged transcript's manifest digest.
    Transcript,
    /// A verdict's rubric's hash.
    Rubric,
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
            | Self::At => "endpoint",
            | Self::Peer => "peer id",
            | Self::Witness => "witness's tree id",
            | Self::Brief => "brief anchor",
            | Self::Content => "content hash",
            | Self::Evidence => "evidence digest",
            | Self::Transcript => "transcript digest",
            | Self::Rubric => "rubric hash",
        })
    }
}

/// A command with its operands read.
#[derive(Debug, PartialEq, Eq)]
enum Command
{
    /// Print the endpoint id, then the peer id.
    Id,
    /// Bind on `port`, print the ids and `listening`, then accept peers and
    /// answer wakes as a seat acting through `surface` until killed.
    Serve
    {
        /// The UDP port the endpoint binds.
        port: BindPort,
        /// What the seat acts through.
        surface: Surface,
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
    /// Bind on `port`, commit this peer's endpoint as its presence in `tree`,
    /// and print the commit id.
    Present
    {
        /// The tree presented in.
        tree: TreeId,
        /// The UDP port the endpoint binds: the one `serve` binds after.
        port: BindPort,
    },
    /// Commit the withdrawal of `of`'s presence from `tree` and print the
    /// commit id.
    Withdraw
    {
        /// The tree withdrawn from.
        tree: TreeId,
        /// Whose presence is withdrawn.
        of: Withdrawn,
    },
    /// Print `tree`'s book.
    Book
    {
        /// The tree folded.
        tree: TreeId,
    },
    /// Reach the trees `reference` reads as `reach` says, print where each
    /// was reached, then print what `reference` resolves to, asking
    /// `witnessing` for a DNS name's candidates and reading a label in
    /// `scope`.
    Whence
    {
        /// The anchor or the commit resolved.
        reference: Reference,
        /// What names a DNS name's candidate trees.
        witnessing: Witnessing,
        /// The tree a label is read in.
        scope: Scope,
        /// Whether, and whom, the trees read are reached.
        reach: Reach,
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
    /// Sync `tree` with the remote `dial` names, and print where its endpoint
    /// came from, the heads after the sync, then the path.
    Sync
    {
        /// The tree synced.
        tree: TreeId,
        /// Whom to dial, and at which endpoint.
        dial: Dial,
    },
    /// Route to `seat` for `tree` as `at` says, commit a dispatch of it to
    /// `brief` unless the current attempt already puts it to that brief,
    /// print the dispatch's commit id, wake the seat, and print where its
    /// endpoint came from and `woken`.
    Dispatch
    {
        /// The task.
        tree: TreeId,
        /// The seat dispatched to.
        seat: PeerKey,
        /// What the seat works from.
        brief: Brief,
        /// The seat's endpoint: `--at`, or the book's.
        at: At,
    },
    /// Keep the content of `file` as evidence, commit a report naming it on
    /// `tree`'s current dispatch with `summary`, and print the commit id.
    Report
    {
        /// The task.
        tree: TreeId,
        /// The file holding the report's content.
        file: PathBuf,
        /// The report's summary.
        summary: Summary,
    },
    /// Commit a handoff of `tree`'s current slot to `to` and print the commit
    /// id.
    Handoff
    {
        /// The task.
        tree: TreeId,
        /// The seat the slot passes to.
        to: PeerKey,
    },
    /// Commit a retirement from `tree`'s current slot and print the commit
    /// id.
    Retire
    {
        /// The task.
        tree: TreeId,
    },
    /// Commit a pause on the current dispatch.
    Pause
    {
        /// The task.
        tree: TreeId,
    },
    /// Reach the peer `replaying` says for `tree`, sync, fetch the evidence
    /// the task names that the local store lacks, and print where its
    /// endpoint came from, the task's steps, where it stands and whether each
    /// evidence is held.
    Replay
    {
        /// The task.
        tree: TreeId,
        /// Whether, and whom, the task is reached at.
        replaying: Replaying,
        /// The protocol used for conformance.
        edition: domhringr_record_tree::Edition,
    },
    /// Print the content of the evidence `digest` names, read from the local
    /// store or else fetched from the peer `reaching` says for `tree`.
    Evidence
    {
        /// The task whose receipts name the evidence.
        tree: TreeId,
        /// The evidence.
        digest: ManifestDigest,
        /// Whether, and whom, the evidence is fetched from.
        reaching: Replaying,
    },
    /// Check `tree`'s bindings against the checkouts at `public` and `vault`,
    /// and print one line per finding.
    Drift
    {
        /// The public checkout, whose tracked text cites the tree's paths.
        public: PathBuf,
        /// The vault checkout, which holds the pages the paths are bound to.
        vault: PathBuf,
        /// The concepts tree.
        tree: TreeId,
    },
    /// Ask `question` about the transcript `transcript` names, as `judging`
    /// says, and print the transcript's digest and the ruling.
    Ask
    {
        /// The question asked.
        question: Question,
        /// Where the transcript comes from.
        transcript: Asked,
        /// What answers.
        judging: Judging,
    },
    /// Ask each of `questions` about the transcript `transcript` names, as
    /// `judging` says, print the transcript's digest and each ruling, keep the
    /// transcript as evidence, commit a verdict of them on `tree`'s current
    /// dispatch under `rubric`, and print the commit id.
    Verdict
    {
        /// The task.
        tree: TreeId,
        /// The hash of the rubric the questions come from.
        rubric: ContentHash,
        /// Where the transcript comes from.
        transcript: Asked,
        /// The questions, in the order asked.
        questions: Vec<Question>,
        /// What answers.
        judging: Judging,
    },
    /// Read the playbook at `file` and each rubric it names, and print
    /// them.
    ValidatePlaybook
    {
        /// The playbook's file.
        file: PathBuf,
    },
    /// Run the playbook at `file` on `tree`'s current dispatch in the task's
    /// state `directory`, its questions answered as `judging` says, and
    /// print each receipt committed.
    RunPlaybook
    {
        /// The playbook's file.
        file: PathBuf,
        /// The task.
        tree: TreeId,
        /// The task's state: where verifiers run and state files are read.
        directory: PathBuf,
        /// What answers.
        judging: Judging,
    },
    /// Read the rubric at `file` and print it.
    ValidateRubric
    {
        /// The rubric's file.
        file: PathBuf,
    },
    /// Grade every question of the rubric at `file` on `tree`'s current
    /// dispatch in the task's state `directory`, the questions answered as
    /// `judging` says, and print each receipt committed.
    GradeRubric
    {
        /// The rubric's file.
        file: PathBuf,
        /// The task.
        tree: TreeId,
        /// The task's state: where state files are read.
        directory: PathBuf,
        /// What answers.
        judging: Judging,
    },
}

/// Where a judged transcript comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Asked
{
    /// `--transcript`: the evidence its digest names, held in the local
    /// store.
    Named(ManifestDigest),
    /// `--transcript-file`: the file holding its content.
    File(PathBuf),
}

/// What answers a judge's questions.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Judging
{
    /// The endpoint the environment configures.
    Endpoint,
    /// `--static`: the table of rulings this file holds.
    Table(PathBuf),
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

/// Whose presence a `withdraw` withdraws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Withdrawn
{
    /// This peer's own.
    Own,
    /// The peer's with this key.
    Of(PeerKey),
}

/// Whom a dial for a tree aims at, and where the endpoint comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dial
{
    /// The peer aimed at: `--peer`, or the tree's owner.
    aim: Aim,
    /// The endpoint: `--at`, or the book's.
    at: At,
}

/// Whether `whence` reaches the trees it reads before resolving.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reach
{
    /// `--local`: resolve from the local store alone.
    Local,
    /// Reach each tree read as the dial says, then resolve.
    Dial(Dial),
}

/// Whom `replay` and `evidence` reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Toward
{
    /// For `replay`, the current attempt's seat — the slot's holder, or the
    /// seat that retired from it — or the task's owner when no dispatch is
    /// admitted; for `evidence`, the peer whose receipt first names the
    /// evidence.
    Seat,
    /// The peer `--peer` names.
    Peer(PeerKey),
}

/// Whether `replay` reaches the task before printing it, and whether
/// `evidence` fetches what the local store lacks.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Replaying
{
    /// `--local`: read the local store alone.
    Local,
    /// Reach the peer `toward` names, at `at`: to sync first, or to fetch.
    Dial
    {
        /// Whom.
        toward: Toward,
        /// The endpoint: `--at`, or the book's.
        at: At,
    },
}

/// A tree a command reached, and the route it reached it by.
#[derive(Debug)]
struct Reached
{
    /// The tree.
    tree: TreeId,
    /// The route dialed.
    route: Route,
}

impl fmt::Display for Reached
{
    /// Write `source <tree> book <commit-id>` for a remote reached at its
    /// presence in the book, `source <tree> at <endpoint>` for one reached at
    /// an endpoint named by hand, and nothing for this peer itself.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        let tree = Anchor::key(self.tree);
        match self.route {
            | Route::Itself => Ok(()),
            | Route::Book { since, .. } => writeln!(f, "source {tree} book {since}"),
            | Route::Given { ref remote } => {
                writeln!(f, "source {tree} at {}", remote.endpoint())
            },
        }
    }
}

/// The two stores a command commits to: the tree store its receipts go to,
/// and the evidence store the values they name are kept in.
#[derive(Clone, Copy)]
struct Stores<'store>
{
    /// The tree store.
    peer: &'store Peer,
    /// The evidence store.
    evidence: &'store Evidence,
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

/// How a command that ran to completion exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion
{
    /// With status 0.
    Success,
    /// With [`DRIFT_STATUS`]: `drift` reported a finding.
    Drifted,
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
    /// `drift`'s `--public` or `--vault` is absent.
    #[error("no {0} checkout given: --{0} <checkout>")]
    NoCheckout(drift::Checkout),
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
    /// An operand is not a manifest digest.
    #[error("cannot read the {operand}")]
    Digest
    {
        /// The operand.
        operand: Operand,
        /// Why it is not a digest.
        #[source]
        source: ParseDigestError,
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
    /// A dispatch's brief kind is not one this binary has.
    #[error("unknown brief kind {0:?}: expected anchor or content")]
    Brief(OsString),
    /// A note's text, a datum, a DNS name, a label or a summary is not UTF-8.
    #[error("the text is not UTF-8: {0:?}")]
    Text(OsString),
    /// A report's summary is not one line of at most 256 bytes.
    #[error("cannot read the summary")]
    Summary(#[source] ParseSummaryError),
    /// `--port`'s value is not a UDP port.
    #[error("cannot read the port")]
    Port(#[source] ParsePortError),
    /// `--local` stands beside `--peer` or `--at`: a local resolution reaches
    /// no one.
    #[error("--local reaches no peer: it takes no --peer or --at")]
    Local,
    /// A judge command names no transcript.
    #[error("no transcript given: --transcript <digest> or --transcript-file <file>")]
    NoTranscript,
    /// `judge verdict` names no rubric.
    #[error("no rubric given: --rubric <content-hash>")]
    NoRubric,
    /// A judge command asks no question.
    #[error("no question given: --question <text> --option <text>...")]
    NoQuestion,
    /// An `--option` comes before any `--question`.
    #[error("an --option follows the --question it answers")]
    Unasked,
    /// A question cannot be asked.
    #[error("cannot ask the question")]
    Question(#[source] QuestionError),
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
    /// The presence cannot be committed.
    #[error(transparent)]
    Present(#[from] PresentError),
    /// The tree has no remote to dial.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// The peer the dial aims at is this peer.
    #[error("no one to reach: the peer aimed at is this peer")]
    Itself,
    /// The task has no dispatch to report on, hand off, retire from or rule
    /// on.
    #[error("the task has no dispatch: nothing to report on, hand off, retire from or rule on")]
    Undispatched,
    /// The seat was not woken.
    #[error(transparent)]
    Wake(#[from] WakeError),
    /// The anchor does not resolve.
    #[error(transparent)]
    Whence(#[from] WhenceError),
    /// The heads cannot be read.
    #[error(transparent)]
    Heads(#[from] HeadsError),
    /// The sync failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// A checkout cannot be read for `drift`.
    #[error(transparent)]
    Drift(#[from] drift::CheckError),
    /// The transcript file cannot be read.
    #[error("cannot read the transcript file")]
    Transcript(#[source] std::io::Error),
    /// The report's file cannot be read.
    #[error("cannot read the report's file")]
    Report(#[source] std::io::Error),
    /// Evidence cannot be kept, or is not held whole.
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    /// Evidence cannot be fetched whole.
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// No admitted receipt of the task names the evidence, and no `--peer`
    /// names whom to fetch it from.
    #[error("the task names no evidence {0}: name its holder with --peer")]
    Unnamed(ManifestDigest),
    /// The table file cannot be read.
    #[error("cannot read the table file")]
    Table(#[source] std::io::Error),
    /// The table file holds no table of rulings.
    #[error("cannot read the table")]
    Rulings(#[source] ParseTableError),
    /// The environment configures no endpoint for the judge.
    #[error("no judge endpoint configured")]
    Config(#[source] ConfigError),
    /// The judge's client cannot be built.
    #[error("cannot build the judge's client")]
    Client(#[source] EndpointError),
    /// Standard output cannot be written.
    #[error("cannot write to standard output")]
    Output(#[source] std::io::Error),
    /// Standard error cannot be written.
    #[error("cannot write to standard error")]
    Diagnostics(#[source] std::io::Error),
    /// A playbook or a rubric does not load.
    #[error(transparent)]
    Load(#[from] domhringr_strategy_document::LoadError),
    /// A verifier does not run to its end.
    #[error(transparent)]
    Verify(#[from] domhringr_strategy_document::VerifyError),
    /// A verifier's thread failed.
    #[error("the verifier's thread failed")]
    Join(#[source] tokio::task::JoinError),
    /// A rubric's transcript cannot be read from its state files, or kept.
    #[error(transparent)]
    State(#[from] domhringr_strategy_document::TranscriptError),
}

/// Read the command line that follows the program name.
///
/// # Specification
/// - ensures: accepts `--state <dir>` (or `--state=<dir>`; the last one given
///   wins) followed by a verb and exactly the operands that verb takes, or, for
///   `serve`, `present`, `sync`, `whence`, `dispatch`, `replay`, `evidence`,
///   `drift`, `judge`, `playbook` and `rubric`, what [`serve_command`],
///   [`present_command`], [`sync_command`], [`whence_command`],
///   [`dispatch_command`], [`replay_command`], [`drift_command`],
///   [`judge_command`] and [`strategy_command`] read. Other verbs' operands are
///   taken verbatim, so a note's text, a datum or a summary beginning with `-`
///   is a text, not an option. A tree operand is a bare anchor in the key form,
///   `bind`'s anchor names a path in the key form, `claim`'s DNS name and
///   `introduce`'s label are read as [`read_name`] reads them, `bind`'s target
///   is read as [`read_target`] reads it, `withdraw` withdraws this peer's own
///   presence unless a peer id follows the tree, `report`'s file is a path and
///   its summary one line [`Summary`] admits, and `handoff`'s recipient is a
///   peer id.
/// - fails: [`UsageError::Arguments`] for any option but `--state` or for
///   `--state` without a value, [`UsageError::NoCommand`] when no verb follows
///   the options, [`UsageError::Command`] for an unknown verb,
///   [`UsageError::State`] when `--state` is absent, [`UsageError::Operands`]
///   for too few or too many operands, checked before any operand is read,
///   [`UsageError::Operand`] for an id or a content hash that does not parse,
///   [`UsageError::Anchor`] for an anchor that does not parse,
///   [`UsageError::NotTree`] for a tree operand naming a path or a commit,
///   [`UsageError::NotKey`] for a tree operand or an anchor to bind naming its
///   tree by a DNS name or a label, [`UsageError::NoPath`] for an anchor to
///   bind that is bare or names a commit, [`UsageError::Text`] for a note's
///   text, a DNS name, a label or a summary that is not UTF-8,
///   [`UsageError::Domain`] and [`UsageError::Label`] for a DNS name or a label
///   that does not parse, [`UsageError::Summary`] for a summary [`Summary`]
///   refuses, as [`read_target`] for `bind`'s target, and as [`serve_command`],
///   [`present_command`], [`sync_command`], [`whence_command`],
///   [`dispatch_command`], [`replay_command`], [`drift_command`],
///   [`judge_command`] and [`strategy_command`] for their verbs.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or `--state` lacks a value.
/// - [`UsageError::NoCommand`]: no verb follows the options.
/// - [`UsageError::Command`]: the verb is unknown.
/// - [`UsageError::State`]: `--state` is absent.
/// - [`UsageError::NoCheckout`]: `drift`'s `--public` or `--vault` is absent.
/// - [`UsageError::Operands`]: the verb's operand count is wrong.
/// - [`UsageError::Operand`]: an operand is not an id.
/// - [`UsageError::Digest`]: as [`replay_command`] and [`judge_command`].
/// - [`UsageError::Anchor`]: an operand is not an anchor.
/// - [`UsageError::NotTree`]: a tree operand names a path or a commit.
/// - [`UsageError::NotKey`]: a tree operand or the anchor to bind is not in the
///   key form.
/// - [`UsageError::NoPath`]: the anchor to bind names no path.
/// - [`UsageError::Domain`]: the DNS name to claim does not parse.
/// - [`UsageError::Label`]: the label to introduce does not parse.
/// - [`UsageError::Witness`]: a `--witness` value has no `=`.
/// - [`UsageError::Target`]: the bind's target kind is unknown.
/// - [`UsageError::Brief`]: the dispatch's brief kind is unknown.
/// - [`UsageError::Text`]: the note's text, a datum, a DNS name, a label or a
///   summary is not UTF-8.
/// - [`UsageError::Summary`]: the summary is empty, too long or not one line.
/// - [`UsageError::Port`]: `serve`'s or `present`'s port is not a UDP port.
/// - [`UsageError::Local`]: `whence`'s, `replay`'s or `evidence`'s `--local`
///   stands beside `--peer` or `--at`.
/// - [`UsageError::NoTranscript`], [`UsageError::NoRubric`],
///   [`UsageError::NoQuestion`], [`UsageError::Unasked`] and
///   [`UsageError::Question`]: as [`judge_command`] refuses a judge command.
///
/// # Adequacy
/// - hypothesis: L3 — each verb with its operands, every bind target kind, a
///   bare, a path and a commit anchor to resolve in each of the three forms and
///   an abbreviated commit, both `--state` spellings, `serve` and `present`
///   with and without a port, `serve` with a surface, `withdraw` with and
///   without a peer, `sync` with and without a peer and an endpoint, `whence`
///   with and without witnesses, a scope, a peer, an endpoint and `--local`,
///   `dispatch` by anchor and by content with and without `--at`, `report`,
///   `handoff`, `retire`, `replay` toward the seat, a peer and `--local`,
///   `drift` with its options before and after its operand, `judge ask` and
///   `judge verdict`, `playbook validate` and `run` and `rubric validate` and
///   `grade` with and without their options, and a dash-leading note, datum and
///   summary separate the accepted lines, and one line per refusal pins which
///   refusal each malformation gets, including an arity error that wins over a
///   malformed operand.
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
        let command = serve_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Dispatch {
        let command = dispatch_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if matches!(verb, Verb::Replay | Verb::Evidence) {
        let command = replay_command(&mut arguments, verb)?;
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Sync {
        let command = sync_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Present {
        let command = present_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Whence {
        let command = whence_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Drift {
        let command = drift_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if verb == Verb::Judge {
        let command = judge_command(&mut arguments)?;
        return Ok(Invocation { state, command });
    }
    if matches!(verb, Verb::Playbook | Verb::Rubric) {
        let command = strategy_command(&mut arguments, verb)?;
        return Ok(Invocation { state, command });
    }
    let mut raw = arguments.raw_args()?;
    // One more operand than any verb takes is read, so that a surplus is seen.
    let operands = (raw.next(), raw.next(), raw.next(), raw.next());
    let command = match (verb, operands) {
        | (Verb::Id, (None, None, None, None)) => Command::Id,
        | (Verb::Open, (None, None, None, None)) => Command::Open,
        | (Verb::Withdraw, (Some(tree), None, None, None)) => Command::Withdraw {
            tree: read_tree(&tree)?,
            of: Withdrawn::Own,
        },
        | (Verb::Withdraw, (Some(tree), Some(of), None, None)) => {
            let tree = read_tree(&tree)?;
            Command::Withdraw {
                tree,
                of: Withdrawn::Of(read_id(&of, Operand::Peer)?),
            }
        },
        | (Verb::Book, (Some(tree), None, None, None)) => Command::Book {
            tree: read_tree(&tree)?,
        },
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
        | (Verb::Report, (Some(tree), Some(file), Some(summary), None)) => Command::Report {
            tree: read_tree(&tree)?,
            file: PathBuf::from(file),
            summary: read_name(summary, UsageError::Summary)?,
        },
        | (Verb::Handoff, (Some(tree), Some(to), None, None)) => {
            let tree = read_tree(&tree)?;
            Command::Handoff {
                tree,
                to: read_id(&to, Operand::Peer)?,
            }
        },
        | (Verb::Retire, (Some(tree), None, None, None)) => Command::Retire {
            tree: read_tree(&tree)?,
        },
        | (Verb::Pause, (Some(tree), None, None, None)) => Command::Pause {
            tree: read_tree(&tree)?,
        },
        | (verb, _) => return Err(UsageError::Operands(verb)),
    };
    Ok(Invocation { state, command })
}

/// Read `sync`'s operand and options from what follows the verb.
///
/// # Specification
/// - ensures: accepts one tree anchor in the key form, with `--peer <peer-id>`
///   and `--at <endpoint>` (or `--peer=<peer-id>` and `--at=<endpoint>`; the
///   last one given of each wins) anywhere around it: the dial aims at the peer
///   `--peer` names, or else at the tree's owner, at the endpoint `--at` names,
///   or else at the book's.
/// - fails: [`UsageError::Arguments`] for any other option or for an option
///   without a value, [`UsageError::Operand`] for a peer id or an endpoint that
///   does not parse, [`UsageError::Operands`] for other than one operand,
///   checked before the operand is read, and as [`read_tree`] for an operand
///   that is no key-form tree anchor.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or an option lacks a value.
/// - [`UsageError::Operand`]: the peer id or the endpoint does not parse.
/// - [`UsageError::Operands`]: there is not one operand.
/// - [`UsageError::Anchor`], [`UsageError::NotTree`], [`UsageError::NotKey`]:
///   as [`read_tree`] for the tree.
///
/// # Adequacy
/// - hypothesis: L3 — no option, both options in both spellings, before and
///   after the operand and repeated, are read to their dial, and a malformed
///   endpoint and peer id, a missing value, a surplus operand and a tree naming
///   a path each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn sync_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut dial = Dial {
        aim: Aim::Owner,
        at: At::Book,
    };
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("peer") => {
                let value = arguments.value()?;
                dial.aim = Aim::Peer(read_id(&value, Operand::Peer)?);
            },
            | lexopt::Arg::Long("at") => {
                let value = arguments.value()?;
                dial.at = At::Given(read_id(&value, Operand::At)?);
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let mut operands = operands.into_iter();
    match (operands.next(), operands.next()) {
        | (Some(tree), None) => Ok(Command::Sync {
            tree: read_tree(&tree)?,
            dial,
        }),
        | _ => Err(UsageError::Operands(Verb::Sync)),
    }
}

/// Read `present`'s operand and options from what follows the verb.
///
/// # Specification
/// - ensures: accepts one tree anchor in the key form, with `--port <port>` (or
///   `--port=<port>`; the last one given wins) anywhere around it, which fixes
///   the port the endpoint binds and is presented at; with none it is
///   ephemeral.
/// - fails: [`UsageError::Arguments`] for any other option or for `--port`
///   without a value, [`UsageError::Port`] for a value that is not a port from
///   1 through 65535, [`UsageError::Operands`] for other than one operand,
///   checked before the operand is read, and as [`read_tree`] for an operand
///   that is no key-form tree anchor.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or `--port` lacks a value.
/// - [`UsageError::Port`]: the value is not a UDP port.
/// - [`UsageError::Operands`]: there is not one operand.
/// - [`UsageError::Anchor`], [`UsageError::NotTree`], [`UsageError::NotKey`]:
///   as [`read_tree`] for the tree.
///
/// # Adequacy
/// - hypothesis: L3 — no option and `--port` in both spellings, before and
///   after the operand, are read to their command, and port 0, a missing
///   operand and a surplus one each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn present_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut port = BindPort::Ephemeral;
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("port") => {
                let value = arguments.value()?;
                let fixed = value.to_string_lossy().parse::<UdpPort>();
                port = BindPort::Fixed(fixed.map_err(UsageError::Port)?);
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let mut operands = operands.into_iter();
    match (operands.next(), operands.next()) {
        | (Some(tree), None) => Ok(Command::Present {
            tree: read_tree(&tree)?,
            port,
        }),
        | _ => Err(UsageError::Operands(Verb::Present)),
    }
}

/// Read `whence`'s operand and options from what follows the verb.
///
/// # Specification
/// - ensures: accepts one reference, an anchor or a commit in any of the three
///   forms, the commit's id whole or abbreviated, with any number of `--witness
///   <domain>=<tree-id>`, at most one effective `--in <tree>`, `--peer
///   <peer-id>` and `--at <endpoint>` (or `--in=<tree>`, `--peer=<peer-id>` and
///   `--at=<endpoint>`; the last one given of each wins), and `--local`,
///   anywhere around it. With no `--witness`, a DNS name's candidates are its
///   `_domhringr.<domain>` TXT records; with any, they are the trees the
///   `--witness` values name for it, and DNS is not asked. With no `--in`, a
///   label is read in no tree. With `--local` the resolution reads the local
///   store alone; without, it reaches the trees it reads first, dialing as
///   [`sync_command`] reads `--peer` and `--at`.
/// - fails: [`UsageError::Arguments`] for any other option or for an option
///   without a value, [`UsageError::Witness`], [`UsageError::Text`],
///   [`UsageError::Domain`] and [`UsageError::Operand`] as [`read_witness`] for
///   a malformed witness, [`UsageError::Operand`] for a peer id or an endpoint
///   that does not parse, [`UsageError::Anchor`], [`UsageError::NotTree`] and
///   [`UsageError::NotKey`] as [`read_tree`] for a malformed `--in`,
///   [`UsageError::Local`] for `--local` beside `--peer` or `--at`,
///   [`UsageError::Operands`] for other than one operand, checked before the
///   operand is read, and [`UsageError::Anchor`] for an operand that is not a
///   reference.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or an option lacks a value.
/// - [`UsageError::Witness`], [`UsageError::Text`], [`UsageError::Domain`],
///   [`UsageError::Operand`]: as [`read_witness`].
/// - [`UsageError::Operand`]: the peer id or the endpoint does not parse.
/// - [`UsageError::NotTree`], [`UsageError::NotKey`]: as [`read_tree`] for
///   `--in`.
/// - [`UsageError::Local`]: `--local` stands beside `--peer` or `--at`.
/// - [`UsageError::Operands`]: there is not one operand.
/// - [`UsageError::Anchor`]: the reference or `--in`'s tree does not parse.
///
/// # Adequacy
/// - hypothesis: L3 — a key, a DNS and a label anchor, a commit whole and
///   abbreviated, two witnesses for one name, a repeated `--in`, a peer and an
///   endpoint, and `--local` are read to their command, and a witness without
///   `=`, with a malformed name or tree id, an `--in` naming a path, a
///   malformed endpoint, `--local` beside `--at` and beside `--peer`, a
///   reserved segment, a commit id too short to read, a missing operand and a
///   surplus one each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn whence_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut scope = Scope::Unscoped;
    let mut witnessed = Vec::new();
    let mut dial = Dial {
        aim: Aim::Owner,
        at: At::Book,
    };
    let (mut named, mut local) = (false, false);
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
            | lexopt::Arg::Long("peer") => {
                let value = arguments.value()?;
                dial.aim = Aim::Peer(read_id(&value, Operand::Peer)?);
                named = true;
            },
            | lexopt::Arg::Long("at") => {
                let value = arguments.value()?;
                dial.at = At::Given(read_id(&value, Operand::At)?);
                named = true;
            },
            | lexopt::Arg::Long("local") => local = true,
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
    let reach = match (local, named) {
        | (false, _) => Reach::Dial(dial),
        | (true, false) => Reach::Local,
        | (true, true) => return Err(UsageError::Local),
    };
    let mut operands = operands.into_iter();
    match (operands.next(), operands.next()) {
        | (Some(reference), None) => Ok(Command::Whence {
            reference: read_anchor(&reference, Operand::Anchor)?,
            witnessing,
            scope,
            reach,
        }),
        | _ => Err(UsageError::Operands(Verb::Whence)),
    }
}

/// Read `drift`'s operand and options from what follows the verb.
///
/// # Specification
/// - ensures: accepts one tree anchor in the key form, the concepts tree, with
///   `--public <checkout>` and `--vault <checkout>` (or `--public=<checkout>`
///   and `--vault=<checkout>`; the last one given of each wins) anywhere around
///   it, naming the public and the vault checkout.
/// - fails: [`UsageError::Arguments`] for any other option or for an option
///   without a value, [`UsageError::Operands`] for other than one operand,
///   checked first, then [`UsageError::NoCheckout`] naming `--public` and then
///   `--vault` when it is absent, and as [`read_tree`] for an operand that is
///   no key-form tree anchor.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or an option lacks a value.
/// - [`UsageError::Operands`]: there is not one operand.
/// - [`UsageError::NoCheckout`]: `--public` or `--vault` is absent.
/// - [`UsageError::Anchor`], [`UsageError::NotTree`], [`UsageError::NotKey`]:
///   as [`read_tree`] for the tree.
///
/// # Adequacy
/// - hypothesis: L3 — both options before the operand, both after it in the `=`
///   spelling with `--public` repeated, are read to their command; a missing
///   `--public`, a missing `--vault`, no operand with neither option, a surplus
///   operand, a path and a DNS-form tree, an option without a value and an
///   unknown option each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn drift_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let (mut public, mut vault) = (None, None);
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("public") => {
                let value = arguments.value()?;
                public = Some(PathBuf::from(value));
            },
            | lexopt::Arg::Long("vault") => {
                let value = arguments.value()?;
                vault = Some(PathBuf::from(value));
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let mut operands = operands.into_iter();
    let (Some(tree), None) = (operands.next(), operands.next())
    else {
        return Err(UsageError::Operands(Verb::Drift));
    };
    let public = public.ok_or(UsageError::NoCheckout(drift::Checkout::Public))?;
    let vault = vault.ok_or(UsageError::NoCheckout(drift::Checkout::Vault))?;
    let tree = read_tree(&tree)?;
    Ok(Command::Drift {
        public,
        vault,
        tree,
    })
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
/// - ensures: accepts nothing, which leaves the port ephemeral and the seat
///   holding without a surface, `--port <port>` (or `--port=<port>`), which
///   fixes the port, and `--surface <program>` (or `--surface=<program>`),
///   which names the program the seat acts through; the last one given of each
///   wins.
/// - fails: [`UsageError::Arguments`] for any other option or for an option
///   without a value, [`UsageError::Operands`] for an operand, and
///   [`UsageError::Port`] for a value that is not a port from 1 through 65535.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or an option lacks a value.
/// - [`UsageError::Operands`]: an operand follows `serve`.
/// - [`UsageError::Port`]: the value is not a UDP port.
///
/// # Adequacy
/// - hypothesis: L3 — no option, both `--port` spellings, a repeated `--port`
///   and `--surface` are read to their command, and a stray operand, an unknown
///   option, a missing value and port 0 each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn serve_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut port = BindPort::Ephemeral;
    let mut surface = Surface::Hold;
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("port") => {
                let value = arguments.value()?;
                let fixed = value.to_string_lossy().parse::<UdpPort>();
                port = BindPort::Fixed(fixed.map_err(UsageError::Port)?);
            },
            | lexopt::Arg::Long("surface") => {
                surface = Surface::Program(PathBuf::from(arguments.value()?));
            },
            | lexopt::Arg::Value(_) => return Err(UsageError::Operands(Verb::Serve)),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    Ok(Command::Serve { port, surface })
}

/// Read `dispatch`'s operands and option from what follows the verb.
///
/// # Specification
/// - ensures: accepts a tree anchor in the key form, the seat's peer id, and a
///   brief read as [`read_brief`] reads it, with `--at <endpoint>` (or
///   `--at=<endpoint>`; the last one given wins) anywhere around them: the seat
///   is reached at the endpoint `--at` names, or else at its presence in the
///   task's book.
/// - fails: [`UsageError::Arguments`] for any other option or for `--at`
///   without a value, [`UsageError::Operand`] for an endpoint that does not
///   parse, [`UsageError::Operands`] for other than four operands, checked
///   before any operand is read, as [`read_tree`] for the tree,
///   [`UsageError::Operand`] for a seat's peer id that does not parse, and as
///   [`read_brief`] for the brief.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or `--at` lacks a value.
/// - [`UsageError::Operand`]: the endpoint or the peer id does not parse.
/// - [`UsageError::Operands`]: there are not four operands.
/// - [`UsageError::Anchor`], [`UsageError::NotTree`], [`UsageError::NotKey`]:
///   as [`read_tree`] for the tree.
/// - [`UsageError::Brief`], [`UsageError::Anchor`], [`UsageError::Operand`]: as
///   [`read_brief`] for the brief.
///
/// # Adequacy
/// - hypothesis: L3 — a brief by anchor and by content, with and without
///   `--at`, are read to their command, and an unknown brief kind, a short
///   content hash, a short peer id, a missing operand and a surplus one each
///   meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn dispatch_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut at = At::Book;
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("at") => {
                let value = arguments.value()?;
                at = At::Given(read_id(&value, Operand::At)?);
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let mut operands = operands.into_iter();
    let (Some(tree), Some(seat), Some(kind), Some(value), None) = (
        operands.next(),
        operands.next(),
        operands.next(),
        operands.next(),
        operands.next(),
    )
    else {
        return Err(UsageError::Operands(Verb::Dispatch));
    };
    let tree = read_tree(&tree)?;
    let seat = read_id(&seat, Operand::Peer)?;
    let brief = read_brief(&kind, &value)?;
    Ok(Command::Dispatch {
        tree,
        seat,
        brief,
        at,
    })
}

/// Read `replay`'s or `evidence`'s operands and options from what follows the
/// verb `verb`.
///
/// # Specification
/// - requires: `verb` is [`Verb::Replay`] or [`Verb::Evidence`].
/// - ensures: accepts one tree anchor in the key form, and for `evidence` a
///   manifest digest after it, with `--peer <peer-id>`, `--at <endpoint>` (or
///   `--peer=<peer-id>` and `--at=<endpoint>`; the last one given of each wins)
///   and `--local` anywhere around them. Without `--local` the peer reached is
///   the one `--peer` names, or else the current attempt's seat for `replay`
///   and the peer whose receipt names the evidence for `evidence`, at the
///   endpoint `--at` names, or else at the book's; with it, the local store
///   alone is read.
/// - fails: [`UsageError::Arguments`] for any other option or for an option
///   without a value, [`UsageError::Operand`] for a peer id or an endpoint that
///   does not parse, [`UsageError::Local`] for `--local` beside `--peer` or
///   `--at`, [`UsageError::Operands`] for other than the verb's operands,
///   checked before any operand is read, as [`read_tree`] for a first operand
///   that is no key-form tree anchor, and [`UsageError::Digest`] for a digest
///   that does not parse.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Arguments`]: an unknown option, or an option lacks a value.
/// - [`UsageError::Operand`]: the peer id or the endpoint does not parse.
/// - [`UsageError::Local`]: `--local` stands beside `--peer` or `--at`.
/// - [`UsageError::Operands`]: the operands are not the verb's.
/// - [`UsageError::Anchor`], [`UsageError::NotTree`], [`UsageError::NotKey`]:
///   as [`read_tree`] for the tree.
/// - [`UsageError::Digest`]: the evidence's digest does not parse.
///
/// # Adequacy
/// - hypothesis: L3 — no option, `--peer` with `--at`, and `--local` are read
///   to their command for both verbs, and `--local` beside `--peer`, a surplus
///   operand, a missing digest and a digest that is no hex each meet their own
///   refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn replay_command(
    arguments: &mut lexopt::Parser,
    verb: Verb,
) -> Result<Command, UsageError>
{
    let (mut toward, mut at) = (Toward::Seat, At::Book);
    let (mut named, mut local) = (false, false);
    let mut edition = domhringr_record_tree::Edition::Paused;
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("peer") => {
                let value = arguments.value()?;
                toward = Toward::Peer(read_id(&value, Operand::Peer)?);
                named = true;
            },
            | lexopt::Arg::Long("at") => {
                let value = arguments.value()?;
                at = At::Given(read_id(&value, Operand::At)?);
                named = true;
            },
            | lexopt::Arg::Long("local") => local = true,
            | lexopt::Arg::Long("base") if verb == Verb::Replay => {
                edition = domhringr_record_tree::Edition::Base;
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let replaying = match (local, named) {
        | (false, _) => Replaying::Dial { toward, at },
        | (true, false) => Replaying::Local,
        | (true, true) => return Err(UsageError::Local),
    };
    let mut operands = operands.into_iter();
    match (verb, operands.next(), operands.next(), operands.next()) {
        | (Verb::Replay, Some(tree), None, None) => Ok(Command::Replay {
            tree: read_tree(&tree)?,
            replaying,
            edition,
        }),
        | (Verb::Evidence, Some(tree), Some(digest), None) => {
            let tree = read_tree(&tree)?;
            let digest = read_digest(&digest, Operand::Evidence)?;
            Ok(Command::Evidence {
                tree,
                digest,
                reaching: replaying,
            })
        },
        | _ => Err(UsageError::Operands(verb)),
    }
}

/// Read a judge command — `ask` or `verdict`, its operands and its options —
/// from what follows `judge`.
///
/// # Specification
/// - ensures: accepts `ask` or `verdict`, then options anywhere around the
///   operands, each also in the `=` spelling: `--question <text>` opening a
///   question and each `--option <text>` adding an option to the question
///   opened last; `--transcript <digest>` or `--transcript-file <file>` naming
///   the transcript, the last one given of the two winning; `--static <file>`,
///   answering from a table rather than the endpoint, the last one given
///   winning; and for `verdict` `--rubric <content-hash>`, the last one given
///   winning. `ask` takes no operand and one question; `verdict` takes one tree
///   anchor in the key form and one or more questions, kept in the order given.
///   Each question is read as [`Question::new`] reads it.
/// - fails: [`UsageError::Operands`] naming `judge` when nothing follows it,
///   [`UsageError::Command`] for a word there other than `ask` or `verdict`,
///   [`UsageError::Arguments`] for any other option, among them `--rubric` to
///   `ask`, or for an option without a value, [`UsageError::Text`] for a
///   question or an option that is not UTF-8, [`UsageError::Unasked`] for an
///   `--option` before any `--question`, [`UsageError::Digest`] for a
///   transcript digest and [`UsageError::Operand`] for a rubric hash that does
///   not parse; then [`UsageError::NoQuestion`] when no question is asked,
///   [`UsageError::Operands`] for operands other than the command takes or for
///   `ask` with more than one question, [`UsageError::NoTranscript`] when no
///   transcript is named, [`UsageError::NoRubric`] for `verdict` without a
///   rubric, as [`read_tree`] for the tree, and [`UsageError::Question`] for a
///   question [`Question::new`] refuses.
/// - panics: none.
///
/// # Errors
/// - [`UsageError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — `ask` with a named transcript and with a file and a
///   table, and `verdict` with two questions in the `=` spelling around its
///   tree, are read to their commands; nothing after `judge`, an unknown word
///   after it, `--rubric` to `ask`, an `--option` before its `--question`, no
///   question, two questions to `ask`, an operand to `ask`, no transcript, no
///   rubric, a short transcript digest and a question of one option each meet
///   their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn judge_command(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let judged = match arguments.next()? {
        | Some(lexopt::Arg::Value(word)) => match word.to_str() {
            | Some("ask") => Verb::Ask,
            | Some("verdict") => Verb::Verdict,
            | Some(_) | None => return Err(UsageError::Command(word)),
        },
        | Some(other) => return Err(UsageError::from(other.unexpected())),
        | None => return Err(UsageError::Operands(Verb::Judge)),
    };
    let (mut transcript, mut rubric, mut judging) = (None, None, Judging::Endpoint);
    let mut asked: Vec<(String, Vec<String>)> = Vec::new();
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("question") => {
                let value = arguments.value()?;
                let text = value.into_string().map_err(UsageError::Text)?;
                asked.push((text, Vec::new()));
            },
            | lexopt::Arg::Long("option") => {
                let value = arguments.value()?;
                let option = value.into_string().map_err(UsageError::Text)?;
                let last = asked.last_mut().ok_or(UsageError::Unasked)?;
                last.1.push(option);
            },
            | lexopt::Arg::Long("transcript") => {
                let value = arguments.value()?;
                transcript = Some(Asked::Named(read_digest(&value, Operand::Transcript)?));
            },
            | lexopt::Arg::Long("transcript-file") => {
                let value = arguments.value()?;
                transcript = Some(Asked::File(PathBuf::from(value)));
            },
            | lexopt::Arg::Long("rubric") if judged == Verb::Verdict => {
                let value = arguments.value()?;
                rubric = Some(read_id(&value, Operand::Rubric)?);
            },
            | lexopt::Arg::Long("static") => {
                let value = arguments.value()?;
                judging = Judging::Table(PathBuf::from(value));
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    if asked.is_empty() {
        return Err(UsageError::NoQuestion);
    }
    let mut operands = operands.into_iter();
    let mut asked = asked.into_iter();
    match (judged, operands.next(), operands.next()) {
        | (Verb::Ask, None, None) => {
            let (Some((text, options)), None) = (asked.next(), asked.next())
            else {
                return Err(UsageError::Operands(Verb::Ask));
            };
            let transcript = transcript.ok_or(UsageError::NoTranscript)?;
            let question = Question::new(text, options).map_err(UsageError::Question)?;
            Ok(Command::Ask {
                question,
                transcript,
                judging,
            })
        },
        | (Verb::Verdict, Some(tree), None) => {
            let transcript = transcript.ok_or(UsageError::NoTranscript)?;
            let rubric = rubric.ok_or(UsageError::NoRubric)?;
            let tree = read_tree(&tree)?;
            let questions = asked
                .map(|(text, options)| Question::new(text, options))
                .collect::<Result<Vec<_>, _>>()
                .map_err(UsageError::Question)?;
            Ok(Command::Verdict {
                tree,
                rubric,
                transcript,
                questions,
                judging,
            })
        },
        | (judged, ..) => Err(UsageError::Operands(judged)),
    }
}

/// Read a `playbook` or a `rubric` command — as `document` names — from what
/// follows its word.
///
/// # Specification
/// - ensures: accepts `validate` or `run` after `playbook`, and `validate` or
///   `grade` after `rubric`; `validate` takes one file operand and no option;
///   `run` and `grade` take a file and a tree anchor in the key form, and the
///   options `--task-state <dir>`, the task's state directory, the working
///   directory when absent, and `--static <file>`, answering from a table
///   rather than the endpoint, anywhere around the operands, each also in the
///   `=` spelling, the last one given winning.
/// - fails: [`UsageError::Operands`] naming `playbook` or `rubric` when nothing
///   follows it, [`UsageError::Command`] for a word there that is not its
///   command, [`UsageError::Arguments`] for any other option, among them either
///   option to `validate`, or for an option without a value; then
///   [`UsageError::Operands`] for operands other than the command takes, and as
///   [`read_tree`] for the tree.
/// - panics: none.
///
/// # Errors
/// - [`UsageError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — `playbook validate`, `playbook run` with both options
///   around its operands, `rubric validate` and `rubric grade` without options
///   are read to their commands; nothing after `playbook`, `grade` after
///   `playbook`, `--static` to `validate`, a missing tree, a surplus operand
///   and a tree that is no anchor each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn strategy_command(
    arguments: &mut lexopt::Parser,
    document: Verb,
) -> Result<Command, UsageError>
{
    let acted = match arguments.next()? {
        | Some(lexopt::Arg::Value(word)) => match (document, word.to_str()) {
            | (Verb::Playbook, Some("validate")) => Verb::ValidatePlaybook,
            | (Verb::Playbook, Some("run")) => Verb::RunPlaybook,
            | (Verb::Rubric, Some("validate")) => Verb::ValidateRubric,
            | (Verb::Rubric, Some("grade")) => Verb::GradeRubric,
            | _ => return Err(UsageError::Command(word)),
        },
        | Some(other) => return Err(UsageError::from(other.unexpected())),
        | None => return Err(UsageError::Operands(document)),
    };
    let checks = matches!(acted, Verb::RunPlaybook | Verb::GradeRubric);
    let (mut directory, mut judging) = (PathBuf::from("."), Judging::Endpoint);
    let mut operands = Vec::new();
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Long("task-state") if checks => {
                directory = PathBuf::from(arguments.value()?);
            },
            | lexopt::Arg::Long("static") if checks => {
                judging = Judging::Table(PathBuf::from(arguments.value()?));
            },
            | lexopt::Arg::Value(operand) => operands.push(operand),
            | other @ (lexopt::Arg::Long(_) | lexopt::Arg::Short(_)) => {
                return Err(UsageError::from(other.unexpected()));
            },
        }
    }
    let mut operands = operands.into_iter();
    match (acted, operands.next(), operands.next(), operands.next()) {
        | (Verb::ValidatePlaybook, Some(file), None, None) => Ok(Command::ValidatePlaybook {
            file: PathBuf::from(file),
        }),
        | (Verb::ValidateRubric, Some(file), None, None) => Ok(Command::ValidateRubric {
            file: PathBuf::from(file),
        }),
        | (Verb::RunPlaybook, Some(file), Some(tree), None) => Ok(Command::RunPlaybook {
            file: PathBuf::from(file),
            tree: read_tree(&tree)?,
            directory,
            judging,
        }),
        | (Verb::GradeRubric, Some(file), Some(tree), None) => Ok(Command::GradeRubric {
            file: PathBuf::from(file),
            tree: read_tree(&tree)?,
            directory,
            judging,
        }),
        | (acted, ..) => Err(UsageError::Operands(acted)),
    }
}

/// Name the verb `word` spells.
///
/// # Specification
/// - ensures: `id`, `serve`, `open`, `grant`, `note`, `bind`, `claim`,
///   `introduce`, `present`, `withdraw`, `book`, `whence`, `view`, `heads`,
///   `sync`, `dispatch`, `report`, `handoff`, `retire`, `replay`, `drift`,
///   `judge`, `playbook` and `rubric` name their verbs.
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
        | Some("present") => Ok(Verb::Present),
        | Some("withdraw") => Ok(Verb::Withdraw),
        | Some("book") => Ok(Verb::Book),
        | Some("whence") => Ok(Verb::Whence),
        | Some("view") => Ok(Verb::View),
        | Some("heads") => Ok(Verb::Heads),
        | Some("sync") => Ok(Verb::Sync),
        | Some("dispatch") => Ok(Verb::Dispatch),
        | Some("report") => Ok(Verb::Report),
        | Some("handoff") => Ok(Verb::Handoff),
        | Some("retire") => Ok(Verb::Retire),
        | Some("pause") => Ok(Verb::Pause),
        | Some("replay") => Ok(Verb::Replay),
        | Some("evidence") => Ok(Verb::Evidence),
        | Some("drift") => Ok(Verb::Drift),
        | Some("judge") => Ok(Verb::Judge),
        | Some("playbook") => Ok(Verb::Playbook),
        | Some("rubric") => Ok(Verb::Rubric),
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

/// Read the manifest digest `text` spells, for the operand `operand`.
///
/// # Specification
/// - ensures: yields the digest of 64 lowercase hex digits `text` spells; text
///   that is not UTF-8 is read with replacement characters, which no digest
///   holds.
/// - fails: [`UsageError::Digest`] naming `operand` and carrying the parser's
///   reason.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Digest`]: the text is not a digest.
///
/// # Adequacy
/// - hypothesis: L3 — a short transcript digest and an evidence digest that is
///   no hex are refused under their own operand names.
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_digest(
    text: &OsStr,
    operand: Operand,
) -> Result<ManifestDigest, UsageError>
{
    text.to_string_lossy()
        .parse::<ParsedDigest>()
        .map(ManifestDigest::from)
        .map_err(|source| UsageError::Digest { operand, source })
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

/// Read a dispatch's brief from its kind and its value.
///
/// # Specification
/// - ensures: `anchor` reads the value as an anchor — a tree, a path or a
///   commit by its whole id, in any of the three forms — and `content` as a
///   content hash, 64 hex digits.
/// - fails: [`UsageError::Brief`] for any other kind, carrying it,
///   [`UsageError::Anchor`] naming the brief anchor for an anchor that does not
///   parse, and [`UsageError::Operand`] naming the content hash for one that
///   does not parse.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Brief`]: the kind is unknown.
/// - [`UsageError::Anchor`]: the anchor does not parse.
/// - [`UsageError::Operand`]: the content hash does not parse.
///
/// # Adequacy
/// - hypothesis: L3 — each kind is read to its brief, and an unknown kind and a
///   short content hash each meet their own refusal.
/// - witness: `tests::every_verb_reads_its_operands`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_brief(
    kind: &OsStr,
    value: &OsStr,
) -> Result<Brief, UsageError>
{
    match kind.to_str() {
        | Some("anchor") => read_anchor(value, Operand::Brief).map(Brief::Anchor),
        | Some("content") => read_id(value, Operand::Content).map(Brief::Content),
        | Some(_) | None => Err(UsageError::Brief(kind.to_os_string())),
    }
}

/// Run `invocation` to completion on a fresh multi-threaded runtime.
///
/// # Specification
/// - ensures: the command runs as [`execute`] specifies and ends as it says;
///   the runtime, and every task the command left running on it, is gone on
///   return.
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
/// - witness: `drift::tests::drift_names_each_finding_and_is_silent_on_a_consistent_pair`
fn run(invocation: Invocation) -> Result<Completion, RunError>
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
///   line. `grant`, `note`, `bind`, `claim`, `introduce` and `withdraw` commit
///   their receipt, under a fresh operation fence, and write the new commit's
///   id line. `present` binds the endpoint on its port, commits the presence of
///   the endpoint ([`Node::present`]), closes the endpoint and writes the
///   commit's id line. `book` writes the tree's book, one `<peer-id> <endpoint>
///   <commit-id>` line per present peer in key order. `whence` reaches the
///   trees the reference reads as [`resolve`] specifies, writes a `source` line
///   for each tree reached at another peer, then what the reference resolves to
///   ([`Peer::whence`]), asking DNS for a DNS name's candidate trees unless
///   `--witness` named them: for a path the target bound to it (`anchor
///   <anchor>`, `endpoint <endpoint-id>` or `datum <text>`) or `unbound`; for a
///   bare DNS or label anchor the anchor of the tree it names by key; for a
///   commit `commit <commit-id> admitted`, `commit <commit-id> refused
///   <reason>`, or `unknown` when the tree holds none. `view` writes the tree's
///   view, one line per fact ([`domhringr_record_tree::View`]'s display).
///   `heads` writes the tree's heads, one sorted hex line each. `sync` routes
///   the dial ([`Peer::route`]), dials the remote at the route's endpoint, and
///   writes the route's `source` line, the heads after the sync the same way,
///   then `path <peer-id> <path>` for the path the connection took, having
///   closed its endpoint. `dispatch` runs as [`dispatch`] specifies, `replay`
///   as [`replay`] and `evidence` as [`evidence`]. `report` keeps its file's
///   content as evidence ([`Evidence::commit`]) before any receipt; `report`,
///   `handoff` and `retire` commit their receipt on the task's current
///   dispatch, under a fresh operation fence, and write the new commit's id
///   line. `serve` runs as [`serve`] specifies. `drift` folds the concepts tree
///   in the local store, closes the store, and writes [`drift::check`]'s report
///   of it against the two checkouts, one line per finding. `judge ask` writes
///   `transcript <digest>` for the transcript [`transcript_of`] names, then
///   rules on its question as [`rulings`] rules. `judge verdict` runs as
///   [`verdict`] specifies, this peer the judge. `playbook validate`, `rubric
///   validate`, `playbook run` and `rubric grade` run as
///   [`strategy::validate_playbook`], [`strategy::validate_rubric`],
///   [`strategy::run_playbook`] and [`strategy::grade_rubric`] specify, this
///   peer the runner and the judge. Every command ends in
///   [`Completion::Success`] but a `drift` whose report holds a finding, which
///   ends in [`Completion::Drifted`].
/// - fails: [`RunError::Identity`], [`RunError::Open`], [`RunError::Bind`],
///   [`RunError::Random`], [`RunError::Commit`], [`RunError::View`],
///   [`RunError::Present`], [`RunError::Route`], [`RunError::Whence`],
///   [`RunError::Heads`] and [`RunError::Sync`] as the record library reports
///   them, [`RunError::Itself`] for a `sync` or a `dispatch` aimed at this
///   peer, [`RunError::Undispatched`] for a `report`, `handoff`, `retire`,
///   `judge verdict`, `playbook run` or `rubric grade` on a task with no
///   dispatch, [`RunError::Wake`] as [`dispatch`] reports it,
///   [`RunError::Drift`] as [`drift::check`] reports it,
///   [`RunError::Transcript`] and [`RunError::Evidence`] as [`transcript_of`],
///   [`RunError::Report`] when `report`'s file cannot be read and
///   [`RunError::Evidence`] when its content cannot be kept,
///   [`RunError::Fetch`] and [`RunError::Unnamed`] as [`evidence`] reports
///   them, [`RunError::Config`], [`RunError::Client`], [`RunError::Table`] and
///   [`RunError::Rulings`] as [`rulings`] report them, [`RunError::Load`],
///   [`RunError::Verify`], [`RunError::Join`] and [`RunError::State`] as the
///   [`strategy`] commands report them, and [`RunError::Output`] when standard
///   output cannot be written. A failed sync, presence, wake or fetch still
///   closes the endpoint.
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
/// - [`RunError::Present`]: the presence cannot be committed.
/// - [`RunError::Route`]: no remote can be named for the dial, as when the book
///   holds no presence of the peer aimed at.
/// - [`RunError::Itself`]: `sync` or `dispatch` aims at this peer.
/// - [`RunError::Undispatched`]: the task has no dispatch to answer or rule on.
/// - [`RunError::Wake`]: the seat was not woken.
/// - [`RunError::Whence`]: the reference does not resolve, as when its DNS name
///   is unclaimed, its label unintroduced or its commit prefix ambiguous.
/// - [`RunError::Heads`]: the heads cannot be read.
/// - [`RunError::Sync`]: the sync failed.
/// - [`RunError::Drift`]: a checkout cannot be read.
/// - [`RunError::Transcript`]: the transcript file cannot be read.
/// - [`RunError::Report`]: the report's file cannot be read.
/// - [`RunError::Evidence`]: evidence cannot be kept, or is not held whole.
/// - [`RunError::Fetch`], [`RunError::Unnamed`]: as [`evidence`].
/// - [`RunError::Config`]: the judge has no endpoint configured.
/// - [`RunError::Client`]: the judge's client cannot be built.
/// - [`RunError::Table`], [`RunError::Rulings`]: the table file cannot be read
///   or holds no table.
/// - [`RunError::Output`]: standard output cannot be written.
/// - [`RunError::Load`]: a playbook or a rubric does not load.
/// - [`RunError::Verify`], [`RunError::Join`]: a verifier does not run to its
///   end.
/// - [`RunError::State`]: a rubric's state file cannot be read, or its
///   transcript kept.
/// - [`RunError::Closed`], [`RunError::Diagnostics`]: as [`serve`].
///
/// # Adequacy
/// - hypothesis: L3 — two processes exchange ids, open a tree and parse its
///   anchor, grant, write notes, bind paths, claim a DNS name, introduce a tree
///   by a label, resolve anchors in all three forms and commits whole and
///   abbreviated, read heads and views, and sync at each other's endpoint in
///   both directions; views are compared byte for byte across processes and
///   with the expected facts, resolutions with the commit bound, across forms
///   and with each commit's verdict, refusals by their diagnostic, and each
///   sync's path line is parsed; a peer presents its endpoint, and the other,
///   after one sync at it, lists it in the book and reaches it through the book
///   alone for `whence` and `sync`, as their source lines say, until it
///   withdraws; `drift` over a fixture pair prints its four findings exactly
///   and exits 3, then nothing and exits 0; an operator dispatches a seat that
///   is down, then up, and replays the task through the seat's presence as the
///   seat reports across a restart of each, the replay fetching the report's
///   content; a reader prints a seat's report fetched by its digest byte for
///   byte, and a report missing a chunk on the seat is refused naming it with
///   nothing printed; a judge asks a question about a transcript, from a table
///   and from no endpoint, and rules on the task's current dispatch, read and
///   unread, and the replay shows the verdict and its transcript held; a
///   playbook and a rubric validate or are refused by file and field, a
///   playbook runs its verifiers and grades its questions on the task's current
///   dispatch, and the replay shows each verification and grading.
/// - witness: `sync::tests::two_peers_fold_one_tree_to_identical_views`
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
/// - witness: `sync::tests::an_anchor_resolves_alike_on_both_peers`
/// - witness: `sync::tests::a_named_anchor_resolves_through_its_claim_or_introduction`
/// - witness: `sync::tests::a_commit_resolves_to_its_verdict_on_both_peers`
/// - witness: `presence::tests::a_peer_is_reached_through_the_book_until_it_withdraws`
/// - witness: `seat::tests::a_dispatched_seat_reports_across_restarts_of_either_side`
/// - witness: `evidence::tests::a_reader_fetches_a_seats_report_and_refuses_a_missing_chunk`
/// - witness: `drift::tests::drift_names_each_finding_and_is_silent_on_a_consistent_pair`
/// - witness: `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
async fn execute(invocation: Invocation) -> Result<Completion, RunError>
{
    let Invocation { state, command } = invocation;
    let identity = Identity::load_or_create(&state)?;
    let evidence = Evidence::open(&state);
    let emitted = match command {
        | Command::Id => emit(&format_args!(
            "{}\n{}\n",
            identity.endpoint_key(),
            identity.peer_key()
        )),
        | Command::Serve { port, surface } => {
            serve(Peer::open(&state, identity)?, evidence, port, surface).await
        },
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
        | Command::Present { tree, port } => {
            let node = Peer::open(&state, identity)?.bind(port, &[]).await?;
            let presented = node.present(tree).await;
            node.close().await;
            drop(node);
            emit(&format_args!("{}\n", presented?))
        },
        | Command::Withdraw { tree, of } => {
            let of = match of {
                | Withdrawn::Own => identity.peer_key(),
                | Withdrawn::Of(peer) => peer,
            };
            let peer = Peer::open(&state, identity)?;
            record(&peer, tree, Receipt::withdraw(tree, of)?).await
        },
        | Command::Book { tree } => {
            let view = Peer::open(&state, identity)?.view(tree).await?;
            view.book()
                .iter()
                .try_for_each(|(peer, presence)| emit(&format_args!("{peer} {presence}\n")))
        },
        | Command::Whence {
            reference,
            witnessing,
            scope,
            reach,
        } => {
            let peer = Peer::open(&state, identity)?;
            let (sources, resolution) = match witnessing {
                | Witnessing::Dns => {
                    resolve(peer, &reference, &Dns::system(), scope, reach).await?
                },
                | Witnessing::ByHand(witness) => {
                    resolve(peer, &reference, &witness, scope, reach).await?
                },
            };
            emit(&format_args!("{sources}{resolution}\n"))
        },
        | Command::View { tree } => {
            let view = Peer::open(&state, identity)?.view(tree).await?;
            emit(&view)
        },
        | Command::Heads { tree } => {
            let heads = Peer::open(&state, identity)?.heads(tree).await?;
            emit(&heads)
        },
        | Command::Sync { tree, dial } => {
            let peer = Peer::open(&state, identity)?;
            let route = peer.route(tree, dial.aim, dial.at).await?;
            let remote = match route {
                | Route::Itself => {
                    drop(peer);
                    return Err(RunError::Itself);
                },
                | Route::Book { ref remote, .. } | Route::Given { ref remote } => remote.clone(),
            };
            let node = peer.bind(BindPort::Ephemeral, &[]).await?;
            let synced = node.sync(&remote, tree).await;
            node.close().await;
            drop(node);
            let synced = synced?;
            emit(&format_args!(
                "{}{}path {} {}\n",
                Reached { tree, route },
                synced.heads(),
                remote.peer(),
                synced.path()
            ))
        },
        | Command::Dispatch {
            tree,
            seat,
            brief,
            at,
        } => {
            let operator = identity.peer_key();
            let peer = Peer::open(&state, identity)?;
            dispatch(peer, operator, tree, seat, brief, at).await
        },
        | Command::Report {
            tree,
            file,
            summary,
        } => {
            let bytes = std::fs::read(file).map_err(RunError::Report)?;
            let content = evidence.commit(&Content::from(bytes))?;
            let peer = Peer::open(&state, identity)?;
            on_current(peer, tree, |dispatch| {
                Receipt::report(tree, dispatch, content, summary)
            })
            .await
        },
        | Command::Handoff { tree, to } => {
            let peer = Peer::open(&state, identity)?;
            on_current(peer, tree, |dispatch| Receipt::handoff(tree, dispatch, to)).await
        },
        | Command::Retire { tree } => {
            let peer = Peer::open(&state, identity)?;
            on_current(peer, tree, |dispatch| Receipt::retire(tree, dispatch)).await
        },
        | Command::Pause { tree } => {
            let peer = Peer::open(&state, identity)?;
            on_current(peer, tree, |dispatch| Receipt::pause(tree, dispatch)).await
        },
        | Command::Replay {
            tree,
            replaying,
            edition,
        } => {
            replay(
                Peer::open(&state, identity)?,
                &evidence,
                tree,
                replaying,
                edition,
            )
            .await
        },
        | Command::Evidence {
            tree,
            digest,
            reaching,
        } => {
            let peer = Peer::open(&state, identity)?;
            self::evidence(peer, &evidence, tree, digest, reaching).await
        },
        | Command::Drift {
            public,
            vault,
            tree,
        } => {
            let view = Peer::open(&state, identity)?.view(tree).await?;
            let report = drift::check(tree, &view, &public, &vault)?;
            emit(&report)?;
            return Ok(if report.findings().is_empty() {
                Completion::Success
            }
            else {
                Completion::Drifted
            });
        },
        | Command::Ask {
            question,
            transcript,
            judging,
        } => {
            let transcript = transcript_of(transcript, &evidence)?;
            emit(&format_args!("transcript {}\n", transcript.digest()))?;
            rulings(judging, slice::from_ref(&question), &transcript)
                .await
                .map(drop)
        },
        | Command::Verdict {
            tree,
            rubric,
            transcript,
            questions,
            judging,
        } => {
            let judge = identity.peer_key();
            let peer = Peer::open(&state, identity)?;
            let on = Stores {
                peer: &peer,
                evidence: &evidence,
            };
            verdict(on, judge, tree, rubric, transcript, questions, judging).await
        },
        | Command::ValidatePlaybook { file } => strategy::validate_playbook(&file),
        | Command::ValidateRubric { file } => strategy::validate_rubric(&file),
        | Command::RunPlaybook {
            file,
            tree,
            directory,
            judging,
        } => {
            let runner = identity.peer_key();
            let peer = Peer::open(&state, identity)?;
            let on = Stores {
                peer: &peer,
                evidence: &evidence,
            };
            strategy::run_playbook(on, runner, tree, &file, &directory, judging).await
        },
        | Command::GradeRubric {
            file,
            tree,
            directory,
            judging,
        } => {
            let judge = identity.peer_key();
            let peer = Peer::open(&state, identity)?;
            let on = Stores {
                peer: &peer,
                evidence: &evidence,
            };
            strategy::grade_rubric(on, judge, tree, &file, &directory, judging).await
        },
    };
    emitted.map(|()| Completion::Success)
}

/// Resolve `reference`, having first reached the trees it reads as `reach`
/// says, and name where each was reached.
///
/// # Specification
/// - ensures: for [`Reach::Local`], resolves from the local store alone and
///   names nothing. For [`Reach::Dial`], routes each tree the resolution reads
///   ([`Peer::reads`], [`Peer::route`]); when every route is this peer itself,
///   resolves locally without binding an endpoint. Otherwise binds an ephemeral
///   endpoint, syncs each tree with its remote in tree order, then for a label
///   routes and syncs the tree the now-synced scope introduces if it was not
///   read before, resolves, and closes the endpoint, success or not. Returns
///   the `source` lines of the trees reached at another peer, in the order
///   reached ([`Reached`]), and the resolution.
/// - fails: [`RunError::Whence`] as [`Peer::reads`] and [`Peer::whence`]
///   refuse, [`RunError::Route`] as [`Peer::route`] refuses, as when the book
///   holds no presence of the peer aimed at, [`RunError::Bind`] when the
///   endpoint cannot bind, and [`RunError::Sync`] when a sync fails.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Whence`]: the trees read cannot be named, or the reference
///   does not resolve.
/// - [`RunError::Route`]: a tree read has no remote to dial.
/// - [`RunError::Bind`]: the endpoint cannot bind.
/// - [`RunError::Sync`]: a sync fails.
///
/// # Adequacy
/// - hypothesis: L3 — the process test resolves an anchor of another peer's
///   tree through its presence in the book, reads the source line, and is
///   refused once the presence is withdrawn, then resolves with `--at`; the
///   owner resolves its own tree's anchor without a source line, and a label
///   read in no tree is refused before any dial.
/// - witness: `presence::tests::a_peer_is_reached_through_the_book_until_it_withdraws`
/// - witness: `sync::tests::a_named_anchor_resolves_through_its_claim_or_introduction`
async fn resolve<W>(
    peer: Peer,
    reference: &Reference,
    witness: &W,
    scope: Scope,
    reach: Reach,
) -> Result<(String, Resolution), RunError>
where
    W: Witness + Sync,
{
    let Reach::Dial(dial) = reach
    else {
        let resolution = peer.whence(reference, witness, scope).await?;
        return Ok((String::new(), resolution));
    };
    let mut routes = Vec::new();
    for tree in peer.reads(reference, witness, scope).await? {
        let route = peer.route(tree, dial.aim, dial.at.clone()).await?;
        routes.push(Reached { tree, route });
    }
    if routes.iter().all(|reached| reached.route == Route::Itself) {
        let resolution = peer.whence(reference, witness, scope).await?;
        return Ok((String::new(), resolution));
    }
    let node = peer.bind(BindPort::Ephemeral, &[]).await?;
    let resolved = reach_and_resolve(&node, reference, witness, scope, &dial, routes).await;
    node.close().await;
    drop(node);
    resolved
}

/// Sync each of `routes` on `node`, then a label's introduced tree if the
/// sync named a new one, and resolve `reference`.
///
/// # Specification
/// - ensures: as [`resolve`] states for a dial, once the endpoint is bound; the
///   endpoint is left open for the caller to close.
/// - fails: as [`resolve`], but for [`RunError::Bind`].
/// - panics: none.
///
/// # Errors
/// - [`RunError::Whence`], [`RunError::Route`], [`RunError::Sync`]: as
///   [`resolve`].
async fn reach_and_resolve<W>(
    node: &Node,
    reference: &Reference,
    witness: &W,
    scope: Scope,
    dial: &Dial,
    routes: Vec<Reached>,
) -> Result<(String, Resolution), RunError>
where
    W: Witness + Sync,
{
    let read: BTreeSet<TreeId> = routes.iter().map(|reached| reached.tree).collect();
    let mut sources = String::new();
    let mut pending = routes;
    if matches!(reference.authority(), Authority::Label(_)) {
        sources.push_str(&sync_routes(node, pending).await?);
        pending = Vec::new();
        let introduced = node.peer().reads(reference, witness, scope).await?;
        for tree in introduced.difference(&read) {
            let route = node.peer().route(*tree, dial.aim, dial.at.clone()).await?;
            pending.push(Reached { tree: *tree, route });
        }
    }
    sources.push_str(&sync_routes(node, pending).await?);
    let resolution = node.peer().whence(reference, witness, scope).await?;
    Ok((sources, resolution))
}

/// Sync each tree of `routes` with its remote on `node`, in order.
///
/// # Specification
/// - ensures: a tree routed to this peer itself is not dialed; every other is
///   synced ([`Node::sync`]). Returns the `source` lines of the trees synced,
///   in order.
/// - fails: [`RunError::Sync`] at the first sync that fails.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Sync`]: a sync fails.
async fn sync_routes(
    node: &Node,
    routes: Vec<Reached>,
) -> Result<String, RunError>
{
    let mut sources = String::new();
    for reached in routes {
        match reached.route {
            | Route::Itself => {},
            | Route::Book { ref remote, .. } | Route::Given { ref remote } => {
                let _synced = node.sync(remote, reached.tree).await?;
            },
        }
        sources.push_str(&reached.to_string());
    }
    Ok(sources)
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

/// The commit of `tree`'s current dispatch.
///
/// # Specification
/// - ensures: the commit of the admitted dispatch last in canonical order.
/// - fails: [`RunError::View`] when the tree cannot be folded,
///   [`RunError::Undispatched`] when no dispatch is admitted.
/// - panics: none.
///
/// # Errors
/// - [`RunError::View`]: the tree cannot be folded.
/// - [`RunError::Undispatched`]: the task has no dispatch.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests answer and rule on a dispatch, and
///   refuse a verdict on a task with none.
/// - witness: `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
async fn current(
    peer: &Peer,
    tree: TreeId,
) -> Result<CommitId, RunError>
{
    match *peer.view(tree).await?.task().current() {
        | Current::Attempt(ref attempt) => Ok(attempt.dispatch()),
        | Current::Undispatched => Err(RunError::Undispatched),
    }
}

/// Commit in `tree` the receipt `answer` makes on the task's current
/// dispatch, and write the new commit's id line.
///
/// # Specification
/// - ensures: `answer` is given the commit [`current`] names, and its receipt
///   is committed as [`record`] commits it.
/// - fails: as [`current`], `answer` and [`record`] fail.
/// - panics: none.
///
/// # Errors
/// - [`RunError::View`], [`RunError::Undispatched`]: as [`current`].
/// - [`RunError::Random`]: no operation fence can be drawn.
/// - [`RunError::Commit`], [`RunError::Output`]: as [`record`].
async fn on_current(
    peer: Peer,
    tree: TreeId,
    answer: impl FnOnce(CommitId) -> Result<Receipt, RandomError>,
) -> Result<(), RunError>
{
    let dispatch = current(&peer, tree).await?;
    record(&peer, tree, answer(dispatch)?).await
}

/// Rule on `tree`'s current dispatch as `judge`, and commit the rulings as a
/// verdict under `rubric`.
///
/// # Specification
/// - ensures: names the current dispatch ([`current`]) before any question is
///   asked; then writes `transcript <digest>` for the transcript
///   [`transcript_of`] names, rules on each of `questions` as [`rulings`]
///   rules, keeps the transcript in `on`'s evidence store, and commits the
///   verdict of `judge` on that dispatch — `rubric`, the transcript's digest,
///   and each question's hash with its ruling, in the order asked — under a
///   fresh operation fence, as [`record`] commits it.
/// - fails: as [`current`], [`transcript_of`], [`rulings`] and [`record`] fail,
///   [`RunError::Evidence`] when the transcript cannot be kept, and
///   [`RunError::Random`] when no operation fence can be drawn.
/// - panics: none.
///
/// # Errors
/// - [`RunError::View`], [`RunError::Undispatched`]: as [`current`].
/// - [`RunError::Transcript`], [`RunError::Evidence`]: as [`transcript_of`], or
///   the transcript cannot be kept.
/// - [`RunError::Config`], [`RunError::Client`], [`RunError::Table`],
///   [`RunError::Rulings`], [`RunError::Diagnostics`]: as [`rulings`].
/// - [`RunError::Random`]: no operation fence can be drawn.
/// - [`RunError::Commit`], [`RunError::Output`]: as [`record`].
///
/// # Adequacy
/// - hypothesis: L3 — the process test refuses a verdict on a task with no
///   dispatch, then rules on the current dispatch, read and unread, replays the
///   verdict with each ruling in the order asked and its transcript held, and
///   asks again by the transcript's digest alone.
/// - witness: `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
async fn verdict(
    on: Stores<'_>,
    judge: PeerKey,
    tree: TreeId,
    rubric: ContentHash,
    asked: Asked,
    questions: Vec<Question>,
    judging: Judging,
) -> Result<(), RunError>
{
    let dispatch = current(on.peer, tree).await?;
    let transcript = transcript_of(asked, on.evidence)?;
    emit(&format_args!("transcript {}\n", transcript.digest()))?;
    let answers = rulings(judging, &questions, &transcript).await?;
    on.evidence.keep(transcript.staged())?;
    let receipt = Receipt::verdict(tree, dispatch, judge, rubric, transcript.digest(), answers)?;
    record(on.peer, tree, receipt).await
}

/// The transcript `asked` names.
///
/// # Specification
/// - ensures: [`Asked::File`] reads the whole file and stages its content
///   ([`Transcript::held`]); [`Asked::Named`] reads the content `evidence`
///   holds under the digest ([`Evidence::read`]) and stages it again, under the
///   same name.
/// - fails: [`RunError::Transcript`] when the file cannot be read, and
///   [`RunError::Evidence`] when the store does not hold the digest whole or
///   the content cannot be staged.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Transcript`]: the file cannot be read.
/// - [`RunError::Evidence`]: the evidence is not held whole, or not staged.
///
/// # Adequacy
/// - hypothesis: L3 — the process test judges one transcript from its file and
///   by its digest once a verdict kept it, reading the same digest printed both
///   ways, and refuses a digest the store does not hold.
/// - witness: `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
fn transcript_of(
    asked: Asked,
    evidence: &Evidence,
) -> Result<Transcript, RunError>
{
    let content = match asked {
        | Asked::Named(digest) => evidence.read(digest)?,
        | Asked::File(path) => {
            let bytes = std::fs::read(path).map_err(RunError::Transcript)?;
            Content::from(bytes)
        },
    };
    let transcript = Transcript::held(content)?;
    Ok(transcript)
}

/// Ask each of `questions` about `transcript` of what `judging` names,
/// writing each ruling's line as it is read.
///
/// # Specification
/// - ensures: builds what answers — for [`Judging::Endpoint`] a client of the
///   endpoint [`Config::from_environment`] configures, for [`Judging::Table`]
///   the table its file holds — then rules as [`rule`] rules.
/// - fails: [`RunError::Config`] when the environment configures no endpoint,
///   [`RunError::Client`] when the client cannot be built, [`RunError::Table`]
///   when the table file cannot be read, [`RunError::Rulings`] when it holds no
///   table, and as [`rule`].
/// - panics: none.
///
/// # Errors
/// - [`RunError::Config`]: no endpoint is configured.
/// - [`RunError::Client`]: the client cannot be built.
/// - [`RunError::Table`]: the table file cannot be read.
/// - [`RunError::Rulings`]: the table file holds no table.
/// - [`RunError::Diagnostics`], [`RunError::Output`]: as [`rule`].
///
/// # Adequacy
/// - hypothesis: L3 — the process test answers from a table file, and refuses a
///   judge with no endpoint configured and a table file that holds no table.
/// - witness: `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
async fn rulings(
    judging: Judging,
    questions: &[Question],
    transcript: &Transcript,
) -> Result<Vec<(ContentHash, Ruling)>, RunError>
{
    match judging {
        | Judging::Endpoint => {
            let config = Config::from_environment().map_err(RunError::Config)?;
            let client = ChatCompletions::new(config).map_err(RunError::Client)?;
            rule(&client, questions, transcript).await
        },
        | Judging::Table(path) => {
            let text = std::fs::read_to_string(path).map_err(RunError::Table)?;
            let table = text
                .parse::<domhringr_judge_oracle::Static>()
                .map_err(RunError::Rulings)?;
            rule(&table, questions, transcript).await
        },
    }
}

/// Ask `backend` each of `questions` about `transcript`, in order, writing
/// each ruling's line as it is read.
///
/// # Specification
/// - ensures: a question answered is read ([`Ruling::Read`]); a question
///   refused is unread for the refusal's reason ([`Ruling::Unread`]), its cause
///   written to standard error, and the next question is still asked — a
///   refusal is recorded, never answered with a default. Writes `ruling
///   <question-hash> <ruling>` per question, and returns the question hashes
///   with their rulings in the order asked.
/// - fails: [`RunError::Diagnostics`] when standard error cannot be written,
///   [`RunError::Output`] when standard output cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Diagnostics`]: standard error cannot be written.
/// - [`RunError::Output`]: standard output cannot be written.
///
/// # Adequacy
/// - hypothesis: L3 — the process test rules on a question the table answers
///   and on one it does not, reading `read` and `unread malformed` lines and
///   the cause on standard error.
/// - witness: `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
async fn rule<Answering>(
    backend: &Answering,
    questions: &[Question],
    transcript: &Transcript,
) -> Result<Vec<(ContentHash, Ruling)>, RunError>
where
    Answering: Backend + Sync,
{
    let mut answers = Vec::with_capacity(questions.len());
    for question in questions {
        let ruling = match backend.ask(question, transcript).await {
            | Ok(readout) => Ruling::Read(readout),
            | Err(refusal) => {
                report(&refusal).map_err(RunError::Diagnostics)?;
                Ruling::Unread(refusal.reason())
            },
        };
        emit(&format_args!("ruling {} {ruling}\n", question.hash()))?;
        answers.push((question.hash(), ruling));
    }
    Ok(answers)
}

/// Dispatch `seat` to `brief` in `tree`, as `operator`, and wake it at the
/// endpoint `at` names.
///
/// # Specification
/// - ensures: routes to `seat` for `tree` first ([`Peer::route`]), so a seat no
///   endpoint names gets no dispatch. When the task's current attempt puts
///   `seat` in its slot, held, to `brief`, that dispatch is re-sent; otherwise
///   a dispatch of `seat` to `brief` is committed under a fresh operation
///   fence. Writes the dispatch's commit id line at once, binds an ephemeral
///   endpoint, wakes the seat ([`domhringr_seat_slot::wake`]), closes the
///   endpoint, and writes the route's `source` line and `woken`.
/// - fails: [`RunError::Route`] when no endpoint names the seat,
///   [`RunError::Itself`] when `seat` is this peer, [`RunError::View`] when the
///   task cannot be folded, [`RunError::Random`] and [`RunError::Commit`] when
///   the dispatch cannot be committed, [`RunError::Bind`] when the endpoint
///   cannot bind, [`RunError::Wake`] when the seat is not woken — the dispatch
///   stays committed, to be re-sent — and [`RunError::Output`] when standard
///   output cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process test dispatches a seat that is down, reads
///   the dispatch id before the wake fails, then re-sends the same dispatch to
///   the seat at an endpoint named by hand and later through its presence in
///   the book, reading the same id, the source line and `woken` each time.
/// - witness: `seat::tests::a_dispatched_seat_reports_across_restarts_of_either_side`
async fn dispatch(
    peer: Peer,
    operator: PeerKey,
    tree: TreeId,
    seat: PeerKey,
    brief: Brief,
    at: At,
) -> Result<(), RunError>
{
    let route = peer.route(tree, Aim::Peer(seat), at).await?;
    let remote = match route {
        | Route::Itself => return Err(RunError::Itself),
        | Route::Book { ref remote, .. } | Route::Given { ref remote } => remote.clone(),
    };
    let view = peer.view(tree).await?;
    let resent = match *view.task().current() {
        | Current::Attempt(ref attempt)
            if attempt.slot() == Slot::Held(seat) && *attempt.brief() == brief =>
        {
            Some(attempt.dispatch())
        },
        | Current::Attempt(_) | Current::Undispatched => None,
    };
    let dispatch = match resent {
        | Some(dispatch) => dispatch,
        | None => {
            let receipt = Receipt::dispatch(tree, seat, brief)?;
            peer.commit(tree, receipt).await?
        },
    };
    emit(&format_args!("{dispatch}\n"))?;
    let node = peer.bind(BindPort::Ephemeral, &[]).await?;
    let woken =
        domhringr_seat_slot::wake(&node, &remote, &Wake::new(tree, dispatch, operator)).await;
    node.close().await;
    drop(node);
    woken?;
    emit(&format_args!("{}woken\n", Reached { tree, route }))
}

/// Print `tree` read as a task, reached first as `replaying` says, and
/// whether each evidence it names is held.
///
/// # Specification
/// - ensures: for [`Replaying::Local`], writes the local store's task, then the
///   evidence lines as [`gather`] reads them from `evidence` alone. For
///   [`Replaying::Dial`], aims at the peer `--peer` named, or else at the local
///   task's current attempt's seat, or at the task's owner when no dispatch is
///   admitted; routes ([`Peer::route`]), and unless the route is this peer
///   itself, binds an ephemeral endpoint, syncs the task ([`Node::sync`]),
///   fetches from the peer reached each evidence the synced task names that
///   `evidence` lacks ([`gather`]) and closes the endpoint; then writes the
///   route's `source` line, the task — one line per admitted seat receipt in
///   canonical order and the line saying where it stands
///   ([`domhringr_record_tree::Task`]'s display) — and the evidence lines
///   ([`attest`]).
/// - fails: [`RunError::View`] when the task cannot be folded, as when the
///   local store holds none of it and no `--peer` names whom to reach,
///   [`RunError::Route`] when no endpoint names the peer aimed at,
///   [`RunError::Bind`] when the endpoint cannot bind, [`RunError::Sync`] when
///   the sync fails, [`RunError::Output`] when standard output cannot be
///   written and [`RunError::Diagnostics`] when standard error cannot be. An
///   evidence that is not held whole is a line, never a failure.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process test replays the task from the local store
///   while the seat is down, then through the seat's presence in the book
///   before and after the seat reports, reading each line, the report's content
///   fetched from the seat and held; the judge's and the playbook's tests
///   replay from the local store and read each transcript and output held.
/// - witness: `seat::tests::a_dispatched_seat_reports_across_restarts_of_either_side`
/// - witness: `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
async fn replay(
    peer: Peer,
    evidence: &Evidence,
    tree: TreeId,
    replaying: Replaying,
    edition: domhringr_record_tree::Edition,
) -> Result<(), RunError>
{
    let Replaying::Dial { toward, at } = replaying
    else {
        let view = peer.view_at(tree, edition).await?;
        emit_refusals(&view)?;
        let gathered = gather(evidence, view.task(), Source::Local).await;
        emit(view.task())?;
        return attest(gathered);
    };
    let aim = match toward {
        | Toward::Peer(named) => Aim::Peer(named),
        | Toward::Seat => match *peer.view(tree).await?.task().current() {
            | Current::Attempt(ref attempt) => Aim::Peer(attempt.seat()),
            | Current::Undispatched => Aim::Owner,
        },
    };
    let route = peer.route(tree, aim, at).await?;
    let (view, gathered) = match route {
        | Route::Itself => {
            let view = peer.view_at(tree, edition).await?;
            let gathered = gather(evidence, view.task(), Source::Local).await;
            (view, gathered)
        },
        | Route::Book { ref remote, .. } | Route::Given { ref remote } => {
            let node = peer.bind(BindPort::Ephemeral, &[]).await?;
            let synced = node.sync(remote, tree).await;
            let view = node.peer().view_at(tree, edition).await;
            let gathered = match (&synced, &view) {
                | (&Ok(_), &Ok(ref view)) => {
                    let source = Source::Remote {
                        node: &node,
                        holder: remote.endpoint(),
                    };
                    gather(evidence, view.task(), source).await
                },
                | _ => Vec::new(),
            };
            node.close().await;
            drop(node);
            let _synced = synced?;
            (view?, gathered)
        },
    };
    emit_refusals(&view)?;
    emit(&format_args!("{}{}", Reached { tree, route }, view.task()))?;
    attest(gathered)
}

/// Print every named conformance or authority refusal in a replayed view.
///
/// # Specification
/// - ensures: each refused commit is printed with its refusal, never omitted.
/// - fails: standard-output errors remain [`RunError::Output`].
/// - panics: none.
///
/// # Errors
/// [`RunError::Output`] if stdout cannot be written or flushed.
///
/// # Adequacy
/// - hypothesis: L3 the process witness observes the pause receipt's identity,
///   name and expected state under Base, and its admission under Paused.
/// - witness: `seat::tests::two_processes_replay_session_editions`
fn emit_refusals(view: &domhringr_record_tree::View) -> Result<(), RunError>
{
    for &(commit, ref refusal) in view.refused() {
        emit(&format_args!("refused {commit} {refusal}\n"))?;
    }
    Ok(())
}

/// Where evidence the local store lacks is fetched from.
#[derive(Clone, Copy)]
enum Source<'reach>
{
    /// Nowhere: the local store alone is read.
    Local,
    /// The holder at this endpoint, dialed from this node.
    Remote
    {
        /// The node dialing.
        node: &'reach Node,
        /// The holder's endpoint.
        holder: &'reach Endpoint,
    },
}

/// Each evidence `task` names, once and in the order first named, with
/// whether it is held whole: read from `evidence`, or else fetched from
/// `source` into it.
///
/// # Specification
/// - ensures: per distinct digest of [`Task::evidence`] in order, `Ok` when
///   [`Evidence::read`] reads it whole, or when it does not and
///   [`domhringr_record_evidence::fetch`] from a [`Source::Remote`] brings it
///   whole; otherwise the refusal: [`RunError::Evidence`] as the local read
///   refused it under [`Source::Local`], [`RunError::Fetch`] as the fetch
///   refused it under [`Source::Remote`].
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — the seat's process test replays a report fetched from the
///   seat; the judge's and the playbook's replay their own evidence from the
///   local store.
/// - witness: `seat::tests::a_dispatched_seat_reports_across_restarts_of_either_side`
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
async fn gather(
    evidence: &Evidence,
    task: &Task,
    source: Source<'_>,
) -> Vec<(ManifestDigest, Result<(), RunError>)>
{
    let mut seen = BTreeSet::new();
    let mut gathered = Vec::new();
    for (_author, digest) in task.evidence() {
        if !seen.insert(digest) {
            continue;
        }
        let outcome = match (evidence.read(digest), source) {
            | (Ok(_content), _) => Ok(()),
            | (Err(refused), Source::Local) => Err(RunError::Evidence(refused)),
            | (Err(_lacking), Source::Remote { node, holder }) => {
                domhringr_record_evidence::fetch(node, holder, digest, evidence)
                    .await
                    .map(drop)
                    .map_err(RunError::Fetch)
            },
        };
        gathered.push((digest, outcome));
    }
    gathered
}

/// Write one line per evidence of `gathered`: `evidence <digest> held`, or
/// `evidence <digest> unheld` with its cause on standard error.
///
/// # Specification
/// - ensures: the lines in order; each cause is written as [`report`] writes
///   it, after its line.
/// - fails: [`RunError::Output`] when standard output cannot be written, and
///   [`RunError::Diagnostics`] when standard error cannot be.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Output`], [`RunError::Diagnostics`]: as listed above.
fn attest(gathered: Vec<(ManifestDigest, Result<(), RunError>)>) -> Result<(), RunError>
{
    for (digest, outcome) in gathered {
        match outcome {
            | Ok(()) => emit(&format_args!("evidence {digest} held\n"))?,
            | Err(failure) => {
                emit(&format_args!("evidence {digest} unheld\n"))?;
                report(&failure).map_err(RunError::Diagnostics)?;
            },
        }
    }
    Ok(())
}

/// Write the content of the evidence `digest` names, read from `evidence`, or
/// else fetched as `reaching` says.
///
/// # Specification
/// - ensures: when `evidence` holds `digest` whole, its content. Otherwise, for
///   [`Replaying::Dial`], aims at the peer `--peer` named, or else at the
///   author of the first admitted receipt of the local task naming `digest`
///   ([`Task::evidence`]); routes ([`Peer::route`]), binds an ephemeral
///   endpoint, fetches ([`domhringr_record_evidence::fetch`]) — the value
///   checked whole and kept before any byte is returned — closes the endpoint,
///   and writes the content. The content is written byte for byte and nothing
///   else; on any failure nothing is written to standard output.
/// - fails: [`RunError::Evidence`] with the local refusal for
///   [`Replaying::Local`] or a route to this peer itself, [`RunError::View`]
///   when the local task cannot be folded, [`RunError::Unnamed`] when no
///   admitted receipt names `digest` and no `--peer` is named,
///   [`RunError::Route`] when no endpoint names the holder, [`RunError::Bind`]
///   when the endpoint cannot bind, [`RunError::Fetch`] as the fetch refuses —
///   among them the value plane's refusal naming the first chunk neither side
///   holds — and [`RunError::Output`] when standard output cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — two processes: a reader prints a seat's report fetched
///   through the book, compared byte for byte with the file reported, then,
///   holding none of it and the seat missing one chunk, is refused naming that
///   chunk with nothing printed.
/// - witness: `evidence::tests::a_reader_fetches_a_seats_report_and_refuses_a_missing_chunk`
async fn evidence(
    peer: Peer,
    evidence: &Evidence,
    tree: TreeId,
    digest: ManifestDigest,
    reaching: Replaying,
) -> Result<(), RunError>
{
    let content = match (evidence.read(digest), reaching) {
        | (Ok(content), _) => content,
        | (Err(refused), Replaying::Local) => return Err(RunError::Evidence(refused)),
        | (Err(refused), Replaying::Dial { toward, at }) => {
            let aim = match toward {
                | Toward::Peer(named) => named,
                | Toward::Seat => peer
                    .view(tree)
                    .await?
                    .task()
                    .evidence()
                    .find(|&(_author, named)| named == digest)
                    .map(|(author, _named)| author)
                    .ok_or(RunError::Unnamed(digest))?,
            };
            let route = peer.route(tree, Aim::Peer(aim), at).await?;
            let (Route::Book { ref remote, .. } | Route::Given { ref remote }) = route
            else {
                return Err(RunError::Evidence(refused));
            };
            let node = peer.bind(BindPort::Ephemeral, &[]).await?;
            let fetched =
                domhringr_record_evidence::fetch(&node, remote.endpoint(), digest, evidence).await;
            node.close().await;
            drop(node);
            fetched?
        },
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(content.as_ref())
        .map_err(RunError::Output)?;
    stdout.flush().map_err(RunError::Output)
}

/// Bind `peer` on `port`, announce it, and serve as a seat acting through
/// `surface` and keeping its reports in `evidence` until the process is
/// killed.
///
/// # Specification
/// - ensures: once the endpoint is bound, accepting the seat protocol and the
///   evidence protocol, writes the endpoint id line, the peer id line and
///   `listening`; then writes the seat's events
///   ([`domhringr_seat_slot::serve`]) as they come: for each peer admitted
///   `accepted <peer-id>` and `path <peer-id> <path>` for the path its
///   connection took when admitted, `woken <tree> <dispatch-id>` for a wake
///   answered, `declined <reason>` for one declined, `reported <tree>
///   <commit-id>` for a report committed, `unreported <tree> <dispatch-id>` for
///   an act that committed none, `served <digest>` for a fetch answered with
///   the evidence it held, and `unserved <digest>` for one answered unheld. A
///   connection that fails its handshake, a declined wake's, a failed act's, an
///   unheld fetch's, a failed fetch stream's and a failed resume's cause are
///   reported on standard error and serving continues.
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
/// - hypothesis: L3 — the process tests serve on a fixed port, read the
///   announced ids and `listening`, sync against the server repeatedly, and
///   read an `accepted` line and a parseable `path` line per sync; a seat is
///   woken, fails to act through a failing program, and once restarted with
///   another program resumes and reports, each read from its lines, and serves
///   its report's content to the replaying operator; a seat missing a chunk of
///   a report still serves what it holds.
/// - witness: `sync::tests::two_peers_fold_one_tree_to_identical_views`
/// - witness: `sync::tests::two_peers_sync_one_tree_to_identical_heads`
/// - witness: `seat::tests::a_dispatched_seat_reports_across_restarts_of_either_side`
/// - witness: `evidence::tests::a_reader_fetches_a_seats_report_and_refuses_a_missing_chunk`
async fn serve(
    peer: Peer,
    evidence: Evidence,
    port: BindPort,
    surface: Surface,
) -> Result<(), RunError>
{
    let protocols = [
        domhringr_seat_slot::PROTOCOL,
        domhringr_record_evidence::PROTOCOL,
    ];
    let node = Arc::new(peer.bind(port, &protocols).await?);
    let mut events = domhringr_seat_slot::serve(Arc::clone(&node), surface, evidence);
    emit(&format_args!(
        "{}\n{}\nlistening\n",
        node.endpoint_key(),
        node.peer().identity().peer_key()
    ))?;
    drop(node);
    while let Some(event) = events.recv().await {
        let diagnosed = match event {
            | Event::Accepted(accepted) => {
                emit(&format_args!(
                    "accepted {peer}\npath {peer} {path}\n",
                    peer = accepted.peer(),
                    path = accepted.path()
                ))?;
                Ok(())
            },
            | Event::Woken { tree, dispatch } => {
                emit(&format_args!("woken {} {dispatch}\n", Anchor::key(tree)))?;
                Ok(())
            },
            | Event::Declined(declined) => {
                emit(&format_args!("declined {}\n", declined.decline()))?;
                report(&declined)
            },
            | Event::Reported { tree, report } => {
                emit(&format_args!("reported {} {report}\n", Anchor::key(tree)))?;
                Ok(())
            },
            | Event::Unreported {
                tree,
                dispatch,
                failure,
            } => {
                emit(&format_args!(
                    "unreported {} {dispatch}\n",
                    Anchor::key(tree)
                ))?;
                report(&failure)
            },
            | Event::Served(Served::Held { digest, .. }) => {
                emit(&format_args!("served {digest}\n"))?;
                Ok(())
            },
            | Event::Served(Served::Unheld { digest, reason }) => {
                emit(&format_args!("unserved {digest}\n"))?;
                report(&reason)
            },
            | Event::Unserved(failure) => report(&failure),
            | Event::Unaccepted(failure) => report(&failure),
            | Event::Unanswered(failure) => report(&failure),
            | Event::Unresumed(failure) => report(&failure),
            | Event::Closed => return Err(RunError::Closed),
        };
        diagnosed.map_err(RunError::Diagnostics)?;
    }
    Err(RunError::Closed)
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
/// - ensures: runs the command line as [`run`] specifies and exits 0, or
///   [`DRIFT_STATUS`] when it ends in [`Completion::Drifted`], having written
///   nothing to standard error.
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
        | Ok(Completion::Success) => ExitCode::SUCCESS,
        | Ok(Completion::Drifted) => ExitCode::from(DRIFT_STATUS),
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

    use domhringr_judge_oracle::Question;
    use domhringr_judge_oracle::QuestionError;
    use domhringr_record_evidence::ParsedDigest;
    use domhringr_record_tree::Aim;
    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::At;
    use domhringr_record_tree::Authority;
    use domhringr_record_tree::BindPort;
    use domhringr_record_tree::Brief;
    use domhringr_record_tree::ContentHash;
    use domhringr_record_tree::Domain;
    use domhringr_record_tree::Endpoint;
    use domhringr_record_tree::EndpointKey;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::Label;
    use domhringr_record_tree::ParseAnchorError;
    use domhringr_record_tree::ParseDomainError;
    use domhringr_record_tree::ParseIdError;
    use domhringr_record_tree::ParseLabelError;
    use domhringr_record_tree::ParseSummaryError;
    use domhringr_record_tree::Path;
    use domhringr_record_tree::PeerKey;
    use domhringr_record_tree::Reference;
    use domhringr_record_tree::Scope;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::Static;
    use domhringr_record_tree::Target;
    use domhringr_record_tree::TreeId;
    use domhringr_record_tree::TreeKey;
    use domhringr_record_tree::UdpPort;
    use domhringr_seat_slot::Surface;
    use gandr_storage_values::ManifestDigest;

    use super::Asked;
    use super::Command;
    use super::Dial;
    use super::Invocation;
    use super::Judging;
    use super::Operand;
    use super::Reach;
    use super::Replaying;
    use super::Toward;
    use super::UsageError;
    use super::Verb;
    use super::Withdrawn;
    use super::Witnessing;
    use super::drift;
    use super::parse;

    /// The id of the tree the command lines name: the all-zero key's.
    const TREE_ID: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    /// That tree's anchor.
    const TREE: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/";

    /// A path in that tree.
    const PATH: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/a/b";

    /// A commit id: 64 hex digits, which no anchor reads where a tree stands.
    const COMMIT: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    /// A content hash: 64 hex digits.
    const CONTENT: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

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

    /// A real endpoint id and peer id, from an identity made for the test.
    ///
    /// # Specification
    /// trivial.
    fn ids() -> (EndpointKey, PeerKey)
    {
        let root = tempfile::tempdir().unwrap();
        let identity =
            Identity::load_or_create(&StateDir::from(root.path().to_path_buf())).unwrap();
        (identity.endpoint_key(), identity.peer_key())
    }

    /// The dial with no option given: the tree's owner, at its presence in
    /// the book.
    ///
    /// # Specification
    /// trivial.
    const fn book() -> Dial
    {
        Dial {
            aim: Aim::Owner,
            at: At::Book,
        }
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
            reach: Reach::Dial(book()),
        };
        let (anchor, path) = (
            PATH.parse::<Anchor>().unwrap(),
            "a/b".parse::<Path>().unwrap(),
        );
        let commit_text = format!("{TREE}.commit/{COMMIT}");
        let commit = commit_text.parse::<Anchor>().unwrap();
        let state = StateDir::from(PathBuf::from("dir"));
        let (endpoint_key, peer_key) = ids();
        let (endpoint, peer) = (endpoint_key.to_string(), peer_key.to_string());
        let at_text = format!("{endpoint}@127.0.0.1:49731");
        let (at_option, peer_option) = (format!("--at={at_text}"), format!("--peer={peer}"));
        let other_at = format!("--at={endpoint}@[::1]:1");
        let at =
            Endpoint::new(endpoint_key).with_direct(SocketAddr::from((Ipv4Addr::LOCALHOST, 49731)));
        let named = Dial {
            aim: Aim::Peer(peer_key),
            at: At::Given(at),
        };
        let port = |text: &str| BindPort::Fixed(text.parse::<UdpPort>().unwrap());
        let content = CONTENT.parse::<ContentHash>().unwrap();
        let digest = ManifestDigest::from(CONTENT.parse::<ParsedDigest>().unwrap());
        let question = |text: &str, options: &[&str]| {
            Question::new(
                text.to_owned(),
                options.iter().map(|&option| option.to_owned()).collect(),
            )
            .unwrap()
        };
        let bind = |target: Target| Command::Bind {
            tree,
            path: path.clone(),
            target,
        };
        let lines = vec![
            (vec!["--state", "dir", "id"], Command::Id),
            (vec!["--state=dir", "serve"], Command::Serve {
                port: BindPort::Ephemeral,
                surface: Surface::Hold,
            }),
            (
                vec!["--state", "dir", "serve", "--port", "49731"],
                Command::Serve {
                    port: port("49731"),
                    surface: Surface::Hold,
                },
            ),
            (
                vec!["--state", "dir", "serve", "--port=1", "--port=65535"],
                Command::Serve {
                    port: port("65535"),
                    surface: Surface::Hold,
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "serve",
                    "--surface",
                    "echo",
                    "--port=49731",
                ],
                Command::Serve {
                    port: port("49731"),
                    surface: Surface::Program(PathBuf::from("echo")),
                },
            ),
            (
                vec!["--state", "dir", "dispatch", TREE, &peer, "anchor", PATH],
                Command::Dispatch {
                    tree,
                    seat: peer_key,
                    brief: Brief::Anchor(anchor.clone()),
                    at: At::Book,
                },
            ),
            (
                vec![
                    "--state", "dir", "dispatch", &at_option, TREE, &peer, "content", CONTENT,
                ],
                Command::Dispatch {
                    tree,
                    seat: peer_key,
                    brief: Brief::Content(content),
                    at: named.at.clone(),
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "report",
                    TREE,
                    "report.txt",
                    "-done: all green",
                ],
                Command::Report {
                    tree,
                    file: PathBuf::from("report.txt"),
                    summary: "-done: all green".parse().unwrap(),
                },
            ),
            (
                vec!["--state", "dir", "handoff", TREE, &peer],
                Command::Handoff { tree, to: peer_key },
            ),
            (vec!["--state", "dir", "retire", TREE], Command::Retire {
                tree,
            }),
            (vec!["--state", "dir", "replay", TREE], Command::Replay {
                tree,
                edition: domhringr_record_tree::Edition::Paused,
                replaying: Replaying::Dial {
                    toward: Toward::Seat,
                    at: At::Book,
                },
            }),
            (
                vec!["--state", "dir", "replay", &peer_option, TREE, &at_option],
                Command::Replay {
                    tree,
                    edition: domhringr_record_tree::Edition::Paused,
                    replaying: Replaying::Dial {
                        toward: Toward::Peer(peer_key),
                        at: named.at.clone(),
                    },
                },
            ),
            (
                vec!["--state", "dir", "replay", "--local", TREE],
                Command::Replay {
                    tree,
                    edition: domhringr_record_tree::Edition::Paused,
                    replaying: Replaying::Local,
                },
            ),
            (
                vec!["--state", "dir", "evidence", TREE, CONTENT],
                Command::Evidence {
                    tree,
                    digest,
                    reaching: Replaying::Dial {
                        toward: Toward::Seat,
                        at: At::Book,
                    },
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "evidence",
                    &peer_option,
                    TREE,
                    CONTENT,
                    &at_option,
                ],
                Command::Evidence {
                    tree,
                    digest,
                    reaching: Replaying::Dial {
                        toward: Toward::Peer(peer_key),
                        at: named.at.clone(),
                    },
                },
            ),
            (
                vec!["--state", "dir", "evidence", "--local", TREE, CONTENT],
                Command::Evidence {
                    tree,
                    digest,
                    reaching: Replaying::Local,
                },
            ),
            (vec!["--state", "dir", "open"], Command::Open),
            (
                vec!["--state", "dir", "grant", TREE, &peer],
                Command::Grant { tree, to: peer_key },
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
                bind(Target::Endpoint(endpoint_key)),
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
            (vec!["--state", "dir", "present", TREE], Command::Present {
                tree,
                port: BindPort::Ephemeral,
            }),
            (
                vec!["--state", "dir", "present", "--port", "49731", TREE],
                Command::Present {
                    tree,
                    port: port("49731"),
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "present",
                    TREE,
                    "--port=1",
                    "--port=65535",
                ],
                Command::Present {
                    tree,
                    port: port("65535"),
                },
            ),
            (
                vec!["--state", "dir", "withdraw", TREE],
                Command::Withdraw {
                    tree,
                    of: Withdrawn::Own,
                },
            ),
            (
                vec!["--state", "dir", "withdraw", TREE, &peer],
                Command::Withdraw {
                    tree,
                    of: Withdrawn::Of(peer_key),
                },
            ),
            (vec!["--state", "dir", "book", TREE], Command::Book { tree }),
            (
                vec!["--state", "dir", "whence", PATH],
                whence(anchor.clone()),
            ),
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
                    "--state", "dir", "whence", PATH, "--peer", &peer, "--at", &at_text,
                ],
                Command::Whence {
                    reference: Reference::from(anchor.clone()),
                    witnessing: Witnessing::Dns,
                    scope: Scope::Unscoped,
                    reach: Reach::Dial(named.clone()),
                },
            ),
            (
                vec!["--state", "dir", "whence", "--local", PATH],
                Command::Whence {
                    reference: Reference::from(anchor),
                    witnessing: Witnessing::Dns,
                    scope: Scope::Unscoped,
                    reach: Reach::Local,
                },
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
                    reach: Reach::Dial(book()),
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
                    reach: Reach::Dial(book()),
                },
            ),
            (vec!["--state", "dir", "view", TREE], Command::View { tree }),
            (
                vec!["--state", "elsewhere", "--state", "dir", "heads", TREE],
                Command::Heads { tree },
            ),
            (vec!["--state", "dir", "sync", TREE], Command::Sync {
                tree,
                dial: book(),
            }),
            (
                vec![
                    "--state", "dir", "sync", "--at", &at_text, TREE, "--peer", &peer,
                ],
                Command::Sync {
                    tree,
                    dial: named.clone(),
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "sync",
                    TREE,
                    &other_at,
                    &at_option,
                    &peer_option,
                ],
                Command::Sync { tree, dial: named },
            ),
            (
                vec![
                    "--state", "dir", "drift", "--public", "public", "--vault", "vault", TREE,
                ],
                Command::Drift {
                    public: PathBuf::from("public"),
                    vault: PathBuf::from("vault"),
                    tree,
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "drift",
                    TREE,
                    "--vault=vault",
                    "--public=elsewhere",
                    "--public=public",
                ],
                Command::Drift {
                    public: PathBuf::from("public"),
                    vault: PathBuf::from("vault"),
                    tree,
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "judge",
                    "ask",
                    "--question",
                    "Did it land?",
                    "--option",
                    "yes",
                    "--option",
                    "-no",
                    "--transcript",
                    CONTENT,
                ],
                Command::Ask {
                    question: question("Did it land?", &["yes", "-no"]),
                    transcript: Asked::Named(digest),
                    judging: Judging::Endpoint,
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "judge",
                    "ask",
                    "--transcript",
                    CONTENT,
                    "--static",
                    "elsewhere",
                    "--question=Did it land?",
                    "--transcript-file=transcript",
                    "--option=yes",
                    "--option=no",
                    "--static=table",
                ],
                Command::Ask {
                    question: question("Did it land?", &["yes", "no"]),
                    transcript: Asked::File(PathBuf::from("transcript")),
                    judging: Judging::Table(PathBuf::from("table")),
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "judge",
                    "verdict",
                    "--question=Did it land?",
                    "--option=yes",
                    "--option=no",
                    "--rubric",
                    COMMIT,
                    TREE,
                    "--rubric",
                    CONTENT,
                    "--transcript-file=transcript",
                    "--question",
                    "Which?",
                    "--option",
                    "a",
                    "--option",
                    "b",
                    "--option",
                    "c",
                ],
                Command::Verdict {
                    tree,
                    rubric: content,
                    transcript: Asked::File(PathBuf::from("transcript")),
                    questions: vec![
                        question("Did it land?", &["yes", "no"]),
                        question("Which?", &["a", "b", "c"]),
                    ],
                    judging: Judging::Endpoint,
                },
            ),
            (
                vec!["--state", "dir", "playbook", "validate", "playbook.toml"],
                Command::ValidatePlaybook {
                    file: PathBuf::from("playbook.toml"),
                },
            ),
            (
                vec![
                    "--state",
                    "dir",
                    "playbook",
                    "run",
                    "--static=table",
                    "playbook.toml",
                    "--task-state",
                    "first",
                    TREE,
                    "--task-state=task",
                ],
                Command::RunPlaybook {
                    file: PathBuf::from("playbook.toml"),
                    tree,
                    directory: PathBuf::from("task"),
                    judging: Judging::Table(PathBuf::from("table")),
                },
            ),
            (
                vec!["--state", "dir", "rubric", "validate", "rubric.toml"],
                Command::ValidateRubric {
                    file: PathBuf::from("rubric.toml"),
                },
            ),
            (
                vec!["--state", "dir", "rubric", "grade", "rubric.toml", TREE],
                Command::GradeRubric {
                    file: PathBuf::from("rubric.toml"),
                    tree,
                    directory: PathBuf::from("."),
                    judging: Judging::Endpoint,
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
                    reach: Reach::Dial(Dial {
                        aim: Aim::Owner,
                        at: At::Book,
                    }),
                } if read == tree && prefix.to_string() == "07070707"
            ),
            "whence reads a commit id abbreviated to eight digits as a prefix"
        );
    }

    #[test]
    fn a_malformed_command_line_is_refused()
    {
        let (endpoint, peer) = ids();
        let (endpoint, peer) = (endpoint.to_string(), peer.to_string());
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
            refused(line(&["--state", "dir", "sync", TREE, "--peer", "nothex"])),
            UsageError::Operand {
                operand: Operand::Peer,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", TREE, "--at", "nothex"])),
            UsageError::Operand {
                operand: Operand::At,
                source: ParseIdError::Endpoint(_),
            }
        ));
        let nowhere = format!("{endpoint}@nowhere");
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", TREE, "--at", &nowhere])),
            UsageError::Operand {
                operand: Operand::At,
                source: ParseIdError::Address(_),
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", PATH])),
            UsageError::NotTree
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", "--peer", &peer])),
            UsageError::Operands(Verb::Sync)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", TREE, "x"])),
            UsageError::Operands(Verb::Sync)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", TREE, "--at"])),
            UsageError::Arguments(_)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "sync", TREE, "-v"])),
            UsageError::Arguments(_)
        ));
        for (option, value) in [("--at", endpoint.as_str()), ("--peer", peer.as_str())] {
            assert!(
                matches!(
                    refused(line(&[
                        "--state", "dir", "whence", "--local", PATH, option, value
                    ])),
                    UsageError::Local
                ),
                "--local reaches no one, so it takes no {option}"
            );
        }
        assert!(matches!(
            refused(line(&["--state", "dir", "present"])),
            UsageError::Operands(Verb::Present)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "present", TREE, TREE])),
            UsageError::Operands(Verb::Present)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "present", TREE, "--port", "0"])),
            UsageError::Port(_)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "withdraw"])),
            UsageError::Operands(Verb::Withdraw)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "withdraw", TREE, &peer, "x"])),
            UsageError::Operands(Verb::Withdraw)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "withdraw", TREE, "nothex"])),
            UsageError::Operand {
                operand: Operand::Peer,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "book"])),
            UsageError::Operands(Verb::Book)
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
        let refused_drift = |words: &[&str]| {
            let mut command_line = line(&["--state", "dir", "drift"]);
            command_line.extend(line(words));
            refused(command_line)
        };
        assert!(
            matches!(
                refused_drift(&["--vault", "vault", TREE]),
                UsageError::NoCheckout(drift::Checkout::Public)
            ),
            "drift names the absent public checkout"
        );
        assert!(
            matches!(
                refused_drift(&["--public", "public", TREE]),
                UsageError::NoCheckout(drift::Checkout::Vault)
            ),
            "drift names the absent vault checkout"
        );
        assert!(
            matches!(refused_drift(&[]), UsageError::Operands(Verb::Drift)),
            "an arity error wins over the absent checkouts"
        );
        assert!(
            matches!(
                refused_drift(&["--public", "public", "--vault", "vault", TREE, TREE]),
                UsageError::Operands(Verb::Drift)
            ),
            "drift reads one tree"
        );
        assert!(
            matches!(
                refused_drift(&["--public", "public", "--vault", "vault", PATH]),
                UsageError::NotTree
            ),
            "drift's tree names no path"
        );
        assert!(
            matches!(
                refused_drift(&[
                    "--public",
                    "public",
                    "--vault",
                    "vault",
                    "domhringr://example.test/"
                ]),
                UsageError::NotKey
            ),
            "drift reads its tree by key"
        );
        assert!(
            matches!(
                refused_drift(&["--vault", "vault", TREE, "--public"]),
                UsageError::Arguments(_)
            ),
            "--public takes a value"
        );
        assert!(
            matches!(
                refused_drift(&["--public", "public", "--vault", "vault", TREE, "--dial"]),
                UsageError::Arguments(_)
            ),
            "drift has no other option"
        );
        assert!(
            matches!(
                refused(line(&["--state", "dir", "dispatch", TREE, &peer, "note", "text"])),
                UsageError::Brief(kind) if kind == "note"
            ),
            "a brief is an anchor or a content hash"
        );
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "dispatch", TREE, &peer, "content", "0e0e"
            ])),
            UsageError::Operand {
                operand: Operand::Content,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "dispatch", TREE, &peer, "anchor", "nothex"
            ])),
            UsageError::Anchor {
                operand: Operand::Brief,
                source: ParseAnchorError::Scheme,
            }
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "dispatch", TREE, "nothex", "content", CONTENT
            ])),
            UsageError::Operand {
                operand: Operand::Peer,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "dispatch", TREE, &peer, "content"
            ])),
            UsageError::Operands(Verb::Dispatch)
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "dispatch", TREE, &peer, "content", CONTENT, "extra"
            ])),
            UsageError::Operands(Verb::Dispatch)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "report", TREE, CONTENT, ""])),
            UsageError::Summary(ParseSummaryError::Empty)
        ));
        assert!(matches!(
            refused(line(&[
                "--state",
                "dir",
                "report",
                TREE,
                CONTENT,
                "two\nlines"
            ])),
            UsageError::Summary(ParseSummaryError::Control)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "report", TREE, COMMIT])),
            UsageError::Operands(Verb::Report)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "handoff", TREE])),
            UsageError::Operands(Verb::Handoff)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "retire", TREE, &peer])),
            UsageError::Operands(Verb::Retire)
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "replay", "--local", "--peer", &peer, TREE
            ])),
            UsageError::Local
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "replay", TREE, TREE])),
            UsageError::Operands(Verb::Replay)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "evidence", TREE])),
            UsageError::Operands(Verb::Evidence)
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "evidence", TREE, CONTENT, CONTENT
            ])),
            UsageError::Operands(Verb::Evidence)
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "evidence", TREE, "nothex"])),
            UsageError::Digest {
                operand: Operand::Evidence,
                ..
            }
        ));
        assert!(matches!(
            refused(line(&[
                "--state", "dir", "evidence", "--local", "--at", &endpoint, TREE, CONTENT
            ])),
            UsageError::Local
        ));
        assert!(matches!(
            refused(line(&["--state", "dir", "serve", "--surface"])),
            UsageError::Arguments(_)
        ));
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
        let mut invalid = line(&["--state", "dir", "report", TREE, CONTENT]);
        invalid.push(not_utf8());
        assert!(matches!(refused(invalid), UsageError::Text(_)));
        let mut invalid = line(&["--state", "dir", "judge", "ask", "--question"]);
        invalid.push(not_utf8());
        assert!(matches!(refused(invalid), UsageError::Text(_)));
        let mut invalid = line(&[
            "--state",
            "dir",
            "judge",
            "ask",
            "--question",
            "Did it land?",
            "--option",
        ]);
        invalid.push(not_utf8());
        assert!(matches!(refused(invalid), UsageError::Text(_)));
        let judged = |words: &[&str]| {
            let mut judged = line(&["--state", "dir", "judge"]);
            judged.extend(line(words));
            refused(judged)
        };
        let asked = [
            "--question",
            "Did it land?",
            "--option",
            "yes",
            "--option",
            "no",
        ];
        let ask = |words: &[&'static str]| {
            let mut ask = vec!["ask"];
            ask.extend(words);
            ask
        };
        let verdict = |words: &[&'static str]| {
            let mut verdict = vec!["verdict", TREE, "--rubric", CONTENT];
            verdict.extend(words);
            verdict
        };
        assert!(matches!(judged(&[]), UsageError::Operands(Verb::Judge)));
        assert!(matches!(judged(&["tally"]), UsageError::Command(word) if word == "tally"));
        assert!(matches!(
            judged(&["--rubric", CONTENT, "ask"]),
            UsageError::Arguments(_)
        ));
        assert!(
            matches!(
                judged(&ask(&["--rubric", CONTENT, "--transcript", CONTENT])),
                UsageError::Arguments(_)
            ),
            "`ask` belongs to no rubric"
        );
        assert!(matches!(
            judged(&ask(&[
                "--option",
                "yes",
                "--question",
                "Did it land?",
                "--option",
                "no",
                "--transcript",
                CONTENT
            ])),
            UsageError::Unasked
        ));
        assert!(matches!(
            judged(&ask(&["--transcript", CONTENT])),
            UsageError::NoQuestion
        ));
        assert!(matches!(
            judged(&verdict(&["--transcript", CONTENT])),
            UsageError::NoQuestion
        ));
        let mut twice = ask(&asked);
        twice.extend(asked);
        twice.extend(["--transcript", CONTENT]);
        assert!(
            matches!(judged(&twice), UsageError::Operands(Verb::Ask)),
            "`ask` asks one question"
        );
        let mut operand = ask(&asked);
        operand.extend(["--transcript", CONTENT, TREE]);
        assert!(matches!(judged(&operand), UsageError::Operands(Verb::Ask)));
        assert!(matches!(judged(&ask(&asked)), UsageError::NoTranscript));
        assert!(matches!(judged(&verdict(&asked)), UsageError::NoTranscript));
        let mut unruled = vec!["verdict", TREE, "--transcript", CONTENT];
        unruled.extend(asked);
        assert!(matches!(judged(&unruled), UsageError::NoRubric));
        let mut treeless = vec!["verdict", "--rubric", CONTENT, "--transcript", CONTENT];
        treeless.extend(asked);
        assert!(matches!(
            judged(&treeless),
            UsageError::Operands(Verb::Verdict)
        ));
        let mut pathed = vec![
            "verdict",
            PATH,
            "--rubric",
            CONTENT,
            "--transcript",
            CONTENT,
        ];
        pathed.extend(asked);
        assert!(matches!(judged(&pathed), UsageError::NotTree));
        let mut short = ask(&asked);
        short.extend(["--transcript", "0e0e0e0e"]);
        assert!(matches!(judged(&short), UsageError::Digest {
            operand: Operand::Transcript,
            ..
        }));
        let mut short = vec!["verdict", TREE, "--rubric", "0e0e0e0e"];
        short.extend(asked);
        assert!(matches!(judged(&short), UsageError::Operand {
            operand: Operand::Rubric,
            ..
        }));
        assert!(matches!(
            judged(&verdict(&[
                "--transcript",
                CONTENT,
                "--question",
                "Did it land?",
                "--option",
                "yes"
            ])),
            UsageError::Question(QuestionError::Few)
        ));
        assert!(matches!(
            judged(&ask(&[
                "--transcript",
                CONTENT,
                "--question",
                "",
                "--option",
                "yes",
                "--option",
                "no"
            ])),
            UsageError::Question(QuestionError::Blank)
        ));
        let strategy = |words: &[&str]| {
            let mut strategy = line(&["--state", "dir"]);
            strategy.extend(line(words));
            refused(strategy)
        };
        assert!(matches!(
            strategy(&["playbook"]),
            UsageError::Operands(Verb::Playbook)
        ));
        assert!(matches!(
            strategy(&["rubric"]),
            UsageError::Operands(Verb::Rubric)
        ));
        assert!(
            matches!(strategy(&["playbook", "grade", "p.toml", TREE]), UsageError::Command(word) if word == "grade"),
            "a playbook runs; a rubric grades"
        );
        assert!(matches!(
            strategy(&["rubric", "--static", "table", "grade"]),
            UsageError::Arguments(_)
        ));
        assert!(
            matches!(
                strategy(&["rubric", "validate", "--static", "table", "r.toml"]),
                UsageError::Arguments(_)
            ),
            "validating asks nothing"
        );
        assert!(matches!(
            strategy(&["playbook", "run", "p.toml", "--task-state"]),
            UsageError::Arguments(_)
        ));
        assert!(matches!(
            strategy(&["playbook", "run", "p.toml"]),
            UsageError::Operands(Verb::RunPlaybook)
        ));
        assert!(matches!(
            strategy(&["rubric", "validate", "r.toml", "s.toml"]),
            UsageError::Operands(Verb::ValidateRubric)
        ));
        assert!(
            matches!(
                strategy(&["rubric", "grade", "r.toml", "not-an-anchor", "extra"]),
                UsageError::Operands(Verb::GradeRubric)
            ),
            "the arity is checked before the tree is read"
        );
        assert!(matches!(
            strategy(&["rubric", "grade", "r.toml", PATH]),
            UsageError::NotTree
        ));
    }
}
