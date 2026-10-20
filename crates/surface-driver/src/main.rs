//! `domhringr`: the operator's binary. It reads the project a task belongs
//! to, lists the project's seats and tasks, dispatches a seat to a task,
//! verifies and decides the change the seat reports, and lands it.
//!
//! ```text
//! domhringr open [--project <tree>]
//! domhringr dispatch <task> --seat <peer-id> --brief <anchor|content-hash>
//!                    [--at <endpoint>] [--project <tree>]
//! domhringr verify <task> --playbook <file> [--repo <dir>] [--project <tree>]
//! domhringr decide <task> --rubric <file>... [--repo <dir>] [--static <file>]
//!                  [--project <tree>]
//! domhringr land <task> --repo <dir> [--project <tree>]
//! ```
//!
//! A project is a tree the operator holds, named by its bare anchor in the
//! key form, `domhringr://<tree-id>/`, by `--project` or else by the
//! `DOMHRINGR_PROJECT` variable. The project's book says where its seats are
//! reached; each task is a tree of its own, bound in the project at
//! `tasks/<name>`. A `<task>` is that name — ASCII letters, digits, `-`, `_`
//! and `.`, not beginning with `.` — or the anchor of its path,
//! `domhringr://<project-id>/tasks/<name>`. The operator's keys and store live
//! in the state directory `DOMHRINGR_STATE` names, or else in `domhringr`
//! beneath `XDG_STATE_HOME`, or else beneath `$HOME/.local/state`. Its
//! endpoint reaches n0's relay and DNS unless `DOMHRINGR_RELAY` is `off`:
//! then it is reached at its direct addresses and through mDNS alone.
//!
//! `open` prints `project <anchor>`, then `seat <peer-id> <endpoint>
//! <commit-id>` for each peer present in the project's book but this one,
//! and `task <anchor> <standing>` for each task, where it stands as the
//! peer's `replay` prints it on its last line, or `unheld` for a task tree
//! this store does not hold. Before it reads a task whose seat holds the
//! slot without a report, it syncs the task from that seat; a sync that
//! fails is reported on standard error and the listing goes on.
//!
//! `dispatch` puts the seat its peer id names in the task's slot to work
//! from a brief — an anchor, or the BLAKE3 hash of its content as 64 hex
//! digits — and wakes it. A name bound to no task yet mints the task: a tree
//! of its own, opened by this peer and bound in the project. The seat is
//! reached at `--at`, or else at its presence in the task's book, or else in
//! the project's. A task whose current attempt already puts that seat to
//! that brief has its dispatch re-sent rather than a second committed. It
//! prints `dispatch <commit-anchor>` at once and `woken` once the seat holds
//! the slot.
//!
//! A seat reports its change as the summary `<branch> <commit>[ <text>]`:
//! the branch it pushed to the repository and the commit at its tip, 40 or
//! 64 hex digits. `verify`, `decide` and `land` act on the current attempt's
//! report, synced from the seat first when the attempt awaits it, in the git
//! repository `--repo` names, the working directory by default, which must
//! hold the reported commit. The report's content is evidence kept in the
//! operator's state beside its store: one the store lacks is fetched from the
//! seat that reported it, every chunk checked before it is kept, and each
//! command reads it whole before it acts. Each prints `change <branch>
//! <commit>` and `report <digest>` first.
//!
//! `verify` checks the commit out into a temporary worktree, runs each
//! verifier step of the playbook there in turn, keeps its output as
//! evidence, commits a verification naming this peer the runner, prints
//! `playbook <hash> <name>` and `verified <commit-id> <step> <output-digest>
//! <status>`, and removes the worktree. A playbook's question steps are left
//! to `decide`. A failing verifier is recorded, and the command still
//! succeeds.
//!
//! `decide` writes the change into a temporary state directory —
//! `change.diff`, the diff from the repository's `HEAD` to the commit, and
//! `commits.txt`, each commit's id and message oldest first — and grades
//! each `--rubric` over it as the peer's `rubric grade` does, keeping each
//! transcript as evidence and naming this peer the judge: `rubric`,
//! `transcript`, `ruling`, `verdict`, `grade` and `graded` lines. It answers
//! from the endpoint the environment configures,
//! as the peer's judge does, or from the `--static` table. It then composes
//! the rubrics' grades with the latest verification of each step on the
//! dispatch, met when it exited 0 and unmet otherwise, prints `step <id>
//! <status>` for each and `composed <grade>`, and decides: met lands the
//! change, unmet reworks it for the first failure, `step <id> <status>` or
//! `question <rubric>/<question> unmet`. It commits the decision naming this
//! peer the operator and prints `decide <commit-id> <decision>`. Undecided
//! or refused decides nothing, and the exit status is 3.
//!
//! `land` carries out a decision to land made by this peer: it merges the
//! reported commit into the branch the repository's `HEAD` names, by fast
//! forward when it can and by a merge commit `Merge branch '<branch>'`
//! otherwise, commits the landing naming the revision the branch then stands
//! at, and prints `landed <commit-id> <revision>`. A repository with
//! uncommitted changes to tracked files, a detached `HEAD` or a merge git
//! refuses is left as it was, and nothing is committed.
//!
//! The exit status is 0 on success, 1 when the command fails, 2 for a
//! command line that cannot be run, and 3 when `decide` decides nothing;
//! diagnostics go to standard error.
//!
//! # Commands
//!
//! | Command | Prints | Commits |
//! | ------- | ------ | ------- |
//! | `open` | `project <anchor>`; `seat <peer-id> <endpoint> <commit-id>` per presence but the operator's; `refused <commit-anchor> <reason>` per refusal and `task <anchor> <standing>` per task, or `unheld` for a task tree the store lacks | nothing |
//! | `dispatch` | `dispatch <commit-anchor>`, then `woken` | `Open` and `Bind` for a new task, then `Dispatch` |
//! | `verify` | `change <branch> <commit>`, `report <digest>`, `playbook <hash> <name>`, `verified <commit-id> <step> <output-digest> <status>` per verifier | `Verified` per verifier |
//! | `decide` | `change`; `report`; `step <id> <status>` per verified step; per rubric `rubric`, `transcript`, `ruling`, `verdict`, `grade` and `graded` lines; `composed <grade>`; `decide <commit-id> <decision>` | `Verdict` and `Graded` per rubric, then `Decide` unless undecided |
//! | `land` | `change <branch> <commit>`, `report <digest>`, `landed <commit-id> <revision>` | `Landed` |
//!
//! After committing, `dispatch`, `verify`, `decide` and `land` close their
//! endpoint, derive the store's project index and commit one `Indexed` when its
//! manifest differs from the operator's latest claim. Multiple receipts in one
//! command still yield one attestation. A re-sent dispatch commits no
//! attestation, even if waking the seat syncs a report. `open` updates only the
//! local cache and commits nothing.
//!
//! Dispatches name the newest edition compiled into the driver: edition 2 by
//! default, edition 1 with `--no-default-features`. Reading a task always uses
//! its dispatch's edition. `open` surfaces unknown-edition and protocol-order
//! refusals by commit anchor;
//! `operator::tests::open_names_unknown_protocol_refusals` witnesses the
//! unknown-edition case.
//!
//! # Decisions
//!
//! **A task is a tree of its own, bound in the project.** `dispatch` mints a
//! tree for a new task, opens it as this peer, and binds `tasks/<name>` in the
//! project to its anchor; `open` reads the project's derived entries for each
//! task's standing and refusals. The local cache retains refreshes between
//! commands, keyed by task heads; an unchanged standing alone is not enough,
//! because a newly refused receipt changes the frontier. A task is the tree its
//! seat receipts live in, and the project is the one place that names them.
//!
//! - one tree for the project and every task: one slot per tree, so one task at
//!   a time.
//! - tasks named by their tree anchors alone, kept by the operator: a second
//!   operator syncing the project would not find them.
//!
//! Reversal: tasks that move between projects, which needs a binding per
//! project and a task tree that names none.
//!
//! **A seat is reached through the task's book, then the project's.** The first
//! dispatch to a new task finds no presence in it, so the seat is reached at
//! its presence in the project; once woken, the seat presents itself in the
//! task, and later syncs reach it there.
//!
//! - the project's book alone: a seat that moved would be reached where it was
//!   when it joined the project.
//! - `--at` on every command: the endpoint the record already holds, typed
//!   again.
//!
//! Reversal: seats with no presence in any project, reached through a discovery
//! service, which needs a route that reads it.
//!
//! **`verify`, `decide` and `land` read the report from the evidence store
//! before they act.** The receipt names the report's content by digest; a store
//! that lacks it fetches it from the seat that reported, reached as a sync
//! reaches it, every chunk checked and the value kept before the command goes
//! on, and each command then reads it whole and prints its digest. An operator
//! on another machine than the seat's acts on what the seat produced, held in
//! its own store, and a report no reader can open stops the command before
//! anything is checked or committed.
//!
//! - acting on the summary alone: the change named by a report the operator
//!   never holds, and a verdict or a landing on bytes nobody here can read
//!   again.
//! - fetching only when a check reads the content: `land` and a step-only
//!   `verify` would act on a report never read.
//!
//! Reversal: reports too large to fetch on every command, when the summary is
//! read alone and the content fetched by the check that reads it.
//!
//! **git is run as a program.** Checkouts, diffs, logs and merges go through
//! the `git` on `PATH`, with the variables that name another repository
//! cleared, as `domhringr-peer`'s drift check does. The repository's own
//! configuration applies — hooks, signing, merge drivers — as it does to the
//! operator by hand.
//!
//! - `gix`: its documented status leaves merge orchestration, checkout and
//!   worktree removal unimplemented, and it signs no commits; the landing needs
//!   all four.
//! - `git2`: it builds libgit2 from C, and it neither runs hooks nor signs
//!   merges as the repository configures.
//!
//! Reversal: `gix` gaining merge, checkout and signing, or a target without a
//! `git` binary.
//!
//! **`verify` runs in a temporary worktree of the reported commit.** `git
//! worktree add --detach` checks the commit out beside the repository, the
//! verifiers run there, and the worktree is removed whatever they did; the
//! repository's own working tree is never touched.
//!
//! - the repository's working tree, switched to the commit: the operator's
//!   checkout would move under them, and a failure would leave it there.
//! - a fresh clone: every object copied for a check that reads one commit.
//!
//! Reversal: verifiers that need state the checkout lacks, such as untracked
//! files, which needs a setup step in the playbook.
//!
//! **`decide` writes the change as the rubric set's state.** `change.diff` is
//! `git diff HEAD...<commit>`, the change from where it branched, and
//! `commits.txt` each commit `HEAD` lacks, oldest first, with its message: the
//! two files the set's `code`, `stable-refs` and `public-private-stance`
//! rubrics read. A rubric reading anything else is refused naming the file.
//!
//! - the checkout as the state: the rubrics would read the whole tree, not the
//!   change.
//! - every artifact the set reads, the issue and the review among them: the
//!   record does not hold them yet.
//!
//! Reversal: tasks whose record holds their issue and review, when `decide`
//! writes those too.
//!
//! **`decide` composes the rubrics with the verifications.** It composes the
//! rubrics' composed grade with the latest verification of each step on the
//! dispatch — met when it exited 0, unmet otherwise — because a change whose
//! gates fail would otherwise land on a reading of its diff. Unmet reworks with
//! the first failure, a step before a question.
//!
//! - the rubrics alone: a failing verifier is recorded and ignored.
//! - every verification on the dispatch: a step fixed by a second run would
//!   still count as failing.
//!
//! Reversal: verifications that are advisory, which needs a playbook field
//! saying so.
//!
//! **Undecided and refused decide nothing.** A grade between the band's bounds,
//! or a question the judge did not read, is no ground to land or to rework:
//! `decide` commits its gradings, prints `composed undecided` or `composed
//! refused`, and exits 3, so the operator can ask again or decide by hand.
//!
//! - reworking on undecided: a seat would be sent back over an answer nobody
//!   gave.
//!
//! Reversal: a policy that resolves undecided grades, which needs it named in
//! the rubric.
//!
//! **`land` merges into the branch `HEAD` names, and commits only once the
//! merge stands.** It refuses a detached `HEAD`, uncommitted changes to tracked
//! files and a commit the repository lacks before running git; then `git merge
//! --ff` fast-forwards, or makes `Merge branch '<branch>'`; a merge that stops
//! is aborted. `Landed` names the revision `HEAD` then stands at, and only the
//! operator that decided can land: the fold admits the landing from that key
//! alone. A rerun after the merge but before the receipt finds the commit
//! already merged and records where the branch stands.
//!
//! - `--ff-only`: every change whose base moved would be refused.
//! - rebase or squash: the landed commit would not be the one verified and
//!   graded.
//! - pushing to a remote: where the repository lives is the operator's
//!   configuration, never the record's.
//!
//! Reversal: a review host that merges, when `land` records the host's merge
//! instead of making one.
//!
//! **Stalled is a retirement, not a clock.** The design sketched stalled as a
//! dispatch without a report past a horizon the surface names. The fold reads
//! receipts only, and a horizon would make a task's standing depend on when it
//! is read; a seat that gives up retires, and the attempt stands stalled from
//! that receipt. An operator who judges a quiet seat stalled dispatches again.
//!
//! - a horizon in `open`: two operators listing the same journal would
//!   disagree.
//!
//! Reversal: a receipt that records the operator's judgement that a seat is
//! quiet.
//!
//! # Not yet
//!
//! - Component installation: fetching, verifying and installing the toolchain's
//!   components from signed release artifacts by `(component, version,
//!   target)`, the driver's other job.
//! - Publication: the package depends on the workspace's crates by path, and is
//!   published once they are.
//!
//! # References
//!
//! - `domhringr-record-tree`: the store, the task view and its lifecycle, the
//!   `Decide` and `Landed` receipts.
//! - `domhringr-record-evidence`: the evidence store a report is read from and
//!   outputs and transcripts are kept in, and the fetch from a seat.
//! - `domhringr-record-index`: cached standings and refusals, provenance and
//!   attested project manifests.
//! - `domhringr-seat-slot`: the wake and the seat that reports.
//! - `domhringr-strategy-document`: playbooks, rubrics, verifiers, grades and
//!   their composition.
//! - `domhringr-judge-oracle`: the judge's backends and their configuration.
//! - The rubric set (`rubrics/`): the rubrics `decide` grades a change of this
//!   repository by.
//! - `git`, [`git-worktree`](https://git-scm.com/docs/git-worktree), [`git-diff`](https://git-scm.com/docs/git-diff)
//!   and [`git-merge`](https://git-scm.com/docs/git-merge) documentation: the
//!   checkout, the state and the landing.
//! - `lexopt`, [crate documentation](https://docs.rs/lexopt): command-line
//!   options and operands.
//! - `tempfile`, [crate documentation](https://docs.rs/tempfile): the
//!   checkout's and the state's temporary directories.

// Module documentation that predates the shape lint: 5 headings outside the
// vocabulary, 10 decision records and 2 budgets exceeded. Each allow leaves
// with the rewrite that clears its count.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    allow(
        module_doc_heading,
        doc_decision_record,
        module_doc_budget,
        reason = "module documentation that predates the shape lint"
    )
)]
// The opt-in quenchant lints: absence named by `Maybe` in signatures and in
// fields outside wire form, arithmetic on nominal types. Selected here because
// Dylint's `-D` cannot reach rustc through `cargo dylint`; see
// `.config/mise/tasks/mise-tasks-check.toml`.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "iroh and subduction straddle the RustCrypto and ed25519-dalek major \
              transitions; the duplicates are theirs and no version this workspace \
              chooses unifies them"
)]
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    expect(linear_search_in_loop, reason = "1 cost-shape site; #35 lists it")
)]

extern crate alloc;

mod change;
mod check;
mod project;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use anodized::spec;
use domhringr_judge_oracle::ConfigError;
use domhringr_judge_oracle::EndpointError;
use domhringr_judge_oracle::ParseTableError;
use domhringr_record_evidence::Evidence;
use domhringr_record_evidence::EvidenceError;
use domhringr_record_evidence::FetchError;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::At;
use domhringr_record_tree::Authority;
use domhringr_record_tree::BindError;
use domhringr_record_tree::Brief;
use domhringr_record_tree::CommitError;
use domhringr_record_tree::ContentHash;
use domhringr_record_tree::Decision;
use domhringr_record_tree::Identity;
use domhringr_record_tree::IdentityError;
use domhringr_record_tree::OpenError;
use domhringr_record_tree::ParseAnchorError;
use domhringr_record_tree::ParseIdError;
use domhringr_record_tree::ParseRevisionError;
use domhringr_record_tree::ParseSummaryError;
use domhringr_record_tree::Path;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::RandomError;
use domhringr_record_tree::Relay;
use domhringr_record_tree::Revision;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::ViewError;
use domhringr_seat_slot::WakeError;
use domhringr_strategy_document::LoadError;
use domhringr_strategy_document::TranscriptError;
use domhringr_strategy_document::VerifyError;

use crate::change::GitAction;
use crate::change::ParseChangeError;
use crate::project::ParseTaskError;
use crate::project::TaskName;
use crate::project::Unreached;

/// The synopsis written after a usage error.
const USAGE: &str = "\
usage: domhringr open [--project <tree>]
       domhringr dispatch <task> --seat <peer-id> --brief <anchor|content-hash>
                          [--at <endpoint>] [--project <tree>]
       domhringr verify <task> --playbook <file> [--repo <dir>] [--project <tree>]
       domhringr decide <task> --rubric <file>... [--repo <dir>] [--static <file>]
                        [--project <tree>]
       domhringr land <task> --repo <dir> [--project <tree>]
";

/// The exit status of a command line that cannot be run.
const USAGE_STATUS: u8 = 2;

/// The exit status of a `decide` that decided nothing.
const UNDECIDED_STATUS: u8 = 3;

/// The variable naming the state directory.
const STATE: &str = "DOMHRINGR_STATE";

/// The variable naming the project, when `--project` does not.
const PROJECT: &str = "DOMHRINGR_PROJECT";

/// The variable that, set to `off`, keeps the endpoint off n0's relay and DNS.
const RELAY: &str = "DOMHRINGR_RELAY";

/// A command, its operands and its options, read from the command line.
#[derive(Debug, PartialEq, Eq)]
struct Invocation
{
    /// Where the project is named.
    project: Project,
    /// The command.
    command: Command,
}

/// Where the project a command acts in is named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Project
{
    /// `--project`: this tree.
    Named(TreeId),
    /// The `DOMHRINGR_PROJECT` variable.
    Environment,
}

/// The operator's commands.
#[derive(Debug, PartialEq, Eq)]
enum Command
{
    /// List the project's seats and tasks.
    Open,
    /// Dispatch `seat` to `brief` on `task` and wake it, reached as `at`
    /// says.
    Dispatch
    {
        /// The task.
        task: TaskName,
        /// The seat dispatched.
        seat: PeerKey,
        /// What the seat works from.
        brief: Brief,
        /// Where the seat is reached.
        at: At,
    },
    /// Run `playbook`'s verifiers on the reported change in `repository`.
    Verify
    {
        /// The task.
        task: TaskName,
        /// The playbook's file.
        playbook: PathBuf,
        /// The repository holding the change.
        repository: PathBuf,
    },
    /// Grade the reported change in `repository` by `rubrics`, answered as
    /// `judging` says, and decide on it.
    Decide
    {
        /// The task.
        task: TaskName,
        /// The rubrics' files, in the order given.
        rubrics: Vec<PathBuf>,
        /// The repository holding the change.
        repository: PathBuf,
        /// What answers the rubrics' questions.
        judging: Judging,
    },
    /// Merge the change the task's decision lands into `repository`.
    Land
    {
        /// The task.
        task: TaskName,
        /// The repository to land in.
        repository: PathBuf,
    },
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

/// The verbs, each standing for its synopsis in a usage error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verb
{
    /// `open`.
    Open,
    /// `dispatch`.
    Dispatch,
    /// `verify`.
    Verify,
    /// `decide`.
    Decide,
    /// `land`.
    Land,
}

impl Verb
{
    /// The options the verb takes.
    ///
    /// # Specification
    /// - ensures: every verb takes `--project`; `dispatch` takes `--seat`,
    ///   `--brief` and `--at`; `verify` takes `--playbook` and `--repo`;
    ///   `decide` takes `--rubric`, `--repo` and `--static`; `land` takes
    ///   `--repo`.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the parser
    ///   witnesses exercise the finite option table.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — each verb accepts its documented options.
    /// - witness: `tests::every_verb_reads_its_options`
    const fn flags(self) -> &'static [Flag]
    {
        match self {
            Self::Open => &[Flag::Project],
            Self::Dispatch => &[Flag::Project, Flag::Seat, Flag::Brief, Flag::At],
            Self::Verify => &[Flag::Project, Flag::Playbook, Flag::Repo],
            Self::Decide => &[Flag::Project, Flag::Rubric, Flag::Repo, Flag::Static],
            Self::Land => &[Flag::Project, Flag::Repo],
        }
    }
}

impl fmt::Display for Verb
{
    /// Write the verb's synopsis.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            Self::Open => "domhringr open [--project <tree>]",
            Self::Dispatch => {
                "domhringr dispatch <task> --seat <peer-id> --brief <anchor|content-hash> [--at \
                 <endpoint>] [--project <tree>]"
            },
            Self::Verify => {
                "domhringr verify <task> --playbook <file> [--repo <dir>] [--project <tree>]"
            },
            Self::Decide => {
                "domhringr decide <task> --rubric <file>... [--repo <dir>] [--static <file>] \
                 [--project <tree>]"
            },
            Self::Land => "domhringr land <task> --repo <dir> [--project <tree>]",
        })
    }
}

/// The options a verb may take, each with a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flag
{
    /// `--project <tree>`.
    Project,
    /// `--seat <peer-id>`.
    Seat,
    /// `--brief <anchor|content-hash>`.
    Brief,
    /// `--at <endpoint>`.
    At,
    /// `--playbook <file>`.
    Playbook,
    /// `--repo <dir>`.
    Repo,
    /// `--rubric <file>`.
    Rubric,
    /// `--static <file>`.
    Static,
}

impl fmt::Display for Flag
{
    /// Write the option as it is spelled with its value.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            Self::Project => "--project <tree>",
            Self::Seat => "--seat <peer-id>",
            Self::Brief => "--brief <anchor|content-hash>",
            Self::At => "--at <endpoint>",
            Self::Playbook => "--playbook <file>",
            Self::Repo => "--repo <dir>",
            Self::Rubric => "--rubric <file>",
            Self::Static => "--static <file>",
        })
    }
}

/// The option values a command line gave, each in the order given.
#[derive(Debug, Default)]
struct Given
{
    /// The `--project` values.
    project: Vec<OsString>,
    /// The `--seat` values.
    seat: Vec<OsString>,
    /// The `--brief` values.
    brief: Vec<OsString>,
    /// The `--at` values.
    at: Vec<OsString>,
    /// The `--playbook` values.
    playbook: Vec<OsString>,
    /// The `--repo` values.
    repo: Vec<OsString>,
    /// The `--rubric` values.
    rubric: Vec<OsString>,
    /// The `--static` values.
    table: Vec<OsString>,
    /// The operands.
    operands: Vec<OsString>,
}

impl Given
{
    /// The values given for `flag`.
    ///
    /// # Specification
    /// trivial.
    const fn values(
        &mut self,
        flag: Flag,
    ) -> &mut Vec<OsString>
    {
        match flag {
            Flag::Project => &mut self.project,
            Flag::Seat => &mut self.seat,
            Flag::Brief => &mut self.brief,
            Flag::At => &mut self.at,
            Flag::Playbook => &mut self.playbook,
            Flag::Repo => &mut self.repo,
            Flag::Rubric => &mut self.rubric,
            Flag::Static => &mut self.table,
        }
    }
}

/// Why a command line cannot be run.
#[derive(Debug, thiserror::Error)]
enum UsageError
{
    /// An option the verb does not take, or an option without its value.
    #[error(transparent)]
    Arguments(#[from] lexopt::Error),
    /// No verb is given.
    #[error("no command given")]
    NoCommand,
    /// The verb is not one this binary has.
    #[error("unknown command {0:?}")]
    Command(OsString),
    /// An option the verb requires is absent.
    #[error("{flag} is required: {verb}")]
    Missing
    {
        /// The verb.
        verb: Verb,
        /// The option.
        flag: Flag,
    },
    /// The verb has too few or too many operands.
    #[error("expected: {0}")]
    Operands(Verb),
    /// The task operand is no task's name.
    #[error("cannot read the task")]
    Task(#[source] ParseTaskError),
    /// `--project` names no tree by its key.
    #[error("cannot read the project")]
    Project(#[source] ParseProjectError),
    /// `--seat` is no peer id.
    #[error("cannot read the seat's peer id")]
    Seat(#[source] ParseIdError),
    /// `--at` is no endpoint.
    #[error("cannot read the endpoint")]
    At(#[source] ParseIdError),
    /// `--brief` is neither an anchor nor a content hash.
    #[error("cannot read the brief as an anchor or a content hash")]
    Brief(#[source] ParseAnchorError),
}

/// Why a text names no project.
#[derive(Debug, thiserror::Error)]
enum ParseProjectError
{
    /// The text is no anchor.
    #[error(transparent)]
    Anchor(#[from] ParseAnchorError),
    /// The anchor names a path or a commit, or its tree by other than its key.
    #[error("a project is a bare anchor in the key form: domhringr://<tree-id>/")]
    NotTree,
}

/// Why a command failed once its command line was read.
#[derive(Debug, thiserror::Error)]
enum RunError
{
    /// The async runtime cannot start.
    #[error("cannot start the async runtime")]
    Runtime(#[source] std::io::Error),
    /// No variable names a state directory.
    #[error("no state directory: set {STATE}, XDG_STATE_HOME or HOME")]
    NoState,
    /// Neither `--project` nor the environment names a project.
    #[error("no project: --project <tree> or {PROJECT}")]
    NoProject,
    /// `DOMHRINGR_PROJECT` names no project.
    #[error("cannot read {PROJECT}")]
    Project(#[source] ParseProjectError),
    /// `DOMHRINGR_RELAY` is neither `n0` nor `off`.
    #[error("{RELAY} must be n0 or off, not {0:?}")]
    Relay(std::ffi::OsString),
    /// The identity cannot be read or created.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The tree store cannot be opened.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// The endpoint cannot bind.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// No operation fence can be drawn for a receipt.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// A commit cannot be appended.
    #[error(transparent)]
    Commit(#[from] CommitError),
    /// A tree cannot be folded.
    #[error(transparent)]
    View(#[from] ViewError),
    /// A frontier could not be read.
    #[error(transparent)]
    Heads(#[from] domhringr_record_tree::HeadsError),
    /// The operator's index could not be refreshed.
    #[error(transparent)]
    Index(#[from] domhringr_record_index::derive::DeriveError),
    /// The refreshed index's manifest could not be named.
    #[error(transparent)]
    Manifest(#[from] domhringr_record_index::WireError),
    /// The seat cannot be reached, or the task synced from it.
    #[error(transparent)]
    Reach(#[from] Unreached),
    /// The seat was not woken.
    #[error(transparent)]
    Wake(#[from] WakeError),
    /// The task's anchor names another project.
    #[error("the task is in the project {0}, not this one")]
    OtherProject(TreeId),
    /// The project binds no task by the name.
    #[error("no task {0} in the project")]
    Unbound(Path),
    /// The project binds the task's path to something other than a tree.
    #[error("{0} is bound to no tree by its key")]
    NotTask(Path),
    /// A task cannot be synced from its seat while listing the project.
    #[error("cannot sync the task {task}")]
    Unsynced
    {
        /// The task's anchor in its project.
        task: String,
        /// Why.
        #[source]
        cause: Box<Unreached>,
    },
    /// The task has no dispatch.
    #[error("the task has no dispatch")]
    Undispatched,
    /// The current dispatch has no report.
    #[error("the current dispatch has no report: no change to act on")]
    Unreported,
    /// The report's summary names no change.
    #[error("the report names no change")]
    Change(#[source] ParseChangeError),
    /// git cannot be run.
    #[error("cannot run git to {action}")]
    Git
    {
        /// What git was run to do.
        action: GitAction,
        /// Why it cannot run.
        source: std::io::Error,
    },
    /// git refused.
    #[error("git refused to {action}: {message}")]
    Refused
    {
        /// What git was run to do.
        action: GitAction,
        /// What git wrote to standard error, trimmed.
        message: String,
    },
    /// git named a revision that does not read.
    #[error("git named a revision that does not read")]
    Revision(#[source] ParseRevisionError),
    /// The repository's `HEAD` names no branch.
    #[error("the repository's HEAD names no branch")]
    Detached,
    /// The repository has uncommitted changes to tracked files.
    #[error("the repository has uncommitted changes")]
    Dirty,
    /// The repository holds no such commit.
    #[error("the repository holds no commit {0}")]
    Missing(Revision),
    /// The attempt's change has landed.
    #[error("the change already landed at {0}")]
    Landed(Revision),
    /// The attempt has no decision.
    #[error("the attempt has no decision to land")]
    NoDecision,
    /// The attempt's decision is not to land.
    #[error("the decision is {0}, not land")]
    NotLand(Decision),
    /// Another operator decided the attempt.
    #[error("the decision is {0}'s to land")]
    OtherOperator(PeerKey),
    /// A playbook or a rubric does not load.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// A verifier does not run to its end.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// A verifier's thread failed.
    #[error("the verifier's thread failed")]
    Join(#[source] tokio::task::JoinError),
    /// A rubric's state file cannot be read into its transcript, or the
    /// transcript cannot be staged as evidence.
    #[error(transparent)]
    State(#[from] TranscriptError),
    /// A report, an output or a transcript cannot be read from or kept in the
    /// evidence store.
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    /// A report's content cannot be fetched from the seat that reported it.
    #[error(transparent)]
    Fetch(#[from] FetchError),
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
    /// A rework's reason is no summary.
    #[error("the rework's reason is no summary")]
    Reason(#[source] ParseSummaryError),
    /// A temporary directory cannot be made.
    #[error("cannot make a temporary directory")]
    Temporary(#[source] std::io::Error),
    /// The change cannot be written into the task's state directory.
    #[error("cannot write the change into the state directory")]
    Write(#[source] std::io::Error),
    /// Standard output cannot be written.
    #[error("cannot write to standard output")]
    Output(#[source] std::io::Error),
    /// Standard error cannot be written.
    #[error("cannot write to standard error")]
    Diagnostics(#[source] std::io::Error),
}

/// How a command that ran ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion
{
    /// The command did what it says.
    Success,
    /// `decide` decided nothing: the grades composed undecided or refused.
    Undecided,
}

/// Read the command line that follows the program name.
///
/// # Specification
/// - ensures: accepts a verb, then its operands and options in any order: one
///   `<task>` operand for every verb but `open`, which takes none, and the
///   options the verb takes ([`Verb::flags`]), each as `--name <value>` or
///   `--name=<value>`, the last one given winning but for `--rubric`, every one
///   of which is kept in order. `<task>` is read as [`TaskName`] reads it,
///   `--project` as a bare anchor in the key form, `--seat` as a peer id,
///   `--at` as an endpoint, and `--brief` as a content hash when it is 64 hex
///   digits and as an anchor otherwise. `--repo` defaults to the working
///   directory for `verify` and `decide`, and `decide` answers from the
///   environment's endpoint without `--static`.
/// - fails: [`UsageError::NoCommand`] when no verb is given,
///   [`UsageError::Command`] for an unknown verb, [`UsageError::Arguments`] for
///   an option the verb does not take or one without its value,
///   [`UsageError::Operands`] for the wrong number of operands,
///   [`UsageError::Missing`] for an absent `--seat` or `--brief` to `dispatch`,
///   `--playbook` to `verify`, `--rubric` to `decide` or `--repo` to `land`,
///   then [`UsageError::Task`], [`UsageError::Project`], [`UsageError::Seat`],
///   [`UsageError::At`] and [`UsageError::Brief`] for a value that does not
///   read.
/// - panics: none.
///
/// # Errors
/// - [`UsageError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — every verb with its options read to its command, a task
///   by name and by anchor, a brief by anchor and by content, repeated rubrics
///   kept in order, and a missing verb, an unknown verb, an option the verb
///   does not take, a missing option, a surplus operand and each malformed
///   value are each refused by name.
/// - witness: `tests::every_verb_reads_its_options`
/// - witness: `tests::a_malformed_command_line_is_refused`
#[spec(ensures: |ref ret| ret.as_ref().map_or(true, |invocation| match invocation.command {
    Command::Decide { ref rubrics, .. } => !rubrics.is_empty(),
    Command::Open | Command::Dispatch { .. } | Command::Verify { .. } | Command::Land { .. } => true,
}))]
fn parse(mut arguments: lexopt::Parser) -> Result<Invocation, UsageError>
{
    let verb = match arguments.next()? {
        Some(lexopt::Arg::Value(word)) => verb(word)?,
        Some(other) => return Err(UsageError::from(other.unexpected())),
        None => return Err(UsageError::NoCommand),
    };
    let mut given = Given::default();
    while let Some(argument) = arguments.next()? {
        let flag = match argument {
            lexopt::Arg::Value(operand) => {
                given.operands.push(operand);
                continue;
            },
            lexopt::Arg::Long(name) => {
                let flag = match name {
                    "project" => Flag::Project,
                    "seat" => Flag::Seat,
                    "brief" => Flag::Brief,
                    "at" => Flag::At,
                    "playbook" => Flag::Playbook,
                    "repo" => Flag::Repo,
                    "rubric" => Flag::Rubric,
                    "static" => Flag::Static,
                    _ => return Err(UsageError::from(lexopt::Arg::Long(name).unexpected())),
                };
                if !verb.flags().contains(&flag) {
                    return Err(UsageError::from(lexopt::Arg::Long(name).unexpected()));
                }
                flag
            },
            other @ lexopt::Arg::Short(_) => return Err(UsageError::from(other.unexpected())),
        };
        let value = arguments.value()?;
        given.values(flag).push(value);
    }
    let project = match given.project.pop() {
        Some(text) => Project::Named(read_project(&text).map_err(UsageError::Project)?),
        None => Project::Environment,
    };
    let mut operands = core::mem::take(&mut given.operands).into_iter();
    let task = match (verb, operands.next(), operands.next()) {
        (Verb::Open, None, None) => {
            return Ok(Invocation {
                project,
                command: Command::Open,
            });
        },
        (Verb::Dispatch | Verb::Verify | Verb::Decide | Verb::Land, Some(task), None) => task,
        (..) => return Err(UsageError::Operands(verb)),
    };
    let required =
        |values: &mut Vec<OsString>, flag| values.pop().ok_or(UsageError::Missing { verb, flag });
    let repository = |values: &mut Vec<OsString>| {
        values
            .pop()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
    };
    let command = match verb {
        Verb::Dispatch => {
            let seat = required(&mut given.seat, Flag::Seat)?;
            let brief = required(&mut given.brief, Flag::Brief)?;
            let task = read_task(&task)?;
            let seat = seat.to_string_lossy().parse().map_err(UsageError::Seat)?;
            let at = match given.at.pop() {
                Some(at) => At::Given(at.to_string_lossy().parse().map_err(UsageError::At)?),
                None => At::Book,
            };
            Command::Dispatch {
                task,
                seat,
                brief: read_brief(&brief)?,
                at,
            }
        },
        Verb::Verify => {
            let playbook = PathBuf::from(required(&mut given.playbook, Flag::Playbook)?);
            Command::Verify {
                task: read_task(&task)?,
                playbook,
                repository: repository(&mut given.repo),
            }
        },
        Verb::Decide => {
            if given.rubric.is_empty() {
                return Err(UsageError::Missing {
                    verb,
                    flag: Flag::Rubric,
                });
            }
            let judging = given.table.pop().map_or(Judging::Endpoint, |file| {
                Judging::Table(PathBuf::from(file))
            });
            Command::Decide {
                task: read_task(&task)?,
                rubrics: given.rubric.into_iter().map(PathBuf::from).collect(),
                repository: repository(&mut given.repo),
                judging,
            }
        },
        Verb::Land => {
            let repository = PathBuf::from(required(&mut given.repo, Flag::Repo)?);
            Command::Land {
                task: read_task(&task)?,
                repository,
            }
        },
        Verb::Open => return Err(UsageError::Operands(verb)),
    };
    Ok(Invocation { project, command })
}

/// Read the verb `word` names.
///
/// # Specification
/// - ensures: `open`, `dispatch`, `verify`, `decide` and `land` name their
///   verbs.
/// - fails: [`UsageError::Command`] for any other word.
/// - panics: none.
/// - executable: none — the function is its own specification; the command-line
///   witnesses exercise the verb table and its refusal.
///
/// # Errors
/// - [`UsageError::Command`]: the word names no verb.
///
/// # Adequacy
/// - hypothesis: L3 — each verb reads, and an unknown verb is refused.
/// - witness: `tests::every_verb_reads_its_options`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn verb(word: OsString) -> Result<Verb, UsageError>
{
    match word.to_str() {
        Some("open") => Ok(Verb::Open),
        Some("dispatch") => Ok(Verb::Dispatch),
        Some("verify") => Ok(Verb::Verify),
        Some("decide") => Ok(Verb::Decide),
        Some("land") => Ok(Verb::Land),
        Some(_) | None => Err(UsageError::Command(word)),
    }
}

/// Read the task operand `text`.
///
/// # Specification
/// - ensures: yields the task [`TaskName`] reads from `text`, text that is not
///   UTF-8 read with replacement characters, which no task name holds.
/// - fails: [`UsageError::Task`] as [`TaskName`] refuses.
/// - panics: none.
/// - executable: none — the function is its own specification; it delegates
///   task admission and only translates its error.
///
/// # Errors
/// - [`UsageError::Task`]: the text is no task's name or anchor.
///
/// # Adequacy
/// - hypothesis: L3 — name and anchor operands read; malformed tasks refuse.
/// - witness: `tests::every_verb_reads_its_options`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_task(text: &OsString) -> Result<TaskName, UsageError>
{
    text.to_string_lossy().parse().map_err(UsageError::Task)
}

/// Read the project a bare anchor `text` names by its key.
///
/// # Specification
/// - ensures: yields the tree of the bare anchor `domhringr://<tree-id>/`.
/// - fails: [`ParseProjectError::Anchor`] for text that is no anchor, and
///   [`ParseProjectError::NotTree`] for an anchor naming a path or a commit, or
///   its tree by a DNS name or a label.
/// - panics: none.
/// - executable: none — the function is its own specification; the parser
///   witnesses distinguish bare tree anchors from other operands.
///
/// # Errors
/// - [`ParseProjectError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — a bare anchor reads as the project from `--project`, and
///   a path anchor and a hex id in its place are refused.
/// - witness: `tests::every_verb_reads_its_options`
/// - witness: `tests::a_malformed_command_line_is_refused`
fn read_project(text: &OsStr) -> Result<TreeId, ParseProjectError>
{
    match text.to_string_lossy().parse::<Anchor>()? {
        Anchor::Tree(Authority::Key(tree)) => Ok(tree),
        Anchor::Tree(_) | Anchor::Path { .. } | Anchor::Commit { .. } => {
            Err(ParseProjectError::NotTree)
        },
    }
}

/// Read the brief `text` names: a content hash, or else an anchor.
///
/// # Specification
/// - ensures: 64 hex digits read as [`Brief::Content`]; any other text that
///   reads as an anchor as [`Brief::Anchor`].
/// - fails: [`UsageError::Brief`] with the anchor parser's reason for text that
///   is neither.
/// - panics: none.
///
/// # Errors
/// - [`UsageError::Brief`]: the text is neither a content hash nor an anchor.
///
/// # Adequacy
/// - hypothesis: L3 — a brief by content and by anchor read to their kinds, and
///   a word that is neither is refused.
/// - witness: `tests::every_verb_reads_its_options`
/// - witness: `tests::a_malformed_command_line_is_refused`
#[spec(ensures: |ref ret| !matches!(*ret, Ok(Brief::Content(_))) || text.len() == 64)]
fn read_brief(text: &OsStr) -> Result<Brief, UsageError>
{
    let text = text.to_string_lossy();
    if let Ok(hash) = text.parse::<ContentHash>() {
        return Ok(Brief::Content(hash));
    }
    text.parse().map(Brief::Anchor).map_err(UsageError::Brief)
}

/// Where the operator's state lives and which project a command acts in.
struct Settings
{
    /// The state directory.
    state: StateDir,
    /// The project.
    project: TreeId,
    /// Whether the endpoint reaches n0's relay and DNS.
    relay: Relay,
}

/// Resolve `project` and the state directory from the environment.
///
/// # Specification
/// - ensures: the state directory is `DOMHRINGR_STATE`, or else `domhringr`
///   beneath `XDG_STATE_HOME`, or else `.local/state/domhringr` beneath `HOME`,
///   an empty variable counting as unset; the project is the one `--project`
///   named, or else the one `DOMHRINGR_PROJECT` names; the relay is
///   [`Relay::Off`] when `DOMHRINGR_RELAY` is `off`, else [`Relay::N0`].
/// - fails: [`RunError::NoState`] when no variable names a state directory,
///   [`RunError::NoProject`] when nothing names a project,
///   [`RunError::Project`] when `DOMHRINGR_PROJECT` is no bare anchor in the
///   key form, and [`RunError::Relay`] when `DOMHRINGR_RELAY` is set to neither
///   `n0` nor `off`.
/// - panics: none.
/// - executable: none — environment precedence depends on process state;
///   process witnesses isolate the operator's environment.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests name the state and the project by the
///   environment and the project by `--project`.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
/// - witness: `operator::tests::open_lists_every_seat_and_task`
fn settings(project: Project) -> Result<Settings, RunError>
{
    let set = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    let state = match (set(STATE), set("XDG_STATE_HOME"), set("HOME")) {
        (Some(state), ..) => PathBuf::from(state),
        (None, Some(base), _) => PathBuf::from(base).join("domhringr"),
        (None, None, Some(home)) => PathBuf::from(home).join(".local/state/domhringr"),
        (None, None, None) => return Err(RunError::NoState),
    };
    let project = match project {
        Project::Named(tree) => tree,
        Project::Environment => {
            let text = set(PROJECT).ok_or(RunError::NoProject)?;
            read_project(&text).map_err(RunError::Project)?
        },
    };
    let relay = match set(RELAY) {
        None => Relay::N0,
        Some(value) if value == "n0" => Relay::N0,
        Some(value) if value == "off" => Relay::Off,
        Some(other) => return Err(RunError::Relay(other)),
    };
    Ok(Settings {
        state: StateDir::from(state),
        project,
        relay,
    })
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
/// - executable: none — runtime teardown and command effects require process
///   observation, not a predicate over the completion value.
///
/// # Errors
/// - [`RunError::Runtime`]: the runtime cannot start.
/// - every other [`RunError`]: as [`execute`].
///
/// # Adequacy
/// - hypothesis: L3 — the process tests run every command through this function
///   and observe its output.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
fn run(invocation: Invocation) -> Result<Completion, RunError>
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(RunError::Runtime)?;
    runtime.block_on(execute(invocation))
}

/// Carry out one command as the operator whose state the environment names.
///
/// # Specification
/// - requires: called within a Tokio runtime.
/// - ensures: resolves the settings ([`settings`]), loads or creates the
///   identity beneath the state directory, opens the store and the evidence
///   store beside it, and runs the command as [`act`] runs it.
/// - fails: as [`settings`], [`RunError::Identity`] and [`RunError::Open`] when
///   the identity or the store cannot be opened, and as [`act`].
/// - panics: none.
/// - executable: none — identity, store and command effects require the process
///   witness; a completion value cannot attest to them.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests run each command against one state
///   directory in turn and read its lines.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
async fn execute(invocation: Invocation) -> Result<Completion, RunError>
{
    let Invocation { project, command } = invocation;
    let Settings {
        state,
        project,
        relay,
    } = settings(project)?;
    let identity = Identity::load_or_create(&state)?;
    let operator = identity.peer_key();
    let evidence = Evidence::open(&state);
    let peer = Peer::open(&state, identity)?.with_relay(relay);
    Box::pin(act(peer, &state, &evidence, operator, project, command)).await
}

/// Run `command` in `project` as `operator`, on the store `peer` opens in
/// `state` and on `evidence`.
///
/// # Specification
/// - requires: called within a Tokio runtime.
/// - ensures: runs `open` as [`project::open`], `dispatch` as
///   [`project::dispatch`], and `verify` as [`check::verify`], `decide` as
///   [`check::decide`] and `land` as [`change::land`], each on the task and the
///   store [`project::caught_up`] returns, its endpoint closed once the command
///   ends.
/// - fails: as each command fails.
/// - panics: none.
/// - executable: none — dispatch and endpoint shutdown are asynchronous effects
///   observed by the operator process witnesses.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests run each command against one state
///   directory in turn and read its lines.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
/// - witness: `operator::tests::open_lists_every_seat_and_task`
async fn act(
    peer: Peer,
    state: &StateDir,
    evidence: &Evidence,
    operator: PeerKey,
    project: TreeId,
    command: Command,
) -> Result<Completion, RunError>
{
    match command {
        Command::Open => project::open(peer, state, operator, project).await?,
        Command::Dispatch {
            task,
            seat,
            brief,
            at,
        } => {
            let on = project::Dispatching {
                state,
                operator,
                project,
            };
            project::dispatch(peer, on, &task, seat, brief, at).await?;
        },
        Command::Verify {
            task,
            playbook,
            repository,
        } => {
            let (tree, store) = project::caught_up(peer, project, &task, evidence).await?;
            let before = store.peer().heads(tree).await?;
            let verified = check::verify(
                store.peer(),
                evidence,
                operator,
                tree,
                &playbook,
                &repository,
            )
            .await;
            store.close().await;
            if store.peer().heads(tree).await? != before {
                project::attest(store.peer(), state, project).await?;
            }
            drop(store);
            verified?;
        },
        Command::Decide {
            task,
            rubrics,
            repository,
            judging,
        } => {
            let (tree, store) = project::caught_up(peer, project, &task, evidence).await?;
            let before = store.peer().heads(tree).await?;
            let decided = check::decide(
                check::Deciding {
                    peer: store.peer(),
                    evidence,
                    operator,
                    tree,
                },
                &rubrics,
                &repository,
                &judging,
            )
            .await;
            store.close().await;
            if store.peer().heads(tree).await? != before {
                project::attest(store.peer(), state, project).await?;
            }
            drop(store);
            return decided;
        },
        Command::Land { task, repository } => {
            let (tree, store) = project::caught_up(peer, project, &task, evidence).await?;
            let before = store.peer().heads(tree).await?;
            let landed = change::land(store.peer(), evidence, operator, tree, &repository).await;
            store.close().await;
            if store.peer().heads(tree).await? != before {
                project::attest(store.peer(), state, project).await?;
            }
            drop(store);
            landed?;
        },
    }
    Ok(Completion::Success)
}

/// Write `lines` to standard output and flush it.
///
/// # Specification
/// - ensures: on success the text is written and flushed, so a reader on a pipe
///   sees it at once.
/// - fails: [`RunError::Output`] when standard output cannot be written.
/// - panics: none.
/// - executable: none — a return value cannot observe the bytes a pipe reader
///   receives or the flush; the process witnesses read those lines.
///
/// # Errors
/// - [`RunError::Output`]: the write or the flush fails.
///
/// # Adequacy
/// - hypothesis: L3 — the operator's piped output exposes each command result.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
fn emit(lines: &dyn fmt::Display) -> Result<(), RunError>
{
    let mut stdout = std::io::stdout().lock();
    write!(stdout, "{lines}").map_err(RunError::Output)?;
    stdout.flush().map_err(RunError::Output)
}

/// Write `error` and its causes to standard error as one line.
///
/// # Specification
/// - ensures: writes `domhringr: `, the error, each of its sources in order
///   each preceded by `: `, and a newline.
/// - fails: the write's own error when standard error cannot be written.
/// - panics: none.
/// - executable: none — diagnostics are external stream effects; the refused
///   merge witness observes the error from a child process.
///
/// # Errors
/// - [`std::io::Error`]: standard error cannot be written.
///
/// # Adequacy
/// - hypothesis: L3 — a refused merge reports a failure and commits nothing.
/// - witness: `operator::tests::a_refused_merge_commits_nothing`
fn report(error: &dyn Error) -> std::io::Result<()>
{
    let mut stderr = std::io::stderr().lock();
    write!(stderr, "domhringr: {error}")?;
    for cause in core::iter::successors(error.source(), |&cause| cause.source()) {
        write!(stderr, ": {cause}")?;
    }
    writeln!(stderr)
}

/// Entry point.
///
/// # Specification
/// - ensures: runs the command line as [`run`] specifies and exits 0, or
///   [`UNDECIDED_STATUS`] when it ends in [`Completion::Undecided`], having
///   written nothing to standard error.
/// - fails: exits 2 after writing the reason and the synopsis to standard error
///   when the command line cannot be run ([`parse`]), and exits 1 after writing
///   the reason when the command fails. When standard error cannot be written
///   the exit status is the only report.
/// - panics: none.
/// - executable: none — process exit and diagnostics require a parent process
///   to observe them; the operator witnesses provide that boundary.
///
/// # Adequacy
/// - hypothesis: L3 — successful commands and a refused merge expose distinct
///   process outcomes.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
/// - witness: `operator::tests::a_refused_merge_commits_nothing`
fn main() -> ExitCode
{
    let invocation = match parse(lexopt::Parser::from_env()) {
        Ok(invocation) => invocation,
        Err(error) => {
            let reported =
                report(&error).and_then(|()| std::io::stderr().write_all(USAGE.as_bytes()));
            return match reported {
                Ok(()) | Err(_) => ExitCode::from(USAGE_STATUS),
            };
        },
    };
    match run(invocation) {
        Ok(Completion::Success) => ExitCode::SUCCESS,
        Ok(Completion::Undecided) => ExitCode::from(UNDECIDED_STATUS),
        Err(error) => match report(&error) {
            Ok(()) | Err(_) => ExitCode::FAILURE,
        },
    }
}

#[cfg(test)]
mod tests
{
    use std::ffi::OsString;
    use std::path::PathBuf;

    use domhringr_record_tree::At;
    use domhringr_record_tree::Brief;

    use super::Command;
    use super::Flag;
    use super::Invocation;
    use super::Judging;
    use super::Project;
    use super::UsageError;
    use super::Verb;
    use super::parse;

    /// A tree's bare anchor.
    const PROJECT: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/";

    /// A peer id.
    const SEAT: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn every_verb_reads_its_options()
    {
        let read =
            |words: &[&str]| parse(lexopt::Parser::from_args(words.iter().map(OsString::from)));
        assert_eq!(
            read(&["open"]).unwrap(),
            Invocation {
                project: Project::Environment,
                command: Command::Open,
            },
            "open reads the project from the environment"
        );
        let named = read(&["open", "--project", PROJECT]).unwrap();
        assert!(
            matches!(named.project, Project::Named(tree) if format!("domhringr://{tree}/") == PROJECT),
            "--project names the project by its bare anchor"
        );
        let dispatched = read(&[
            "dispatch",
            "--brief",
            &"ab".repeat(32),
            "fix-1",
            &format!("--seat={SEAT}"),
        ])
        .unwrap();
        let Command::Dispatch {
            ref task,
            seat,
            ref brief,
            ref at,
        } = dispatched.command
        else {
            panic!("dispatch reads to its command");
        };
        assert_eq!(
            task.to_string(),
            "tasks/fix-1",
            "a bare task name is its path"
        );
        assert_eq!(seat.to_string(), SEAT, "the seat is its peer id");
        assert!(
            matches!(*brief, Brief::Content(_)),
            "64 hex digits are a content brief"
        );
        assert_eq!(
            *at,
            At::Book,
            "without --at the seat is reached by the book"
        );
        let anchored = read(&[
            "dispatch",
            &format!("{PROJECT}tasks/fix-1"),
            "--seat",
            SEAT,
            "--brief",
            &format!("{PROJECT}briefs/one"),
            "--at",
            SEAT,
        ])
        .unwrap();
        let Command::Dispatch {
            ref task,
            ref brief,
            ref at,
            ..
        } = anchored.command
        else {
            panic!("dispatch reads to its command");
        };
        assert_eq!(task.to_string(), "tasks/fix-1", "a task anchor is its path");
        assert!(
            matches!(*brief, Brief::Anchor(_)),
            "an anchor is an anchor brief"
        );
        assert!(
            matches!(*at, At::Given(_)),
            "--at names the endpoint by hand"
        );
        assert_eq!(
            read(&["verify", "fix-1", "--playbook", "p.toml"])
                .unwrap()
                .command,
            Command::Verify {
                task: "fix-1".parse().unwrap(),
                playbook: PathBuf::from("p.toml"),
                repository: PathBuf::from("."),
            },
            "verify checks the working directory's repository by default"
        );
        assert_eq!(
            read(&[
                "decide", "fix-1", "--rubric", "a.toml", "--repo", "r", "--rubric", "b.toml",
                "--static", "t",
            ])
            .unwrap()
            .command,
            Command::Decide {
                task: "fix-1".parse().unwrap(),
                rubrics: vec![PathBuf::from("a.toml"), PathBuf::from("b.toml")],
                repository: PathBuf::from("r"),
                judging: Judging::Table(PathBuf::from("t")),
            },
            "decide keeps every rubric in order"
        );
        assert!(
            matches!(
                read(&["decide", "fix-1", "--rubric", "a.toml"])
                    .unwrap()
                    .command,
                Command::Decide {
                    judging: Judging::Endpoint,
                    ..
                }
            ),
            "decide asks the environment's endpoint without --static"
        );
        assert_eq!(
            read(&["land", "fix-1", "--repo", "r"]).unwrap().command,
            Command::Land {
                task: "fix-1".parse().unwrap(),
                repository: PathBuf::from("r"),
            },
            "land names its repository"
        );
    }

    #[test]
    fn a_malformed_command_line_is_refused()
    {
        let read =
            |words: &[&str]| parse(lexopt::Parser::from_args(words.iter().map(OsString::from)));
        let refusal = |words: &[&str]| read(words).unwrap_err();
        assert!(matches!(refusal(&[]), UsageError::NoCommand), "no verb");
        assert!(
            matches!(refusal(&["replay"]), UsageError::Command(_)),
            "an unknown verb"
        );
        assert!(
            matches!(
                refusal(&["open", "--repo", "r"]),
                UsageError::Arguments(lexopt::Error::UnexpectedOption(ref option)) if option == "--repo"
            ),
            "an option the verb does not take"
        );
        assert!(
            matches!(
                refusal(&["open", "fix-1"]),
                UsageError::Operands(Verb::Open)
            ),
            "a surplus operand"
        );
        assert!(
            matches!(
                refusal(&["land", "--repo", "r"]),
                UsageError::Operands(Verb::Land)
            ),
            "a missing task"
        );
        assert!(
            matches!(refusal(&["land", "fix-1"]), UsageError::Missing {
                verb: Verb::Land,
                flag: Flag::Repo
            }),
            "land without --repo"
        );
        assert!(
            matches!(refusal(&["decide", "fix-1"]), UsageError::Missing {
                verb: Verb::Decide,
                flag: Flag::Rubric
            }),
            "decide without a rubric"
        );
        assert!(
            matches!(
                refusal(&["dispatch", "fix-1", "--seat", SEAT]),
                UsageError::Missing {
                    verb: Verb::Dispatch,
                    flag: Flag::Brief
                }
            ),
            "dispatch without a brief"
        );
        assert!(
            matches!(
                refusal(&["land", "a/b", "--repo", "r"]),
                UsageError::Task(_)
            ),
            "a task name holding a slash"
        );
        assert!(
            matches!(
                refusal(&["open", "--project", &format!("{PROJECT}tasks")]),
                UsageError::Project(_)
            ),
            "a project that is no bare anchor"
        );
        assert!(
            matches!(
                refusal(&["dispatch", "fix-1", "--seat", "01", "--brief", PROJECT]),
                UsageError::Seat(_)
            ),
            "a short peer id"
        );
        assert!(
            matches!(
                refusal(&["dispatch", "fix-1", "--seat", SEAT, "--brief", "word"]),
                UsageError::Brief(_)
            ),
            "a brief that is neither"
        );
        assert!(
            matches!(
                refusal(&[
                    "dispatch", "fix-1", "--seat", SEAT, "--brief", PROJECT, "--at", "x"
                ]),
                UsageError::At(_)
            ),
            "an endpoint that does not read"
        );
    }
}
