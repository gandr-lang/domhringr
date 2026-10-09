//! The change a seat reports, and the git repository it lands in.
//!
//! A seat names its change in its report's summary: `<branch> <commit>[
//! <text>]`, the branch it pushed and the commit at its tip. The commit is
//! what the operator checks and lands; the branch names it in a merge
//! commit's message. git is run as the `git` program, in the repository at
//! its path, so the repository's own configuration — hooks, signing, merge
//! drivers — applies as it does to the operator by hand.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

use domhringr_record_tree::Answer;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Current;
use domhringr_record_tree::Decision;
use domhringr_record_tree::ParseRevisionError;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Progress;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use domhringr_record_tree::Step;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;
use tempfile::TempDir;

use crate::RunError;
use crate::emit;

/// The variables that name a repository to git, as `git rev-parse
/// --local-env-vars` lists them, less the two that carry `-c` configuration:
/// git clears exactly these before it runs a command in another repository,
/// and the driver clears them so that `--repo` is read as the repository at
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

/// The change a seat reports: the branch it pushed and the commit at its tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change
{
    /// The branch.
    branch: String,
    /// The commit.
    commit: Revision,
}

impl FromStr for Change
{
    type Err = ParseChangeError;

    /// Read a change from a report's summary, `<branch> <commit>[ <text>]`.
    ///
    /// # Specification
    /// - ensures: the branch is the first word, one or more ASCII letters,
    ///   digits, `-`, `_`, `.` and `/`, not beginning with `-`; the commit is
    ///   the second, 40 or 64 lowercase hex digits; whatever follows a third
    ///   space is the seat's own text, not read.
    /// - fails: [`ParseChangeError::Branch`] for a first word that is no
    ///   branch, [`ParseChangeError::NoCommit`] when no second word follows,
    ///   and [`ParseChangeError::Commit`] for a second word that is no commit.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseChangeError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a summary with and without trailing text reads to its
    ///   branch and commit; a missing commit, a short one, an uppercase one and
    ///   a branch beginning with `-` are each refused by name.
    /// - witness: `change::tests::a_change_is_a_branch_and_a_commit`
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut words = text.splitn(3, ' ');
        let branch = words.next().unwrap_or_default();
        let named = !branch.is_empty()
            && !branch.starts_with('-')
            && branch.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')
            });
        if !named {
            return Err(ParseChangeError::Branch);
        }
        let commit = words.next().ok_or(ParseChangeError::NoCommit)?;
        Ok(Self {
            branch: branch.into(),
            commit: commit.parse().map_err(ParseChangeError::Commit)?,
        })
    }
}

impl fmt::Display for Change
{
    /// Write the change as `<branch> <commit>`.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        write!(f, "{} {}", self.branch, self.commit)
    }
}

/// Why a report's summary names no change.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseChangeError
{
    /// The first word is no branch.
    #[error(
        "a change begins with its branch: ASCII letters, digits, `-`, `_`, `.` and `/`, not \
         beginning with `-`"
    )]
    Branch,
    /// No commit follows the branch.
    #[error("a change names its commit after its branch")]
    NoCommit,
    /// The second word is no commit.
    #[error("cannot read the change's commit")]
    Commit(#[source] ParseRevisionError),
}

/// The current dispatch of the task `view` folds and the change its report
/// names.
///
/// # Specification
/// - ensures: yields the current attempt's dispatch and the change the summary
///   of its report reads as ([`Change`]).
/// - fails: [`RunError::Undispatched`] when the task has no dispatch,
///   [`RunError::Unreported`] when the current dispatch has no report, and
///   [`RunError::Change`] when the summary names no change.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests verify, decide and land the change a
///   seat's script reports.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
pub fn reported(view: &View) -> Result<(CommitId, Change), RunError>
{
    let Current::Attempt(ref attempt) = *view.task().current()
    else {
        return Err(RunError::Undispatched);
    };
    let Answer::Reported(report) = attempt.answer()
    else {
        return Err(RunError::Unreported);
    };
    let summary = view
        .task()
        .steps()
        .iter()
        .find_map(|&(commit, ref step)| match *step {
            | Step::Report { ref summary, .. } if commit == report => Some(summary),
            | Step::Report { .. }
            | Step::Dispatch { .. }
            | Step::Handoff { .. }
            | Step::Retire { .. }
            | Step::Verdict { .. }
            | Step::Verified { .. }
            | Step::Graded { .. }
            | Step::Decide { .. }
            | Step::Landed { .. } => None,
        })
        .ok_or(RunError::Unreported)?;
    let change = summary.as_ref().parse().map_err(RunError::Change)?;
    Ok((attempt.dispatch(), change))
}

/// What git is run to do, as an error names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitAction
{
    /// `symbolic-ref`: read the branch `HEAD` names.
    Branch,
    /// `status`: read whether tracked files changed.
    Status,
    /// `cat-file`: find the change's commit.
    Find,
    /// `worktree add`: check the change out.
    CheckOut,
    /// `worktree remove`: remove the checkout.
    Remove,
    /// `diff`: diff the change.
    Diff,
    /// `log`: read the change's commits.
    Log,
    /// `merge`: merge the change.
    Merge,
    /// `merge --abort`: abort a merge that stopped.
    Abort,
    /// `rev-parse`: read where `HEAD` stands.
    Head,
}

impl fmt::Display for GitAction
{
    /// Write what git was run to do.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Branch => "read the branch HEAD names",
            | Self::Status => "read the working tree's status",
            | Self::Find => "find the change's commit",
            | Self::CheckOut => "check the change out",
            | Self::Remove => "remove the change's checkout",
            | Self::Diff => "diff the change",
            | Self::Log => "read the change's commits",
            | Self::Merge => "merge the change",
            | Self::Abort => "abort the merge",
            | Self::Head => "read where HEAD stands",
        })
    }
}

/// git, to run in the repository at `directory` as the repository there.
///
/// # Specification
/// - ensures: the command runs the `git` found on the path, in `directory`,
///   with every variable of [`REPOSITORY_VARIABLES`] removed from its
///   environment and its standard input closed.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests run every git command of the loop
///   through this function in a throwaway repository.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
fn git(directory: &Path) -> Command
{
    let mut command = Command::new("git");
    command.current_dir(directory).stdin(Stdio::null());
    for variable in REPOSITORY_VARIABLES {
        command.env_remove(variable);
    }
    command
}

/// Run `command` for `action` and read how it ended.
///
/// # Specification
/// - ensures: returns the command's status and everything it wrote.
/// - fails: [`RunError::Git`] when the command cannot start or its output
///   cannot be read.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Git`]: the command cannot run.
fn ran(
    command: &mut Command,
    action: GitAction,
) -> Result<Output, RunError>
{
    // economy: git runs on the runtime's thread; each command is short and
    // the driver runs one command at a time.
    command
        .output()
        .map_err(|source| RunError::Git { action, source })
}

/// Run `command` for `action`, when it exits 0.
///
/// # Specification
/// - ensures: returns the command's output when it exits 0.
/// - fails: as [`ran`], and as [`refused`] when it exits otherwise.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
fn succeeded(
    command: &mut Command,
    action: GitAction,
) -> Result<Output, RunError>
{
    let output = ran(command, action)?;
    if output.status.success() {
        return Ok(output);
    }
    Err(refused(action, &output))
}

/// The refusal of a git command run for `action` that exited non-zero with
/// `output`.
///
/// # Specification
/// - ensures: [`RunError::Refused`] carrying what the command wrote to standard
///   error, or else to standard output, its lines trimmed and joined by `; `.
/// - panics: none.
fn refused(
    action: GitAction,
    output: &Output,
) -> RunError
{
    let told = if output.stderr.is_empty() {
        &output.stdout
    }
    else {
        &output.stderr
    };
    let message = String::from_utf8_lossy(told)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    RunError::Refused { action, message }
}

/// Check that the repository at `repository` holds `commit`.
///
/// # Specification
/// - ensures: `Ok` when `git cat-file -e <commit>^{commit}` exits 0.
/// - fails: as [`ran`], and [`RunError::Missing`] otherwise.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
fn holds(
    repository: &Path,
    commit: Revision,
) -> Result<(), RunError>
{
    let output = ran(
        git(repository)
            .args(["cat-file", "-e"])
            .arg(format!("{commit}^{{commit}}")),
        GitAction::Find,
    )?;
    if output.status.success() {
        Ok(())
    }
    else {
        Err(RunError::Missing(commit))
    }
}

/// A detached worktree of a repository at a change's commit, in a temporary
/// directory.
pub struct Checkout
{
    /// The repository the worktree belongs to.
    repository: PathBuf,
    /// The worktree's directory.
    directory: TempDir,
}

impl Checkout
{
    /// Check `change` out of the repository at `repository`.
    ///
    /// # Specification
    /// - ensures: the commit is checked out, detached, into a fresh temporary
    ///   directory registered as a worktree of the repository (`git worktree
    ///   add --detach`).
    /// - fails: as [`holds`], [`RunError::Temporary`] when the directory cannot
    ///   be made, and as [`succeeded`] when git refuses the worktree.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RunError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process tests run a verifier that reads a file
    ///   only the change's commit holds, and find no worktree registered after.
    /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
    pub fn new(
        repository: &Path,
        change: &Change,
    ) -> Result<Self, RunError>
    {
        holds(repository, change.commit)?;
        let directory = tempfile::Builder::new()
            .prefix("domhringr-checkout-")
            .tempdir()
            .map_err(RunError::Temporary)?;
        let _added = succeeded(
            git(repository)
                .args(["worktree", "add", "--detach", "--quiet"])
                .arg(directory.path())
                .arg(change.commit.to_string()),
            GitAction::CheckOut,
        )?;
        Ok(Self {
            repository: repository.to_path_buf(),
            directory,
        })
    }

    /// The worktree's directory.
    ///
    /// # Specification
    /// trivial.
    pub fn path(&self) -> &Path
    {
        self.directory.path()
    }

    /// Remove the worktree and its directory.
    ///
    /// # Specification
    /// - ensures: the worktree is unregistered and its directory removed (`git
    ///   worktree remove --force`), whatever it holds.
    /// - fails: as [`succeeded`] when git refuses; the temporary directory is
    ///   removed even so.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RunError`]: as listed above.
    pub fn remove(self) -> Result<(), RunError>
    {
        let removed = succeeded(
            git(&self.repository)
                .args(["worktree", "remove", "--force"])
                .arg(self.directory.path()),
            GitAction::Remove,
        );
        drop(self.directory);
        removed.map(drop)
    }
}

/// A temporary state directory holding `change` as the rubrics read it.
///
/// # Specification
/// - ensures: the directory holds `change.diff`, the diff from the repository's
///   `HEAD` to the change's commit through their merge base (`git diff
///   HEAD...<commit>`), and `commits.txt`, each commit `HEAD` lacks oldest
///   first as `commit <id>`, a newline and its message.
/// - fails: as [`holds`], [`RunError::Temporary`] when the directory cannot be
///   made, as [`succeeded`] when git refuses, and [`RunError::Write`] when a
///   file cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests grade a rubric reading both files by a
///   table keyed on the transcript they make.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
pub fn state(
    repository: &Path,
    change: &Change,
) -> Result<TempDir, RunError>
{
    holds(repository, change.commit)?;
    let state = tempfile::Builder::new()
        .prefix("domhringr-state-")
        .tempdir()
        .map_err(RunError::Temporary)?;
    let diff = succeeded(
        git(repository)
            .args(["diff", "--no-color", "--no-ext-diff"])
            .arg(format!("HEAD...{}", change.commit)),
        GitAction::Diff,
    )?;
    std::fs::write(state.path().join("change.diff"), diff.stdout).map_err(RunError::Write)?;
    let log = succeeded(
        git(repository)
            .args(["log", "--reverse", "--no-color", "--format=commit %H%n%B"])
            .arg(format!("HEAD..{}", change.commit)),
        GitAction::Log,
    )?;
    std::fs::write(state.path().join("commits.txt"), log.stdout).map_err(RunError::Write)?;
    Ok(state)
}

/// Merge `change` into the branch the repository at `repository` has checked
/// out, and read where the branch then stands.
///
/// # Specification
/// - ensures: requires `HEAD` to name a branch, no tracked file to differ from
///   `HEAD`, and the repository to hold the commit; then merges the commit
///   (`git merge --ff --no-edit -m "Merge branch '<branch>'"`), fast forward
///   when it can and by a merge commit otherwise, and returns the revision
///   `HEAD` then names. A commit already merged leaves the branch where it is,
///   and that is the revision returned.
/// - fails: [`RunError::Detached`] when `HEAD` names no branch,
///   [`RunError::Dirty`] when a tracked file differs, as [`holds`], and
///   [`RunError::Refused`] when git refuses the merge, the merge aborted when
///   it stopped part way (`git merge --abort`) so the repository is as it was;
///   [`RunError::Revision`] when `HEAD` reads as no revision; and as [`ran`].
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests merge a change by a merge commit naming
///   its branch once main moved past its base, fast-forward another on main's
///   tip, and refuse a dirty tree and a conflicting change, main, the index and
///   the working tree left as they were.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
/// - witness: `operator::tests::a_refused_merge_commits_nothing`
fn merge(
    repository: &Path,
    change: &Change,
) -> Result<Revision, RunError>
{
    let branch = ran(
        git(repository).args(["symbolic-ref", "--quiet", "--short", "HEAD"]),
        GitAction::Branch,
    )?;
    match branch.status.code() {
        | Some(0_i32) => {},
        | Some(1_i32) => return Err(RunError::Detached),
        | Some(_) | None => return Err(refused(GitAction::Branch, &branch)),
    }
    let status = succeeded(
        git(repository).args(["status", "--porcelain", "--untracked-files=no"]),
        GitAction::Status,
    )?;
    if !status.stdout.is_empty() {
        return Err(RunError::Dirty);
    }
    holds(repository, change.commit)?;
    let merged = succeeded(
        git(repository)
            .args(["merge", "--ff", "--no-edit", "-m"])
            .arg(format!("Merge branch '{}'", change.branch))
            .arg(change.commit.to_string()),
        GitAction::Merge,
    );
    if let Err(refused) = merged {
        let stopped = ran(
            git(repository).args(["rev-parse", "--quiet", "--verify", "MERGE_HEAD"]),
            GitAction::Abort,
        )?;
        if stopped.status.success() {
            let _aborted = succeeded(git(repository).args(["merge", "--abort"]), GitAction::Abort)?;
        }
        return Err(refused);
    }
    let head = succeeded(git(repository).args(["rev-parse", "HEAD"]), GitAction::Head)?;
    String::from_utf8_lossy(&head.stdout)
        .trim_end()
        .parse()
        .map_err(RunError::Revision)
}

/// Land the change of `tree`'s current attempt in the repository at
/// `repository`, as `operator`.
///
/// # Specification
/// - ensures: requires the attempt's progress to be a decision to land made by
///   `operator`; writes `change <branch> <commit>`, merges the change
///   ([`merge`]), commits the landing of that decision at the revision the
///   branch then stands at, and writes `landed <commit-id> <revision>`.
/// - fails: [`RunError::View`] when the task cannot be folded, as [`reported`],
///   [`RunError::Landed`] when the attempt has landed, [`RunError::NotLand`]
///   when its decision is to rework or abandon, [`RunError::NoDecision`] when
///   it has no decision, [`RunError::OtherOperator`] when another operator
///   decided it — each before git is run — as [`merge`], with nothing
///   committed, and [`RunError::Random`], [`RunError::Commit`] and
///   [`RunError::Output`].
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests land a change decided to land, refuse
///   to land one decided to rework with main where it was, and refuse a dirty
///   tree and a conflicting merge with nothing committed.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
/// - witness: `operator::tests::a_refused_merge_commits_nothing`
pub async fn land(
    peer: &Peer,
    operator: PeerKey,
    tree: TreeId,
    repository: &Path,
) -> Result<(), RunError>
{
    let view = peer.view(tree).await?;
    let (_dispatch, change) = reported(&view)?;
    let Current::Attempt(ref attempt) = *view.task().current()
    else {
        return Err(RunError::Undispatched);
    };
    let decided = match *attempt.progress() {
        | Progress::Decided {
            decide,
            decision: Decision::Land,
        } => decide,
        | Progress::Decided { ref decision, .. } => {
            return Err(RunError::NotLand(decision.clone()));
        },
        | Progress::Landed { merge, .. } => return Err(RunError::Landed(merge)),
        | Progress::Unchecked | Progress::Verified(_) | Progress::Graded { .. } => {
            return Err(RunError::NoDecision);
        },
    };
    let decider = view
        .task()
        .steps()
        .iter()
        .find_map(|&(commit, ref step)| match *step {
            | Step::Decide { operator, .. } if commit == decided => Some(operator),
            | Step::Dispatch { .. }
            | Step::Report { .. }
            | Step::Handoff { .. }
            | Step::Retire { .. }
            | Step::Verdict { .. }
            | Step::Verified { .. }
            | Step::Graded { .. }
            | Step::Decide { .. }
            | Step::Landed { .. } => None,
        });
    if let Some(decider) = decider.filter(|&decider| decider != operator) {
        return Err(RunError::OtherOperator(decider));
    }
    emit(&format_args!("change {change}\n"))?;
    let merge = merge(repository, &change)?;
    let landed = peer
        .commit(tree, Receipt::landed(tree, decided, merge)?)
        .await?;
    emit(&format_args!("landed {landed} {merge}\n"))
}

#[cfg(test)]
mod tests
{
    use super::Change;
    use super::ParseChangeError;

    #[test]
    fn a_change_is_a_branch_and_a_commit()
    {
        let sha1 = "0123456789abcdef0123456789abcdef01234567";
        let sha256 = "ab".repeat(32);
        for (summary, written) in [
            (format!("seat/fix-1 {sha1}"), format!("seat/fix-1 {sha1}")),
            (
                format!("fix_1.v2 {sha256} closes the issue"),
                format!("fix_1.v2 {sha256}"),
            ),
        ] {
            assert_eq!(
                summary.parse::<Change>().unwrap().to_string(),
                written,
                "the summary {summary:?} names its branch and commit"
            );
        }
        for (summary, refusal) in [
            ("", ParseChangeError::Branch),
            (
                "-f 0123456789abcdef0123456789abcdef01234567",
                ParseChangeError::Branch,
            ),
            (
                "a:b 0123456789abcdef0123456789abcdef01234567",
                ParseChangeError::Branch,
            ),
            ("seat/fix-1", ParseChangeError::NoCommit),
        ] {
            assert_eq!(
                summary.parse::<Change>(),
                Err(refusal),
                "the summary {summary:?} is refused by name"
            );
        }
        for summary in [
            "seat/fix-1 0123456789abcdef",
            "seat/fix-1 0123456789ABCDEF0123456789ABCDEF01234567",
        ] {
            assert!(
                matches!(summary.parse::<Change>(), Err(ParseChangeError::Commit(_))),
                "the summary {summary:?} names no commit"
            );
        }
    }
}
