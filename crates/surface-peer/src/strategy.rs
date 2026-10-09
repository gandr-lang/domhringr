//! `playbook` and `rubric`: reading the documents, running a playbook's
//! checks on a task's current dispatch, and grading a rubric's questions.
//!
//! A run names the task's current dispatch before it checks anything. Each
//! verifier step runs in turn in the task's state directory and commits a
//! verification naming this peer the runner; then each rubric the steps name
//! is graded once, over the questions its steps name: the transcript is read
//! from the state files, each question is asked as `judge verdict` asks it,
//! the rulings are committed as a verdict naming this peer the judge, each
//! ruling is graded against the rubric's band, and the grades and their
//! composition are committed as a grading of that verdict. A failing
//! verifier, an unmet grade and a refused one are recorded, and the command
//! still succeeds: what they decide is the operator's.

use alloc::vec::Vec;
use std::path::Path;

use domhringr_judge_oracle::Question;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Grade;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::TreeId;
use domhringr_strategy_document::Bound;
use domhringr_strategy_document::Loaded;
use domhringr_strategy_document::Name;
use domhringr_strategy_document::Plan;
use domhringr_strategy_document::Rubric;
use domhringr_strategy_document::compose;

use crate::Judging;
use crate::RunError;
use crate::current;
use crate::emit;
use crate::rulings;

/// Read the playbook at `file` with each rubric it names, and print it.
///
/// # Specification
/// - ensures: writes `playbook <hash> <name>`, then per step in order `step
///   <id> verifier` or `step <id> question <rubric-hash> <question>
///   <question-hash>`, each hash the BLAKE3 of the file's bytes or of the
///   question's canonical form.
/// - fails: [`RunError::Load`] as [`Plan::read`] refuses, naming the file and
///   the field at fault; [`RunError::Output`] when standard output cannot be
///   written.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Load`]: the playbook or a rubric it names does not load.
/// - [`RunError::Output`]: standard output cannot be written.
///
/// # Adequacy
/// - hypothesis: L3 — the process test validates a playbook of two verifiers
///   and three questions, reading each step's line and the question hashes the
///   rubric's validation prints, and refuses a playbook with a missing field
///   and a rubric with an inverted band by file and field.
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
pub fn validate_playbook(file: &Path) -> Result<(), RunError>
{
    let plan = Plan::read(file)?;
    let playbook = plan.playbook();
    emit(&format_args!(
        "playbook {} {}\n",
        playbook.hash(),
        playbook.document().name()
    ))?;
    for step in playbook.document().steps() {
        match *step.bound() {
            | Bound::Verifier(_) => emit(&format_args!("step {} verifier\n", step.id()))?,
            | Bound::Question {
                ref rubric,
                ref question,
            } => {
                let Some(loaded) = plan.rubrics().get(rubric)
                else {
                    continue;
                };
                let Some(asked) = loaded.document().questions().get(question)
                else {
                    continue;
                };
                emit(&format_args!(
                    "step {} question {} {question} {}\n",
                    step.id(),
                    loaded.hash(),
                    asked.hash()
                ))?;
            },
        }
    }
    Ok(())
}

/// Read the rubric at `file` and print it.
///
/// # Specification
/// - ensures: writes `rubric <hash> <name>`, then `question <name> <hash>` per
///   question in the names' order: the hashes a `--static` table names its
///   questions by.
/// - fails: [`RunError::Load`] as [`Loaded::read`] refuses, naming the file and
///   the field at fault; [`RunError::Output`] when standard output cannot be
///   written.
/// - panics: none.
///
/// # Errors
/// - [`RunError::Load`]: the rubric does not load.
/// - [`RunError::Output`]: standard output cannot be written.
///
/// # Adequacy
/// - hypothesis: L3 — the process test validates a rubric of three questions
///   and builds its table from the hashes printed.
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
pub fn validate_rubric(file: &Path) -> Result<(), RunError>
{
    let rubric = Loaded::<Rubric>::read(file)?;
    emit(&format_args!(
        "rubric {} {}\n",
        rubric.hash(),
        rubric.document().name()
    ))?;
    rubric
        .document()
        .questions()
        .iter()
        .try_for_each(|(name, question)| {
            emit(&format_args!("question {name} {}\n", question.hash()))
        })
}

/// Run the playbook at `file` on `tree`'s current dispatch as `runner`, in
/// the task's state `directory`, its questions answered as `judging` says.
///
/// # Specification
/// - ensures: reads the playbook and its rubrics, then names the current
///   dispatch ([`current`]) before running anything; writes `playbook <hash>
///   <name>`; runs each verifier step in order in `directory` on a blocking
///   thread and commits its verification — `runner`, the playbook's hash, the
///   step, the output's hash and the status — writing `verified <commit> <step>
///   <output-hash> <status>`; then grades each rubric the steps name, in the
///   order first named, over the questions they name, as [`grade`] grades,
///   `runner` its judge.
/// - fails: [`RunError::Load`] as [`Plan::read`] refuses, as [`current`] fails,
///   [`RunError::Join`] when a verifier's thread fails, [`RunError::Verify`]
///   when a verifier does not run to its end — the verifications before it stay
///   committed — [`RunError::Random`] and [`RunError::Commit`] when a receipt
///   cannot be committed, as [`grade`] fails, and [`RunError::Output`] when
///   standard output cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process test refuses a run on a task with no dispatch
///   before any verifier runs; then runs a passing and a failing verifier and
///   three questions on the current dispatch, reads each line, and replays the
///   verifications, the verdict and the grading under the same commits and
///   hashes.
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
pub async fn run_playbook(
    peer: &Peer,
    runner: PeerKey,
    tree: TreeId,
    file: &Path,
    directory: &Path,
    judging: Judging,
) -> Result<(), RunError>
{
    let plan = Plan::read(file)?;
    let dispatch = current(peer, tree).await?;
    let playbook = plan.playbook();
    emit(&format_args!(
        "playbook {} {}\n",
        playbook.hash(),
        playbook.document().name()
    ))?;
    for step in playbook.document().steps() {
        let Bound::Verifier(ref verifier) = *step.bound()
        else {
            continue;
        };
        let (verifier, state) = (verifier.clone(), directory.to_path_buf());
        let run = tokio::task::spawn_blocking(move || verifier.run(&state))
            .await
            .map_err(RunError::Join)??;
        let receipt = Receipt::verified(
            tree,
            dispatch,
            runner,
            playbook.hash(),
            step.id().clone(),
            run.output(),
            run.status(),
        )?;
        let commit = peer.commit(tree, receipt).await?;
        emit(&format_args!(
            "verified {commit} {} {} {}\n",
            step.id(),
            run.output(),
            run.status()
        ))?;
    }
    for grading in plan.gradings() {
        grade(
            Grader {
                peer,
                judge: runner,
                tree,
                dispatch,
            },
            grading.rubric(),
            grading.questions(),
            directory,
            judging.clone(),
        )
        .await?;
    }
    Ok(())
}

/// Grade every question of the rubric at `file` on `tree`'s current
/// dispatch as `judge`, in the task's state `directory`, the questions
/// answered as `judging` says.
///
/// # Specification
/// - ensures: reads the rubric, names the current dispatch ([`current`]) before
///   asking anything, and grades every question in the names' order as
///   [`grade`] grades.
/// - fails: [`RunError::Load`] as [`Loaded::read`] refuses, as [`current`] and
///   [`grade`] fail.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process test grades a rubric from an empty table,
///   every question refused and the rubric with them, then from a table reading
///   one question met, one undecided and one unmet, the rubric unmet.
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
pub async fn grade_rubric(
    peer: &Peer,
    judge: PeerKey,
    tree: TreeId,
    file: &Path,
    directory: &Path,
    judging: Judging,
) -> Result<(), RunError>
{
    let rubric = Loaded::<Rubric>::read(file)?;
    let dispatch = current(peer, tree).await?;
    let asked = rubric.document().questions().iter().collect::<Vec<_>>();
    let on = Grader {
        peer,
        judge,
        tree,
        dispatch,
    };
    grade(on, &rubric, &asked, directory, judging).await
}

/// Where a grading is committed: the store, the judge, the task and its
/// dispatch.
#[derive(Clone, Copy)]
struct Grader<'store>
{
    /// The store the receipts are committed to.
    peer: &'store Peer,
    /// This peer: the judge of the verdict and the author of the grading.
    judge: PeerKey,
    /// The task.
    tree: TreeId,
    /// The dispatch ruled on.
    dispatch: CommitId,
}

/// Ask `asked` of `rubric` about the transcript of `directory`, commit the
/// rulings as a verdict, grade them, and commit the grading, as `on` names.
///
/// # Specification
/// - ensures: writes `rubric <hash> <name>` and `transcript <hash>`; asks each
///   question in order as [`rulings`] asks, writing each ruling's line; commits
///   the verdict of `on`'s judge on its dispatch — the rubric's hash, the
///   transcript's and each question's with its ruling — and writes `verdict
///   <commit>`; grades each ruling against the rubric's band, writing `grade
///   <question-hash> <grade>` per question, and composes the grades; then
///   commits the grading of that verdict and writes `graded <commit>
///   <composed>`.
/// - fails: [`RunError::State`] when a state file cannot be read, as
///   [`rulings`] fails, [`RunError::Random`] and [`RunError::Commit`] when a
///   receipt cannot be committed, and [`RunError::Output`] when standard output
///   cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process test reads every line of three gradings — all
///   refused, refused beside met and undecided, and unmet beside met and
///   undecided — and the replay holds each verdict and grading by the commits
///   printed.
/// - witness: `strategy::tests::a_playbook_runs_its_checks_and_replay_shows_the_receipts`
async fn grade(
    on: Grader<'_>,
    rubric: &Loaded<Rubric>,
    asked: &[(&Name, &Question)],
    directory: &Path,
    judging: Judging,
) -> Result<(), RunError>
{
    emit(&format_args!(
        "rubric {} {}\n",
        rubric.hash(),
        rubric.document().name()
    ))?;
    let transcript = rubric.document().transcript(directory)?;
    emit(&format_args!("transcript {}\n", transcript.hash()))?;
    let questions = asked
        .iter()
        .map(|&(_name, question)| question.clone())
        .collect::<Vec<_>>();
    let answers = rulings(judging, &questions, &transcript).await?;
    let band = rubric.document().band();
    let graded = answers
        .iter()
        .map(|&(question, ref ruling)| (question, band.grade(ruling)))
        .collect::<Vec<_>>();
    let grades = graded
        .iter()
        .map(|&(_question, grade)| grade)
        .collect::<Vec<Grade>>();
    let composed = compose(&grades);
    let verdict = Receipt::verdict(
        on.tree,
        on.dispatch,
        on.judge,
        rubric.hash(),
        transcript.hash(),
        answers,
    )?;
    let verdict = on.peer.commit(on.tree, verdict).await?;
    emit(&format_args!("verdict {verdict}\n"))?;
    for &(question, grade) in &graded {
        emit(&format_args!("grade {question} {grade}\n"))?;
    }
    let grading = Receipt::graded(on.tree, verdict, grades, composed)?;
    let grading = on.peer.commit(on.tree, grading).await?;
    emit(&format_args!("graded {grading} {composed}\n"))
}
