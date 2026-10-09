//! `verify` and `decide`: checking a reported change, and deciding on it.
//!
//! Both name the task's current dispatch and its change, and read its report
//! from the evidence store, before they check anything, and record each check
//! as the peer's `playbook run` and `rubric grade` do: a verification per
//! verifier, its output kept as evidence, and a verdict and its grading per
//! rubric, its transcript kept as evidence, this peer the runner and the
//! judge. `decide` then reads every check on the dispatch together — the
//! rubrics it graded and the latest verification of each step — and records
//! the operator's decision.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use std::path::Path;
use std::path::PathBuf;

use domhringr_judge_oracle::Backend;
use domhringr_judge_oracle::ChatCompletions;
use domhringr_judge_oracle::Config;
use domhringr_judge_oracle::Question;
use domhringr_judge_oracle::Transcript;
use domhringr_record_evidence::Evidence;
use domhringr_record_tree::Code;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::ContentHash;
use domhringr_record_tree::Decision;
use domhringr_record_tree::Grade;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Ruling;
use domhringr_record_tree::Status;
use domhringr_record_tree::Step;
use domhringr_record_tree::StepId;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;
use domhringr_strategy_document::Bound;
use domhringr_strategy_document::Loaded;
use domhringr_strategy_document::Plan;
use domhringr_strategy_document::Rubric;
use domhringr_strategy_document::compose;

use crate::Completion;
use crate::Judging;
use crate::RunError;
use crate::change;
use crate::change::Checkout;
use crate::emit;
use crate::report;

/// Run the verifier steps of the playbook at `file` on the change `tree`'s
/// current attempt reports, as `runner`, in a checkout of it from the
/// repository at `repository`, the report read from and the outputs kept in
/// `evidence`.
///
/// # Specification
/// - ensures: reads the playbook and its rubrics, then names the current
///   dispatch and its change ([`change::reported`]) and reads its report
///   ([`change::announce`]) before running anything, writing `change <branch>
///   <commit>`, `report <digest>` and `playbook <hash> <name>`; checks the
///   commit out ([`Checkout::new`]), runs each verifier step in order in the
///   checkout on a blocking thread, keeps its output in `evidence` and commits
///   its verification — `runner`, the playbook's hash, the step, the output's
///   digest and the status — writing `verified <commit-id> <step>
///   <output-digest> <status>`; then removes the checkout, whatever the steps
///   did. Question steps are not asked.
/// - fails: [`RunError::Load`] as [`Plan::read`] refuses, [`RunError::View`]
///   and as [`change::reported`] and [`change::announce`], as
///   [`Checkout::new`], [`RunError::Join`] when a verifier's thread fails,
///   [`RunError::Verify`] when a verifier does not run to its end and
///   [`RunError::Evidence`] when its output cannot be kept — the verifications
///   before it stay committed — [`RunError::Random`] and [`RunError::Commit`]
///   when a receipt cannot be committed, [`RunError::Output`] when standard
///   output cannot be written, and as [`Checkout::remove`], a failure of the
///   steps reported first.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests verify two reported changes by a
///   verifier that passes only in a checkout of a change's own commit, read its
///   lines, find the checkout removed, read the report and the output in the
///   operator's store by the digests printed, and read the task verified.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
pub async fn verify(
    peer: &Peer,
    evidence: &Evidence,
    runner: PeerKey,
    tree: TreeId,
    file: &Path,
    repository: &Path,
) -> Result<(), RunError>
{
    let plan = Plan::read(file)?;
    let view = peer.view(tree).await?;
    let reported = change::reported(&view)?;
    change::announce(&reported, evidence)?;
    let playbook = plan.playbook();
    emit(&format_args!(
        "playbook {} {}\n",
        playbook.hash(),
        playbook.document().name()
    ))?;
    let checkout = Checkout::new(repository, &reported.change)?;
    let mut ran = Ok(());
    for step in playbook.document().steps() {
        let Bound::Verifier(ref verifier) = *step.bound()
        else {
            continue;
        };
        let (verifier, directory, keeping) = (
            verifier.clone(),
            checkout.path().to_path_buf(),
            evidence.clone(),
        );
        let kept = tokio::task::spawn_blocking(move || -> Result<_, RunError> {
            let run = verifier.run(&directory)?;
            let output = keeping.commit(run.output())?;
            Ok((output, run.status()))
        })
        .await;
        let (output, status) = match kept {
            | Ok(Ok(kept)) => kept,
            | Ok(Err(failure)) => {
                ran = Err(failure);
                break;
            },
            | Err(failure) => {
                ran = Err(RunError::Join(failure));
                break;
            },
        };
        let verified = record(
            peer,
            tree,
            Receipt::verified(
                tree,
                reported.dispatch,
                runner,
                playbook.hash(),
                step.id().clone(),
                output,
                status,
            ),
        )
        .await
        .and_then(|commit| {
            emit(&format_args!(
                "verified {commit} {} {output} {status}\n",
                step.id()
            ))
        });
        if verified.is_err() {
            ran = verified;
            break;
        }
    }
    let removed = checkout.remove();
    ran?;
    removed
}

/// Commit `receipt` in `tree`.
///
/// # Specification
/// - ensures: the receipt is committed and its commit returned.
/// - fails: [`RunError::Random`] when the receipt could not be built, and
///   [`RunError::Commit`] when it cannot be committed.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
async fn record(
    peer: &Peer,
    tree: TreeId,
    receipt: Result<Receipt, domhringr_record_tree::RandomError>,
) -> Result<CommitId, RunError>
{
    Ok(peer.commit(tree, receipt?).await?)
}

/// Where a decision is committed: the stores, the operator and the task.
#[derive(Clone, Copy)]
pub struct Deciding<'store>
{
    /// The tree store.
    pub peer: &'store Peer,
    /// The evidence store the report is read from and transcripts kept in.
    pub evidence: &'store Evidence,
    /// This peer: the operator, and the judge of each verdict.
    pub operator: PeerKey,
    /// The task.
    pub tree: TreeId,
}

/// Grade the change `on`'s task reports by `rubrics`, answered as `judging`
/// says, and decide on it with the dispatch's verifications.
///
/// # Specification
/// - ensures: reads every rubric, names the current dispatch and its change
///   ([`change::reported`]) and reads its report ([`change::announce`]) before
///   asking anything, writing `change <branch> <commit>` and `report <digest>`,
///   and writes the change into a temporary state directory
///   ([`change::state`]). Writes `step <id> <status>` for the latest
///   verification of each step on the dispatch, in step order, each met when it
///   exited 0 and unmet otherwise; grades each rubric in order over every
///   question it holds, as [`grade`] grades; composes the steps' grades and the
///   rubrics' ([`compose`]) and writes `composed <grade>`. Met commits the
///   decision to land; unmet commits the decision to rework for the first
///   failure, `step <id> <status>` among the steps or else `question
///   <rubric>/<question> unmet` among the rubrics in order; either names `on`'s
///   operator and writes `decide <commit-id> <decision>`. Undecided or refused
///   commits nothing and ends in [`Completion::Undecided`].
/// - fails: [`RunError::Load`] as [`Loaded::read`] refuses, [`RunError::View`]
///   and as [`change::reported`] and [`change::announce`], as
///   [`change::state`], as [`grade`], and [`RunError::Random`],
///   [`RunError::Commit`] and [`RunError::Output`].
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests decide a change whose rubric is refused
///   by an empty table, nothing decided and the exit status 3; then from a
///   table reading the rubric met beside a passing verification, a decision to
///   land; and a second change unmet, a decision to rework naming the failing
///   question.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
pub async fn decide(
    on: Deciding<'_>,
    rubrics: &[PathBuf],
    repository: &Path,
    judging: &Judging,
) -> Result<Completion, RunError>
{
    let rubrics = rubrics
        .iter()
        .map(|file| Loaded::<Rubric>::read(file))
        .collect::<Result<Vec<_>, _>>()?;
    let view = on.peer.view(on.tree).await?;
    let reported = change::reported(&view)?;
    change::announce(&reported, on.evidence)?;
    let (dispatch, change) = (reported.dispatch, reported.change);
    let state = change::state(repository, &change)?;
    let mut grades = Vec::new();
    let mut failure = None;
    for (step, status) in verifications(&view, dispatch) {
        emit(&format_args!("step {step} {status}\n"))?;
        if status == Status::Exited(Code::from(0_i32)) {
            grades.push(Grade::Met);
        }
        else {
            grades.push(Grade::Unmet);
            failure = failure.or_else(|| Some(format!("step {step} {status}")));
        }
    }
    for rubric in &rubrics {
        let graded = grade(on, dispatch, rubric, state.path(), judging).await?;
        grades.push(graded.composed);
        if let Unmet::Question(question) = graded.unmet {
            failure = failure.or_else(|| {
                Some(format!(
                    "question {}/{question} unmet",
                    rubric.document().name()
                ))
            });
        }
    }
    drop(state);
    let composed = compose(&grades);
    emit(&format_args!("composed {composed}\n"))?;
    let decision = match (composed, failure) {
        | (Grade::Met, _) => Decision::Land,
        | (Grade::Unmet, Some(reason)) => Decision::Rework {
            reason: reason.parse().map_err(RunError::Reason)?,
        },
        | (Grade::Unmet, None) | (Grade::Undecided | Grade::Refused, _) => {
            return Ok(Completion::Undecided);
        },
    };
    let receipt = Receipt::decide(on.tree, dispatch, on.operator, decision.clone());
    let decided = record(on.peer, on.tree, receipt).await?;
    emit(&format_args!("decide {decided} {decision}\n"))?;
    Ok(Completion::Success)
}

/// The latest verification of each step on `dispatch` in the task `view`
/// folds: each step's status, in step order.
///
/// # Specification
/// trivial.
fn verifications(
    view: &View,
    dispatch: CommitId,
) -> BTreeMap<StepId, Status>
{
    let mut latest = BTreeMap::new();
    for entry in view.task().steps() {
        if let Step::Verified {
            dispatch: verified,
            ref step,
            status,
            ..
        } = entry.1
            && verified == dispatch
        {
            let _earlier = latest.insert(step.clone(), status);
        }
    }
    latest
}

/// Which of a rubric's questions its grading found unmet first.
enum Unmet
{
    /// None.
    Nothing,
    /// This one, by name.
    Question(String),
}

/// A rubric's grading, as `decide` composes it.
struct Graded
{
    /// The grades composed across the rubric.
    composed: Grade,
    /// Its first question graded unmet, in the names' order.
    unmet: Unmet,
}

/// Ask every question of `rubric` about the transcript of `directory`, as
/// `judging` answers, commit the rulings as a verdict on `dispatch`, grade
/// them, and commit the grading, as `on` names.
///
/// # Specification
/// - ensures: writes `rubric <hash> <name>` and `transcript <digest>`; asks
///   each question in the names' order as [`rulings`] asks, writing each
///   ruling's line; keeps the transcript in `on`'s evidence store and commits
///   the verdict of `on`'s operator, the judge, on `dispatch` — the rubric's
///   hash, the transcript's digest and each question's hash with its ruling —
///   and writes `verdict <commit-id>`; grades each ruling against the rubric's
///   band, writing `grade <question-hash> <grade>` per question; commits the
///   grading of that verdict and writes `graded <commit-id> <composed>`.
/// - fails: [`RunError::State`] when a state file cannot be read or the
///   transcript cannot be staged, [`RunError::Evidence`] when it cannot be
///   kept, as [`rulings`] fails, [`RunError::Random`] and [`RunError::Commit`]
///   when a receipt cannot be committed, and [`RunError::Output`] when standard
///   output cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests read every line of a grading all
///   refused, one met and one unmet, and the task holds each grading.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
async fn grade(
    on: Deciding<'_>,
    dispatch: CommitId,
    rubric: &Loaded<Rubric>,
    directory: &Path,
    judging: &Judging,
) -> Result<Graded, RunError>
{
    emit(&format_args!(
        "rubric {} {}\n",
        rubric.hash(),
        rubric.document().name()
    ))?;
    let transcript = rubric.document().transcript(directory)?;
    emit(&format_args!("transcript {}\n", transcript.digest()))?;
    let (names, questions): (Vec<_>, Vec<_>) = rubric
        .document()
        .questions()
        .iter()
        .map(|(name, question)| (name, question.clone()))
        .unzip();
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
    let unmet = names
        .iter()
        .zip(&grades)
        .find(|&(_name, &grade)| grade == Grade::Unmet)
        .map_or(Unmet::Nothing, |(name, _grade)| {
            Unmet::Question(name.to_string())
        });
    on.evidence.keep(transcript.staged())?;
    let verdict = Receipt::verdict(
        on.tree,
        dispatch,
        on.operator,
        rubric.hash(),
        transcript.digest(),
        answers,
    );
    let verdict = record(on.peer, on.tree, verdict).await?;
    emit(&format_args!("verdict {verdict}\n"))?;
    for &(question, grade) in &graded {
        emit(&format_args!("grade {question} {grade}\n"))?;
    }
    let grading = Receipt::graded(on.tree, verdict, grades, composed);
    let grading = record(on.peer, on.tree, grading).await?;
    emit(&format_args!("graded {grading} {composed}\n"))?;
    Ok(Graded { composed, unmet })
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
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests answer from an empty table and from a
///   table seeded met and unmet.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
async fn rulings(
    judging: &Judging,
    questions: &[Question],
    transcript: &Transcript,
) -> Result<Vec<(ContentHash, Ruling)>, RunError>
{
    match *judging {
        | Judging::Endpoint => {
            let config = Config::from_environment().map_err(RunError::Config)?;
            let client = ChatCompletions::new(config).map_err(RunError::Client)?;
            rule(&client, questions, transcript).await
        },
        | Judging::Table(ref path) => {
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
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests rule from a table that answers none of
///   a rubric's questions and from one that answers each.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
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
