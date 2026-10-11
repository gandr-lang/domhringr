//! Render authenticated original receipts in the existing replay language.

use alloc::collections::BTreeMap;
use core::fmt::Write as _;

use domhringr_record_index::AttemptNumber;
use domhringr_record_index::IndexKind;
use domhringr_record_index::MoveKey;
use domhringr_record_index::SequenceNumber;
use domhringr_record_index::prove;
use domhringr_record_index::prove::Move;
use domhringr_record_index::prove::Query;
use domhringr_record_index::prove::Verified;
use domhringr_record_index::stream::Request;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::Kind;
use domhringr_record_tree::Step;
use domhringr_record_tree::StepLine;
use domhringr_record_tree::TreeId;
use gandr_storage_records::Record;

use super::IndexError;
use super::Question;
use super::Reader;

/// Verify the dialogue answer before interpreting or printing any of its moves.
///
/// # Specification
/// - ensures: move and play use the replay language; after reports none only
///   when absence has no successor; all receipts name the selected task.
/// - fails: a false proof, foreign task or unresolved move reference fails.
/// - panics: none.
///
/// # Errors
/// - [`IndexError`]: proof, move language, transport or formatting refusal.
///
/// # Adequacy
/// - hypothesis: L1 — a project-only reader verifies all four questions.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
pub(super) async fn question(
    reader: Reader,
    tree: TreeId,
    digest: IndexDigest,
    question: Question,
    mut output: String,
) -> Result<(Reader, String), IndexError>
{
    let query = match question {
        | Question::Task(ref _name) => return Err(IndexError::Shape),
        | Question::Move(ref _name, key) => Query::Key(key.owned()),
        | Question::Play(ref _name, attempt) => {
            let range = attempt.range()?;
            Query::Range(range)
        },
        | Question::After(ref _name, attempt) => {
            let next = attempt.next()?;
            Query::Key(MoveKey::new(next, SequenceNumber(0)).owned())
        },
    };
    let request = Request { digest, query };
    let (reader, answer) = reader.ask(&request, IndexKind::Dialogue).await?;
    let verified = answer.verify(digest, IndexKind::Dialogue, &request.query)?;
    writeln!(output, "proved {digest} {}", reader.author)?;
    match question {
        | Question::Task(_name) => Err(IndexError::Shape),
        | Question::After(_name, attempt) => {
            let later = prove::later(tree, &verified)?;
            match later {
                | prove::Later::None => writeln!(output, "after {attempt} none")?,
                | prove::Later::Dispatch(movement) => {
                    writeln!(output, "after {attempt} {}", movement.commit)?;
                },
            }
            Ok((reader, output))
        },
        | Question::Play(_name, _attempt) => {
            let Verified::Range(records) = verified
            else {
                return Err(IndexError::Shape);
            };
            let moves = moves(tree, &records)?;
            let related = moves
                .iter()
                .map(|movement| (movement.commit, movement))
                .collect();
            for movement in &moves {
                emit(&mut output, movement, &related)?;
            }
            Ok((reader, output))
        },
        | Question::Move(_name, key) => {
            let value = match verified {
                | Verified::Present(value) => value,
                | Verified::Absent(_evidence) => {
                    let (attempt, seq) = key.coordinates();
                    return Err(IndexError::MoveAbsent(attempt, seq));
                },
                | Verified::Range(_records) => return Err(IndexError::Shape),
            };
            let movement = prove::read_move(tree, value)?;
            self::movement(reader, tree, digest, key, movement, output).await
        },
    }
}

/// Render an authenticated move, proving context only for indirect fields.
///
/// # Specification
/// - ensures: grading and landing context comes from the same attested attempt;
///   direct moves need no second membership request.
/// - fails: malformed references, proofs or transport are refused.
/// - panics: none.
///
/// # Errors
/// - [`IndexError`]: proof, reference or output failure.
///
/// # Adequacy
/// - hypothesis: L1 — a project-only reader obtains the original move line.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
/// - witness: `index::tests::a_transcript_resolves_to_its_verdict_by_proof`
pub(super) async fn movement(
    reader: Reader,
    tree: TreeId,
    digest: IndexDigest,
    key: MoveKey,
    movement: Move,
    mut output: String,
) -> Result<(Reader, String), IndexError>
{
    if matches!(
        movement.receipt.kind(),
        Kind::Graded { .. } | Kind::Landed { .. }
    ) {
        let (attempt, _seq) = key.coordinates();
        let (reader, context) = play(reader, tree, digest, attempt).await?;
        let related = context
            .iter()
            .map(|movement| (movement.commit, movement))
            .collect();
        emit(&mut output, &movement, &related)?;
        Ok((reader, output))
    }
    else {
        emit(&mut output, &movement, &BTreeMap::new())?;
        Ok((reader, output))
    }
}

/// Read the authenticated context needed by an indirect move reference.
///
/// # Specification
/// trivial.
async fn play(
    reader: Reader,
    tree: TreeId,
    digest: IndexDigest,
    attempt: AttemptNumber,
) -> Result<(Reader, Vec<Move>), IndexError>
{
    let range = attempt.range()?;
    let request = Request {
        digest,
        query: Query::Range(range),
    };
    let (reader, answer) = reader.ask(&request, IndexKind::Dialogue).await?;
    let Verified::Range(records) = answer.verify(digest, IndexKind::Dialogue, &request.query)?
    else {
        return Err(IndexError::Shape);
    };
    let moves = moves(tree, &records)?;
    Ok((reader, moves))
}

/// Decode range values with the same tree check used for a single-key answer.
///
/// # Specification
/// trivial.
fn moves(
    tree: TreeId,
    records: &[Record],
) -> Result<Vec<Move>, IndexError>
{
    records
        .iter()
        .map(|record| prove::read_move(tree, record.value()).map_err(IndexError::from))
        .collect()
}

/// Resolve only presentation fields; proof membership is not fold admission.
///
/// # Specification
/// - ensures: each replay field comes from the authenticated move or the exact
///   verdict or decision it references; a non-move never prints as a move.
/// - fails: an absent, wrong-kind or wrong-arity reference is refused.
/// - panics: none.
///
/// # Errors
/// - [`IndexError::Shape`]: an unresolved or non-move receipt.
/// - [`IndexError::Format`]: the output sink refused text.
///
/// # Adequacy
/// - hypothesis: L1 — proved moves print the same original identities as
///   replay.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
fn emit(
    output: &mut String,
    movement: &Move,
    related: &BTreeMap<CommitId, &Move>,
) -> Result<(), IndexError>
{
    let author = movement.author;
    let step = match *movement.receipt.kind() {
        | Kind::Dispatch {
            seat,
            edition,
            ref brief,
        } => Step::Dispatch {
            seat,
            edition,
            brief: brief.clone(),
        },
        | Kind::Report {
            dispatch,
            content,
            ref summary,
        } => Step::Report {
            dispatch,
            content,
            author,
            summary: summary.clone(),
        },
        | Kind::Handoff { dispatch, to } => Step::Handoff {
            dispatch,
            from: author,
            to,
        },
        | Kind::Retire { dispatch } => Step::Retire { dispatch, author },
        | Kind::Pause { dispatch } => Step::Pause { dispatch, author },
        | Kind::Verdict {
            dispatch,
            judge,
            rubric,
            transcript,
            ref answers,
        } => Step::Verdict {
            dispatch,
            judge,
            rubric,
            transcript,
            answers: answers.clone(),
        },
        | Kind::Verified {
            dispatch,
            runner,
            playbook,
            ref step,
            output,
            status,
        } => Step::Verified {
            dispatch,
            runner,
            playbook,
            step: step.clone(),
            output,
            status,
        },
        | Kind::Graded {
            verdict,
            ref grades,
            composed,
        } => {
            let verdict_move = related.get(&verdict).ok_or(IndexError::Shape)?;
            let Kind::Verdict {
                dispatch,
                rubric,
                ref answers,
                ..
            } = *verdict_move.receipt.kind()
            else {
                return Err(IndexError::Shape);
            };
            if grades.len() != answers.len() {
                return Err(IndexError::Shape);
            }
            let grades = answers
                .iter()
                .zip(grades)
                .map(|(answer, grade)| (answer.0, *grade))
                .collect();
            Step::Graded {
                dispatch,
                verdict,
                rubric,
                grades,
                composed,
            }
        },
        | Kind::Decide {
            dispatch,
            operator,
            ref decision,
        } => Step::Decide {
            dispatch,
            operator,
            decision: decision.clone(),
        },
        | Kind::Landed { decided, merge } => {
            let decision = related.get(&decided).ok_or(IndexError::Shape)?;
            let Kind::Decide {
                dispatch, operator, ..
            } = *decision.receipt.kind()
            else {
                return Err(IndexError::Shape);
            };
            Step::Landed {
                dispatch,
                decided,
                operator,
                merge,
            }
        },
        | Kind::Indexed { .. }
        | Kind::Open { .. }
        | Kind::Grant { .. }
        | Kind::Note { .. }
        | Kind::Bind { .. }
        | Kind::Claim { .. }
        | Kind::Introduce { .. }
        | Kind::Present { .. }
        | Kind::Withdraw { .. } => return Err(IndexError::Shape),
    };
    write!(output, "{}", StepLine {
        commit: movement.commit,
        step: &step
    })?;
    Ok(())
}
