//! Render authenticated original receipts in the existing replay language.

use alloc::collections::BTreeMap;
use core::fmt::Write as _;

use domhringr_record_index::AttemptNumber;
use domhringr_record_index::MoveKey;
use domhringr_record_index::SequenceNumber;
use domhringr_record_index::keyed::Keyed;
use domhringr_record_index::prove;
use domhringr_record_index::prove::Move;
use domhringr_record_index::prove::ProveError;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Kind;
use domhringr_record_tree::StepLine;

use super::Found;
use super::IndexError;
use super::Question;
use super::Reader;

/// Read the proved play of `at`'s attempt, every move of the bound tree.
///
/// # Specification
/// - ensures: the attempt's complete play, each move naming `tree`.
/// - fails: an attempt the task doesn't have, refused as `at` absent; a move of
///   another tree; or a proof that doesn't verify.
/// - panics: none.
/// - executable: none — the reads are proofs; the project-only witness observes
///   them.
///
/// # Errors
/// - [`IndexError`]: as above.
///
/// # Adequacy
/// - hypothesis: L1 — a project-only reader verifies every question.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
pub(super) async fn play(
    reader: &mut Reader,
    found: &Found,
    at: MoveKey,
) -> Result<Vec<(MoveKey, Move)>, IndexError>
{
    let (attempt, seq) = at.coordinates();
    let index = (1_u32 ..)
        .map(AttemptNumber)
        .zip(&found.claim.attempts)
        .find_map(|(number, &part)| (number == attempt).then_some(part));
    let Some(part) = index
    else {
        return Err(IndexError::MoveAbsent(attempt, seq));
    };
    let moves = prove::play(reader, Keyed::shared()?, attempt, part).await?;
    if let Some(first) = moves.first() {
        let actual = first.1.receipt.tree();
        if actual != found.tree {
            return Err(ProveError::Tree {
                expected: found.tree,
                actual,
            }
            .into());
        }
    }
    Ok(moves)
}

/// Answer a move, play or later-attempt question in the replay language.
///
/// # Specification
/// - ensures: move and play use the replay language; after reports none only
///   when the task has no later attempt; all receipts name the bound task.
/// - fails: a false proof, foreign task or unresolved move reference fails.
/// - panics: none.
/// - executable: none — proof queries and their network resources are
///   asynchronous effects; the project-only witness compares authenticated
///   output without acquiring task trees.
///
/// # Errors
/// - [`IndexError`]: proof, move language, transport or formatting refusal.
///
/// # Adequacy
/// - hypothesis: L1 — a project-only reader verifies all four questions.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
pub(super) async fn question(
    mut reader: Reader,
    found: &Found,
    question: Question,
    mut output: String,
) -> Result<(Reader, String), IndexError>
{
    match question {
        Question::Task(_name) | Question::Replay(_name) => Err(IndexError::Shape),
        Question::After(_name, attempt) => {
            let later = prove::later(&mut reader, Keyed::shared()?, &found.claim, attempt).await?;
            match later {
                prove::Later::None => writeln!(output, "after {attempt} none")?,
                prove::Later::Dispatch(movement) => {
                    writeln!(output, "after {attempt} {}", movement.commit)?;
                },
            }
            Ok((reader, output))
        },
        Question::Play(_name, attempt) => {
            let moves = play(&mut reader, found, MoveKey::new(attempt, SequenceNumber(0))).await?;
            let related = moves
                .iter()
                .map(|entry| (entry.1.commit, &entry.1))
                .collect();
            for entry in &moves {
                emit(&mut output, &entry.1, &related)?;
            }
            Ok((reader, output))
        },
        Question::Move(_name, key) => {
            let moves = play(&mut reader, found, key).await?;
            let (attempt, seq) = key.coordinates();
            let movement = moves
                .iter()
                .find(|entry| entry.0 == key)
                .ok_or(IndexError::MoveAbsent(attempt, seq))?;
            emit_with(&mut output, &movement.1, &moves)?;
            Ok((reader, output))
        },
    }
}

/// Render a move, resolving a grading or landing against its own play.
///
/// # Specification
/// trivial.
pub(super) fn emit_with(
    output: &mut String,
    movement: &Move,
    play: &[(MoveKey, Move)],
) -> Result<(), IndexError>
{
    let related = if matches!(
        movement.receipt.kind(),
        Kind::Graded { .. } | Kind::Landed { .. }
    ) {
        play.iter()
            .map(|entry| (entry.1.commit, &entry.1))
            .collect()
    }
    else {
        BTreeMap::new()
    };
    emit(output, movement, &related)
}

/// Resolve only presentation fields; proof membership is not fold admission.
///
/// # Specification
/// - ensures: each replay field comes from the authenticated move or the exact
///   verdict or decision it references; a non-move never prints as a move.
/// - fails: an absent, wrong-kind or wrong-arity reference is refused.
/// - panics: none.
/// - executable: none — the function is its own specification; the project-only
///   witness compares proved original identities with receipt replay.
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
    let step = domhringr_record_index::replay::resolve(movement, related)
        .map_err(|_reason| IndexError::Shape)?;
    write!(output, "{}", StepLine {
        commit: movement.commit,
        step: &step
    })?;
    Ok(())
}
