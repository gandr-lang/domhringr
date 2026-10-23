//! Replay proved attempts without acquiring the task's receipt tree.

use core::fmt::Write as _;

use domhringr_record_index::AttemptNumber;
use domhringr_record_index::MoveKey;
use domhringr_record_index::SequenceNumber;
use domhringr_record_index::keyed::Standing;
use domhringr_record_index::replay;
use domhringr_record_tree::Current;
use domhringr_record_tree::StepLine;

use super::Found;
use super::IndexError;
use super::Reader;
use super::render;

/// Replay each attested attempt and compare the standing's kind.
///
/// # Specification
/// - requires: `found` was read from the chosen attestation's store.
/// - ensures: every attempt's complete play passes its dispatch's monitor; the
///   kind of the final standing equals the task's.
/// - fails: invalid proof, named move refusal, or a standing mismatch naming
///   both values.
/// - panics: none.
/// - executable: none — authentication and comparison span asynchronous proof
///   requests; process witnesses observe the remote reader's full outcome.
///
/// # Errors
/// Returns `IndexError` preserving proof, protocol and standing boundaries.
///
/// # Adequacy
/// - hypothesis: L2 project-only processes agree with each lifecycle standing;
///   L3 dishonest but authenticated plays separate proof and protocol checks.
/// - witness: `index::tests::a_project_only_reader_replays_every_standing`
/// - witness: `index::tests::attested_plays_are_refused_at_the_move`
pub(super) async fn answer(
    mut reader: Reader,
    found: Found,
    mut output: String,
) -> Result<(Reader, String), IndexError>
{
    let arena = domhringr_arena_session::Arena::new()
        .map_err(Box::new)
        .map_err(replay::ReplayError::from)?;
    let mut reached = Current::Undispatched;
    let attempts = found.claim.attempts.len();
    for number in (1_u32 ..).map(AttemptNumber).take(attempts) {
        let moves =
            render::play(&mut reader, &found, MoveKey::new(number, SequenceNumber(0))).await?;
        let played = replay::replay(&arena, number, &moves)?;
        for entry in &played.steps {
            write!(output, "{}", StepLine {
                commit: entry.0,
                step: &entry.1
            })?;
        }
        writeln!(output, "replayed {number} {}", played.current)?;
        reached = played.current;
    }
    if found.claim.standing != Standing::of(&reached) {
        return Err(IndexError::Standing {
            claimed: found.claim.standing,
            replayed: Box::new(reached),
        });
    }
    writeln!(output, "current {reached}")?;
    Ok((reader, output))
}
