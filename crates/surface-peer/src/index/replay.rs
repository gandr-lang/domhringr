//! Replay range-proved attempts without acquiring the task's receipt tree.

use core::fmt::Write as _;

use domhringr_record_index::AttemptNumber;
use domhringr_record_index::IndexKind;
use domhringr_record_index::MoveKey;
use domhringr_record_index::SequenceNumber;
use domhringr_record_index::project::TaskEntry;
use domhringr_record_index::prove;
use domhringr_record_index::prove::Query;
use domhringr_record_index::replay;
use domhringr_record_index::stream::Request;
use domhringr_record_tree::Current;
use domhringr_record_tree::StepLine;

use super::IndexError;
use super::Reader;

/// Replay each attested attempt and compare the complete current value.
///
/// # Specification
/// - requires: `entry` was authenticated under the chosen project attestation.
/// - ensures: every attempt's complete range passes its dispatch's monitor; the
///   final standing equals the entry, including fields hidden by Display.
/// - fails: unheld task, invalid proof, absent attempt, named move refusal,
///   omitted later attempt, or a standing mismatch naming both values.
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
    entry: TaskEntry,
    mut output: String,
) -> Result<(Reader, String), IndexError>
{
    let TaskEntry::Held {
        tree,
        current,
        attempts,
        dialogue,
        ..
    } = entry
    else {
        return Err(IndexError::Unheld(entry.tree()));
    };
    let arena = domhringr_arena_session::Arena::new()
        .map_err(Box::new)
        .map_err(replay::ReplayError::from)?;
    let mut reached = Current::Undispatched;
    for number in 1 ..= attempts.0 {
        let attempt = AttemptNumber(number);
        let range = attempt.range()?;
        let request = Request {
            digest: dialogue,
            query: Query::Range(range),
        };
        let (next, answer) = reader.ask(&request, IndexKind::Dialogue).await?;
        reader = next;
        let moves = prove::play(&answer, dialogue, tree, attempt)?;
        if number == 1 {
            writeln!(output, "proved {dialogue} {}", reader.author)?;
        }
        let played = replay::replay(&arena, attempt, &moves)?;
        for entry in &played.steps {
            write!(output, "{}", StepLine {
                commit: entry.0,
                step: &entry.1
            })?;
        }
        writeln!(output, "replayed {attempt} {}", played.current)?;
        reached = played.current;
    }
    if let Ok(next) = attempts.next() {
        let request = Request {
            digest: dialogue,
            query: Query::Key(MoveKey::new(next, SequenceNumber(0)).owned()),
        };
        let (next, answer) = reader.ask(&request, IndexKind::Dialogue).await?;
        reader = next;
        let verified = answer.verify(dialogue, IndexKind::Dialogue, &request.query)?;
        if !matches!(prove::later(tree, &verified)?, prove::Later::None) {
            return Err(IndexError::Shape);
        }
        if attempts == AttemptNumber(0) {
            writeln!(output, "proved {dialogue} {}", reader.author)?;
        }
    }
    if current != reached {
        return Err(IndexError::Standing {
            claimed: Box::new(current),
            replayed: Box::new(reached),
        });
    }
    writeln!(output, "current {reached}")?;
    Ok((reader, output))
}
