//! Protocol admission of attested attempts, independently of receipt authority.
//!
//! Proof membership and protocol conformance are independent. `prove::play`
//! verifies the complete attempt range and returns ordered coordinates,
//! authors, commit identities and original receipt bytes. [`replay`] feeds
//! those moves to the arena monitor under the dispatch's edition: one slot and
//! decision channel per attempt, one judge channel per verdict and one runner
//! channel per runner. Unknown editions and invalid transitions are refused at
//! their `(attempt, seq)` with the movement named.
//!
//! Replay resolves grading and landing references only from earlier moves in
//! that attempt and projects admitted steps through `Current::record`. It
//! checks neither signed causal authority nor completeness against the task's
//! receipt tree. Omitting a move can leave a conformant play; historical
//! `index check` detects that omission when the task frontier is held.

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;

use anodized::spec;
use domhringr_arena_session::Arena;
use domhringr_arena_session::Channel;
use domhringr_arena_session::Choice;
use domhringr_arena_session::Movement;
use domhringr_arena_session::Play;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Current;
use domhringr_record_tree::Decision;
use domhringr_record_tree::Kind;
use domhringr_record_tree::Step;
use gandr_core_session::PayloadDigest;

use crate::AttemptNumber;
use crate::MoveKey;
use crate::SequenceNumber;
use crate::prove::Move;

/// A protocol-conformant attempt and its resolved original moves.
#[derive(Debug)]
pub struct Replayed
{
    /// The standing projected from admitted moves.
    pub current: Current,
    /// The moves in their attested order, ready for the replay line language.
    pub steps: Vec<(CommitId, Step)>,
}

/// A refused move retains its attested coordinate and its semantic cause.
#[derive(Debug, thiserror::Error)]
#[error("move {attempt}.{seq}: {reason}")]
pub struct Refusal
{
    /// The attempt in the attested dialogue.
    pub attempt: AttemptNumber,
    /// The move's position in that attempt.
    pub seq: SequenceNumber,
    /// The monitor or cross-channel refusal.
    pub reason: Reason,
}

/// A protocol refusal is distinct from a malformed cross-channel reference.
#[derive(Debug, thiserror::Error)]
pub enum Reason
{
    /// The attempt has no dispatch at sequence zero.
    #[error("dispatch missing at sequence zero")]
    Dispatch,
    /// The independent monitor refuses this named action.
    #[error(transparent)]
    Protocol(#[from] Box<domhringr_arena_session::Refusal>),
    /// The receipt cannot be resolved to a move of this dispatch.
    #[error("{0} names no preceding move of this dispatch")]
    Reference(Movement),
    /// A receipt outside the task's move language appears in the range.
    #[error("receipt is not a task move")]
    NotMove,
}

/// Why a whole attempt cannot be replayed.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError
{
    /// No move was attested in the requested attempt.
    #[error("absent attempt {0}")]
    Absent(AttemptNumber),
    /// The first inadmissible move, with its original coordinate.
    #[error(transparent)]
    Move(#[from] Refusal),
    /// The protocol arena could not be constructed.
    #[error(transparent)]
    Arena(#[from] Box<domhringr_arena_session::ArenaError>),
}

/// Replay an authenticated attempt through each channel's named protocol.
///
/// # Specification
/// - requires: `moves` is the ordered range returned by `prove::play` for
///   `attempt`; proof authentication remains separate from protocol admission.
/// - ensures: success contains exactly the supplied moves and their standing;
///   the dispatch's edition governs every channel without a default fallback.
/// - fails: an absent dispatch, non-move, unresolved cross-channel reference,
///   or monitor refusal is reported at the first failing coordinate.
/// - panics: none.
/// - intension: retains one prefix per channel; the monitor replays a prefix
///   per move because it has no resumable cursor.
///
/// # Errors
/// Returns `ReplayError` for an absent attempt, arena failure, or named move.
///
/// # Adequacy
/// - hypothesis: L2 the receipt fold supplies the lifecycle oracle; L3 forged
///   endings, unknown editions and repeated choices distinguish admission from
///   mere membership and channel isolation from a shared prefix.
/// - witness: `replay::tests::proved_attempts_replay_every_standing`
/// - witness: `replay::tests::proof_membership_does_not_admit_a_play`
#[spec(ensures: |ref output| output.as_ref().map_or(true, |replayed|
    replayed.steps.len() == moves.len()
    && replayed.steps.iter().zip(moves).all(|(step, movement)| step.0 == movement.1.commit)))]
#[inline]
pub fn replay(
    arena: &Arena,
    attempt: AttemptNumber,
    moves: &[(MoveKey, Move)],
) -> Result<Replayed, ReplayError>
{
    let Some(entry) = moves.first()
    else {
        return Err(ReplayError::Absent(attempt));
    };
    let first = &entry.1;
    let (number, seq) = entry.0.coordinates();
    let refused = |reason| Refusal {
        attempt: number,
        seq,
        reason,
    };
    let Kind::Dispatch { edition, .. } = *first.receipt.kind()
    else {
        return Err(refused(Reason::Dispatch).into());
    };
    if seq != SequenceNumber(0) {
        return Err(refused(Reason::Dispatch).into());
    }
    let mut slot = Play::new(Channel::Slot);
    let mut judges = BTreeMap::new();
    let mut runners = BTreeMap::new();
    let mut decision = Play::new(Channel::Decision);
    let mut related = BTreeMap::new();
    let mut result = Replayed {
        current: Current::Undispatched,
        steps: Vec::with_capacity(moves.len()),
    };
    for entry in moves {
        let movement = &entry.1;
        let (attempt, seq) = entry.0.coordinates();
        let refused = |reason| Refusal {
            attempt,
            seq,
            reason,
        };
        let action = action(movement.receipt.kind()).map_err(&refused)?;
        let channel = match *movement.receipt.kind() {
            | Kind::Verdict { .. } => judges
                .entry(movement.commit)
                .or_insert_with(|| Play::new(Channel::Judge)),
            | Kind::Graded { verdict, .. } => judges
                .entry(verdict)
                .or_insert_with(|| Play::new(Channel::Judge)),
            | Kind::Verified { runner, .. } => runners
                .entry(runner)
                .or_insert_with(|| Play::new(Channel::Runner)),
            | Kind::Decide { .. } | Kind::Landed { .. } => &mut decision,
            | _ => &mut slot,
        };
        let _progress = channel
            .record(
                arena,
                edition,
                action,
                PayloadDigest(*movement.commit.as_bytes()),
            )
            .map_err(|reason| refused(Reason::Protocol(reason)))?;
        let step = resolve(movement, &related).map_err(&refused)?;
        let dispatch = match step {
            | Step::Dispatch { .. } => movement.commit,
            | Step::Report { dispatch, .. }
            | Step::Handoff { dispatch, .. }
            | Step::Retire { dispatch, .. }
            | Step::Pause { dispatch, .. }
            | Step::Verdict { dispatch, .. }
            | Step::Verified { dispatch, .. }
            | Step::Graded { dispatch, .. }
            | Step::Decide { dispatch, .. }
            | Step::Landed { dispatch, .. } => dispatch,
        };
        if dispatch != first.commit {
            return Err(refused(Reason::Reference(action)).into());
        }
        result.current.record(movement.commit, &step);
        result.steps.push((movement.commit, step));
        let _previous = related.insert(movement.commit, movement);
    }
    Ok(result)
}

/// Name the endpoint action carried by a task receipt.
///
/// # Specification
/// - ensures: each task kind maps to its channel action; decisions retain their
///   branch rather than sharing an undifferentiated label.
/// - fails: receipts outside the move language return `Reason::NotMove`.
/// - panics: none.
///
/// # Errors
/// Returns `Reason::NotMove` for a non-task receipt.
///
/// # Adequacy
/// - hypothesis: L2 the full lifecycle exercises every channel; L3 rework and
///   abandon distinguish decision branches and their terminal state.
/// - witness: `replay::tests::proved_attempts_replay_every_standing`
/// - witness: `replay::tests::proof_membership_does_not_admit_a_play`
#[spec(ensures: |ref output| !matches!(kind, Kind::Dispatch { .. }) || matches!(output, Ok(Movement::Dispatch)))]
fn action(kind: &Kind) -> Result<Movement, Reason>
{
    Ok(match *kind {
        | Kind::Dispatch { .. } => Movement::Dispatch,
        | Kind::Report { .. } => Movement::Report,
        | Kind::Handoff { .. } => Movement::Handoff,
        | Kind::Retire { .. } => Movement::Retire,
        | Kind::Pause { .. } => Movement::Pause,
        | Kind::Verdict { .. } => Movement::Verdict,
        | Kind::Graded { .. } => Movement::Graded,
        | Kind::Verified { .. } => Movement::Verified,
        | Kind::Decide { ref decision, .. } => Movement::Decide(match *decision {
            | Decision::Land => Choice::Land,
            | Decision::Rework { .. } => Choice::Rework,
            | Decision::Abandon => Choice::Abandon,
        }),
        | Kind::Landed { .. } => Movement::Landed,
        | Kind::Indexed { .. }
        | Kind::Open { .. }
        | Kind::Grant { .. }
        | Kind::Note { .. }
        | Kind::Bind { .. }
        | Kind::Claim { .. }
        | Kind::Introduce { .. }
        | Kind::Present { .. }
        | Kind::Withdraw { .. } => return Err(Reason::NotMove),
    })
}

/// Resolve the original receipt's presentation fields without admitting it.
///
/// # Specification
/// - requires: moves and references are authenticated under one dialogue.
/// - ensures: fields come from the receipt or the verdict or decision it names.
/// - fails: non-moves, absent or wrong-kind references, and wrong grading
///   arity.
/// - panics: none.
///
/// # Errors
/// Returns `Reason::NotMove` or a named `Reason::Reference`.
///
/// # Adequacy
/// - hypothesis: L2 resolved receipt fields agree with the independent fold; L3
///   missing predecessors distinguish resolution from membership.
/// - witness: `replay::tests::proved_attempts_replay_every_standing`
/// - witness: `replay::tests::proof_membership_does_not_admit_a_play`
#[spec(ensures: |ref output| !matches!(movement.receipt.kind(), Kind::Dispatch { .. }) || matches!(output, Ok(Step::Dispatch { .. })))]
#[inline]
pub fn resolve(
    movement: &Move,
    related: &BTreeMap<CommitId, &Move>,
) -> Result<Step, Reason>
{
    let author = movement.author;
    Ok(match *movement.receipt.kind() {
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
            let verdict_move = related
                .get(&verdict)
                .ok_or(Reason::Reference(Movement::Graded))?;
            let Kind::Verdict {
                dispatch,
                rubric,
                ref answers,
                ..
            } = *verdict_move.receipt.kind()
            else {
                return Err(Reason::Reference(Movement::Graded));
            };
            if grades.len() != answers.len() {
                return Err(Reason::Reference(Movement::Graded));
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
            let decision = related
                .get(&decided)
                .ok_or(Reason::Reference(Movement::Landed))?;
            let Kind::Decide {
                dispatch, operator, ..
            } = *decision.receipt.kind()
            else {
                return Err(Reason::Reference(Movement::Landed));
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
        | Kind::Withdraw { .. } => return Err(Reason::NotMove),
    })
}
