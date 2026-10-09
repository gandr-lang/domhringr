//! Tasks: a tree read as a task — the operator's dispatch of a brief to a
//! seat, that seat's reports, handoffs and retirement, and the verdicts
//! judges rule on it — and where the task stands once its commits are
//! folded.
//!
//! A dispatch names the seat it puts in the task's slot and the brief
//! ([`Brief`]): an anchor, or the hash of the brief's content
//! ([`ContentHash`]), never the brief's text. The seat holding the slot
//! reports its content by hash with a one-line [`Summary`], passes the slot
//! to another key, or retires from it; each of those names the dispatch it
//! answers. Dispatches are attempts: the one last in canonical order is the
//! current attempt ([`Current`]), and what the task's view says of it — held,
//! reported, or stalled because its slot was retired without a report — is
//! read from the receipts alone, never from a clock. A judge's verdict names
//! the current dispatch, the rubric and the transcript by hash, and rules on
//! each question asked ([`Ruling`]); it is a step of the task and leaves the
//! attempt's standing as it was: which judge a task trusts, and what its
//! rulings decide, is the rubric's.
//!
//! [`ContentHash`]: crate::id::ContentHash

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;

use sedimentree_core::loose_commit::id::CommitId;

use crate::anchor::Anchor;
use crate::id::ContentHash;
use crate::id::PeerKey;
use crate::line::Field;
use crate::line::OneLine;
use crate::ruling::Ruling;

/// The longest summary, in bytes of UTF-8: a line a reader takes in at a
/// glance, the content carrying the rest.
const SUMMARY_BYTES: usize = 256;

/// What a dispatch hands its seat to work from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Brief
{
    /// The brief is what this anchor names.
    Anchor(Anchor),
    /// The brief is the content with this hash.
    Content(ContentHash),
}

impl fmt::Display for Brief
{
    /// Write the brief as `anchor <anchor>` or `content <hash>`.
    ///
    /// # Specification
    /// - ensures: one line with no newline: an anchor's backslashes and control
    ///   characters are escaped as a bind target's are.
    /// - panics: none.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Anchor(ref anchor) => {
                f.write_str("anchor ")?;
                write!(OneLine::new(f, Field::Last), "{anchor}")
            },
            | Self::Content(hash) => write!(f, "content {hash}"),
        }
    }
}

/// A report's summary: one line of UTF-8, neither empty nor longer than 256
/// bytes, holding no control character.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Summary(String);

impl FromStr for Summary
{
    type Err = ParseSummaryError;

    /// Read a summary from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the texts of 1 to 256 bytes holding no
    ///   control character, and keeps the text as written, so [`Display`]
    ///   writes it back.
    /// - fails: [`ParseSummaryError::Empty`] for the empty text,
    ///   [`ParseSummaryError::Long`] for more than 256 bytes, then
    ///   [`ParseSummaryError::Control`] for a control character, a newline or a
    ///   tab among them.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseSummaryError::Empty`]: the text is empty.
    /// - [`ParseSummaryError::Long`]: the text is longer than 256 bytes.
    /// - [`ParseSummaryError::Control`]: the text holds a control character.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — 1 and 256 bytes are accepted and 0 and 257 refused, a
    ///   newline, a tab and a bell are each refused as control characters, and
    ///   a multi-byte character counts its bytes.
    /// - witness: `task::tests::a_summary_is_one_short_line`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.is_empty() {
            return Err(ParseSummaryError::Empty);
        }
        if text.len() > SUMMARY_BYTES {
            return Err(ParseSummaryError::Long);
        }
        if text.chars().any(char::is_control) {
            return Err(ParseSummaryError::Control);
        }
        Ok(Self(text.into()))
    }
}

impl fmt::Display for Summary
{
    /// Write the summary as written.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Summary
{
    /// The summary's text, as written.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &str
    {
        &self.0
    }
}

/// Why a text is not a summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseSummaryError
{
    /// The text is empty.
    #[error("a summary is not empty")]
    Empty,
    /// The text is longer than the longest summary.
    #[error("a summary is {SUMMARY_BYTES} bytes at most")]
    Long,
    /// The text holds a control character, so it is not one line.
    #[error("a summary is one line holding no control character")]
    Control,
}

/// A receipt the fold admitted into a task, as the task records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step
{
    /// The author put `seat` in the task's slot to work from `brief`.
    Dispatch
    {
        /// The seat dispatched to.
        seat: PeerKey,
        /// What the seat works from.
        brief: Brief,
    },
    /// The slot's holder reported on `dispatch`.
    Report
    {
        /// The dispatch reported on.
        dispatch: CommitId,
        /// The holder who reported.
        author: PeerKey,
        /// The hash of the report's content.
        content: ContentHash,
        /// The report's summary.
        summary: Summary,
    },
    /// The slot's holder passed the slot of `dispatch` to `to`.
    Handoff
    {
        /// The dispatch whose slot passed.
        dispatch: CommitId,
        /// The holder who passed it.
        from: PeerKey,
        /// The holder it passed to.
        to: PeerKey,
    },
    /// The slot's holder retired from the slot of `dispatch`.
    Retire
    {
        /// The dispatch whose slot was retired from.
        dispatch: CommitId,
        /// The holder who retired.
        author: PeerKey,
    },
    /// The judge ruled on `dispatch`: each question asked about `transcript`
    /// under `rubric`, with its ruling.
    Verdict
    {
        /// The dispatch ruled on.
        dispatch: CommitId,
        /// The judge who ruled.
        judge: PeerKey,
        /// The hash of the rubric the questions come from.
        rubric: ContentHash,
        /// The hash of the transcript the questions were asked about.
        transcript: ContentHash,
        /// Each question's hash and its ruling, in the order asked.
        answers: Vec<(ContentHash, Ruling)>,
    },
}

/// Who a dispatch's slot is with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot
{
    /// This seat holds it.
    Held(PeerKey),
    /// Its last holder retired from it.
    Retired
    {
        /// The holder who retired.
        by: PeerKey,
        /// The retirement's commit.
        at: CommitId,
    },
}

/// Whether a dispatch is reported on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer
{
    /// No report on it was admitted.
    Awaited,
    /// This commit is the report on it admitted last in canonical order.
    Reported(CommitId),
}

/// The current attempt: the dispatch last in canonical order, its slot, and
/// its report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt
{
    /// The dispatch's commit.
    dispatch: CommitId,
    /// What the dispatch hands its seat; kept beside the dispatch's step so a
    /// reader of the attempt needs no walk of the steps.
    brief: Brief,
    /// Who the slot is with.
    slot: Slot,
    /// Whether the dispatch is reported on.
    answer: Answer,
}

impl Attempt
{
    /// The dispatch's commit.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn dispatch(&self) -> CommitId
    {
        self.dispatch
    }

    /// What the dispatch hands its seat.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn brief(&self) -> &Brief
    {
        &self.brief
    }

    /// Who the slot is with.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn slot(&self) -> Slot
    {
        self.slot
    }

    /// Whether the dispatch is reported on.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn answer(&self) -> Answer
    {
        self.answer
    }

    /// The seat the slot is with: its holder, or the holder who retired from
    /// it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn seat(&self) -> PeerKey
    {
        match self.slot {
            | Slot::Held(seat) | Slot::Retired { by: seat, .. } => seat,
        }
    }
}

/// Where a task stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "one per task, held in place, never collected: boxing the attempt would \
              allocate to save bytes no caller keeps"
)]
pub enum Current
{
    /// No dispatch was admitted.
    Undispatched,
    /// The current attempt.
    Attempt(Attempt),
}

/// A tree read as a task: the seat receipts the fold admitted, and the
/// current attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task
{
    /// The admitted dispatches, reports, handoffs and retirements, each with
    /// its commit, in canonical order.
    steps: Vec<(CommitId, Step)>,
    /// The current attempt.
    current: Current,
}

impl Task
{
    /// The task of a tree with no seat receipt.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn new() -> Self
    {
        Self {
            steps: Vec::new(),
            current: Current::Undispatched,
        }
    }

    /// The admitted dispatches, reports, handoffs and retirements, each with
    /// its commit, in canonical order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn steps(&self) -> &[(CommitId, Step)]
    {
        &self.steps
    }

    /// The current attempt, or that no dispatch was admitted.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn current(&self) -> &Current
    {
        &self.current
    }

    /// Record the admitted dispatch `commit` of `seat` to `brief`, the latest
    /// in canonical order so far.
    ///
    /// # Specification
    /// - ensures: the step is appended, and the dispatch is the current
    ///   attempt, its slot held by `seat` and its report awaited.
    /// - panics: none.
    pub(crate) fn dispatch(
        &mut self,
        commit: CommitId,
        seat: PeerKey,
        brief: Brief,
    )
    {
        self.current = Current::Attempt(Attempt {
            dispatch: commit,
            brief: brief.clone(),
            slot: Slot::Held(seat),
            answer: Answer::Awaited,
        });
        self.steps.push((commit, Step::Dispatch { seat, brief }));
    }

    /// Record the admitted `step` of `commit`: a report, a handoff, a
    /// retirement or a verdict.
    ///
    /// # Specification
    /// - ensures: the step is appended; when it answers the current attempt's
    ///   dispatch, a report makes `commit` the attempt's report, a handoff puts
    ///   its recipient in the slot, and a retirement retires the slot at
    ///   `commit`. A verdict changes no attempt, and a step answering an
    ///   earlier dispatch changes none either: a later dispatch superseded it.
    /// - panics: none.
    pub(crate) fn answer(
        &mut self,
        commit: CommitId,
        step: Step,
    )
    {
        if let Current::Attempt(ref mut attempt) = self.current {
            match step {
                | Step::Report { dispatch, .. } if dispatch == attempt.dispatch => {
                    attempt.answer = Answer::Reported(commit);
                },
                | Step::Handoff { dispatch, to, .. } if dispatch == attempt.dispatch => {
                    attempt.slot = Slot::Held(to);
                },
                | Step::Retire { dispatch, author } if dispatch == attempt.dispatch => {
                    attempt.slot = Slot::Retired {
                        by: author,
                        at: commit,
                    };
                },
                | Step::Dispatch { .. }
                | Step::Report { .. }
                | Step::Handoff { .. }
                | Step::Retire { .. }
                | Step::Verdict { .. } => {},
            }
        }
        self.steps.push((commit, step));
    }
}

impl fmt::Display for Task
{
    /// Write the task as lines: one per step in canonical order — `dispatch
    /// <commit> <seat> <brief>`, `report <commit> <dispatch> <author>
    /// <content> <summary>`, `handoff <commit> <dispatch> <from> <to>`,
    /// `retire <commit> <dispatch> <author>`, or `verdict <commit> <dispatch>
    /// <judge> <rubric> <transcript>` followed by `ruling <commit> <question>
    /// <ruling>` per question asked — then where it stands: `undispatched`,
    /// `reported <dispatch> <report>`, `stalled <dispatch> <retirement>` for a
    /// slot retired from without a report, or `dispatched <dispatch>
    /// <holder>`.
    ///
    /// # Specification
    /// - ensures: every line ends in a newline, and each step stays one line: a
    ///   brief's anchor and a summary have their backslashes escaped as a
    ///   note's are, a summary holds no control character, and a ruling is
    ///   written as one line ([`Ruling`]'s `Display`).
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a task with a dispatch by anchor, a handoff, a report
    ///   whose summary holds a backslash, a retirement, a verdict with a read
    ///   and an unread ruling and a second dispatch by content is printed and
    ///   compared line for line, and each standing is printed by a case of its
    ///   own.
    /// - witness: `fold::tests::a_task_prints_one_line_per_step_and_its_standing`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        for &(commit, ref step) in &self.steps {
            match *step {
                | Step::Dispatch { seat, ref brief } => {
                    writeln!(f, "dispatch {commit} {seat} {brief}")?;
                },
                | Step::Report {
                    dispatch,
                    author,
                    content,
                    ref summary,
                } => {
                    write!(f, "report {commit} {dispatch} {author} {content} ")?;
                    OneLine::new(f, Field::Last).write_str(summary.as_ref())?;
                    writeln!(f)?;
                },
                | Step::Handoff { dispatch, from, to } => {
                    writeln!(f, "handoff {commit} {dispatch} {from} {to}")?;
                },
                | Step::Retire { dispatch, author } => {
                    writeln!(f, "retire {commit} {dispatch} {author}")?;
                },
                | Step::Verdict {
                    dispatch,
                    judge,
                    rubric,
                    transcript,
                    ref answers,
                } => {
                    writeln!(
                        f,
                        "verdict {commit} {dispatch} {judge} {rubric} {transcript}"
                    )?;
                    for &(question, ref ruling) in answers {
                        writeln!(f, "ruling {commit} {question} {ruling}")?;
                    }
                },
            }
        }
        match self.current {
            | Current::Undispatched => writeln!(f, "undispatched"),
            | Current::Attempt(ref attempt) => {
                let dispatch = attempt.dispatch;
                match (attempt.answer, attempt.slot) {
                    | (Answer::Reported(report), _) => writeln!(f, "reported {dispatch} {report}"),
                    | (Answer::Awaited, Slot::Retired { at, .. }) => {
                        writeln!(f, "stalled {dispatch} {at}")
                    },
                    | (Answer::Awaited, Slot::Held(holder)) => {
                        writeln!(f, "dispatched {dispatch} {holder}")
                    },
                }
            },
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::ParseSummaryError;
    use super::Summary;

    #[test]
    fn a_summary_is_one_short_line()
    {
        for text in ["d", "done: all gates green", "größer", &"x".repeat(256)] {
            assert_eq!(
                text.parse::<Summary>().unwrap().to_string(),
                text,
                "the summary {text:?} reads back as written"
            );
        }
        assert_eq!(
            "".parse::<Summary>(),
            Err(ParseSummaryError::Empty),
            "the empty text"
        );
        for text in ["x".repeat(257), format!("{}ö", "x".repeat(255))] {
            assert_eq!(
                text.parse::<Summary>(),
                Err(ParseSummaryError::Long),
                "{} bytes are too many",
                text.len()
            );
        }
        for text in ["two\nlines", "a\ttab", "a bell \u{7}"] {
            assert_eq!(
                text.parse::<Summary>(),
                Err(ParseSummaryError::Control),
                "the control character in {text:?}"
            );
        }
    }
}
