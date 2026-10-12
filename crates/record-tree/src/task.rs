//! Tasks: a tree read as a task — the operator's dispatch of a brief to a
//! seat, that seat's reports, handoffs and retirement, the verdicts judges
//! rule on it, the verifications runners record on it, the gradings of its
//! verdicts, and the operator's decisions and landings — and where the task
//! stands once its commits are folded.
//!
//! A dispatch names the seat it puts in the task's slot and the brief
//! ([`Brief`]): an anchor, or the hash of the brief's content
//! ([`ContentHash`]), never the brief's text. The seat holding the slot
//! reports its content by the identity of its value manifest
//! ([`ManifestDigest`]) with a one-line [`Summary`], passes the slot to
//! another key, or retires from it; each of those names the dispatch it
//! answers. Dispatches are attempts: the one last in canonical order is the
//! current attempt ([`Current`]), and what the task's view says of it — held,
//! reported, or stalled because its slot was retired without a report — is
//! read from the receipts alone, never from a clock. A judge's verdict names
//! the current dispatch, the rubric by hash and the transcript by its
//! manifest, and rules on each question asked ([`Ruling`]); a runner's
//! verification names the current dispatch, the playbook by hash, the step
//! by its identifier ([`StepId`]), the verifier's output by its manifest and
//! how its process ended ([`Status`]); a grading names a verdict and grades
//! each of its answers ([`Grade`]); the operator's decision names the current
//! dispatch and what is decided of it ([`Decision`]), and a landing the
//! decision to land it carries out and the revision the change landed at
//! ([`Revision`]). Each is a step of the task. A verdict moves the attempt no
//! further; a verification, a grading, a decision and a landing each advance
//! its [`Progress`], which ranks them in that order and never falls back:
//! which judge or runner a task trusts, and what its checks decide, is the
//! playbook's, the rubric's and the operator's.
//!
//! [`ContentHash`]: crate::id::ContentHash
//!
//! # Tasks
//!
//! A tree is also a task. A `Dispatch { seat, edition, brief }` names the peer
//! that is to act and the brief it acts on — an anchor, or a content hash; a
//! `Report { dispatch, content, summary }` answers a dispatch with the manifest
//! digest of what the seat produced, kept as evidence, and a one-line summary
//! of at most 256 bytes; a `Handoff { dispatch, to }` moves the dispatch's slot
//! to another peer; a `Retire { dispatch }` gives the slot up. `View::task`
//! holds every admitted seat receipt in canonical order and the current attempt
//! — the admitted dispatch last in canonical order, its slot, held or retired,
//! its answer, awaited or reported, and its progress past the report, as the
//! decisions below state it — and prints as one line per step and one saying
//! where the task stands: `undispatched`; for an attempt checked past its
//! report, `verified <dispatch> <verification>`, `graded <dispatch> <grading>
//! <composed>`, `decided <dispatch> <decision-commit> <decision>` or `landed
//! <dispatch> <landing> <revision>`; otherwise `dispatched <dispatch>
//! <holder>`, `reported <dispatch> <report>` or `stalled <dispatch>
//! <retirement>`.
//!
//! **Causal authority and protocol conformance are independent conditions.**
//! The owner or a member may dispatch; only the causal holder of the current
//! dispatch may report, hand off, retire or pause. The fold also replays each
//! dispatch's accepted canonical prefix through the Seat session type of
//! `domhringr-arena-session`. Report is required before handoff or retirement,
//! and either ending closes the endpoint. A protocol refusal names the move,
//! expected action and endpoint index. It precedes the authority refusal for
//! that candidate; probing an unauthorized move never advances the play.
//!
//! - the canonical-order latest dispatch instead of the causal one: a report
//!   written before a concurrent dispatch arrived would be refused by where the
//!   dispatch sorts, not by what its author saw.
//! - a second receipt automaton embedded in the fold: its protocol could drift
//!   from the arena and the kernel-certified widening.
//!
//! Reversal: a dispatch that names several seats or slots, which needs a slot
//! per seat in the course.
//!
//! **Silence does not end a play.** The record names no time. A dispatch
//! without a report stays open; retirement before the first report is a named
//! protocol refusal, not an inferred stall. Whether abandonment should be an
//! explicit widening is a protocol decision, not a timeout or a default in the
//! fold.
//!
//! Every dispatch names its numeric protocol edition. Edition 1 requires
//! dispatch → report⁺ → handoff or retire; edition 2 also permits `Pause {
//! dispatch }`, retaining the holder and report phase without suspending a
//! process. A peer refuses every slot move under an uncompiled edition by
//! number, never under its own latest protocol. Editionless dispatches denote
//! edition 1; their pause and ordering refusals remain refusals.
//! `View::transport(dispatch, target)` locally derives and kernel-checks
//! transport of the complete admitted play between named editions without
//! changing receipts. Pause occupies tag `0x12`.
//!
//! Every task channel replays through the monitor under that edition: judge per
//! verdict, runner per runner and dispatch, operator decision per dispatch. The
//! judge sends one verdict and one grading; the runner may verify repeatedly;
//! the operator chooses once, with only land continuing to a landing. Under a
//! current dispatch, missing causal predecessors replay on empty channels.
//! Duplicate grading, decision and landing receipts are refused as `protocol
//! edition <edition> <move> <reason>`, naming the offending move. Canonical
//! order chooses between concurrent candidates; a refused candidate consumes no
//! channel state. Authorship, grading contents and the relation to the current
//! dispatch remain fold checks.
//!
//! `Current::record` projects an already admitted step into the current
//! standing, preserving the dispatch, slot, answer and progress precedence. The
//! receipt fold and attested-index replay share this projection; it establishes
//! neither authority nor protocol conformance on its own.
//!
//! **A receipt names evidence by its value manifest and carries no bytes.** A
//! report's content, a verdict's transcript and a verification's output are
//! committed into gandr's value plane as chunk DAGs, and the receipt names each
//! by its `ManifestDigest`: the BLAKE3 digest of the manifest, which binds the
//! root, the length and the profile the value was cut under.
//! `domhringr-record-evidence` holds the bytes beside the tree store and reads
//! them back by that digest, from its own store or fetched from the peer that
//! holds them; `Task::evidence` lists every digest a task names with that peer
//! — a report's author, a verdict's judge, a verification's runner — in
//! canonical order. The tree records what was produced; the evidence plane
//! holds it, so an operator on another machine reads what it judges.
//!
//! - the bytes in the receipt: a tree grows with every artifact, and a sync
//!   carries what only a reader of that artifact needs.
//! - the BLAKE3 hash of the flat bytes: names the bytes but resolves through
//!   nothing the record can reach, and a reader can check them only whole.
//!
//! Reversal: a change to the value plane's manifest identity, which needs a new
//! receipt version naming the new one.
//!
//! **A judge's verdict is admitted from the judge alone, on the current
//! dispatch, judged in the receipt's causal past.** A `Verdict { dispatch,
//! judge, rubric, transcript, answers }` names the judge, the BLAKE3 hash of
//! the rubric its questions come from, the manifest digest of the transcript it
//! read, kept as evidence, and one ruling per question, each question named by
//! its hash, in the order asked. A ruling is `read <letter> A=<p> B=<p> …
//! outside=<p>` — the answer, each option's probability, summing to one, and
//! the mass the judge put outside the options — or `unread <reason>`: `no
//! letter`, `outside`, `tied`, `endpoint` or `malformed`. A verdict whose
//! author is not the judge it names is refused `not judge`, one on another
//! dispatch `not current`; an admitted verdict is a step of the task, printed
//! `verdict <commit> <dispatch> <judge> <rubric> <transcript>` and one `ruling
//! <commit> <question> <ruling>` line per question, and changes no attempt: a
//! ruling informs the operator, who acts on it with a receipt of their own.
//!
//! - a judge granted by the tree: the operator chooses the judge by acting on
//!   its verdict, so the fold checks only that the judge speaks for itself.
//! - a verdict as a report: a report answers the dispatch, and the seat alone
//!   answers it.
//! - a ruling that defaults an unread question to a letter: a judge that did
//!   not answer would read as one that did.
//!
//! Reversal: a verdict that settles the task — accepting or reopening the
//! attempt — which needs the judge's authority in the course.
//!
//! **A runner's verification is admitted from the runner alone, on the current
//! dispatch.** A `Verified { dispatch, runner, playbook, step, output, status
//! }` records that the runner ran a playbook step's verifier on the dispatch:
//! the BLAKE3 hash of the playbook, the step's identifier in it (`StepId`: 1 to
//! 64 lowercase ASCII letters, digits and hyphens, beginning with a letter),
//! the manifest digest of what the process wrote to its output and error
//! streams, kept as evidence, and how the process ended (`Status`): `exit
//! <code>` or `signal <number>`. A verification whose author is not the runner
//! it names is refused `not runner`, one on another dispatch `not current`; an
//! admitted one is a step of the task, printed `verified <commit> <dispatch>
//! <runner> <playbook> <step> <output> <status>`, and advances the attempt to
//! verified: a failing verifier is recorded as it ended, and the operator acts
//! on it.
//!
//! - the step without its playbook: a step's identifier names it only within
//!   its playbook, so two playbooks' `test` steps would read as one check.
//! - a pass or fail flag: a process ended by a signal would read as one that
//!   failed its check, and what a nonzero code means is the verifier's to say.
//! - the output's bytes in the receipt: the receipt grows with every run, as a
//!   report's would.
//!
//! Reversal: a check that reads the output and error streams apart, which needs
//! a digest per stream.
//!
//! **A verdict is graded once, by its judge.** `Graded { verdict, grades,
//! composed }` names the verdict and one `Grade` per answer in its order:
//! `met`, `unmet`, `undecided`, or `refused` exactly for an unread ruling. The
//! rubric and question identities come from the verdict. The judge channel
//! requires the verdict in the grading's causal past and refuses a second
//! grading by name. Wrong authorship is `not judge`, wrong answer shape
//! `misgraded`, wrong composition `miscomposed`, and a superseded dispatch `not
//! current`.
//!
//! **Composition is checked from the receipt alone.** `compose` lives beside
//! `Grade`, shared by writers and the fold without an added dependency. Any
//! unmet grade makes the conjunction unmet; otherwise any refused grade makes
//! it refused; otherwise any undecided grade makes it undecided; otherwise it
//! is met, including the empty composition. Refused gradings remain in the DAG
//! without advancing the task; `open` prints their commit anchors and
//! `miscomposed`. An admitted grading is a task step naming its dispatch,
//! verdict, rubric, question grades and composition.
//!
//! - the task and the rubric in the grading: a second statement of what the
//!   verdict records, free to disagree with it.
//! - the grades inside the verdict: the readout and its classification would
//!   lose their separate receipt identities.
//! - a grading from any member: two keys could grade one verdict differently,
//!   and the grades would not be the asking key's.
//! - the fold recomputing individual grades: it needs the rubric's band, which
//!   is not in the record.
//!
//! Reversal: a reader holding the rubric as evidence can also check each grade
//! against its band. Rubrics with a rule other than conjunction require that
//! rule to be named in the record before the fold can check it.
//!
//! **One operator decision binds each dispatch.** `Decide { dispatch, operator,
//! decision }` selects `land`, `rework <reason>` or `abandon`. The operator is
//! the owner or a granted member, and signs the key the receipt names. The
//! monitor refuses a second choice, including one concurrent with the first.
//! Rework and abandon end this decision channel; land requires one later
//! landing. A changed mind requires a fresh dispatch. Missing operator
//! authority is `no authority`, wrong identity `not operator`, and another
//! dispatch `not current`.
//!
//! The tree identifies the task; the decision names its dispatch. `Verdict`
//! names the judge's receipt, while `decision` names the operator's choice.
//!
//! - the signer alone, no operator field: the decision would say who made it
//!   only through the commit, unlike every other ruling the fold admits from
//!   the key it names.
//! - the decision as a verdict or a grading: a judge rules and grades, and its
//!   key holds no authority over the attempt; deciding on those readings is the
//!   operator's act.
//! - repeated decisions on one dispatch: competing choices would overwrite one
//!   another rather than bind once.
//!
//! Reversal: an explicit reconsideration protocol, with independently checked
//! widening and a specified relation to the original choice.
//!
//! **A landing carries out its operator's one decision to land.** `Landed {
//! decided, merge }` names that decision and the repository revision after
//! landing: a merge commit or a fast-forwarded change, represented by
//! `Revision` as 20 or 32 bytes. The decision channel refuses landing without a
//! causal decision, after rework or abandon, and after an earlier landing.
//! Every order refusal names `landed`. Wrong authorship remains `not operator`,
//! and a superseded dispatch `not current`. An admitted landing records its
//! dispatch, decision, operator and revision as a task step.
//!
//! The landing names the decision commit, retaining the exact choice it carries
//! out.
//!
//! - the landing naming only the task or dispatch: it would omit the specific
//!   admitted choice it carries out.
//! - a landing from any operator: two operators could land one decision, and
//!   the landing would not be the deciding key's.
//! - the revision as text: a second spelling of a fixed-width id, and a parser
//!   in the decoder.
//! - the repository or the branch in the receipt: where the repository lives is
//!   the operator's configuration, never the record's.
//!
//! Reversal: a repository the record can reach, when the fold checks that the
//! revision holds the reported change.
//!
//! **An attempt's progress only advances.** Verification, grading, decision and
//! landing rank in that order. Within a rank the latest admitted step in
//! canonical order holds; a lower rank cannot undo a higher one. Verification
//! after grading leaves the attempt graded. A verdict moves nothing until
//! graded. Second decisions and landings are refused rather than ranked. A
//! fresh dispatch starts an unchecked attempt.
//!
//! - the latest of any kind: a verifier run after a landing would read the task
//!   as no longer landed.
//! - one standing per kind: a reader would rebuild the lifecycle the fold
//!   already orders.
//!
//! Reversal: a lifecycle that goes back — a landing reverted — which needs a
//! receipt that undoes a step and a rank to fall to.

mod codec;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;

use anodized::spec;
use gandr_storage_values::ManifestDigest;
use sedimentree_core::loose_commit::id::CommitId;

use crate::anchor::Anchor;
use crate::check::Grade;
use crate::check::Status;
use crate::check::StepId;
use crate::decision::Decision;
use crate::decision::Revision;
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
    /// - executable: none — the formatter is write-only; the replay fixture
    ///   observes line boundaries and escaped fields.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the task replay fixture compares both brief forms and
    ///   escaped anchor text.
    /// - witness: `fold::tests::a_task_prints_one_line_per_step_and_its_standing`
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
    #[spec(ensures: |ref output| output.as_ref().map_or(true, |summary| summary.as_ref() == text))]
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
        /// The protocol named by this dispatch.
        edition: crate::Edition,
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
        /// The report's content, by its value manifest.
        content: ManifestDigest,
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
    /// The holder paused work without changing the slot.
    Pause
    {
        /// The dispatch paused.
        dispatch: CommitId,
        /// The holder who paused.
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
        /// The transcript the questions were asked about, by its value
        /// manifest.
        transcript: ManifestDigest,
        /// Each question's hash and its ruling, in the order asked.
        answers: Vec<(ContentHash, Ruling)>,
    },
    /// The runner ran the verifier of `step` of `playbook` on `dispatch`:
    /// the process wrote `output` and ended with `status`.
    Verified
    {
        /// The dispatch the step was run on.
        dispatch: CommitId,
        /// The runner who ran it.
        runner: PeerKey,
        /// The hash of the playbook the step belongs to.
        playbook: ContentHash,
        /// The step whose verifier ran.
        step: StepId,
        /// The process's output, by its value manifest.
        output: ManifestDigest,
        /// How the process ended.
        status: Status,
    },
    /// The judge of `verdict` graded its answers against the band of the
    /// rubric it ruled under.
    Graded
    {
        /// The dispatch the verdict ruled on.
        dispatch: CommitId,
        /// The verdict graded.
        verdict: CommitId,
        /// The hash of the rubric the verdict ruled under.
        rubric: ContentHash,
        /// Each question's hash and its grade, in the verdict's order.
        grades: Vec<(ContentHash, Grade)>,
        /// The grades composed across the rubric.
        composed: Grade,
    },
    /// The operator decided the attempt `dispatch` made.
    Decide
    {
        /// The dispatch decided.
        dispatch: CommitId,
        /// The operator who decided.
        operator: PeerKey,
        /// What was decided.
        decision: Decision,
    },
    /// The operator carried out `decided`, a decision to land the change of
    /// `dispatch`: the repository's default branch stood at `merge` once the
    /// change was in.
    Landed
    {
        /// The dispatch whose change landed.
        dispatch: CommitId,
        /// The decision carried out.
        decided: CommitId,
        /// The operator who decided it, and landed it.
        operator: PeerKey,
        /// The revision the change landed at.
        merge: Revision,
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

/// How far an attempt has gone past its report.
///
/// The furthest of the verifications, gradings, decisions and landings
/// admitted on its dispatch, ranked in that order, and within the furthest
/// rank the one last in canonical order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress
{
    /// No verification, grading, decision or landing names the dispatch.
    Unchecked,
    /// A verifier ran on the dispatch: this verification.
    Verified(CommitId),
    /// A verdict on the dispatch was graded: this grading, composed so.
    Graded
    {
        /// The grading's commit.
        grading: CommitId,
        /// Its grades composed across the rubric.
        composed: Grade,
    },
    /// The operator decided the dispatch: this decision.
    Decided
    {
        /// The decision's commit.
        decide: CommitId,
        /// What was decided.
        decision: Decision,
    },
    /// The dispatch's change landed: this landing, at this revision.
    Landed
    {
        /// The landing's commit.
        landed: CommitId,
        /// The revision the change landed at.
        merge: Revision,
    },
}

impl Progress
{
    /// Where the progress ranks: unchecked, then verified, graded, decided
    /// and landed.
    ///
    /// # Specification
    /// trivial.
    const fn rank(&self) -> Rank
    {
        match *self {
            | Self::Unchecked => Rank::Unchecked,
            | Self::Verified(_) => Rank::Verified,
            | Self::Graded { .. } => Rank::Graded,
            | Self::Decided { .. } => Rank::Decided,
            | Self::Landed { .. } => Rank::Landed,
        }
    }
}

/// The rank of a [`Progress`], in the order an attempt advances through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Rank
{
    /// Nothing past the report.
    Unchecked,
    /// A verification.
    Verified,
    /// A grading.
    Graded,
    /// A decision.
    Decided,
    /// A landing.
    Landed,
}

/// The current attempt: the dispatch last in canonical order, its slot, its
/// report, and how far past it the attempt has gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt
{
    /// The dispatch's commit.
    dispatch: CommitId,
    /// The protocol named by this dispatch.
    edition: crate::Edition,
    /// What the dispatch hands its seat; kept beside the dispatch's step so a
    /// reader of the attempt needs no walk of the steps.
    brief: Brief,
    /// Who the slot is with.
    slot: Slot,
    /// Whether the dispatch is reported on.
    answer: Answer,
    /// How far the attempt has gone past its report.
    progress: Progress,
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

    /// The protocol under which this attempt replays.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn edition(&self) -> crate::Edition
    {
        self.edition
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

    /// How far the attempt has gone past its report.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn progress(&self) -> &Progress
    {
        &self.progress
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

    /// Advance the attempt to `next` unless it has gone further already.
    ///
    /// # Specification
    /// - ensures: the progress is `next` iff `next` ranks at or above the
    ///   progress held, so a later step of the same rank replaces an earlier
    ///   one and a lower rank never undoes a higher.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the
    ///   lifecycle witness checks that lower-ranked steps never undo later
    ///   progress.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the lifecycle advances through every rank and retains
    ///   later progress when an earlier rank arrives.
    /// - witness: `fold::tests::an_attempt_advances_through_its_lifecycle`
    fn advance(
        &mut self,
        next: Progress,
    )
    {
        if next.rank() >= self.progress.rank() {
            self.progress = next;
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

impl Current
{
    /// Project an admitted move into its task standing without checking
    /// authority.
    ///
    /// # Specification
    /// - requires: the caller has admitted the step under its dispatch
    ///   protocol.
    /// - ensures: a dispatch starts a fresh attempt; a matching answer updates
    ///   its slot or report, or advances progress without lowering its rank.
    ///   Answers to a superseded dispatch leave the standing unchanged.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 lifecycle and superseded-dispatch witnesses distinguish
    ///   slot, report, progress precedence and dispatch selection.
    /// - witness: `fold::tests::an_attempt_advances_through_its_lifecycle`
    /// - witness: `fold::tests::a_task_prints_one_line_per_step_and_its_standing`
    #[spec(ensures: !matches!(step, Step::Dispatch { .. })
        || matches!(&*self, Self::Attempt(attempt) if attempt.dispatch == commit))]
    #[inline]
    pub fn record(
        &mut self,
        commit: CommitId,
        step: &Step,
    )
    {
        if let Step::Dispatch {
            seat,
            edition,
            ref brief,
        } = *step
        {
            *self = Self::Attempt(Attempt {
                dispatch: commit,
                edition,
                brief: brief.clone(),
                slot: Slot::Held(seat),
                answer: Answer::Awaited,
                progress: Progress::Unchecked,
            });
            return;
        }
        if let Self::Attempt(ref mut attempt) = *self {
            match *step {
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
                | Step::Verified { dispatch, .. } if dispatch == attempt.dispatch => {
                    attempt.advance(Progress::Verified(commit));
                },
                | Step::Graded {
                    dispatch, composed, ..
                } if dispatch == attempt.dispatch => {
                    attempt.advance(Progress::Graded {
                        grading: commit,
                        composed,
                    });
                },
                | Step::Decide {
                    dispatch,
                    ref decision,
                    ..
                } if dispatch == attempt.dispatch => {
                    attempt.advance(Progress::Decided {
                        decide: commit,
                        decision: decision.clone(),
                    });
                },
                | Step::Landed {
                    dispatch, merge, ..
                } if dispatch == attempt.dispatch => {
                    attempt.advance(Progress::Landed {
                        landed: commit,
                        merge,
                    });
                },
                | Step::Dispatch { .. }
                | Step::Report { .. }
                | Step::Handoff { .. }
                | Step::Retire { .. }
                | Step::Pause { .. }
                | Step::Verdict { .. }
                | Step::Verified { .. }
                | Step::Graded { .. }
                | Step::Decide { .. }
                | Step::Landed { .. } => {},
            }
        }
    }
}

impl fmt::Display for Current
{
    /// Write where the task stands, as one line without its newline:
    /// `undispatched`; for an attempt checked past its report, its progress —
    /// `landed <dispatch> <landing> <merge>`, `decided <dispatch>
    /// <decision-commit> <decision>`, `graded <dispatch> <grading>
    /// <composed>` or `verified <dispatch> <verification>`; otherwise
    /// `reported <dispatch> <report>`, `stalled <dispatch> <retirement>` for a
    /// slot retired from without a report, or `dispatched <dispatch>
    /// <holder>`.
    ///
    /// # Specification
    /// - ensures: the line holds no newline: a rework's reason is escaped as
    ///   [`Decision`]'s `Display` escapes it.
    /// - panics: none.
    /// - executable: none — the formatter is write-only; the task replay
    ///   fixture observes each standing.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — each standing is printed as a task's last line by a
    ///   case of its own.
    /// - witness: `fold::tests::a_task_prints_one_line_per_step_and_its_standing`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        let Self::Attempt(ref attempt) = *self
        else {
            return f.write_str("undispatched");
        };
        let dispatch = attempt.dispatch;
        match (&attempt.progress, attempt.answer, attempt.slot) {
            | (&Progress::Landed { landed, merge }, ..) => {
                write!(f, "landed {dispatch} {landed} {merge}")
            },
            | (
                &Progress::Decided {
                    decide,
                    ref decision,
                },
                ..,
            ) => write!(f, "decided {dispatch} {decide} {decision}"),
            | (&Progress::Graded { grading, composed }, ..) => {
                write!(f, "graded {dispatch} {grading} {composed}")
            },
            | (&Progress::Verified(verification), ..) => {
                write!(f, "verified {dispatch} {verification}")
            },
            | (&Progress::Unchecked, Answer::Reported(report), _) => {
                write!(f, "reported {dispatch} {report}")
            },
            | (&Progress::Unchecked, Answer::Awaited, Slot::Retired { at, .. }) => {
                write!(f, "stalled {dispatch} {at}")
            },
            | (&Progress::Unchecked, Answer::Awaited, Slot::Held(holder)) => {
                write!(f, "dispatched {dispatch} {holder}")
            },
        }
    }
}

/// The original bytes and verified author of an admitted move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoveSource
{
    /// The original receipt's identity.
    pub commit: CommitId,
    /// The verified commit signer.
    pub author: PeerKey,
    /// The original flat receipt, including any supported legacy layout.
    pub blob: sedimentree_core::blob::Blob,
}

/// A tree read as a task: the seat receipts the fold admitted, and the
/// current attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task
{
    /// The admitted dispatches, reports, handoffs and retirements, each with
    /// its commit, in canonical order.
    steps: Vec<(CommitId, Step)>,
    /// The original author and blob for each folded step, in the same order.
    sources: Vec<MoveSource>,
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
            sources: Vec::new(),
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
    /// The original source of each admitted move in canonical order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn sources(&self) -> &[MoveSource]
    {
        &self.sources
    }

    /// Retain the source of the step the fold just admitted.
    ///
    /// # Specification
    /// trivial.
    pub(crate) fn record_source(
        &mut self,
        source: MoveSource,
    )
    {
        self.sources.push(source);
    }

    /// The evidence the admitted steps name, each with the peer whose receipt
    /// names it, in canonical order: where a reader fetches it first.
    ///
    /// # Specification
    /// - ensures: per step in order, a report's content with its author, a
    ///   verdict's transcript with its judge, and a verification's output with
    ///   its runner; every other step names none.
    /// - panics: none.
    /// - executable: none — checking a lazy iterator would consume it; the
    ///   lifecycle witness observes the evidence sequence and authors.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a task holding a report, two verifications and a
    ///   verdict among steps that name no evidence lists the four in order,
    ///   each with its author.
    /// - witness: `fold::tests::an_attempt_advances_through_its_lifecycle`
    #[inline]
    pub fn evidence(&self) -> impl Iterator<Item = (PeerKey, ManifestDigest)>
    {
        self.steps
            .iter()
            .filter_map(|&(_commit, ref step)| match *step {
                | Step::Report {
                    author, content, ..
                } => Some((author, content)),
                | Step::Verdict {
                    judge, transcript, ..
                } => Some((judge, transcript)),
                | Step::Verified { runner, output, .. } => Some((runner, output)),
                | Step::Dispatch { .. }
                | Step::Handoff { .. }
                | Step::Retire { .. }
                | Step::Pause { .. }
                | Step::Graded { .. }
                | Step::Decide { .. }
                | Step::Landed { .. } => None,
            })
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
    ///   attempt, its slot held by `seat`, its report awaited and nothing past
    ///   it checked.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a dispatch starts an attempt and later admitted steps
    ///   advance its lifecycle.
    /// - witness: `fold::tests::an_attempt_advances_through_its_lifecycle`
    #[spec(ensures: self.steps.iter().any(|entry| entry.0 == commit))]
    pub(crate) fn dispatch(
        &mut self,
        commit: CommitId,
        seat: PeerKey,
        edition: crate::Edition,
        brief: Brief,
    )
    {
        let step = Step::Dispatch {
            seat,
            edition,
            brief,
        };
        self.current.record(commit, &step);
        self.steps.push((commit, step));
    }

    /// Record the admitted `step` of `commit`: a report, a handoff, a
    /// retirement, a verdict, a verification, a grading, a decision or a
    /// landing.
    ///
    /// # Specification
    /// - ensures: the step is appended; when it answers the current attempt's
    ///   dispatch, a report makes `commit` the attempt's report, a handoff puts
    ///   its recipient in the slot, a retirement retires the slot at `commit`,
    ///   and a verification, a grading, a decision and a landing advance its
    ///   progress ([`Attempt::advance`]). A verdict changes no attempt, and a
    ///   step answering an earlier dispatch changes none either: a later
    ///   dispatch superseded it.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the lifecycle records admitted responses and
    ///   preserves progress when earlier ranks arrive.
    /// - witness: `fold::tests::an_attempt_advances_through_its_lifecycle`
    #[spec(ensures: self.steps.iter().any(|entry| entry.0 == commit))]
    pub(crate) fn answer(
        &mut self,
        commit: CommitId,
        step: Step,
    )
    {
        self.current.record(commit, &step);
        self.steps.push((commit, step));
    }
}

impl fmt::Display for Task
{
    /// Write the task as lines: one per step in canonical order — `dispatch
    /// <commit> <seat> edition <edition> <brief>`, `report <commit> <dispatch>
    /// <author> <content> <summary>`, `handoff <commit> <dispatch> <from>
    /// <to>`, `retire <commit> <dispatch> <author>`, `verdict <commit>
    /// <dispatch> <judge> <rubric> <transcript>` followed by `ruling
    /// <commit> <question> <ruling>` per question asked, `verified <commit>
    /// <dispatch> <runner> <playbook> <step> <output> <status>`, `graded
    /// <commit> <dispatch> <verdict> <rubric> <composed>` followed by
    /// `grade <commit> <question> <grade>` per question graded, `decide
    /// <commit> <dispatch> <operator> <decision>`, or `landed <commit>
    /// <dispatch> <decided> <operator> <merge>` — then where it stands, as
    /// [`Current`]'s `Display` writes it.
    ///
    /// # Specification
    /// - ensures: every line ends in a newline, and each step stays one line: a
    ///   brief's anchor and a summary have their backslashes escaped as a
    ///   note's are, a summary holds no control character, and a ruling is
    ///   written as one line ([`Ruling`]'s `Display`).
    /// - panics: none.
    /// - executable: none — the formatter is write-only; the replay fixture
    ///   compares every step and the final standing.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a task with a dispatch by anchor, a handoff, a report
    ///   whose summary holds a backslash, a retirement, a verdict with a read
    ///   and an unread ruling, a verification, a grading of that verdict, a
    ///   decision of each kind, the rework's reason holding a backslash, a
    ///   landing and a second dispatch by content is printed and compared line
    ///   for line, and each standing is printed by a case of its own.
    /// - witness: `fold::tests::a_task_prints_one_line_per_step_and_its_standing`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        for &(commit, ref step) in &self.steps {
            StepLine { commit, step }.fmt(f)?;
        }
        writeln!(f, "{}", self.current)
    }
}

/// One admitted or authenticated move in the replay line language.
#[derive(Debug)]
pub struct StepLine<'step>
{
    /// The original receipt's commit identity.
    pub commit: CommitId,
    /// The resolved move, with its referenced receipt fields.
    pub step: &'step Step,
}

impl fmt::Display for StepLine<'_>
{
    /// Render the same line language used by a task replay.
    ///
    /// # Specification
    /// - ensures: one move and its detail rows are rendered, without a
    ///   standing.
    /// - fails: only when the formatter refuses output.
    /// - panics: none.
    /// - executable: none — the formatter is write-only; the replay fixture
    ///   independently fixes each move and its detail rows.
    ///
    /// # Errors
    /// - [`fmt::Error`]: the output sink refused a write.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the replay fixture pins each move line and its
    ///   fields.
    /// - witness: `fold::tests::a_task_prints_one_line_per_step_and_its_standing`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        let commit = self.commit;
        match *self.step {
            | Step::Dispatch {
                seat,
                edition,
                ref brief,
            } => writeln!(f, "dispatch {commit} {seat} edition {edition} {brief}"),
            | Step::Report {
                dispatch,
                author,
                content,
                ref summary,
            } => {
                write!(f, "report {commit} {dispatch} {author} {content} ")?;
                OneLine::new(f, Field::Last).write_str(summary.as_ref())?;
                writeln!(f)
            },
            | Step::Handoff { dispatch, from, to } => {
                writeln!(f, "handoff {commit} {dispatch} {from} {to}")
            },
            | Step::Retire { dispatch, author } => {
                writeln!(f, "retire {commit} {dispatch} {author}")
            },
            | Step::Pause { dispatch, author } => writeln!(f, "pause {commit} {dispatch} {author}"),
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
                Ok(())
            },
            | Step::Verified {
                dispatch,
                runner,
                playbook,
                ref step,
                output,
                status,
            } => writeln!(
                f,
                "verified {commit} {dispatch} {runner} {playbook} {step} {output} {status}"
            ),
            | Step::Graded {
                dispatch,
                verdict,
                rubric,
                ref grades,
                composed,
            } => {
                writeln!(
                    f,
                    "graded {commit} {dispatch} {verdict} {rubric} {composed}"
                )?;
                for &(question, grade) in grades {
                    writeln!(f, "grade {commit} {question} {grade}")?;
                }
                Ok(())
            },
            | Step::Decide {
                dispatch,
                operator,
                ref decision,
            } => writeln!(f, "decide {commit} {dispatch} {operator} {decision}"),
            | Step::Landed {
                dispatch,
                decided,
                operator,
                merge,
            } => writeln!(f, "landed {commit} {dispatch} {decided} {operator} {merge}"),
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
