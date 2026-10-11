//! Numbered task channels, endpoint replay, and kernel-certified widening.

#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "the pinned gandr specifications use anodized with syn 2; thiserror uses syn 3"
)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::fmt;

use anodized::spec;
use gandr_core_session::Action;
use gandr_core_session::Move;
use gandr_core_session::Node;
use gandr_core_session::NodeId;
use gandr_core_session::Payload;
use gandr_core_session::PayloadDigest;
use gandr_core_session::ReplayError;
use gandr_core_session::Session;
use gandr_core_session::ValueTypeId;
use gandr_core_session::certified::PayloadCodes;
use gandr_core_session::certified::Protocol;
use gandr_core_session::certified::TransportError;
use gandr_kernel_core::ReplayBudget;
use gandr_kernel_core::flow_universe::Certificate;
use gandr_kernel_core::flow_universe::Family;
use gandr_kernel_core::flow_universe::Flow;
use gandr_kernel_core::flow_universe::Flows;
use gandr_kernel_term::BaseType;
use gandr_kernel_term::TermArena;

/// A durable protocol name; unknown numbers remain names, not defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Edition(u64);

impl Edition
{
    /// Dispatch, one or more reports, then handoff or retirement.
    pub const ONE: Self = Self(1);
    /// Edition 1 widened with pause before or between reports.
    pub const TWO: Self = Self(2);
    /// The edition new dispatches name in this build.
    #[cfg(feature = "edition-2")]
    pub const CURRENT: Self = Self::TWO;
    /// The edition new dispatches name in this build.
    #[cfg(not(feature = "edition-2"))]
    pub const CURRENT: Self = Self::ONE;
}

impl From<u64> for Edition
{
    /// Preserve the number even when this build does not know its protocol.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(number: u64) -> Self
    {
        Self(number)
    }
}

impl From<Edition> for u64
{
    /// Return the durable number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(edition: Edition) -> Self
    {
        edition.0
    }
}

impl core::str::FromStr for Edition
{
    type Err = core::num::ParseIntError;

    /// Read an unsigned edition number without claiming protocol knowledge.
    ///
    /// # Specification
    /// - ensures: preserves every representable unsigned edition number.
    /// - fails: rejects nonnumeric or overflowing input.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the witness
    ///   distinguishes parsing a number from knowing its protocol.
    ///
    /// # Errors
    /// Returns the integer parser's error for malformed input.
    ///
    /// # Adequacy
    /// - hypothesis: L3 known, unknown, and malformed names distinguish parsing
    ///   from protocol availability.
    /// - witness: `tests::unknown_editions_never_replay_as_known_protocols`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        text.parse().map(Self)
    }
}

impl fmt::Display for Edition
{
    /// Print the durable number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        self.0.fmt(f)
    }
}

/// One independently replayed binary channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Channel
{
    /// One slot play per dispatch.
    #[default]
    Slot,
    /// One verdict and grading per verdict commit.
    Judge,
    /// Repeated verifications per runner and dispatch.
    Runner,
    /// One operator choice per dispatch.
    Decision,
}

/// The operator's selection; receipt contents remain opaque to the arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice
{
    /// Decide to land, then record the landing.
    Land,
    /// Request a new dispatch for rework.
    Rework,
    /// Abandon this dispatch.
    Abandon,
}

/// A receipt move on a task channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Movement
{
    /// The operator supplies a dispatch.
    Dispatch,
    /// The current holder supplies a report.
    Report,
    /// The current holder passes the slot.
    Handoff,
    /// The current holder closes the slot.
    Retire,
    /// The current holder pauses, retaining the slot.
    Pause,
    /// The judge supplies its verdict.
    Verdict,
    /// The judge grades its verdict and closes the channel.
    Graded,
    /// The runner supplies another verification.
    Verified,
    /// The operator selects its decision once.
    Decide(Choice),
    /// The deciding operator records the landing and closes the channel.
    Landed,
}

impl fmt::Display for Movement
{
    /// Print the receipt action's name.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Dispatch => "dispatch",
            | Self::Report => "report",
            | Self::Handoff => "handoff",
            | Self::Retire => "retire",
            | Self::Pause => "pause",
            | Self::Verdict => "verdict",
            | Self::Graded => "graded",
            | Self::Verified => "verified",
            | Self::Decide(_) => "decide",
            | Self::Landed => "landed",
        })
    }
}

/// Whether the recorded prefix is still open or has explicitly closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress
{
    /// The prefix conforms and owes this next action.
    Open(Action),
    /// The channel reached its explicit end.
    Complete,
}

/// A protocol this build does not contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown edition {0}")]
#[repr(transparent)]
pub struct UnknownEdition(pub Edition);

/// The named receipt move refused by the independent monitor.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("edition {edition} {movement}: {reason}")]
pub struct Refusal
{
    /// The edition named by the dispatch.
    pub edition: Edition,
    /// The receipt action, rather than an internal label or payload step.
    pub movement: Movement,
    /// Missing protocol knowledge or the first failed endpoint step.
    pub reason: Reason,
}

/// Why a move cannot enter its named protocol.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reason
{
    /// The protocol is not compiled into this build.
    #[error(transparent)]
    Unknown(UnknownEdition),
    /// The known protocol refuses this endpoint step.
    #[error("{0:?}")]
    Replay(ReplayError),
}

/// Construction or certified transport failed; no protocol is substituted.
#[derive(Debug, thiserror::Error)]
pub enum ArenaError
{
    /// Invalid finite protocol syntax.
    #[error(transparent)]
    Type(#[from] gandr_core_session::TypeError),
    /// One of the named protocols is not compiled in.
    #[error(transparent)]
    Unknown(#[from] UnknownEdition),
    /// The candidate extension is not a session subtype.
    #[error("edition {source_edition} is not a widening to edition {target_edition}")]
    NotWidening
    {
        /// The source protocol.
        source_edition: Edition,
        /// The proposed target protocol.
        target_edition: Edition,
    },
    /// Native code export or recorded transport failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The kernel refused the candidate certificate.
    #[error(transparent)]
    Kernel(#[from] gandr_kernel_core::flow_universe::FlowError),
}

/// Opaque receipt payload types. Each digest names its receipt commit.
const DISPATCH: ValueTypeId = ValueTypeId([1; 32]);
/// The report receipt type.
const REPORT: ValueTypeId = ValueTypeId([2; 32]);
/// The handoff receipt type.
const HANDOFF: ValueTypeId = ValueTypeId([3; 32]);
/// The retirement receipt type.
const RETIRE: ValueTypeId = ValueTypeId([4; 32]);
/// The pause receipt type.
const PAUSE: ValueTypeId = ValueTypeId([5; 32]);

/// The verdict receipt type.
const VERDICT: ValueTypeId = ValueTypeId([6; 32]);
/// The grading receipt type.
const GRADED: ValueTypeId = ValueTypeId([7; 32]);
/// The verification receipt type.
const VERIFIED: ValueTypeId = ValueTypeId([8; 32]);
/// The decision receipt type.
const DECIDE: ValueTypeId = ValueTypeId([9; 32]);
/// The landing receipt type.
const LANDED: ValueTypeId = ValueTypeId([10; 32]);

/// The binary protocols compiled under one edition.
struct Channels
{
    /// The slot holder's endpoint.
    slot: Session,
    /// The judge's endpoint.
    judge: Session,
    /// The runner's endpoint.
    runner: Session,
    /// The deciding operator's endpoint.
    decision: Session,
}

/// Validated endpoint types keyed by their compiled edition numbers.
#[cfg_attr(not(feature = "edition-2"), repr(transparent))]
pub struct Arena
{
    /// Edition 1's task channels.
    base: Channels,
    /// Edition 2's protocol; absent from edition-1-only binaries.
    #[cfg(feature = "edition-2")]
    paused: Channels,
}

impl Arena
{
    /// Construct only the protocols compiled into this build.
    ///
    /// # Specification
    /// - ensures: edition 1 is available; edition 2 is available exactly when
    ///   the `edition-2` feature is enabled.
    /// - fails: invalid finite session syntax remains a typed error.
    /// - panics: none.
    ///
    /// # Errors
    /// Returns `ArenaError::Type` for invalid session syntax.
    ///
    /// # Adequacy
    /// - hypothesis: L3 known and unknown editions distinguish lookup from a
    ///   peer-local default; directed traces pin the compiled protocols.
    /// - witness: `tests::unknown_editions_never_replay_as_known_protocols`
    /// - witness: `tests::named_refusal_preserves_the_prefix`
    /// - witness: `tests::task_channels_replay_with_their_duals`
    #[spec(ensures: |ref output| output.as_ref().map_or(true, |arena|
        arena.session(Edition::ONE, Channel::Slot).is_ok()
        && arena.session(Edition::TWO, Channel::Slot).is_ok() == cfg!(feature = "edition-2")
    ))]
    #[inline]
    pub fn new() -> Result<Self, ArenaError>
    {
        let base = channels(Edition::ONE)?;
        #[cfg(feature = "edition-2")]
        let paused = channels(Edition::TWO)?;
        Ok(Self {
            base,
            #[cfg(feature = "edition-2")]
            paused,
        })
    }

    /// Borrow one channel under the named edition, never a substitute.
    ///
    /// # Specification
    /// - ensures: returns the selected channel of exactly the named edition.
    /// - fails: unknown numbers name themselves in `UnknownEdition`.
    /// - panics: none.
    /// - executable: none — the function is its own specification; directed
    ///   replay and unknown-edition witnesses check the finite lookup table.
    ///
    /// # Errors
    /// Returns `UnknownEdition` when the edition is not compiled in.
    ///
    /// # Adequacy
    /// - hypothesis: L3 unknown numbers and edition-1-only builds expose any
    ///   fallback to a known protocol.
    /// - witness: `tests::unknown_editions_never_replay_as_known_protocols`
    #[inline]
    pub const fn session(
        &self,
        edition: Edition,
        channel: Channel,
    ) -> Result<&Session, UnknownEdition>
    {
        let channels = match edition {
            | Edition::ONE => &self.base,
            #[cfg(feature = "edition-2")]
            | Edition::TWO => &self.paused,
            | unknown => return Err(UnknownEdition(unknown)),
        };
        Ok(match channel {
            | Channel::Slot => &channels.slot,
            | Channel::Judge => &channels.judge,
            | Channel::Runner => &channels.runner,
            | Channel::Decision => &channels.decision,
        })
    }

    /// Re-derive and kernel-check the widening between two named editions,
    /// then transport a complete play without changing its moves or digests.
    ///
    /// # Specification
    /// - ensures: the transported play conforms to the target protocol; the
    ///   candidate relation and its certificate are derived locally.
    /// - fails: unknown editions, non-widenings, incomplete or nonconforming
    ///   source plays, code export and kernel failures retain their identities.
    /// - panics: none.
    ///
    /// # Errors
    /// Returns the corresponding `ArenaError`; no certificate is received
    /// from a peer or retained in a receipt.
    ///
    /// # Adequacy
    /// - hypothesis: L1 independent kernel checking validates the candidate; L3
    ///   forward, reverse, unknown and incomplete traces separate the names,
    ///   relation direction, conformance and completion obligations.
    /// - witness: `tests::pause_is_certified_and_old_runs_transport`
    #[spec(ensures: |ref output| output.as_ref().map_or(true, |transported| transported.channel == play.channel && transported.moves == play.moves))]
    #[inline]
    pub fn transport(
        &self,
        source_edition: Edition,
        target_edition: Edition,
        play: &Play,
    ) -> Result<Play, ArenaError>
    {
        let source = self.session(source_edition, play.channel)?;
        let target = self.session(target_edition, play.channel)?;
        let evidence = match gandr_core_session::relate(
            source,
            target,
            gandr_core_session::Relation::Subtype,
        )? {
            | gandr_core_session::RelationResult::Related(evidence) => evidence,
            | gandr_core_session::RelationResult::Unrelated => {
                return Err(ArenaError::NotWidening {
                    source_edition,
                    target_edition,
                });
            },
        };
        let mut terms = TermArena::new();
        let unit = terms.value_type_unit();
        let integer = terms.value_type_base(BaseType::Integer);
        let string = terms.value_type_base(BaseType::String);
        let numeric = terms.value_type_base(BaseType::Numeric);
        let pair = terms.value_type_product(unit, unit);
        let verdict = terms.value_type_product(integer, unit);
        let graded = terms.value_type_product(string, unit);
        let verified = terms.value_type_product(numeric, unit);
        let decide = terms.value_type_product(unit, integer);
        let landed = terms.value_type_product(unit, string);
        let payloads = PayloadCodes(
            [
                (DISPATCH, integer),
                (REPORT, string),
                (HANDOFF, numeric),
                (RETIRE, unit),
                (PAUSE, pair),
                (VERDICT, verdict),
                (GRADED, graded),
                (VERIFIED, verified),
                (DECIDE, decide),
                (LANDED, landed),
            ]
            .into(),
        );
        let source_code = gandr_core_session::certified::encode(&mut terms, source, &payloads)?;
        let target_code = gandr_core_session::certified::encode(&mut terms, target, &payloads)?;
        let proofs = terms.value_unit();
        let mut flows = Flows::new();
        let flow = flows.push(Flow::Session {
            source: source_code,
            target: target_code,
            evidence: Arc::new(evidence),
            payload_paths: proofs,
        })?;
        let certificate = Certificate::Flow(flow);
        let _classifier = gandr_kernel_core::flow_universe::form_certificate(
            &mut terms,
            &flows,
            certificate,
            Family::Flow,
            ReplayBudget::DEFAULT,
        )?;
        let source = Protocol {
            session: source,
            code: source_code,
            payloads: &payloads,
        };
        let target = Protocol {
            session: target,
            code: target_code,
            payloads: &payloads,
        };
        let moves = gandr_core_session::certified::transport(
            &mut terms,
            &flows,
            certificate,
            (source, target),
            &play.moves,
            ReplayBudget::DEFAULT,
        )?;
        Ok(Play {
            channel: play.channel,
            moves,
        })
    }
}

/// One channel's accepted prefix; bodies stay behind their digests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Play
{
    /// The endpoint whose session interprets this prefix.
    channel: Channel,
    /// Only admitted endpoint moves, including explicit closes.
    moves: Vec<Move>,
}

impl Play
{
    /// Start an empty prefix on the selected channel.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(channel: Channel) -> Self
    {
        Self {
            channel,
            moves: Vec::new(),
        }
    }

    /// Append a receipt action only if the named protocol admits its prefix.
    ///
    /// # Specification
    /// - ensures: success extends the prefix by the action's skeleton; failure
    ///   leaves the prefix unchanged.
    /// - fails: names the edition, receipt action and missing protocol or first
    ///   failed monitor step.
    /// - panics: none.
    ///
    /// # Errors
    /// Returns a named `Refusal` without consuming the admitted prefix.
    ///
    /// # Adequacy
    /// - hypothesis: L3 early report, pause width and use after close expose
    ///   ordering errors; unknown names expose fallback; a following report
    ///   distinguishes refusal from prefix mutation.
    /// - witness: `tests::named_refusal_preserves_the_prefix`
    /// - witness: `tests::unknown_editions_never_replay_as_known_protocols`
    /// - witness: `tests::task_channels_refuse_missing_and_repeated_moves`
    #[spec(ensures: |ref output| !matches!(*output, Ok(Progress::Complete)) || self.moves.last() == Some(&Move::End))]
    #[inline]
    pub fn record(
        &mut self,
        arena: &Arena,
        edition: Edition,
        movement: Movement,
        digest: PayloadDigest,
    ) -> Result<Progress, Box<Refusal>>
    {
        let session = arena.session(edition, self.channel).map_err(|unknown| {
            Box::new(Refusal {
                edition,
                movement,
                reason: Reason::Unknown(unknown),
            })
        })?;
        let before = self.moves.len();
        let (label, identity) = match movement {
            | Movement::Dispatch => (None, DISPATCH),
            | Movement::Report => (Some("report"), REPORT),
            | Movement::Handoff => (Some("handoff"), HANDOFF),
            | Movement::Retire => (Some("retire"), RETIRE),
            | Movement::Pause => (Some("pause"), PAUSE),
            | Movement::Verdict => (None, VERDICT),
            | Movement::Graded => (None, GRADED),
            | Movement::Verified => (None, VERIFIED),
            | Movement::Decide(Choice::Land) => (Some("land"), DECIDE),
            | Movement::Decide(Choice::Rework) => (Some("rework"), DECIDE),
            | Movement::Decide(Choice::Abandon) => (Some("abandon"), DECIDE),
            | Movement::Landed => (None, LANDED),
        };
        let payload = Payload { identity, digest };
        if let Some(label) = label {
            self.moves.push(Move::Select(label.into()));
        }
        if movement == Movement::Dispatch {
            self.moves.push(Move::Receive(payload));
        }
        else {
            self.moves.push(Move::Send(payload));
        }
        if matches!(
            movement,
            Movement::Retire
                | Movement::Handoff
                | Movement::Graded
                | Movement::Landed
                | Movement::Decide(Choice::Rework | Choice::Abandon)
        ) {
            self.moves.push(Move::End);
        }
        // economy: replay each canonical prefix because the upstream monitor has no
        // cursor API; a resumable monitor removes this quadratic cost.
        match gandr_core_session::replay(session, &self.moves) {
            | Ok(_) => Ok(Progress::Complete),
            | Err(ReplayError::IncompleteRun { expected, .. }) => Ok(Progress::Open(expected)),
            | Err(reason) => {
                self.moves.truncate(before);
                Err(Box::new(Refusal {
                    edition,
                    movement,
                    reason: Reason::Replay(reason),
                }))
            },
        }
    }

    /// Observe a candidate receipt without admitting it.
    ///
    /// # Specification
    /// - ensures: returns the same observation as `record`, leaving the
    ///   admitted prefix unchanged on both success and failure.
    /// - fails: propagates the named monitor refusal.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the trace
    ///   witness distinguishes observation from admitting the candidate.
    ///
    /// # Errors
    /// Returns `Refusal` when the action cannot enter the named protocol.
    ///
    /// # Adequacy
    /// - hypothesis: L3 inspecting a report leaves the report obligation
    ///   unsatisfied, so immediate retirement remains refused.
    /// - witness: `tests::named_refusal_preserves_the_prefix`
    #[inline]
    pub fn inspect(
        &mut self,
        arena: &Arena,
        edition: Edition,
        movement: Movement,
        digest: PayloadDigest,
    ) -> Result<Progress, Box<Refusal>>
    {
        let before = self.moves.len();
        let result = self.record(arena, edition, movement, digest);
        self.moves.truncate(before);
        result
    }

    /// Borrow the recorded endpoint skeleton for independent replay.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn moves(&self) -> &[Move]
    {
        &self.moves
    }
}

/// Form every binary channel under a compiled edition.
///
/// # Specification
/// - ensures: judge sends verdict then grading once; runner repeats
///   verification; operator selects once and only land continues to a landing.
/// - fails: malformed finite session syntax returns its type error.
/// - panics: none.
/// - executable: none — the function is its own specification; independent dual
///   replay witnesses check the channel tables rather than duplicating them.
///
/// # Errors
/// - [`TypeError`]: invalid channel syntax.
///
/// # Adequacy
/// - hypothesis: L3 directed runs distinguish ordering, repetition and each
///   terminal choice; structural duals accept the opposite endpoint moves.
/// - witness: `tests::task_channels_replay_with_their_duals`
///
/// [`TypeError`]: gandr_core_session::TypeError
fn channels(edition: Edition) -> Result<Channels, gandr_core_session::TypeError>
{
    let slot = session(edition)?;
    let judge = Session::new(
        vec![
            Node::Send(VERDICT, NodeId(1)),
            Node::Send(GRADED, NodeId(2)),
            Node::End,
        ],
        NodeId(0),
    )?;
    let runner = Session::new(
        vec![
            Node::Mu(NodeId(1)),
            Node::Send(VERIFIED, NodeId(2)),
            Node::Var(NodeId(0)),
        ],
        NodeId(0),
    )?;
    let decision = Session::new(
        vec![
            Node::Select(BTreeMap::from([
                ("land".into(), NodeId(1)),
                ("rework".into(), NodeId(4)),
                ("abandon".into(), NodeId(6)),
            ])),
            Node::Send(DECIDE, NodeId(2)),
            Node::Send(LANDED, NodeId(3)),
            Node::End,
            Node::Send(DECIDE, NodeId(5)),
            Node::End,
            Node::Send(DECIDE, NodeId(7)),
            Node::End,
        ],
        NodeId(0),
    )?;
    Ok(Channels {
        slot,
        judge,
        runner,
        decision,
    })
}

/// Form the finite slot protocol for one compiled edition.
///
/// # Specification
/// - requires: the edition is known by the caller.
/// - ensures: report is required before either closing move; edition 2
///   additionally offers pause before and between reports.
/// - fails: malformed finite syntax is a typed session error.
/// - panics: none.
///
/// # Errors
/// Returns the session syntax error without a fallback.
///
/// # Adequacy
/// - hypothesis: L3 traces distinguish first report, repetition, pause width
///   and both closing moves.
/// - witness: `tests::named_refusal_preserves_the_prefix`
/// - witness: `tests::pause_is_certified_and_old_runs_transport`
#[spec(requires: edition == Edition::ONE || (cfg!(feature = "edition-2") && edition == Edition::TWO))]
fn session(edition: Edition) -> Result<Session, gandr_core_session::TypeError>
{
    let mut before = BTreeMap::from([("report".into(), NodeId(3))]);
    let mut after = [
        ("report".into(), NodeId(6)),
        ("handoff".into(), NodeId(8)),
        ("retire".into(), NodeId(10)),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    if cfg!(feature = "edition-2") && edition == Edition::TWO {
        let _absent = before.insert("pause".into(), NodeId(12));
        let _absent = after.insert("pause".into(), NodeId(14));
    }
    let mut nodes = Vec::with_capacity(16);
    nodes.extend([
        Node::Receive(DISPATCH, NodeId(1)),
        Node::Mu(NodeId(2)),
        Node::Select(before),
        Node::Send(REPORT, NodeId(4)),
        Node::Mu(NodeId(5)),
        Node::Select(after),
        Node::Send(REPORT, NodeId(7)),
        Node::Var(NodeId(4)),
        Node::Send(HANDOFF, NodeId(9)),
        Node::End,
        Node::Send(RETIRE, NodeId(11)),
        Node::End,
    ]);
    if cfg!(feature = "edition-2") && edition == Edition::TWO {
        nodes.extend([
            Node::Send(PAUSE, NodeId(13)),
            Node::Var(NodeId(1)),
            Node::Send(PAUSE, NodeId(15)),
            Node::Var(NodeId(4)),
        ]);
    }
    Session::new(nodes, NodeId(0))
}

#[cfg(test)]
mod tests;
