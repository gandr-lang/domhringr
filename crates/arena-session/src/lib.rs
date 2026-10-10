//! Numbered Seat protocols, endpoint replay, and kernel-certified widening.

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

/// A move in the slot's dialogue. Handoff and retirement close this endpoint.
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
        })
    }
}

/// Whether the recorded prefix is still open or has explicitly closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress
{
    /// The prefix conforms and owes this next action.
    Open(Action),
    /// Handoff or retirement closed the endpoint.
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

/// Validated endpoint types keyed by their compiled edition numbers.
#[cfg_attr(not(feature = "edition-2"), repr(transparent))]
pub struct Arena
{
    /// Edition 1's slot protocol.
    base: Session,
    /// Edition 2's protocol; absent from edition-1-only binaries.
    #[cfg(feature = "edition-2")]
    paused: Session,
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
    #[inline]
    pub fn new() -> Result<Self, ArenaError>
    {
        let base = session(Edition::ONE)?;
        #[cfg(feature = "edition-2")]
        let paused = session(Edition::TWO)?;
        Ok(Self {
            base,
            #[cfg(feature = "edition-2")]
            paused,
        })
    }

    /// Borrow the protocol named by an edition, never a substitute.
    ///
    /// # Specification
    /// - ensures: returns exactly the named compiled protocol.
    /// - fails: unknown numbers name themselves in `UnknownEdition`.
    /// - panics: none.
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
    ) -> Result<&Session, UnknownEdition>
    {
        match edition {
            | Edition::ONE => Ok(&self.base),
            #[cfg(feature = "edition-2")]
            | Edition::TWO => Ok(&self.paused),
            | unknown => Err(UnknownEdition(unknown)),
        }
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
    #[inline]
    pub fn transport(
        &self,
        source_edition: Edition,
        target_edition: Edition,
        play: &Play,
    ) -> Result<Play, ArenaError>
    {
        let source = self.session(source_edition)?;
        let target = self.session(target_edition)?;
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
        let payloads = PayloadCodes(
            [
                (DISPATCH, integer),
                (REPORT, string),
                (HANDOFF, numeric),
                (RETIRE, unit),
                (PAUSE, pair),
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
        Ok(Play { moves })
    }
}

/// State owned by one attempt; bodies stay behind their digests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Play
{
    /// Only admitted endpoint moves, including retirement's explicit close.
    moves: Vec<Move>,
}

impl Play
{
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
    #[inline]
    pub fn record(
        &mut self,
        arena: &Arena,
        edition: Edition,
        movement: Movement,
        digest: PayloadDigest,
    ) -> Result<Progress, Box<Refusal>>
    {
        let session = arena.session(edition).map_err(|unknown| {
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
        };
        let payload = Payload { identity, digest };
        if let Some(label) = label {
            self.moves.push(Move::Select(label.into()));
            self.moves.push(Move::Send(payload));
        }
        else {
            self.moves.push(Move::Receive(payload));
        }
        if matches!(movement, Movement::Retire | Movement::Handoff) {
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
