//! The Seat slot protocol, endpoint replay, and kernel-certified pause
//! widening.

#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "the pinned gandr contracts use anodized with syn 2; thiserror uses syn 3"
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
use gandr_kernel_term::ValueId;

/// The protocol under which a record is interpreted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Edition
{
    /// Dispatch, report, handoff and retire.
    Base,
    /// The certified extension admitting pause without relinquishing the slot.
    #[default]
    Paused,
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
    /// Write the stable receipt move name.
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

/// The named receipt move refused by the independent monitor.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{movement}: {reason:?}")]
pub struct Refusal
{
    /// The receipt action, rather than an internal label or payload step.
    pub movement: Movement,
    /// The first failed endpoint step and its expected action.
    pub reason: ReplayError,
}

/// Construction or certified transport failed; no unchecked protocol is
/// substituted.
#[derive(Debug, thiserror::Error)]
pub enum ArenaError
{
    /// Invalid finite protocol syntax.
    #[error(transparent)]
    Type(#[from] gandr_core_session::TypeError),
    /// The candidate extension is not a session subtype.
    #[error("pause is not a widening")]
    NotWidening,
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

/// Validated endpoint types and the independently checked widening between
/// them.
///
/// # Specification
/// - provides: the Seat type, its dual, and a kernel-checked Base-to-Paused
///   Flow.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L1 kernel checking validates candidate evidence; L3 directed
///   traces distinguish move order, pause width, retirement and continued use.
/// - witness: `tests::pause_is_certified_and_old_runs_transport`
/// - witness: `tests::named_refusal_preserves_the_prefix`
pub struct Arena
{
    /// The original slot protocol.
    base: Session,
    /// The protocol with pause in its recursive selection.
    paused: Session,
    /// Native session codes and their payload classifiers.
    terms: TermArena,
    /// The mapping checked at the recorded transport boundary.
    payloads: PayloadCodes,
    /// The base protocol's quoted native code.
    base_code: ValueId,
    /// The widened protocol's quoted native code.
    paused_code: ValueId,
    /// The candidate graph the kernel independently checked.
    flows: Flows,
    /// The checked widening's identity in that graph.
    certificate: Certificate,
}

impl Arena
{
    /// Construct the protocol pair and certify the pause widening.
    ///
    /// # Specification
    /// - ensures: Base is a subtype of Paused and the kernel accepts its Flow.
    /// - fails: syntax, code-export, relation and kernel failures remain
    ///   distinct.
    /// - panics: none.
    ///
    /// # Errors
    /// Returns the corresponding [`ArenaError`], never an unchecked fallback.
    ///
    /// # Adequacy
    /// - hypothesis: L1 the kernel independently checks the engine's relation;
    ///   L3 reverse subtyping is refused while forward transport preserves
    ///   moves.
    /// - witness: `tests::pause_is_certified_and_old_runs_transport`
    #[inline]
    pub fn new() -> Result<Self, ArenaError>
    {
        let base = session(Edition::Base)?;
        let paused = session(Edition::Paused)?;
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
        let base_code = gandr_core_session::certified::encode(&mut terms, &base, &payloads)?;
        let paused_code = gandr_core_session::certified::encode(&mut terms, &paused, &payloads)?;
        let evidence = match gandr_core_session::relate(
            &base,
            &paused,
            gandr_core_session::Relation::Subtype,
        )? {
            | gandr_core_session::RelationResult::Related(evidence) => evidence,
            | gandr_core_session::RelationResult::Unrelated => return Err(ArenaError::NotWidening),
        };
        let proofs = terms.value_unit();
        let mut flows = Flows::new();
        let flow = flows.push(Flow::Session {
            source: base_code,
            target: paused_code,
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
        Ok(Self {
            base,
            paused,
            terms,
            payloads,
            base_code,
            paused_code,
            flows,
            certificate,
        })
    }

    /// Borrow the endpoint type for a protocol edition.
    ///
    /// # Specification
    /// trivial.
    #[must_use]
    #[inline]
    pub const fn session(
        &self,
        edition: Edition,
    ) -> &Session
    {
        match edition {
            | Edition::Base => &self.base,
            | Edition::Paused => &self.paused,
        }
    }

    /// The operator endpoint dual to the slot endpoint.
    ///
    /// # Specification
    /// trivial.
    #[must_use]
    #[inline]
    pub fn dual(
        &self,
        edition: Edition,
    ) -> Session
    {
        self.session(edition).dual()
    }

    /// Transport a completed Base play through the checked pause widening.
    ///
    /// # Specification
    /// - ensures: every payload digest and move is preserved and the result
    ///   conforms to Paused after the kernel and both monitors replay it.
    /// - fails: incomplete, non-Base or invalid certificate runs are refused.
    /// - panics: none.
    ///
    /// # Errors
    /// [`ArenaError::Transport`] retains the kernel, binding or replay refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L1 destination replay checks the transported run; L3 exact
    ///   moves and digests expose alteration, with a paused-source near miss.
    /// - witness: `tests::pause_is_certified_and_old_runs_transport`
    #[inline]
    pub fn transport(
        &mut self,
        play: &Play,
    ) -> Result<Play, ArenaError>
    {
        let source = Protocol {
            session: &self.base,
            code: self.base_code,
            payloads: &self.payloads,
        };
        let target = Protocol {
            session: &self.paused,
            code: self.paused_code,
            payloads: &self.payloads,
        };
        let moves = gandr_core_session::certified::transport(
            &mut self.terms,
            &self.flows,
            self.certificate,
            (source, target),
            &play.moves,
            ReplayBudget::DEFAULT,
        )?;
        Ok(Play { moves })
    }
}

/// State owned by one causal branch; bodies stay behind their digests.
#[derive(Clone, Debug, Default)]
#[repr(transparent)]
pub struct Play
{
    /// Only admitted endpoint moves, including retirement's explicit close.
    moves: Vec<Move>,
}

impl Play
{
    /// Append a receipt only if the monitor admits its complete action.
    ///
    /// # Specification
    /// - ensures: success retains the appended action and distinguishes an open
    ///   prefix from an explicitly closed run; a refusal leaves the play
    ///   unchanged.
    /// - fails: the first wrong direction, label, payload or post-end move is
    ///   named.
    /// - panics: none.
    ///
    /// # Errors
    /// [`Refusal`] carries the receipt name and the monitor's first failed
    /// step.
    ///
    /// # Adequacy
    /// - hypothesis: L3 an out-of-order report, pause under Base and a
    ///   post-retire action pin named refusals; retrying after refusal checks
    ///   rollback.
    /// - witness: `tests::named_refusal_preserves_the_prefix`
    /// - witness: `tests::pause_is_certified_and_old_runs_transport`
    #[inline]
    pub fn record(
        &mut self,
        arena: &Arena,
        edition: Edition,
        movement: Movement,
        digest: PayloadDigest,
    ) -> Result<Progress, Box<Refusal>>
    {
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
        // cursor API; an upstream resumable monitor removes this quadratic cost.
        match gandr_core_session::replay(arena.session(edition), &self.moves) {
            | Ok(_) => Ok(Progress::Complete),
            | Err(ReplayError::IncompleteRun { expected, .. }) => Ok(Progress::Open(expected)),
            | Err(reason) => {
                self.moves.truncate(before);
                Err(Box::new(Refusal { movement, reason }))
            },
        }
    }

    /// Observe a candidate receipt without admitting it.
    ///
    /// # Specification
    /// - ensures: the same verdict as record, with the original play unchanged.
    /// - fails: the same named monitor refusal as record.
    /// - panics: none.
    ///
    /// # Errors
    /// [`Refusal`] if the candidate violates the session.
    ///
    /// # Adequacy
    /// - hypothesis: L3 probing a valid report leaves the report requirement
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
    #[must_use]
    #[inline]
    pub fn moves(&self) -> &[Move]
    {
        &self.moves
    }
}

/// Build the finite slot syntax, with recursion only through bound variables.
///
/// # Specification
/// - ensures: dispatch requires one or more reports, then handoff or retirement
///   closes; Paused alone permits pause while retaining the current report
///   phase.
/// - fails: [`gandr_core_session::TypeError`] identifies malformed syntax.
/// - panics: none.
///
/// # Errors
/// The upstream constructor's structural validation error.
///
/// # Adequacy
/// - hypothesis: L3 independently stated endpoint actions distinguish every
///   branch, repetition, retirement without report and pause's width.
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
    if edition == Edition::Paused {
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
    if edition == Edition::Paused {
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
