//! The fold: what a peer makes of a tree's commits.
//!
//! Every peer holding the same commits computes the same [`View`]. The
//! commits are placed in one canonical order — a topological order of the
//! DAG that, among the commits whose parents are all placed, places the
//! smallest commit id next — and each receipt is admitted or refused by causal
//! authority and by endpoint replay of its dispatch's accepted canonical
//! prefix. Refused commits stay in the DAG and sync like any other; the fold
//! retains their named reasons without admitting their effects.
//!
//! # Index attestations
//!
//! `Indexed { index }` attests an `IndexDigest`: a project manifest's 32-byte
//! identity, distinct from an evidence digest. The owner or a causally granted
//! member may attest; a dispatch alone grants no attestation authority.
//! `View::indexes` holds each author's last admitted claim in canonical order,
//! including its commit and parents; `View::attestations` retains every claim.
//! The receipt uses kind `0x13` under version 3, leaving other kinds unchanged.
//!
//! `Peer::view_at(tree, heads)` folds precisely the heads' causal past and
//! names a missing head or ancestor as a refusal. `Task::sources` retains
//! original receipt bytes and verified authors beside the admitted steps, so
//! the index plane, `domhringr-record-index`, derives move identities without
//! re-encoding receipts. `StepLine` shares the task replay's move renderer.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::Entry;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::fmt::Write as _;

use anodized::spec;
use domhringr_arena_session::Arena;
use domhringr_arena_session::Channel;
use domhringr_arena_session::Choice;
use domhringr_arena_session::Edition;
use domhringr_arena_session::Movement;
use domhringr_arena_session::Play;
use gandr_core_session::PayloadDigest;

/// One checked protocol pair per process; construction failures remain fold
/// facts.
static ARENA: std::sync::LazyLock<Result<Arena, domhringr_arena_session::ArenaError>> =
    std::sync::LazyLock::new(Arena::new);
use gandr_storage_values::ValueError;
use sedimentree_core::loose_commit::LooseCommit;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::peer::id::PeerId;
use subduction_crypto::verified_meta::VerifiedMeta;

use crate::anchor::Anchor;
use crate::anchor::Path;
use crate::anchor::Resolution;
use crate::anchor::Target;
use crate::check::Grade;
use crate::check::compose;
use crate::decision::Decision;
use crate::id::CommitPrefix;
use crate::id::ContentHash;
use crate::id::PeerKey;
use crate::id::TreeId;
use crate::line::Field;
use crate::line::OneLine;
use crate::name::Domain;
use crate::name::Label;
use crate::presence::Presence;
use crate::receipt::Kind;
use crate::receipt::Operation;
use crate::receipt::Receipt;
use crate::ruling::Ruling;
use crate::task::Step;
use crate::task::Task;

/// An author's claim about an index, at the project heads it read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexAttestation
{
    /// The attested project manifest.
    pub index: crate::IndexDigest,
    /// The receipt carrying the claim.
    pub commit: CommitId,
    /// The project frontier from which the index was derived.
    pub parents: crate::Heads,
}

/// What a peer makes of a tree.
///
/// Its owner, the peers granted write authority, the admitted notes, the paths
/// bound, the DNS names claimed, the trees introduced, the book of who is
/// reachable at which endpoint, the tree read as a task, the commits admitted,
/// and the commits refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View
{
    /// The author of the tree's Open.
    owner: PeerKey,
    /// The peers an admitted grant names.
    members: BTreeSet<PeerKey>,
    /// The admitted notes and their authors, in canonical order.
    notes: Vec<(PeerKey, String)>,
    /// Each bound path's binding: the admitted bind last in canonical order,
    /// its author and its target.
    bindings: BTreeMap<Path, (PeerKey, Target)>,
    /// The DNS names an admitted claim names.
    claims: BTreeSet<Domain>,
    /// Each introduced label's introduction: the admitted introduction last in
    /// canonical order, its author and the tree it names.
    introductions: BTreeMap<Label, (PeerKey, TreeId)>,
    /// Each present author's presence: the admitted presence last in
    /// canonical order, unless an admitted withdrawal follows it.
    book: BTreeMap<PeerKey, Presence>,
    /// Every admitted attestation, retained for pinning and canonical
    /// selection.
    attestations: Vec<(PeerKey, IndexAttestation)>,
    /// Each author's last attestation in canonical order.
    indexes: BTreeMap<PeerKey, IndexAttestation>,
    /// The admitted seat receipts and the current attempt.
    task: Task,
    /// Each dispatch's named protocol and admitted endpoint skeleton.
    plays: BTreeMap<CommitId, (Edition, Play)>,
    /// The admitted commits' ids.
    admitted: BTreeSet<CommitId>,
    /// The refused commits and why, in canonical order.
    refused: Vec<(CommitId, Refusal)>,
}

/// Why a recorded play cannot be transported.
#[derive(Debug, thiserror::Error)]
pub enum PlayTransportError
{
    /// No dispatch with this commit was admitted for monitoring.
    #[error("no monitored dispatch {0}")]
    Missing(CommitId),
    /// Protocol lookup, certificate formation or complete-play conformance
    /// failed.
    #[error(transparent)]
    Arena(#[from] domhringr_arena_session::ArenaError),
}

impl View
{
    /// Each author's last admitted index, with its exact project frontier.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn indexes(&self) -> &BTreeMap<PeerKey, IndexAttestation>
    {
        &self.indexes
    }

    /// Every admitted index in canonical order, including superseded claims.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn attestations(&self) -> &[(PeerKey, IndexAttestation)]
    {
        &self.attestations
    }

    /// The author of the tree's Open.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn owner(&self) -> PeerKey
    {
        self.owner
    }

    /// The peers an admitted grant names.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn members(&self) -> &BTreeSet<PeerKey>
    {
        &self.members
    }

    /// The admitted notes and their authors, in canonical order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn notes(&self) -> &[(PeerKey, String)]
    {
        &self.notes
    }

    /// Each bound path's binding — its author and its target — in path
    /// order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn bindings(&self) -> &BTreeMap<Path, (PeerKey, Target)>
    {
        &self.bindings
    }

    /// What `path` resolves to in this view.
    ///
    /// # Specification
    /// - ensures: [`Resolution::Bound`] with the author and target of the
    ///   admitted bind of `path` last in canonical order, and
    ///   [`Resolution::Unbound`] when no admitted bind names `path`; never a
    ///   default.
    /// - panics: none.
    /// - executable: none — the function is its own specification; competing
    ///   and refused bind witnesses are the independent resolution oracle.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a path bound twice resolves to the later bind from
    ///   every arrival order, a path whose only other bind was refused keeps
    ///   the admitted one, and a path nobody bound is unbound.
    /// - witness: `fold::tests::the_later_bind_in_canonical_order_wins`
    /// - witness: `fold::tests::a_bind_by_a_non_member_is_refused`
    #[inline]
    #[must_use]
    pub fn resolve(
        &self,
        path: &Path,
    ) -> Resolution
    {
        match self.bindings.get(path) {
            | Some(&(author, ref target)) => Resolution::Bound(author, target.clone()),
            | None => Resolution::Unbound,
        }
    }

    /// What the commit `commit` resolves to in this view.
    ///
    /// # Specification
    /// - ensures: [`Resolution::Commit`] with [`Verdict::Admitted`] when the
    ///   fold admitted a commit with this id; with [`Verdict::Refused`] and the
    ///   first refusal in canonical order when it refused one and admitted
    ///   none; and [`Resolution::Unknown`] when the tree holds no commit with
    ///   this id, never [`Resolution::Unbound`].
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — through resolution, an admitted commit, a commit
    ///   refused for want of authority, an undecodable commit, and a commit of
    ///   another tree are each located to their own answer.
    /// - witness: `store::tests::a_commit_resolves_by_its_anchor_to_its_verdict`
    /// - witness: `store::tests::an_ambiguous_prefix_is_refused_naming_it`
    #[spec(ensures: |ref output| matches!(output, Resolution::Commit { .. } | Resolution::Unknown))]
    #[inline]
    #[must_use]
    pub fn locate(
        &self,
        commit: CommitId,
    ) -> Resolution
    {
        if self.admitted.contains(&commit) {
            return Resolution::Commit {
                id: commit,
                verdict: Verdict::Admitted,
            };
        }
        match self.refused.iter().find(|&&(refused, _)| refused == commit) {
            | Some(&(_, ref refusal)) => Resolution::Commit {
                id: commit,
                verdict: Verdict::Refused(refusal.clone()),
            },
            | None => Resolution::Unknown,
        }
    }

    /// The ids of the commits the tree holds that `prefix` abbreviates, in id
    /// order.
    ///
    /// # Specification
    /// - ensures: every commit the fold admitted or refused whose id begins
    ///   with the prefix's digits, each once, and no other.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — through resolution, prefixes of an admitted and of a
    ///   refused commit expand to that commit alone, a prefix two refused
    ///   commits share expands to both and one digit more to one, and a prefix
    ///   no commit begins with expands to none.
    /// - witness: `store::tests::a_commit_resolves_by_its_anchor_to_its_verdict`
    /// - witness: `store::tests::an_ambiguous_prefix_is_refused_naming_it`
    #[spec(ensures: |ref output| {
        let digits = prefix.to_string();
        output.iter().all(|commit| commit.to_string().starts_with(&digits)
            && matches!(self.locate(*commit), Resolution::Commit { .. }))
    })]
    #[inline]
    #[must_use]
    pub fn expand(
        &self,
        prefix: &CommitPrefix,
    ) -> BTreeSet<CommitId>
    {
        let span = prefix.span();
        let mut commits: BTreeSet<CommitId> = self.admitted.range(span.clone()).copied().collect();
        commits.extend(
            self.refused
                .iter()
                .map(|&(commit, _)| commit)
                .filter(|commit| span.contains(commit)),
        );
        commits
    }

    /// The DNS names the tree's owner claims, in name order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn claims(&self) -> &BTreeSet<Domain>
    {
        &self.claims
    }

    /// Each introduced label's introduction — its author and the tree it
    /// names — in label order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn introductions(&self) -> &BTreeMap<Label, (PeerKey, TreeId)>
    {
        &self.introductions
    }

    /// The book: each present author's presence — the endpoint it is reached
    /// at and the commit that presented it — in key order.
    ///
    /// # Specification
    /// - ensures: an author is in the book iff the fold admitted a presence of
    ///   it, and no withdrawal of it was admitted later in canonical order; its
    ///   entry is the presence admitted last. A withdrawn or superseded
    ///   presence is absent, and an author never presented is absent; no entry
    ///   is a default.
    /// - panics: none.
    /// - executable: none — this const field projection performs no fold;
    ///   supersession and withdrawal witnesses establish the stored book
    ///   invariant.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a presence later superseded by its author, and one
    ///   withdrawn by the owner or by its author, are read back absent or
    ///   replaced, while refused presences and withdrawals leave the book as it
    ///   was.
    /// - witness: `fold::tests::the_later_presence_of_an_author_wins`
    /// - witness: `fold::tests::the_book_after_a_withdrawal_does_not_offer_the_endpoint`
    /// - witness: `fold::tests::the_owner_withdraws_a_members_presence`
    /// - witness: `fold::tests::a_member_cannot_withdraw_the_owners_presence`
    #[inline]
    #[must_use]
    pub const fn book(&self) -> &BTreeMap<PeerKey, Presence>
    {
        &self.book
    }

    /// The tree read as a task: its admitted dispatches, reports, handoffs,
    /// retirements, verdicts, verifications, gradings, decisions and landings
    /// in canonical order, and the current attempt.
    ///
    /// # Specification
    /// - ensures: the current attempt is the admitted dispatch last in
    ///   canonical order, or none when no dispatch was admitted; its slot is
    ///   held by the dispatched seat, or by the recipient of the admitted
    ///   handoff of it last in canonical order, or retired by the admitted
    ///   retirement of it when that comes later; its answer is the admitted
    ///   report on it last in canonical order, or awaited; its progress is the
    ///   furthest-ranked of the admitted verifications, gradings, decisions and
    ///   landings on it — in that order of rank — and the one of that rank last
    ///   in canonical order, or unchecked. A report, handoff or retirement of
    ///   an earlier dispatch is a step and moves no attempt, and a verdict is a
    ///   step and moves none.
    /// - panics: none.
    /// - executable: none — this const field projection performs no replay;
    ///   lifecycle and authority witnesses establish the stored task invariant.
    ///
    /// # Adequacy
    /// - hypothesis: L3 a dispatched seat reports; pre-report handoff and
    ///   retirement remain named refusals; reports on superseded dispatches,
    ///   verdicts on a held slot, and an attempt verified, graded, verified
    ///   again, decided to rework, then dispatched anew and landed are each
    ///   read back by a case of their own.
    /// - witness: `fold::tests::the_dispatched_seat_reports_on_its_dispatch`
    /// - witness: `fold::tests::a_handoff_before_report_is_a_named_protocol_refusal`
    /// - witness: `fold::tests::retirement_before_report_is_refused_without_relinquishing_the_slot`
    /// - witness: `fold::tests::a_report_on_a_superseded_dispatch_is_refused`
    /// - witness: `fold::tests::a_judge_rules_on_the_current_dispatch`
    /// - witness: `fold::tests::an_attempt_advances_through_its_lifecycle`
    #[inline]
    #[must_use]
    pub const fn task(&self) -> &Task
    {
        &self.task
    }

    /// Transport one complete admitted play to a named edition without writing
    /// receipts.
    ///
    /// # Specification
    /// - ensures: the source edition comes from the dispatch; the returned play
    ///   preserves every admitted move and digest after local certificate
    ///   formation.
    /// - fails: a missing dispatch, unavailable protocol, incomplete play or
    ///   invalid widening is refused, never substituted.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`PlayTransportError`]: the named play or widening cannot be
    ///   established.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — complete, incomplete, missing and unknown-edition
    ///   attempts distinguish transport from replay under a local default.
    /// - witness: `fold::tests::dispatch_editions_govern_each_attempt`
    #[spec(ensures: |ref output| output.is_err() || self.plays.contains_key(&dispatch))]
    #[inline]
    pub fn transport(
        &self,
        dispatch: CommitId,
        target: Edition,
    ) -> Result<Play, PlayTransportError>
    {
        let &(source, ref play) = self
            .plays
            .get(&dispatch)
            .ok_or(PlayTransportError::Missing(dispatch))?;
        let arena = Arena::new()?;
        let play = arena.transport(source, target, play)?;
        Ok(play)
    }

    /// The refused commits and why, in canonical order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn refused(&self) -> &[(CommitId, Refusal)]
    {
        &self.refused
    }
}

impl fmt::Display for View
{
    /// Write the view as lines: `owner <key>`, one `member <key>` per member
    /// in key order, one `note <key> <text>` per note in canonical order, one
    /// `bind <path> <target>` per bound path in path order, one `claim
    /// <domain>` per claimed name in name order, one `introduce <label>
    /// <anchor>` per introduced label in label order, the anchor the
    /// introduced tree's key form, one `present <key> <endpoint> <commit>` per
    /// author in the book in key order, the endpoint in its text form and the
    /// commit the one that presented it, and one `refused <commit> <reason>`
    /// per refusal in canonical order.
    ///
    /// # Specification
    /// - ensures: every line ends in a newline, and each fact stays one line: a
    ///   backslash in a note, a path, a label, a datum or an anchor target is
    ///   written `\\` and a control character as its Rust escape (`\n`,
    ///   `\u{7}`), and a space in a path or a label as `\u{20}`, so equal views
    ///   print equal bytes and distinct facts print distinct lines.
    /// - panics: none.
    /// - executable: none — the formatter is write-only; the view fixture
    ///   independently observes escaped facts and line boundaries.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a view with a member, notes, a multi-line note, a
    ///   path with a space bound to a datum with a newline, a path bound to a
    ///   commit in another tree, a path bound to an anchor whose label holds a
    ///   space and whose path holds a newline, two claims, two introductions,
    ///   one by a label with a space, a presence at an IPv4 address and a
    ///   relay, and a refusal is printed and compared line for line.
    /// - witness: `fold::tests::a_view_prints_one_line_per_fact`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        writeln!(f, "owner {}", self.owner)?;
        for member in &self.members {
            writeln!(f, "member {member}")?;
        }
        for &(author, ref text) in &self.notes {
            write!(f, "note {author} ")?;
            OneLine::new(f, Field::Last).write_str(text)?;
            writeln!(f)?;
        }
        for (path, &(_author, ref target)) in &self.bindings {
            f.write_str("bind ")?;
            write!(OneLine::new(f, Field::Inner), "{path}")?;
            writeln!(f, " {target}")?;
        }
        for domain in &self.claims {
            writeln!(f, "claim {domain}")?;
        }
        for (label, &(_author, tree)) in &self.introductions {
            f.write_str("introduce ")?;
            write!(OneLine::new(f, Field::Inner), "{label}")?;
            writeln!(f, " {}", Anchor::key(tree))?;
        }
        for (author, presence) in &self.book {
            writeln!(f, "present {author} {presence}")?;
        }
        for (author, attestation) in &self.indexes {
            writeln!(
                f,
                "indexed {author} {} {}",
                attestation.commit, attestation.index
            )?;
        }
        for &(commit, ref refusal) in &self.refused {
            writeln!(f, "refused {commit} {refusal}")?;
        }
        Ok(())
    }
}

/// Why the fold gives a commit no meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal
{
    /// A receipt move failed endpoint replay.
    Protocol(alloc::boxed::Box<domhringr_arena_session::Refusal>),
    /// Protocol construction or its kernel certificate failed.
    Arena(String),
    /// The blob is not a receipt.
    Undecodable(ValueError),
    /// The receipt belongs to another tree.
    WrongTree
    {
        /// The tree the receipt names.
        named: TreeId,
    },
    /// An admitted receipt earlier in canonical order carries the same
    /// operation.
    Duplicate
    {
        /// The admitted commit carrying the operation.
        first: CommitId,
    },
    /// The author is not the owner, and no admitted grant to the author is
    /// an ancestor of the receipt — nor, for a presence or a withdrawal, a
    /// dispatch or handoff to it.
    NoAuthority,
    /// An Open whose proof is not the tree key's signature naming its author.
    BadProof,
    /// An Open that is not the tree's.
    SecondOpen,
    /// A claim whose author is not the tree's owner: only the owner names the
    /// tree by a DNS name, whatever authority a grant gave.
    NotOwner,
    /// A presence whose proof is not the presented endpoint key's signature
    /// naming its author: a member presents its own endpoint alone.
    ForeignEndpoint,
    /// A withdrawal of another member's presence by anyone but the owner: a
    /// member withdraws its own presence alone.
    ForeignPresence,
    /// A report, a handoff, a retirement, a verdict, a verification or a
    /// decision whose dispatch is not the admitted dispatch last in canonical
    /// order among the receipt's ancestors — or a grading whose verdict's
    /// dispatch is not, or a landing whose decision's dispatch is not: a later
    /// dispatch superseded it, or it names none.
    NotCurrent,
    /// A report, a handoff or a retirement whose author does not hold the
    /// dispatch's slot among the receipt's ancestors: the seat dispatched, or
    /// the recipient of the slot's last handoff, holds it until it retires.
    NotHolder,
    /// A verdict whose author is not the judge it names, or a grading whose
    /// author is not its verdict's judge: a judge's verdict, and its grading,
    /// is signed by its own key.
    NotJudge,
    /// A verification whose author is not the runner it names: a runner's
    /// verification is signed by its own key.
    NotRunner,
    /// A grading whose grades do not answer its verdict's: one grade per
    /// answer, refused exactly where the judge read no ruling.
    Misgraded,
    /// A grading whose composed grade differs from its grades' conjunction.
    Miscomposed,
    /// A decision whose author is not the operator it names, or a landing
    /// whose author is not its decision's operator: an operator's decision,
    /// and its landing, is signed by its own key.
    NotOperator,
}

impl fmt::Display for Refusal
{
    /// Write the reason as the view prints it.
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
            | Self::Protocol(ref reason) => return write!(f, "protocol {reason}"),
            | Self::Arena(ref reason) => return write!(f, "arena {reason}"),
            | Self::Undecodable(_) => "undecodable",
            | Self::WrongTree { .. } => "wrong tree",
            | Self::Duplicate { .. } => "duplicate operation",
            | Self::NoAuthority => "no authority",
            | Self::BadProof => "bad proof",
            | Self::NotOwner => "not owner",
            | Self::SecondOpen => "second open",
            | Self::ForeignEndpoint => "foreign endpoint",
            | Self::ForeignPresence => "foreign presence",
            | Self::NotCurrent => "not current",
            | Self::NotHolder => "not holder",
            | Self::NotJudge => "not judge",
            | Self::NotRunner => "not runner",
            | Self::Misgraded => "misgraded",
            | Self::Miscomposed => "miscomposed",
            | Self::NotOperator => "not operator",
        })
    }
}

/// The fold's verdict on a commit the tree holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict
{
    /// The fold admitted the commit.
    Admitted,
    /// The fold refused the commit, for this reason.
    Refused(Refusal),
}

impl fmt::Display for Verdict
{
    /// Write `admitted`, or `refused` followed by the reason as the view
    /// prints it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Admitted => f.write_str("admitted"),
            | Self::Refused(ref refusal) => write!(f, "refused {refusal}"),
        }
    }
}

/// Why a tree has no view: no commit in it is the tree's Open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the tree holds no Open receipt, so it has no owner")]
pub struct Unopened;

/// A commit's place in the commit list sorted by [`canonical`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct Position(usize);

/// A commit's place in the canonical order: how many commits the fold placed
/// before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct Placed(usize);

/// Who a dispatch's slot is with in a commit's causal past.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Holder
{
    /// This seat holds it.
    Seat(PeerKey),
    /// Its last holder retired from it.
    Vacant,
}

/// The admitted dispatch last in canonical order in a commit's causal past,
/// and its slot there.
///
/// The derived order is the order two pasts merge by: a later dispatch
/// supersedes an earlier one, and of one dispatch the slot's later move wins.
/// One placement names one commit, so the fields after a placement never
/// decide between two courses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Course
{
    /// No admitted dispatch is in the causal past.
    Undispatched,
    /// This dispatch is.
    Dispatched
    {
        /// Where the dispatch was placed.
        placed: Placed,
        /// The dispatch's commit.
        dispatch: CommitId,
        /// Where the slot's last move — the dispatch, a handoff or a
        /// retirement — was placed.
        moved: Placed,
        /// Who the slot is with after that move.
        holder: Holder,
    },
}

impl Course
{
    /// Whether `author` may report on, hand off or retire from `dispatch`
    /// here.
    ///
    /// # Specification
    /// - ensures: `Ok` iff `dispatch` is this course's dispatch and `author`
    ///   holds its slot; [`Refusal::NotCurrent`] when the course is of another
    ///   dispatch or of none, and [`Refusal::NotHolder`] when the slot is with
    ///   another seat or retired.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — wrong holders and superseded dispatches are refused
    ///   without changing the current attempt.
    /// - witness: `fold::tests::a_report_on_a_superseded_dispatch_is_refused`
    #[spec(ensures: |ref output| output.is_err() || self.current(dispatch).is_ok())]
    fn answerable(
        self,
        dispatch: CommitId,
        author: PeerKey,
    ) -> Result<(), Refusal>
    {
        match self {
            | Self::Dispatched {
                dispatch: current,
                holder,
                ..
            } if current == dispatch => match holder {
                | Holder::Seat(seat) if seat == author => Ok(()),
                | Holder::Seat(_) | Holder::Vacant => Err(Refusal::NotHolder),
            },
            | Self::Dispatched { .. } | Self::Undispatched => Err(Refusal::NotCurrent),
        }
    }

    /// Check the cross-channel relation to the current slot dispatch.
    ///
    /// # Specification
    /// - ensures: `Ok` iff `dispatch` is this course's dispatch, whoever holds
    ///   its slot and whether or not it was retired from;
    ///   [`Refusal::NotCurrent`] when the course is of another dispatch or of
    ///   none.
    /// - panics: none.
    /// - executable: none — the function is its own specification; current and
    ///   stale dispatch witnesses provide the independent relation oracle.
    ///
    /// # Errors
    /// - [`Refusal::NotCurrent`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a receipt naming a superseded dispatch cannot answer
    ///   the current attempt.
    /// - witness: `fold::tests::a_report_on_a_superseded_dispatch_is_refused`
    fn current(
        self,
        dispatch: CommitId,
    ) -> Result<(), Refusal>
    {
        match self {
            | Self::Dispatched {
                dispatch: current, ..
            } if current == dispatch => Ok(()),
            | Self::Dispatched { .. } | Self::Undispatched => Err(Refusal::NotCurrent),
        }
    }

    /// This course with its slot moved to `holder` by the commit placed at
    /// `moved`.
    ///
    /// # Specification
    /// - ensures: a dispatched course keeps its dispatch and takes `moved` and
    ///   `holder`; an undispatched one is returned unchanged.
    /// - panics: none.
    /// - executable: none — the const function is its own specification; slot
    ///   transition witnesses observe which holder retains authority.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the first handoff changes the holder; a repeated
    ///   handoff is refused without restoring the earlier holder.
    /// - witness: `fold::tests::handoff_closes_the_play_instead_of_permitting_a_second_handoff`
    const fn moved(
        self,
        moved: Placed,
        holder: Holder,
    ) -> Self
    {
        match self {
            | Self::Dispatched {
                placed, dispatch, ..
            } => Self::Dispatched {
                placed,
                dispatch,
                moved,
                holder,
            },
            | Self::Undispatched => self,
        }
    }
}

/// What a commit's causal past, the commit itself included, hands its
/// children.
struct Past
{
    /// The peers named by admitted grants.
    grantees: BTreeSet<PeerKey>,
    /// The peers given a slot by an admitted dispatch or handoff.
    seats: BTreeSet<PeerKey>,
    /// The admitted verdicts.
    verdicts: BTreeSet<CommitId>,
    /// The admitted decisions.
    decisions: BTreeSet<CommitId>,
    /// The latest dispatch and its slot.
    course: Course,
}

/// Replay one named receipt against the process's kernel-checked protocol.
///
/// # Specification
/// - ensures: an admitted move advances the play; a refusal leaves it
///   unchanged.
/// - fails: protocol initialization and monitor refusals remain distinct facts.
/// - panics: none.
/// - executable: none — the function is its own specification; edition and
///   refusal witnesses observe the delegated monitor transitions.
///
/// # Errors
/// [`Refusal::Arena`] or [`Refusal::Protocol`].
///
/// # Adequacy
/// - hypothesis: L3 order and pause-width near misses pin the receipt and
///   state.
/// - witness: `fold::tests::dispatch_editions_govern_each_attempt`
fn record_move(
    play: &mut Play,
    edition: Edition,
    movement: Movement,
    commit: CommitId,
) -> Result<(), Refusal>
{
    let arena = ARENA
        .as_ref()
        .map_err(|error| Refusal::Arena(error.to_string()))?;
    let _progress = play
        .record(arena, edition, movement, PayloadDigest(*commit.as_bytes()))
        .map_err(Refusal::Protocol)?;
    Ok(())
}

/// Check authority and replay without letting an unauthorized move advance.
///
/// # Specification
/// - ensures: only an authorized, conforming receipt advances the play.
/// - fails: monitor order failures name the move; otherwise authority failures
///   retain their existing classification.
/// - panics: none.
///
/// # Errors
/// The authority refusal, [`Refusal::Arena`] or [`Refusal::Protocol`].
///
/// # Adequacy
/// - hypothesis: L3 out-of-order and wrong-author twins distinguish protocol
///   state from authority, and a refused pause leaves the next report
///   admissible.
/// - witness: `fold::tests::dispatch_editions_govern_each_attempt`
#[spec(ensures: |ref output| output.is_err() || plays.contains_key(&dispatch))]
fn admit_move(
    plays: &mut BTreeMap<CommitId, (Edition, Play)>,
    dispatch: CommitId,
    authority: Result<(), Refusal>,
    movement: Movement,
    commit: CommitId,
) -> Result<(), Refusal>
{
    let Some(&mut (edition, ref mut play)) = plays.get_mut(&dispatch)
    else {
        return Err(Refusal::NotCurrent);
    };
    if let Err(authority) = authority {
        let arena = ARENA
            .as_ref()
            .map_err(|error| Refusal::Arena(error.to_string()))?;
        let _progress = play
            .inspect(arena, edition, movement, PayloadDigest(*commit.as_bytes()))
            .map_err(Refusal::Protocol)?;
        return Err(authority);
    }
    record_move(play, edition, movement, commit)
}

/// Replay a channel move under the edition of its current dispatch.
///
/// # Specification
/// - ensures: only a move naming the current dispatch reaches its monitor.
/// - fails: an absent or superseded dispatch is not current; otherwise replay
///   returns its named refusal without advancing the accepted prefix.
/// - panics: none.
///
/// # Errors
/// - [`Refusal`]: cross-channel, arena or protocol failure.
///
/// # Adequacy
/// - hypothesis: L3 current and stale dispatches separate the cross-channel
///   relation from duplicate-choice refusals in the monitor.
/// - witness: `fold::tests::task_channels_refuse_second_choices`
#[spec(ensures: |ref output| output.is_err() || plays.contains_key(&dispatch))]
fn advance(
    plays: &BTreeMap<CommitId, (Edition, Play)>,
    course: Course,
    dispatch: CommitId,
    play: &mut Play,
    movement: Movement,
    commit: CommitId,
) -> Result<(), Refusal>
{
    course.current(dispatch)?;
    let &(edition, _) = plays.get(&dispatch).ok_or(Refusal::NotCurrent)?;
    record_move(play, edition, movement, commit)
}

/// Replay a receipt with no causal predecessor on an empty channel.
///
/// # Specification
/// - requires: movement is grading or landing, whose predecessor is absent.
/// - fails: no current dispatch returns not current; otherwise the monitor
///   refuses the move at the channel's initial state under that edition.
/// - panics: none.
///
/// # Errors
/// - [`Refusal`]: cross-channel, arena or protocol failure.
///
/// # Adequacy
/// - hypothesis: L3 unknown and concurrent predecessors are both absent from
///   the candidate's causal prefix and fail at the initial monitor state.
/// - witness: `fold::tests::a_verdicts_judge_grades_its_answers`
/// - witness: `fold::tests::a_landing_carries_out_a_decision_to_land`
#[spec(requires: matches!(movement, Movement::Graded | Movement::Landed), ensures: |ref output| output.is_err())]
fn unstarted(
    plays: &BTreeMap<CommitId, (Edition, Play)>,
    course: Course,
    channel: Channel,
    movement: Movement,
    commit: CommitId,
) -> Result<(), Refusal>
{
    match course {
        | Course::Dispatched { dispatch, .. } => advance(
            plays,
            course,
            dispatch,
            &mut Play::new(channel),
            movement,
            commit,
        ),
        | Course::Undispatched => Err(Refusal::NotCurrent),
    }
}

/// An admitted decision, as a landing of it reads it.
struct Decided
{
    /// The dispatch decided.
    dispatch: CommitId,
    /// The operator who decided.
    operator: PeerKey,
}

/// An admitted verdict, as a grading of it reads it.
struct Ruled
{
    /// The accepted verdict and grading prefix.
    play: Play,
    /// The judge who ruled.
    judge: PeerKey,
    /// The dispatch ruled on.
    dispatch: CommitId,
    /// The hash of the rubric the questions come from.
    rubric: ContentHash,
    /// Each question's hash and whether the judge read its ruling, in the
    /// order asked.
    questions: Vec<(ContentHash, Reading)>,
}

/// Whether the judge read a question's ruling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading
{
    /// A readout: a grade places it against the band.
    Read,
    /// No readout: its grade is refused.
    Unread,
}

/// A commit awaiting its place in the canonical order.
struct Node
{
    /// The commit's id.
    commit: CommitId,
    /// The commit's verified signer.
    author: PeerKey,
    /// The receipt the commit's blob carries, or why it carries none.
    receipt: Result<Receipt, ValueError>,
    /// The receipt's original bytes, transferred to the admitted move.
    blob: sedimentree_core::blob::Blob,
    /// Original parent ids for an attestation; empty for other receipts.
    attested_parents: crate::Heads,
    /// The commits held in the tree that this one names as parents.
    parents: Vec<Position>,
    /// Those parents not placed yet.
    waiting: BTreeSet<Position>,
    /// The commits held in the tree that name this one as a parent.
    children: Vec<Position>,
}

/// The authority a placed commit hands down to its children.
struct Carry
{
    /// The commit's causal past, the commit itself included.
    past: Past,
    /// The children not placed yet, each of which reads this once.
    readers: BTreeSet<Position>,
}

/// Fold `tree`'s commits into its view.
///
/// # Specification
/// - requires: `commits` are the commits held for `tree`, in any order and with
///   any repetition.
/// - ensures: the view depends only on the set of commits, never on their
///   order. Commits are placed in canonical order: among the commits whose
///   parents held in the set are all placed, the one with the smallest commit
///   id goes next, and among equal ids the one with the smaller signed bytes. A
///   commit is admitted iff it is the tree's Open — of the commits with no
///   parents whose receipt is an Open of `tree` with a proof that verifies
///   under `tree` for its author ([`OpenProof::verify`]), the first in
///   canonical order, whose author is the owner — or it is a claim whose author
///   is the owner, or it is a grant, a note, a bind, an introduction or a
///   dispatch whose author is the owner or has an admitted grant among its
///   ancestors, or it is a presence by such an author or by a seat — a peer an
///   admitted dispatch or handoff among its ancestors names — whose proof
///   verifies under the presented endpoint's key for its author
///   ([`EndpointProof::verify`]), or it is a withdrawal whose author is the
///   owner, or is granted or a seat and withdraws its own presence, or it is a
///   report, a handoff or a retirement whose dispatch is the admitted dispatch
///   last in canonical order among its ancestors and whose author holds that
///   dispatch's slot there: the seat dispatched, or the recipient of the slot's
///   admitted handoff last in canonical order there, unless an admitted
///   retirement from the slot comes later; or it is a verdict whose author is
///   the judge it names, or a verification whose author is the runner it names,
///   and whose dispatch is the admitted dispatch last in canonical order among
///   its ancestors, whoever holds the slot; or it is a grading whose verdict is
///   admitted among its ancestors, whose author is that verdict's judge, whose
///   grades number its answers with a refused grade exactly for each unread
///   ruling, and whose verdict's dispatch is the admitted dispatch last in
///   canonical order among its ancestors; or it is a decision whose author is
///   the operator it names and holds the operator role — the owner, or granted
///   among its ancestors — and whose dispatch is the admitted dispatch last in
///   canonical order among its ancestors; or it is a landing whose decision is
///   an admitted decision to land among its ancestors, whose author is that
///   decision's operator, and whose decision's dispatch is the admitted
///   dispatch last in canonical order among its ancestors.
/// - ensures: every task move conforms to its binary channel under the
///   dispatch's edition: slot per dispatch, judge per verdict, runner per
///   runner and dispatch, decision per dispatch. A second grading, decision or
///   landing is refused by the monitor. A refused candidate changes neither its
///   accepted canonical prefix nor causal authority.
/// - ensures: a refused commit is listed with the first refusal that holds,
///   checked in this order: [`Refusal::Undecodable`], [`Refusal::WrongTree`],
///   [`Refusal::Duplicate`] (an admitted commit earlier in canonical order
///   carries the same operation), then [`Refusal::Arena`] or
///   [`Refusal::Protocol`] for a Seat move, then for an Open
///   [`Refusal::BadProof`] when its proof fails and [`Refusal::SecondOpen`]
///   when it is not the tree's, [`Refusal::NotOwner`] for a claim,
///   [`Refusal::NoAuthority`] for a grant, a note, a bind, an introduction or a
///   dispatch by an author neither the owner nor granted and for a presence or
///   a withdrawal by an author neither that nor a seat, then
///   [`Refusal::ForeignEndpoint`] for a presence whose proof fails and
///   [`Refusal::ForeignPresence`] for a member's or a seat's withdrawal of
///   another's presence, for a report, a handoff or a retirement
///   [`Refusal::NotCurrent`] when its dispatch is not the latest among its
///   ancestors and [`Refusal::NotHolder`] when its author does not hold the
///   slot there, for a verdict [`Refusal::NotJudge`] when its author is not the
///   judge it names and for a verification [`Refusal::NotRunner`] when its
///   author is not the runner it names, then [`Refusal::NotCurrent`] when its
///   dispatch is not the latest among its ancestors. A grading or landing with
///   no causal predecessor replays on an empty channel and receives a named
///   protocol refusal. Otherwise grading checks judge, answer shape and
///   composition, refusing [`Refusal::Miscomposed`] when its composition
///   differs from [`compose`]. Landing checks the deciding operator, and both
///   check the current dispatch before replay. A decision checks operator
///   authority, identity and current dispatch before replay. Unknown editions
///   never fall back to a local protocol.
/// - ensures: each path's binding is the admitted bind of that path last in
///   canonical order, each label's introduction the admitted introduction of
///   that label last in canonical order, the claims the domains of every
///   admitted claim, each author's presence in the book its admitted presence
///   last in canonical order unless an admitted withdrawal of it comes later,
///   whose `since` is that presence's commit, the task as [`View::task`] states
///   it, and the admitted commits the ids of every commit admitted.
/// - fails: [`Unopened`] when no commit is the tree's Open.
/// - panics: none.
/// - intension: when parents claim a cycle no topological order exists; the
///   smallest unplaced commit is then placed next, and authority flows only
///   from parents already placed. The fold is O(n log n) in the commits,
///   verifies each Open's proof once, and holds authority sets only for placed
///   commits with unplaced children.
///
/// # Errors
/// - [`Unopened`]: no root Open of `tree` carries a proof for its author.
///
/// # Adequacy
/// - hypothesis: L3 — one DAG with concurrent branches, a refused note, a grant
///   and a merge is folded from three arrival orders and compared exactly; each
///   refusal reason, the causal reading of a grant, the first-wins duplicate,
///   the smallest-root Open, a forged and a replayed proof, the last-wins bind
///   from every arrival order, the owner-only claim refused to a member and a
///   non-member, the last-wins introduction and an introduction refused to a
///   non-member, a presence refused to a non-member, a presence of another
///   member's endpoint and one proved by another key, the last-wins presence
///   from every arrival order, the owner's withdrawal of a member's presence
///   and a member's of its own, a member's withdrawal of the owner's refused, a
///   dispatch refused to a non-member, a seat's presence, its report, a report
///   by a peer not holding the slot, handoff and retirement before a report, a
///   report on a superseded and on an unknown dispatch, a report concurrent
///   with a later dispatch, a judge's verdict on a held and on a retired slot,
///   a verdict signed by another key than its judge's, a verdict on a
///   superseded and on an unknown dispatch, a runner's verification on a held
///   and on a retired slot, one signed by another key than its runner's and one
///   on a superseded dispatch, a judge's grading of its verdict, a grading
///   signed by another key, of an unknown verdict and of one only concurrent
///   with it, with a grade too few, a read answer refused and an unread answer
///   met, and a grading after a later dispatch, a decision by the owner and by
///   a member, by a seat and by a stranger, signed by a member for the owner,
///   on an unknown and on a superseded dispatch, a landing of a decision to
///   land, by the seat and by a member who did not decide, without a decision,
///   of a decision only concurrent with it, of a decision to rework and after a
///   later dispatch, an unopened tree and a parent cycle are each pinned by a
///   case of their own.
/// - witness: `fold::tests::a_view_is_the_same_whatever_order_commits_arrive_in`
/// - witness: `fold::tests::a_note_by_a_non_member_is_refused`
/// - witness: `fold::tests::a_note_by_a_peer_granted_in_its_causal_past_is_admitted`
/// - witness: `fold::tests::a_duplicate_operation_keeps_the_first`
/// - witness: `fold::tests::a_receipt_under_the_wrong_tree_is_refused`
/// - witness: `fold::tests::the_smallest_root_open_names_the_owner`
/// - witness: `fold::tests::an_open_proved_by_another_key_is_refused`
/// - witness: `fold::tests::the_later_bind_in_canonical_order_wins`
/// - witness: `fold::tests::a_bind_by_a_non_member_is_refused`
/// - witness: `fold::tests::a_claim_by_anyone_but_the_owner_is_refused`
/// - witness: `fold::tests::the_later_introduction_of_a_label_rebinds_it`
/// - witness: `fold::tests::a_presence_by_a_non_member_is_refused`
/// - witness: `fold::tests::a_presence_naming_another_members_endpoint_is_refused`
/// - witness: `fold::tests::the_later_presence_of_an_author_wins`
/// - witness: `fold::tests::the_owner_withdraws_a_members_presence`
/// - witness: `fold::tests::a_member_cannot_withdraw_the_owners_presence`
/// - witness: `fold::tests::the_book_after_a_withdrawal_does_not_offer_the_endpoint`
/// - witness: `fold::tests::an_undecodable_blob_is_refused_and_an_unopened_tree_has_no_view`
/// - witness: `fold::tests::a_parent_cycle_is_placed_in_commit_id_order`
/// - witness: `fold::tests::the_dispatched_seat_reports_on_its_dispatch`
/// - witness: `fold::tests::a_handoff_before_report_is_a_named_protocol_refusal`
/// - witness: `fold::tests::retirement_before_report_is_refused_without_relinquishing_the_slot`
/// - witness: `fold::tests::a_report_on_a_superseded_dispatch_is_refused`
/// - witness: `fold::tests::a_judge_rules_on_the_current_dispatch`
/// - witness: `fold::tests::a_verdict_on_a_superseded_dispatch_is_refused`
/// - witness: `fold::tests::a_runner_verifies_on_the_current_dispatch`
/// - witness: `fold::tests::a_verdicts_judge_grades_its_answers`
/// - witness: `fold::tests::an_operator_decides_on_the_current_dispatch`
/// - witness: `fold::tests::a_landing_carries_out_a_decision_to_land`
///
/// [`OpenProof::verify`]: crate::receipt::OpenProof::verify
/// [`EndpointProof::verify`]: crate::receipt::EndpointProof::verify
#[spec(ensures: |ref output| output.as_ref().map_or(true, |view|
    view.task.steps().iter().all(|entry| view.admitted.contains(&entry.0))
        && view.book.values().all(|presence| view.admitted.contains(&presence.since()))
        && view.indexes.values().all(|index| view.admitted.contains(&index.commit))))]
pub fn fold(
    tree: TreeId,
    commits: Vec<VerifiedMeta<LooseCommit>>,
) -> Result<View, Unopened>
{
    let mut commits = commits;
    commits.sort_by(canonical);
    commits.dedup_by(|later, earlier| canonical(later, earlier).is_eq());
    let heads: Vec<CommitId> = commits
        .iter()
        .map(|commit| commit.payload().head())
        .collect();
    let parents: Vec<Vec<Position>> = commits
        .iter()
        .map(|commit| {
            commit
                .payload()
                .parents()
                .iter()
                .flat_map(|parent| {
                    let first = heads.partition_point(|head| head < parent);
                    let end = heads.partition_point(|head| head <= parent);
                    (first .. end).map(Position)
                })
                .collect()
        })
        .collect();
    let mut children: BTreeMap<Position, Vec<Position>> = BTreeMap::new();
    for (child, parents) in parents.iter().enumerate() {
        for parent in parents {
            children.entry(*parent).or_default().push(Position(child));
        }
    }

    let mut open = None;
    let mut bad_proofs = BTreeSet::new();
    let mut nodes = BTreeMap::new();
    for (index, (commit, parents)) in commits.into_iter().zip(parents).enumerate() {
        let position = Position(index);
        let author = PeerKey::new(PeerId::from(commit.issuer()));
        let receipt = Receipt::decode(commit.blob());
        let attested_parents = if matches!(receipt, Ok(ref receipt) if matches!(receipt.kind(), Kind::Indexed { .. }))
        {
            commit.payload().parents().iter().copied().collect()
        }
        else {
            crate::Heads::default()
        };
        let (commit, blob) = commit.into_parts();
        let proof = match receipt {
            | Ok(ref receipt) if receipt.tree() == tree => match *receipt.kind() {
                | Kind::Open { proof } => Some(proof.verify(tree, author)),
                | Kind::Grant { .. }
                | Kind::Note { .. }
                | Kind::Indexed { .. }
                | Kind::Bind { .. }
                | Kind::Claim { .. }
                | Kind::Introduce { .. }
                | Kind::Present { .. }
                | Kind::Withdraw { .. }
                | Kind::Dispatch { .. }
                | Kind::Report { .. }
                | Kind::Handoff { .. }
                | Kind::Retire { .. }
                | Kind::Pause { .. }
                | Kind::Verdict { .. }
                | Kind::Verified { .. }
                | Kind::Graded { .. }
                | Kind::Decide { .. }
                | Kind::Landed { .. } => None,
            },
            | Ok(_) | Err(_) => None,
        };
        match proof {
            | Some(Ok(())) if open.is_none() && commit.payload().parents().is_empty() => {
                open = Some((position, author));
            },
            | Some(Err(_forged)) => {
                let _first_seen = bad_proofs.insert(position);
            },
            | Some(Ok(())) | None => {},
        }
        let node = Node {
            commit: commit.payload().head(),
            author,
            receipt,
            blob,
            attested_parents,
            waiting: parents.iter().copied().collect(),
            parents,
            children: children.remove(&position).unwrap_or_default(),
        };
        drop(nodes.insert(position, node));
    }
    let Some((open, owner)) = open
    else {
        return Err(Unopened);
    };

    let mut view = View {
        owner,
        members: BTreeSet::new(),
        notes: Vec::new(),
        bindings: BTreeMap::new(),
        claims: BTreeSet::new(),
        introductions: BTreeMap::new(),
        book: BTreeMap::new(),
        attestations: Vec::new(),
        indexes: BTreeMap::new(),
        task: Task::new(),
        plays: BTreeMap::new(),
        admitted: BTreeSet::new(),
        refused: Vec::new(),
    };
    let mut ready: BTreeSet<Position> = nodes
        .iter()
        .filter(|&(_, node)| node.waiting.is_empty())
        .map(|(position, _)| *position)
        .collect();
    let mut carries = BTreeMap::new();
    let mut admitted = BTreeMap::new();
    let mut ruled = BTreeMap::new();
    let mut decisions = BTreeMap::new();
    let mut plays = BTreeMap::new();
    let mut runner_plays = BTreeMap::new();
    let mut decision_plays = BTreeMap::new();
    for placed in (0_usize ..).map(Placed) {
        let ready_node = core::iter::from_fn(|| ready.pop_first())
            .find_map(|position| nodes.remove_entry(&position));
        let Some((position, node)) = ready_node.or_else(|| nodes.pop_first())
        else {
            break;
        };
        for child in &node.children {
            if let Some(child_node) = nodes.get_mut(child) {
                let _was_waiting = child_node.waiting.remove(&position);
                if child_node.waiting.is_empty() {
                    let _was_ready = ready.insert(*child);
                }
            }
        }
        let mut past = inherit(&mut carries, &node.parents, position);
        let refusal = match node.receipt {
            | Err(failure) => Some(Refusal::Undecodable(failure)),
            | Ok(receipt) => {
                let (named, operation, kind) = receipt.into_parts();
                let authorized = node.author == owner || past.grantees.contains(&node.author);
                let present = authorized || past.seats.contains(&node.author);
                if named != tree {
                    Some(Refusal::WrongTree { named })
                }
                else if let Some(first) = admitted.get(&operation) {
                    Some(Refusal::Duplicate { first: *first })
                }
                else {
                    let protocol = match kind {
                        | Kind::Dispatch { edition, .. } if authorized => {
                            let mut play = Play::default();
                            let result =
                                record_move(&mut play, edition, Movement::Dispatch, node.commit);
                            // Keep unknown names so subsequent moves cannot fall back.
                            drop(plays.insert(node.commit, (edition, play)));
                            result
                        },
                        | Kind::Report { dispatch, .. } => admit_move(
                            &mut plays,
                            dispatch,
                            past.course.answerable(dispatch, node.author),
                            Movement::Report,
                            node.commit,
                        ),
                        | Kind::Handoff { dispatch, .. } => admit_move(
                            &mut plays,
                            dispatch,
                            past.course.answerable(dispatch, node.author),
                            Movement::Handoff,
                            node.commit,
                        ),
                        | Kind::Retire { dispatch, .. } => admit_move(
                            &mut plays,
                            dispatch,
                            past.course.answerable(dispatch, node.author),
                            Movement::Retire,
                            node.commit,
                        ),
                        | Kind::Pause { dispatch, .. } => admit_move(
                            &mut plays,
                            dispatch,
                            past.course.answerable(dispatch, node.author),
                            Movement::Pause,
                            node.commit,
                        ),
                        | _ => Ok(()),
                    };
                    let refusal = match protocol {
                        | Err(refusal) => Some(refusal),
                        | Ok(()) => match kind {
                            | Kind::Open { .. } if bad_proofs.contains(&position) => {
                                Some(Refusal::BadProof)
                            },
                            | Kind::Open { .. } => {
                                (position != open).then_some(Refusal::SecondOpen)
                            },
                            | Kind::Grant { to } if authorized => {
                                let _was_member = view.members.insert(to);
                                let _was_granted = past.grantees.insert(to);
                                None
                            },
                            | Kind::Note { text } if authorized => {
                                view.notes.push((node.author, text));
                                None
                            },
                            | Kind::Indexed { index } if authorized => {
                                let attestation = IndexAttestation {
                                    index,
                                    commit: node.commit,
                                    parents: node.attested_parents,
                                };
                                // Both the retention set and the latest claim own their frontier.
                                view.attestations.push((node.author, attestation.clone()));
                                drop(view.indexes.insert(node.author, attestation));
                                None
                            },
                            | Kind::Bind { path, target } if authorized => {
                                let _rebound = view.bindings.insert(path, (node.author, target));
                                None
                            },
                            | Kind::Claim { domain } if node.author == owner => {
                                let _claimed_before = view.claims.insert(domain);
                                None
                            },
                            | Kind::Claim { .. } => Some(Refusal::NotOwner),
                            | Kind::Introduce {
                                tree: introduced,
                                label,
                            } if authorized => {
                                let _reintroduced =
                                    view.introductions.insert(label, (node.author, introduced));
                                None
                            },
                            | Kind::Present { endpoint, proof } if present => {
                                match proof.verify(endpoint.key(), node.author) {
                                    | Ok(()) => {
                                        let presence = Presence::new(endpoint, node.commit);
                                        let _superseded = view.book.insert(node.author, presence);
                                        None
                                    },
                                    | Err(_foreign) => Some(Refusal::ForeignEndpoint),
                                }
                            },
                            | Kind::Withdraw { of }
                                if node.author == owner || (present && of == node.author) =>
                            {
                                let _withdrawn = view.book.remove(&of);
                                None
                            },
                            | Kind::Withdraw { .. } if present => Some(Refusal::ForeignPresence),
                            | Kind::Dispatch {
                                seat,
                                edition,
                                brief,
                            } if authorized => {
                                past.course = Course::Dispatched {
                                    placed,
                                    dispatch: node.commit,
                                    moved: placed,
                                    holder: Holder::Seat(seat),
                                };
                                let _seated_before = past.seats.insert(seat);
                                view.task.dispatch(node.commit, seat, edition, brief);
                                None
                            },
                            | Kind::Report {
                                dispatch,
                                content,
                                summary,
                            } => {
                                view.task.answer(node.commit, Step::Report {
                                    dispatch,
                                    author: node.author,
                                    content,
                                    summary,
                                });
                                None
                            },
                            | Kind::Handoff { dispatch, to } => {
                                past.course = past.course.moved(placed, Holder::Seat(to));
                                let _seated_before = past.seats.insert(to);
                                view.task.answer(node.commit, Step::Handoff {
                                    dispatch,
                                    from: node.author,
                                    to,
                                });
                                None
                            },
                            | Kind::Retire { dispatch } => {
                                past.course = past.course.moved(placed, Holder::Vacant);
                                view.task.answer(node.commit, Step::Retire {
                                    dispatch,
                                    author: node.author,
                                });
                                None
                            },
                            | Kind::Pause { dispatch } => {
                                view.task.answer(node.commit, Step::Pause {
                                    dispatch,
                                    author: node.author,
                                });
                                None
                            },
                            | Kind::Verdict { judge, .. } if node.author != judge => {
                                Some(Refusal::NotJudge)
                            },
                            | Kind::Verdict {
                                dispatch,
                                judge,
                                rubric,
                                transcript,
                                answers,
                            } => {
                                let mut play = Play::new(Channel::Judge);
                                match advance(
                                    &plays,
                                    past.course,
                                    dispatch,
                                    &mut play,
                                    Movement::Verdict,
                                    node.commit,
                                ) {
                                    | Ok(()) => {
                                        let questions = answers
                                            .iter()
                                            .map(|&(question, ref ruling)| {
                                                (question, match *ruling {
                                                    | Ruling::Read(_) => Reading::Read,
                                                    | Ruling::Unread(_) => Reading::Unread,
                                                })
                                            })
                                            .collect();
                                        let _ruled_before = ruled.insert(node.commit, Ruled {
                                            play,
                                            judge,
                                            dispatch,
                                            rubric,
                                            questions,
                                        });
                                        let _verdict_before = past.verdicts.insert(node.commit);
                                        view.task.answer(node.commit, Step::Verdict {
                                            dispatch,
                                            judge,
                                            rubric,
                                            transcript,
                                            answers,
                                        });
                                        None
                                    },
                                    | Err(refusal) => Some(refusal),
                                }
                            },
                            | Kind::Verified { runner, .. } if node.author != runner => {
                                Some(Refusal::NotRunner)
                            },
                            | Kind::Verified {
                                dispatch,
                                runner,
                                playbook,
                                step,
                                output,
                                status,
                            } => match advance(
                                &plays,
                                past.course,
                                dispatch,
                                runner_plays
                                    .entry((dispatch, runner))
                                    .or_insert_with(|| Play::new(Channel::Runner)),
                                Movement::Verified,
                                node.commit,
                            ) {
                                | Ok(()) => {
                                    view.task.answer(node.commit, Step::Verified {
                                        dispatch,
                                        runner,
                                        playbook,
                                        step,
                                        output,
                                        status,
                                    });
                                    None
                                },
                                | Err(refusal) => Some(refusal),
                            },
                            | Kind::Graded {
                                verdict,
                                grades,
                                composed,
                            } => match ruled
                                .get_mut(&verdict)
                                .filter(|_ruling| past.verdicts.contains(&verdict))
                            {
                                | Some(ruling) => {
                                    match grading(ruling, node.author, &grades, composed).and_then(
                                        |()| {
                                            advance(
                                                &plays,
                                                past.course,
                                                ruling.dispatch,
                                                &mut ruling.play,
                                                Movement::Graded,
                                                node.commit,
                                            )
                                        },
                                    ) {
                                        | Ok(()) => {
                                            let grades = ruling
                                                .questions
                                                .iter()
                                                .zip(grades)
                                                .map(|(&(question, _), grade)| (question, grade))
                                                .collect();
                                            view.task.answer(node.commit, Step::Graded {
                                                dispatch: ruling.dispatch,
                                                verdict,
                                                rubric: ruling.rubric,
                                                grades,
                                                composed,
                                            });
                                            None
                                        },
                                        | Err(refusal) => Some(refusal),
                                    }
                                },
                                | None => unstarted(
                                    &plays,
                                    past.course,
                                    Channel::Judge,
                                    Movement::Graded,
                                    node.commit,
                                )
                                .err(),
                            },
                            | Kind::Decide { operator, .. }
                                if authorized && node.author != operator =>
                            {
                                Some(Refusal::NotOperator)
                            },
                            | Kind::Decide {
                                dispatch,
                                operator,
                                decision,
                            } if authorized => {
                                let choice = match decision {
                                    | Decision::Land => Choice::Land,
                                    | Decision::Rework { .. } => Choice::Rework,
                                    | Decision::Abandon => Choice::Abandon,
                                };
                                match advance(
                                    &plays,
                                    past.course,
                                    dispatch,
                                    decision_plays
                                        .entry(dispatch)
                                        .or_insert_with(|| Play::new(Channel::Decision)),
                                    Movement::Decide(choice),
                                    node.commit,
                                ) {
                                    | Ok(()) => {
                                        let _decided_before = decisions
                                            .insert(node.commit, Decided { dispatch, operator });
                                        let _decision_before = past.decisions.insert(node.commit);
                                        view.task.answer(node.commit, Step::Decide {
                                            dispatch,
                                            operator,
                                            decision,
                                        });
                                        None
                                    },
                                    | Err(refusal) => Some(refusal),
                                }
                            },
                            | Kind::Landed { decided, merge } => {
                                match decisions
                                    .get(&decided)
                                    .filter(|_decision| past.decisions.contains(&decided))
                                {
                                    | Some(decision) => match landing(decision, node.author)
                                        .and_then(|()| {
                                            advance(
                                                &plays,
                                                past.course,
                                                decision.dispatch,
                                                decision_plays
                                                    .entry(decision.dispatch)
                                                    .or_insert_with(|| {
                                                        Play::new(Channel::Decision)
                                                    }),
                                                Movement::Landed,
                                                node.commit,
                                            )
                                        }) {
                                        | Ok(()) => {
                                            view.task.answer(node.commit, Step::Landed {
                                                dispatch: decision.dispatch,
                                                decided,
                                                operator: node.author,
                                                merge,
                                            });
                                            None
                                        },
                                        | Err(refusal) => Some(refusal),
                                    },
                                    | None => unstarted(
                                        &plays,
                                        past.course,
                                        Channel::Decision,
                                        Movement::Landed,
                                        node.commit,
                                    )
                                    .err(),
                                }
                            },
                            | Kind::Grant { .. }
                            | Kind::Note { .. }
                            | Kind::Indexed { .. }
                            | Kind::Bind { .. }
                            | Kind::Introduce { .. }
                            | Kind::Present { .. }
                            | Kind::Withdraw { .. }
                            | Kind::Dispatch { .. }
                            | Kind::Decide { .. } => Some(Refusal::NoAuthority),
                        },
                    };
                    if refusal.is_none() {
                        admit(&mut admitted, operation, node.commit);
                    }
                    refusal
                }
            },
        };
        match refusal {
            | Some(refusal) => view.refused.push((node.commit, refusal)),
            | None => {
                let _first_admission = view.admitted.insert(node.commit);
                if view
                    .task
                    .steps()
                    .last()
                    .is_some_and(|&(commit, _)| commit == node.commit)
                {
                    view.task.record_source(crate::task::MoveSource {
                        commit: node.commit,
                        author: node.author,
                        blob: node.blob,
                    });
                }
            },
        }
        let readers: BTreeSet<Position> = node
            .children
            .iter()
            .copied()
            .filter(|child| nodes.contains_key(child))
            .collect();
        if !readers.is_empty() {
            drop(carries.insert(position, Carry { past, readers }));
        }
    }
    view.plays = plays;
    Ok(view)
}

/// The canonical order of two commits: by commit id, then by signed bytes.
///
/// # Specification
/// - ensures: a total order on stored commits that two peers compute alike; it
///   ties only commits with identical signed bytes, which are one commit.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — arrival permutations give the same canonical view, and
///   competing root Opens select one owner.
/// - witness: `fold::tests::a_view_is_the_same_whatever_order_commits_arrive_in`
/// - witness: `fold::tests::the_smallest_root_open_names_the_owner`
#[spec(ensures: |output| output.is_eq() == (left.signed().as_bytes() == right.signed().as_bytes()))]
fn canonical(
    left: &VerifiedMeta<LooseCommit>,
    right: &VerifiedMeta<LooseCommit>,
) -> Ordering
{
    left.payload()
        .head()
        .cmp(&right.payload().head())
        .then_with(|| left.signed().as_bytes().cmp(right.signed().as_bytes()))
}

/// The causal past of the commit at `reader` — its grantees, its seats, its
/// verdicts, its decisions and its latest dispatch — read from its placed
/// `parents`.
///
/// # Specification
/// - ensures: returns the union of the placed parents' grantees, seats,
///   verdicts and decisions, and the latest of their courses; a parent not
///   placed yet (a cycle) contributes nothing. Each carry is read once per
///   reader and dropped after its last reader, moved rather than copied when it
///   is.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — causal grants admit descendants but not concurrent
///   receipts; a cycle still yields a finite view.
/// - witness: `fold::tests::a_note_by_a_peer_granted_in_its_causal_past_is_admitted`
/// - witness: `fold::tests::a_parent_cycle_is_placed_in_commit_id_order`
#[spec(ensures: parents.iter().all(|parent| carries.get(parent).is_none_or(|carry| !carry.readers.contains(&reader))))]
fn inherit(
    carries: &mut BTreeMap<Position, Carry>,
    parents: &[Position],
    reader: Position,
) -> Past
{
    let mut past = Past {
        grantees: BTreeSet::new(),
        seats: BTreeSet::new(),
        verdicts: BTreeSet::new(),
        decisions: BTreeSet::new(),
        course: Course::Undispatched,
    };
    for parent in parents {
        let Entry::Occupied(mut slot) = carries.entry(*parent)
        else {
            continue;
        };
        let _was_reader = slot.get_mut().readers.remove(&reader);
        if slot.get().readers.is_empty() {
            let carried = slot.remove().past;
            join(&mut past.grantees, carried.grantees);
            join(&mut past.seats, carried.seats);
            join(&mut past.verdicts, carried.verdicts);
            join(&mut past.decisions, carried.decisions);
            past.course = past.course.max(carried.course);
        }
        else {
            let carried = &slot.get().past;
            past.grantees.extend(carried.grantees.iter().copied());
            past.seats.extend(carried.seats.iter().copied());
            past.verdicts.extend(carried.verdicts.iter().copied());
            past.decisions.extend(carried.decisions.iter().copied());
            past.course = past.course.max(carried.course);
        }
    }
    past
}

/// Add `carried` to `set`, moving it whole when `set` is empty.
///
/// # Specification
/// trivial.
fn join<Member>(
    set: &mut BTreeSet<Member>,
    carried: BTreeSet<Member>,
) where
    Member: Ord,
{
    if set.is_empty() {
        *set = carried;
    }
    else {
        set.extend(carried);
    }
}

/// Check a grading's authorship, answer shape and composition.
///
/// # Specification
/// - ensures: the verdict's judge supplies one grade per answer, with refused
///   exactly for unread rulings, and `composed` is [`compose`] of `grades`.
/// - fails: wrong author, malformed grades and wrong composition remain
///   distinct refusals; the channel monitor owns ordering and repetition.
/// - panics: none.
///
/// # Errors
/// - [`Refusal::NotJudge`]: `author` is not the verdict's judge.
/// - [`Refusal::Misgraded`]: `grades` does not answer the verdict's answers.
/// - [`Refusal::Miscomposed`]: `composed` differs from [`compose`] of `grades`.
///
/// # Adequacy
/// - hypothesis: L3 wrong-author and answer-shape boundaries remain distinct
///   from monitor refusals for missing or repeated grading. Each composition
///   mismatch is refused without advancing the task; a correct descendant is
///   admitted.
/// - witness: `fold::tests::a_verdicts_judge_grades_its_answers`
/// - witness: `fold::tests::a_gradings_composition_is_checked_before_it_advances_the_task`
#[spec(ensures: |ref output| output.is_err() || grades.is_empty() || grades.contains(&composed))]
fn grading(
    ruling: &Ruled,
    author: PeerKey,
    grades: &[Grade],
    composed: Grade,
) -> Result<(), Refusal>
{
    if author != ruling.judge {
        return Err(Refusal::NotJudge);
    }
    let answered = grades.len() == ruling.questions.len()
        && grades
            .iter()
            .zip(&ruling.questions)
            .all(|(&grade, &(_, reading))| {
                (grade == Grade::Refused) == (reading == Reading::Unread)
            });
    if !answered {
        return Err(Refusal::Misgraded);
    }
    if composed != compose(grades) {
        return Err(Refusal::Miscomposed);
    }
    Ok(())
}

/// Check that a landing is signed by its deciding operator.
///
/// # Specification
/// - ensures: only the deciding operator may supply its landing.
/// - fails: wrong authorship is not operator; the monitor owns the decision
///   branch and landing order.
/// - panics: none.
/// - executable: none — the function is its own specification; owner, member
///   and seat landing witnesses independently distinguish signing authority.
///
/// # Errors
/// - [`Refusal`]: not operator.
///
/// # Adequacy
/// - hypothesis: L3 authorship and stale-dispatch boundaries remain separate
///   from the monitor's missing-decision and closed-channel refusals.
/// - witness: `fold::tests::a_landing_carries_out_a_decision_to_land`
fn landing(
    decision: &Decided,
    author: PeerKey,
) -> Result<(), Refusal>
{
    if author != decision.operator {
        return Err(Refusal::NotOperator);
    }
    Ok(())
}

/// Record that `commit` admitted `operation`.
///
/// # Specification
/// - requires: no admitted commit carries `operation` yet.
/// - ensures: later receipts carrying `operation` are duplicates of `commit`.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — repeating an operation retains its first admitted commit
///   and refuses the duplicate.
/// - witness: `fold::tests::a_duplicate_operation_keeps_the_first`
#[spec(requires: !admitted.contains_key(&operation), ensures: admitted.values().any(|held| *held == commit))]
fn admit(
    admitted: &mut BTreeMap<Operation, CommitId>,
    operation: Operation,
    commit: CommitId,
)
{
    let _first_admission = admitted.insert(operation, commit);
}

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeMap;
    use alloc::collections::BTreeSet;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::net::Ipv4Addr;
    use core::net::SocketAddr;

    use gandr_storage_values::ManifestDigest;
    use gandr_storage_values::TokenOffset;
    use gandr_storage_values::ValueError;
    use sedimentree_core::blob::Blob;
    use sedimentree_core::loose_commit::id::CommitId;
    use subduction_crypto::signer::memory::MemorySigner;

    use super::Refusal;
    use super::Unopened;
    use super::View;
    use super::fold;
    use crate::anchor::Anchor;
    use crate::anchor::Authority;
    use crate::anchor::Path;
    use crate::anchor::Resolution;
    use crate::anchor::Target;
    use crate::check::Code;
    use crate::check::Grade;
    use crate::check::Signal;
    use crate::check::Status;
    use crate::decision::Decision;
    use crate::decision::Revision;
    use crate::id::Content;
    use crate::id::ContentHash;
    use crate::id::Endpoint;
    use crate::id::EndpointKey;
    use crate::id::PeerKey;
    use crate::id::TreeId;
    use crate::name::Label;
    use crate::presence::Presence;
    use crate::receipt::EndpointProof;
    use crate::receipt::Kind;
    use crate::receipt::Operation;
    use crate::receipt::Receipt;
    use crate::ruling::Probability;
    use crate::ruling::Readout;
    use crate::ruling::Ruling;
    use crate::ruling::Unread;
    use crate::task::Answer;
    use crate::task::Attempt;
    use crate::task::Brief;
    use crate::task::Current;
    use crate::task::Progress;
    use crate::task::Slot;
    use crate::task::Step;
    use crate::task::Task;
    use crate::testing::commit;
    use crate::testing::digest;
    use crate::testing::elsewhere_key;
    use crate::testing::id;
    use crate::testing::key;
    use crate::testing::other;
    use crate::testing::owner;
    use crate::testing::runtime;
    use crate::testing::seal;
    use crate::testing::seal_on;
    use crate::testing::tree_key;

    /// The tree every test folds.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        tree_key().tree()
    }

    /// A fresh Open of the tree, proved for `signer`'s key.
    ///
    /// # Specification
    /// trivial.
    fn open(signer: &MemorySigner) -> Receipt
    {
        Receipt::open(&tree_key(), key(signer)).unwrap()
    }

    /// A fresh grant on the tree to `signer`'s key.
    ///
    /// # Specification
    /// trivial.
    fn grant(signer: &MemorySigner) -> Receipt
    {
        Receipt::grant(tree(), key(signer)).unwrap()
    }

    /// A fresh note of `text` on the tree.
    ///
    /// # Specification
    /// trivial.
    fn note(text: String) -> Receipt
    {
        Receipt::note(tree(), text).unwrap()
    }

    /// A fresh bind of `path` on the tree to `target`.
    ///
    /// # Specification
    /// trivial.
    fn bind(
        path: &Path,
        target: Target,
    ) -> Receipt
    {
        Receipt::bind(tree(), path.clone(), target).unwrap()
    }

    /// A note of `text` on the tree carrying `operation`.
    ///
    /// # Specification
    /// trivial.
    fn fenced(
        operation: Operation,
        text: String,
    ) -> Receipt
    {
        Receipt::new(tree(), operation, Kind::Note { text })
    }

    /// A loopback UDP port an endpoint in a test is reached at.
    #[derive(Clone, Copy, Debug)]
    #[repr(transparent)]
    struct Port(u16);

    /// The endpoint secret of the peer `a`.
    ///
    /// # Specification
    /// trivial.
    fn a_secret() -> iroh::SecretKey
    {
        iroh::SecretKey::from_bytes(&[5; 32])
    }

    /// The endpoint secret of the peer `b`.
    ///
    /// # Specification
    /// trivial.
    fn b_secret() -> iroh::SecretKey
    {
        iroh::SecretKey::from_bytes(&[6; 32])
    }

    /// The endpoint of `secret` at the loopback address and `port`.
    ///
    /// # Specification
    /// trivial.
    fn endpoint(
        secret: &iroh::SecretKey,
        port: Port,
    ) -> Endpoint
    {
        let key = EndpointKey::new(secret.public());
        Endpoint::new(key).with_direct(SocketAddr::from((Ipv4Addr::LOCALHOST, port.0)))
    }

    /// A fresh presence of `secret`'s endpoint at `port`, proved for
    /// `holder`.
    ///
    /// # Specification
    /// trivial.
    fn present(
        secret: &iroh::SecretKey,
        port: Port,
        holder: PeerKey,
    ) -> Receipt
    {
        let proof = EndpointProof::sign(secret, holder);
        Receipt::present(tree(), endpoint(secret, port), proof).unwrap()
    }

    /// A fresh withdrawal of `of`'s presence.
    ///
    /// # Specification
    /// trivial.
    fn withdraw(of: PeerKey) -> Receipt
    {
        Receipt::withdraw(tree(), of).unwrap()
    }

    /// The brief the tests dispatch: a path in the tree.
    ///
    /// # Specification
    /// trivial.
    fn brief() -> Brief
    {
        Brief::Anchor(Anchor::Path {
            authority: Authority::Key(tree()),
            path: "briefs/one".parse().unwrap(),
        })
    }

    /// The hash the tests name a rubric, a playbook or a question by: the
    /// hash of `text`.
    ///
    /// # Specification
    /// trivial.
    fn content(text: String) -> ContentHash
    {
        ContentHash::of(&Content::from(text.into_bytes()))
    }

    /// The evidence the tests' reports, verdicts and verifications name: a
    /// manifest digest spelled by the BLAKE3 of `text`, which the fold never
    /// dereferences.
    ///
    /// # Specification
    /// trivial.
    fn evidence(text: String) -> ManifestDigest
    {
        ManifestDigest::from(*blake3::hash(&text.into_bytes()).as_bytes())
    }

    /// A fresh dispatch on the tree of `seat` to [`brief`].
    ///
    /// # Specification
    /// trivial.
    fn dispatch(seat: PeerKey) -> Receipt
    {
        Receipt::dispatch(tree(), seat, crate::Edition::ONE, brief()).unwrap()
    }

    /// A fresh report on `dispatch` of the content `text`, summarized as it.
    ///
    /// # Specification
    /// trivial.
    fn report(
        dispatch: CommitId,
        text: String,
    ) -> Receipt
    {
        let summary = text.parse().unwrap();
        Receipt::report(tree(), dispatch, evidence(text), summary).unwrap()
    }

    /// The answers the tests' verdicts carry: a question read as `B`, and one
    /// left unread for want of a letter.
    ///
    /// # Specification
    /// trivial.
    fn answers() -> Vec<(ContentHash, Ruling)>
    {
        let probability = |value: f64| Probability::try_from(value).unwrap();
        let readout = Readout::new(
            vec![probability(0.25_f64), probability(0.75_f64)],
            probability(0.0_f64),
        )
        .unwrap();
        vec![
            (content("read".into()), Ruling::Read(readout)),
            (content("unread".into()), Ruling::Unread(Unread::NoLetter)),
        ]
    }

    /// A fresh verdict on `dispatch` naming `judge`, carrying [`answers`].
    ///
    /// # Specification
    /// trivial.
    fn verdict(
        dispatch: CommitId,
        judge: PeerKey,
    ) -> Receipt
    {
        let rubric = content("rubric".into());
        let transcript = evidence("transcript".into());
        Receipt::verdict(tree(), dispatch, judge, rubric, transcript, answers()).unwrap()
    }

    /// A fresh verification on `dispatch` by `runner` of the step `test`,
    /// whose process wrote `output` and exited with `code`.
    ///
    /// # Specification
    /// trivial.
    fn verified(
        dispatch: CommitId,
        runner: PeerKey,
        code: Code,
    ) -> Receipt
    {
        let (playbook, output) = (content("playbook".into()), evidence("output".into()));
        let step = "test".parse().unwrap();
        let status = Status::Exited(code);
        Receipt::verified(tree(), dispatch, runner, playbook, step, output, status).unwrap()
    }

    /// A fresh grading of `verdict` into `grades`, composed as refused.
    ///
    /// # Specification
    /// trivial.
    fn graded(
        verdict: CommitId,
        grades: Vec<Grade>,
    ) -> Receipt
    {
        let composed = crate::compose(&grades);
        Receipt::graded(tree(), verdict, grades, composed).unwrap()
    }

    /// A fresh decision on `dispatch`: `decision`.
    ///
    /// # Specification
    /// trivial.
    fn decide(
        dispatch: CommitId,
        operator: &MemorySigner,
        decision: Decision,
    ) -> Receipt
    {
        Receipt::decide(tree(), dispatch, key(operator), decision).unwrap()
    }

    /// The revision the tests' landings land at.
    ///
    /// # Specification
    /// trivial.
    fn revision() -> Revision
    {
        "0123456789abcdef0123456789abcdef01234567".parse().unwrap()
    }

    /// A fresh landing of `decided` at [`revision`].
    ///
    /// # Specification
    /// trivial.
    fn landed(decided: CommitId) -> Receipt
    {
        Receipt::landed(tree(), decided, revision()).unwrap()
    }

    /// A decision to rework for a red lint.
    ///
    /// # Specification
    /// trivial.
    fn rework() -> Decision
    {
        Decision::Rework {
            reason: "lint red".parse().unwrap(),
        }
    }

    /// The current attempt of `view`'s task.
    ///
    /// # Specification
    /// trivial.
    fn attempt(view: &View) -> &Attempt
    {
        match *view.task().current() {
            | Current::Attempt(ref attempt) => attempt,
            | Current::Undispatched => panic!("the task is undispatched"),
        }
    }

    #[test]
    fn a_view_is_the_same_whatever_order_commits_arrive_in()
    {
        let (a, b) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let a1 = commit(&a, tree(), &[&opened], &note("a1".into())).await;
            let early = commit(&b, tree(), &[&a1], &note("early".into())).await;
            let granted = commit(&a, tree(), &[&early], &grant(&b)).await;
            let late = commit(&b, tree(), &[&granted], &note("late".into())).await;
            let a2 = commit(&a, tree(), &[&a1], &note("a2".into())).await;
            let side = commit(&b, tree(), &[&a2], &note("side".into())).await;
            let merged = commit(&a, tree(), &[&late, &side], &note("merged".into())).await;
            let arrived = vec![
                opened,
                a1,
                early.clone(),
                granted,
                late,
                a2,
                side.clone(),
                merged,
            ];

            let view = fold(tree(), arrived.clone()).unwrap();
            let mut reversed = arrived.clone();
            reversed.reverse();
            assert_eq!(
                fold(tree(), reversed).unwrap(),
                view,
                "children first folds to the same view"
            );
            let mut repeated = arrived.clone();
            repeated.rotate_left(3);
            repeated.extend(arrived.iter().cloned());
            assert_eq!(
                fold(tree(), repeated).unwrap(),
                view,
                "a rotated order with every commit twice folds to the same view"
            );

            assert_eq!(view.owner(), key(&a), "the Open's signer owns the tree");
            assert_eq!(
                *view.members(),
                BTreeSet::from([key(&b)]),
                "the grant's peer is the one member"
            );
            assert_eq!(
                view.notes().iter().cloned().collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    (key(&a), String::from("a1")),
                    (key(&a), String::from("a2")),
                    (key(&b), String::from("late")),
                    (key(&a), String::from("merged")),
                ]),
                "the owner's notes and the member's note after its grant are admitted"
            );
            assert_eq!(
                view.notes().first(),
                Some(&(key(&a), String::from("a1"))),
                "an ancestor of every other note comes first"
            );
            assert_eq!(
                view.notes().last(),
                Some(&(key(&a), String::from("merged"))),
                "a descendant of every other note comes last"
            );
            assert_eq!(view.refused().len(), 2, "{:?}", view.refused());
            for refused in [&early, &side] {
                assert!(
                    view.refused()
                        .contains(&(id(refused), Refusal::NoAuthority)),
                    "a note with no grant in its past is refused, granted later or beside"
                );
            }
        });
    }

    #[test]
    fn an_attestation_is_admitted_from_the_owner_or_a_member()
    {
        let (owner, member) = (owner(), other());
        let seat = MemorySigner::from_bytes(&[8; 32]);
        let stranger = MemorySigner::from_bytes(&[9; 32]);
        let receipt =
            |byte: u8| Receipt::indexed(tree(), crate::IndexDigest::from([byte; 32])).unwrap();
        runtime().block_on(async {
            let opened = commit(&owner, tree(), &[], &open(&owner)).await;
            let granted = commit(&owner, tree(), &[&opened], &grant(&member)).await;
            let dispatched = commit(&owner, tree(), &[&granted], &dispatch(key(&seat))).await;
            let first = commit(&owner, tree(), &[&dispatched], &receipt(1)).await;
            let second = commit(&owner, tree(), &[&first], &receipt(2)).await;
            let theirs = commit(&member, tree(), &[&second], &receipt(3)).await;
            let seated = commit(&seat, tree(), &[&theirs], &receipt(4)).await;
            let alien = commit(&stranger, tree(), &[&theirs], &receipt(5)).await;
            let view = fold(tree(), vec![
                opened,
                granted,
                dispatched,
                first,
                second.clone(),
                theirs.clone(),
                seated.clone(),
                alien.clone(),
            ])
            .unwrap();
            assert_eq!(view.indexes().len(), 2);
            let own = view.indexes().get(&key(&owner)).unwrap();
            assert_eq!(own.index, crate::IndexDigest::from([2; 32]));
            assert_eq!(own.commit, id(&second));
            assert_eq!(
                own.parents.iter().copied().collect::<BTreeSet<_>>(),
                *second.payload().parents()
            );
            assert_eq!(
                view.indexes().get(&key(&member)).unwrap().commit,
                id(&theirs)
            );
            assert_eq!(view.attestations().len(), 3);
            for refused in [seated, alien] {
                assert!(
                    view.refused()
                        .contains(&(id(&refused), Refusal::NoAuthority))
                );
            }
        });
    }

    #[test]
    fn a_note_by_a_non_member_is_refused()
    {
        let (a, b) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let stranger = commit(&b, tree(), &[&opened], &note("hello".into())).await;
            let view = fold(tree(), vec![opened, stranger.clone()]).unwrap();
            assert_eq!(view.notes(), [], "no note is admitted");
            assert!(view.members().is_empty(), "nobody was granted");
            assert_eq!(
                view.refused(),
                [(id(&stranger), Refusal::NoAuthority)],
                "the non-member's note is refused for want of authority"
            );
        });
    }

    #[test]
    fn a_note_by_a_peer_granted_in_its_causal_past_is_admitted()
    {
        let (a, b) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let granted = commit(&a, tree(), &[&opened], &grant(&b)).await;
            let after = commit(&b, tree(), &[&granted], &note("after".into())).await;
            let beside = commit(&b, tree(), &[&opened], &note("beside".into())).await;
            let view = fold(tree(), vec![opened, granted, after, beside.clone()]).unwrap();
            assert_eq!(
                view.notes(),
                [(key(&b), String::from("after"))],
                "the note descending from the grant is admitted"
            );
            assert_eq!(
                view.refused(),
                [(id(&beside), Refusal::NoAuthority)],
                "a note concurrent with the grant is not under it"
            );
        });
    }

    #[test]
    fn a_duplicate_operation_keeps_the_first()
    {
        let (a, b) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let fence = Operation::random().unwrap();
            let first = commit(&a, tree(), &[&opened], &fenced(fence, "first".into())).await;
            let again = commit(&a, tree(), &[&first], &fenced(fence, "again".into())).await;
            let view = fold(tree(), vec![opened.clone(), first.clone(), again.clone()]).unwrap();
            assert_eq!(
                view.notes(),
                [(key(&a), String::from("first"))],
                "the ancestor keeps the operation"
            );
            assert_eq!(
                view.refused(),
                [(id(&again), Refusal::Duplicate { first: id(&first) })],
                "the descendant repeating it is a duplicate of the first"
            );

            let fence = Operation::random().unwrap();
            let x = commit(&a, tree(), &[&opened], &fenced(fence, "x".into())).await;
            let y = commit(&a, tree(), &[&opened], &fenced(fence, "y".into())).await;
            let (kept, dropped, text) = if id(&x) < id(&y) {
                (&x, &y, "x")
            }
            else {
                (&y, &x, "y")
            };
            let view = fold(tree(), vec![y.clone(), x.clone(), opened.clone()]).unwrap();
            assert_eq!(
                view.notes(),
                [(key(&a), String::from(text))],
                "of two concurrent copies the smaller commit id keeps the operation"
            );
            assert_eq!(
                view.refused(),
                [(id(dropped), Refusal::Duplicate { first: id(kept) })],
                "the larger is the duplicate"
            );

            let fence = Operation::random().unwrap();
            let squat = commit(&b, tree(), &[&opened], &fenced(fence, "squat".into())).await;
            let owned = commit(&a, tree(), &[&squat], &fenced(fence, "owned".into())).await;
            let view = fold(tree(), vec![opened, squat.clone(), owned]).unwrap();
            assert_eq!(
                view.notes(),
                [(key(&a), String::from("owned"))],
                "a refused receipt claims no operation"
            );
            assert_eq!(view.refused(), [(id(&squat), Refusal::NoAuthority)]);
        });
    }

    #[test]
    fn a_receipt_under_the_wrong_tree_is_refused()
    {
        let a = owner();
        let elsewhere = elsewhere_key().tree();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let astray = Receipt::note(elsewhere, "astray".into()).unwrap();
            let astray = commit(&a, tree(), &[&opened], &astray).await;
            let view = fold(tree(), vec![opened, astray.clone()]).unwrap();
            assert_eq!(view.notes(), [], "the misplaced note is not admitted");
            assert_eq!(
                view.refused(),
                [(id(&astray), Refusal::WrongTree { named: elsewhere })],
                "it is refused naming the tree it belongs to"
            );
        });
    }

    #[test]
    fn the_smallest_root_open_names_the_owner()
    {
        let (a, b) = (owner(), other());
        runtime().block_on(async {
            let by_a = commit(&a, tree(), &[], &open(&a)).await;
            let by_b = commit(&b, tree(), &[], &open(&b)).await;
            let reopened = commit(&a, tree(), &[&by_a], &open(&a)).await;
            let view = fold(tree(), vec![reopened.clone(), by_b.clone(), by_a.clone()]).unwrap();
            let (second, owner_key) = if id(&by_a) < id(&by_b) {
                (&by_b, key(&a))
            }
            else {
                (&by_a, key(&b))
            };
            assert_eq!(
                view.owner(),
                owner_key,
                "the root Open with the smaller commit id names the owner"
            );
            assert_eq!(view.refused().len(), 2, "{:?}", view.refused());
            for refused in [second, &reopened] {
                assert!(
                    view.refused().contains(&(id(refused), Refusal::SecondOpen)),
                    "every other proved Open, root or not, is a second Open"
                );
            }
        });
    }

    #[test]
    fn an_open_proved_by_another_key_is_refused()
    {
        let (a, b) = (owner(), other());
        runtime().block_on(async {
            let forged = Receipt::new(tree(), Operation::random().unwrap(), Kind::Open {
                proof: elsewhere_key().prove(key(&a)),
            });
            let forged = commit(&a, tree(), &[], &forged).await;
            assert_eq!(
                fold(tree(), vec![forged.clone()]),
                Err(Unopened),
                "an Open proved by another key opens nothing"
            );
            let replayed = commit(&b, tree(), &[], &open(&a)).await;
            assert_eq!(
                fold(tree(), vec![replayed.clone()]),
                Err(Unopened),
                "an Open proved for another author opens nothing"
            );
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let view = fold(tree(), vec![forged.clone(), replayed.clone(), opened]).unwrap();
            assert_eq!(
                view.owner(),
                key(&a),
                "the Open the tree key proved for its author names the owner"
            );
            assert_eq!(view.refused().len(), 2, "{:?}", view.refused());
            for refused in [&forged, &replayed] {
                assert!(
                    view.refused().contains(&(id(refused), Refusal::BadProof)),
                    "a forged or replayed proof is refused as a bad proof"
                );
            }
        });
    }

    #[test]
    fn the_later_bind_in_canonical_order_wins()
    {
        let a = owner();
        let (x, y) = ("x".parse::<Path>().unwrap(), "y".parse::<Path>().unwrap());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let target = Target::Anchor(Anchor::commit(tree(), id(&opened)));
            let first = commit(&a, tree(), &[&opened], &bind(&x, target)).await;
            let rebound = Target::Datum(String::from("rebound"));
            let second = commit(&a, tree(), &[&first], &bind(&x, rebound.clone())).await;
            let left = Target::Datum(String::from("left"));
            let left = commit(&a, tree(), &[&opened], &bind(&y, left)).await;
            let right = Target::Datum(String::from("right"));
            let right = commit(&a, tree(), &[&opened], &bind(&y, right)).await;
            let later = if id(&left) < id(&right) {
                Target::Datum(String::from("right"))
            }
            else {
                Target::Datum(String::from("left"))
            };
            let arrived = vec![opened, first, second, left, right];
            let mut orders = vec![arrived.clone()];
            for turn in 1 .. arrived.len() {
                let mut rotated = arrived.clone();
                rotated.rotate_left(turn);
                orders.push(rotated.clone());
                rotated.reverse();
                orders.push(rotated);
            }
            for order in orders {
                let view = fold(tree(), order).unwrap();
                assert_eq!(
                    view.resolve(&x),
                    Resolution::Bound(key(&a), rebound.clone()),
                    "a rebind descending from the bind wins"
                );
                assert_eq!(
                    view.resolve(&y),
                    Resolution::Bound(key(&a), later.clone()),
                    "of two concurrent binds the larger commit id, placed later, wins"
                );
                assert_eq!(view.bindings().len(), 2, "two paths are bound");
            }
        });
    }

    #[test]
    fn a_bind_by_a_non_member_is_refused()
    {
        let (a, b) = (owner(), other());
        let (x, y) = ("x".parse::<Path>().unwrap(), "y".parse::<Path>().unwrap());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let target = Target::Anchor(Anchor::commit(tree(), id(&opened)));
            let bound = commit(&a, tree(), &[&opened], &bind(&x, target.clone())).await;
            let squat = Target::Datum(String::from("squat"));
            let squat = commit(&b, tree(), &[&bound], &bind(&x, squat)).await;
            let view = fold(tree(), vec![opened, bound, squat.clone()]).unwrap();
            assert_eq!(
                view.refused(),
                [(id(&squat), Refusal::NoAuthority)],
                "the non-member's bind is refused for want of authority"
            );
            assert_eq!(
                view.resolve(&x),
                Resolution::Bound(key(&a), target),
                "the path stays as the owner bound it"
            );
            assert_eq!(
                view.resolve(&y),
                Resolution::Unbound,
                "a path nobody bound is unbound"
            );
        });
    }

    #[test]
    fn a_claim_by_anyone_but_the_owner_is_refused()
    {
        let (a, b, c) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        let claim = |domain: &str| Receipt::claim(tree(), domain.parse().unwrap()).unwrap();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let granted = commit(&a, tree(), &[&opened], &grant(&b)).await;
            let noted = commit(&b, tree(), &[&granted], &note("member".into())).await;
            let by_member = commit(&b, tree(), &[&noted], &claim("member.test")).await;
            let by_stranger = commit(&c, tree(), &[&noted], &claim("stranger.test")).await;
            let by_owner = commit(&a, tree(), &[&noted], &claim("example.test")).await;
            let view = fold(tree(), vec![
                opened,
                granted,
                noted,
                by_member.clone(),
                by_stranger.clone(),
                by_owner,
            ])
            .unwrap();
            assert_eq!(
                view.notes(),
                [(key(&b), String::from("member"))],
                "the member holds write authority"
            );
            assert_eq!(
                *view.claims(),
                BTreeSet::from(["example.test".parse().unwrap()]),
                "the owner's claim alone is admitted"
            );
            assert_eq!(view.refused().len(), 2, "{:?}", view.refused());
            for refused in [&by_member, &by_stranger] {
                assert!(
                    view.refused().contains(&(id(refused), Refusal::NotOwner)),
                    "a claim by a member or by a stranger is refused as not the owner's"
                );
            }
        });
    }

    #[test]
    fn a_presence_by_a_non_member_is_refused()
    {
        let (a, b) = (owner(), other());
        let secret = b_secret();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let squat = commit(&b, tree(), &[&opened], &present(&secret, Port(9), key(&b))).await;
            let view = fold(tree(), vec![opened, squat.clone()]).unwrap();
            assert_eq!(
                view.refused(),
                [(id(&squat), Refusal::NoAuthority)],
                "a non-member's presence of its own endpoint is refused for want of authority"
            );
            assert!(view.book().is_empty(), "the book offers no endpoint");
        });
    }

    #[test]
    fn a_presence_naming_another_members_endpoint_is_refused()
    {
        let (a, b) = (owner(), other());
        let (mine, theirs) = (a_secret(), b_secret());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let granted = commit(&a, tree(), &[&opened], &grant(&b)).await;
            let presented =
                commit(&a, tree(), &[&granted], &present(&mine, Port(5), key(&a))).await;
            let stolen = commit(&b, tree(), &[&presented], &present(&mine, Port(7), key(&a))).await;
            let theirs_for_them = EndpointProof::sign(&theirs, key(&b));
            let misproved =
                Receipt::present(tree(), endpoint(&mine, Port(8)), theirs_for_them).unwrap();
            let misproved = commit(&b, tree(), &[&stolen], &misproved).await;
            let view = fold(tree(), vec![
                opened,
                granted,
                presented.clone(),
                stolen.clone(),
                misproved.clone(),
            ])
            .unwrap();
            assert_eq!(
                view.refused(),
                [
                    (id(&stolen), Refusal::ForeignEndpoint),
                    (id(&misproved), Refusal::ForeignEndpoint),
                ],
                "a member presenting the owner's endpoint, under the proof naming the owner or \
                 one its own endpoint key signed, is refused by name"
            );
            assert_eq!(
                view.book().get(&key(&a)),
                Some(&Presence::new(endpoint(&mine, Port(5)), id(&presented))),
                "the owner's own presence stands"
            );
            assert_eq!(
                view.book().get(&key(&b)),
                None,
                "the member holds no presence"
            );
        });
    }

    #[test]
    fn the_later_presence_of_an_author_wins()
    {
        let a = owner();
        let secret = a_secret();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let first = commit(&a, tree(), &[&opened], &present(&secret, Port(1), key(&a))).await;
            let moved = commit(&a, tree(), &[&first], &present(&secret, Port(2), key(&a))).await;
            let left = commit(&a, tree(), &[&moved], &present(&secret, Port(3), key(&a))).await;
            let right = commit(&a, tree(), &[&moved], &present(&secret, Port(4), key(&a))).await;
            let later = if id(&left) < id(&right) {
                Presence::new(endpoint(&secret, Port(4)), id(&right))
            }
            else {
                Presence::new(endpoint(&secret, Port(3)), id(&left))
            };
            let arrived = vec![opened, first, moved, left, right];
            let mut orders = vec![arrived.clone()];
            for turn in 1 .. arrived.len() {
                let mut rotated = arrived.clone();
                rotated.rotate_left(turn);
                orders.push(rotated.clone());
                rotated.reverse();
                orders.push(rotated);
            }
            for order in orders {
                let view = fold(tree(), order).unwrap();
                assert_eq!(
                    view.book(),
                    &BTreeMap::from([(key(&a), later.clone())]),
                    "of two concurrent presences the larger commit id, placed later, wins over \
                     the presences they descend from"
                );
            }
        });
    }

    #[test]
    fn the_owner_withdraws_a_members_presence()
    {
        let (a, b) = (owner(), other());
        let secret = b_secret();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let granted = commit(&a, tree(), &[&opened], &grant(&b)).await;
            let presented =
                commit(&b, tree(), &[&granted], &present(&secret, Port(9), key(&b))).await;
            let before = fold(tree(), vec![
                opened.clone(),
                granted.clone(),
                presented.clone(),
            ])
            .unwrap();
            assert_eq!(
                before.book(),
                &BTreeMap::from([(
                    key(&b),
                    Presence::new(endpoint(&secret, Port(9)), id(&presented))
                )]),
                "a member presents its own endpoint"
            );
            let withdrawn = commit(&a, tree(), &[&presented], &withdraw(key(&b))).await;
            let view = fold(tree(), vec![opened, granted, presented, withdrawn]).unwrap();
            assert!(view.refused().is_empty(), "{:?}", view.refused());
            assert!(
                view.book().is_empty(),
                "the owner's withdrawal removes the member's presence"
            );
        });
    }

    #[test]
    fn a_member_cannot_withdraw_the_owners_presence()
    {
        let (a, b, c) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        let secret = a_secret();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let granted = commit(&a, tree(), &[&opened], &grant(&b)).await;
            let presented =
                commit(&a, tree(), &[&granted], &present(&secret, Port(5), key(&a))).await;
            let by_member = commit(&b, tree(), &[&presented], &withdraw(key(&a))).await;
            let by_stranger = commit(&c, tree(), &[&presented], &withdraw(key(&a))).await;
            let own = commit(&b, tree(), &[&presented], &withdraw(key(&b))).await;
            let view = fold(tree(), vec![
                opened,
                granted,
                presented.clone(),
                by_member.clone(),
                by_stranger.clone(),
                own.clone(),
            ])
            .unwrap();
            assert_eq!(view.refused().len(), 2, "{:?}", view.refused());
            assert!(
                view.refused()
                    .contains(&(id(&by_member), Refusal::ForeignPresence)),
                "a member's withdrawal of the owner's presence is refused by name"
            );
            assert!(
                view.refused()
                    .contains(&(id(&by_stranger), Refusal::NoAuthority)),
                "a non-member's withdrawal is refused for want of authority"
            );
            assert!(
                view.admitted.contains(&id(&own)),
                "a member withdraws its own presence, absent or not"
            );
            assert_eq!(
                view.book(),
                &BTreeMap::from([(
                    key(&a),
                    Presence::new(endpoint(&secret, Port(5)), id(&presented))
                )]),
                "the owner's presence stands"
            );
        });
    }

    #[test]
    fn the_book_after_a_withdrawal_does_not_offer_the_endpoint()
    {
        let (a, b) = (owner(), other());
        let (mine, theirs) = (a_secret(), b_secret());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let granted = commit(&a, tree(), &[&opened], &grant(&b)).await;
            let presented =
                commit(&a, tree(), &[&granted], &present(&mine, Port(5), key(&a))).await;
            let member = commit(
                &b,
                tree(),
                &[&presented],
                &present(&theirs, Port(6), key(&b)),
            )
            .await;
            let withdrawn = commit(&a, tree(), &[&member], &withdraw(key(&a))).await;
            let view = fold(tree(), vec![
                opened.clone(),
                granted.clone(),
                presented.clone(),
                member.clone(),
                withdrawn.clone(),
            ])
            .unwrap();
            assert_eq!(
                view.book(),
                &BTreeMap::from([(
                    key(&b),
                    Presence::new(endpoint(&theirs, Port(6)), id(&member))
                )]),
                "the withdrawn presence is absent and the other stands"
            );
            let back = commit(&a, tree(), &[&withdrawn], &present(&mine, Port(7), key(&a))).await;
            let view = fold(tree(), vec![
                opened,
                granted,
                presented,
                member,
                withdrawn,
                back.clone(),
            ])
            .unwrap();
            assert_eq!(
                view.book().get(&key(&a)),
                Some(&Presence::new(endpoint(&mine, Port(7)), id(&back))),
                "a presence after the withdrawal is offered again, at its own commit"
            );
        });
    }

    #[test]
    fn the_later_introduction_of_a_label_rebinds_it()
    {
        let (a, b, c) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        let (first, second, third) = (
            elsewhere_key().tree(),
            TreeId::new(iroh::SecretKey::from_bytes(&[6; 32]).public()),
            TreeId::new(iroh::SecretKey::from_bytes(&[7; 32]).public()),
        );
        let label = |text: &str| text.parse::<Label>().unwrap();
        let introduce =
            |text: &str, introduced: TreeId| Receipt::introduce(tree(), label(text), introduced);
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let introduced = commit(&a, tree(), &[&opened], &introduce("b", first).unwrap()).await;
            let reintroduced = introduce("b", second).unwrap();
            let reintroduced = commit(&a, tree(), &[&introduced], &reintroduced).await;
            let granted = commit(&a, tree(), &[&reintroduced], &grant(&b)).await;
            let by_member = introduce("my friend", third).unwrap();
            let by_member = commit(&b, tree(), &[&granted], &by_member).await;
            let by_stranger = introduce("b", third).unwrap();
            let by_stranger = commit(&c, tree(), &[&by_member], &by_stranger).await;
            let arrived = vec![
                opened,
                introduced,
                reintroduced,
                granted,
                by_member,
                by_stranger.clone(),
            ];
            let mut reversed = arrived.clone();
            reversed.reverse();
            for order in [arrived, reversed] {
                let view = fold(tree(), order).unwrap();
                assert_eq!(
                    *view.introductions(),
                    BTreeMap::from([
                        (label("b"), (key(&a), second)),
                        (label("my friend"), (key(&b), third)),
                    ]),
                    "the later introduction of b rebinds it, and a member introduces under its \
                     grant"
                );
                assert_eq!(
                    view.refused(),
                    [(id(&by_stranger), Refusal::NoAuthority)],
                    "a stranger's introduction is refused for want of authority"
                );
            }
        });
    }

    #[test]
    fn an_undecodable_blob_is_refused_and_an_unopened_tree_has_no_view()
    {
        let a = owner();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let garbage = Blob::new(b"not a receipt".to_vec());
            let garbage = seal(&a, tree(), &[&opened], garbage).await;
            let view = fold(tree(), vec![opened, garbage.clone()]).unwrap();
            assert_eq!(
                view.refused(),
                [(
                    id(&garbage),
                    Refusal::Undecodable(ValueError::UnknownTokenKind {
                        position: TokenOffset::ZERO
                    })
                )],
                "a blob that is not a receipt is refused with the decoder's reason"
            );

            let foreign = Receipt::open(&elsewhere_key(), key(&a)).unwrap();
            let foreign = commit(&a, tree(), &[], &foreign).await;
            let orphan = commit(&a, tree(), &[&foreign], &note("orphan".into())).await;
            assert_eq!(
                fold(tree(), vec![foreign, orphan]),
                Err(Unopened),
                "an Open of another tree does not open this one"
            );
            assert_eq!(
                fold(tree(), Vec::new()),
                Err(Unopened),
                "nothing opens an empty tree"
            );
        });
    }

    #[test]
    fn a_parent_cycle_is_placed_in_commit_id_order()
    {
        let a = owner();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let (x, y) = (note("x".into()), note("y".into()));
            let (x_id, y_id) = (digest(&x), digest(&y));
            let x = seal_on(
                &a,
                tree(),
                BTreeSet::from([id(&opened), y_id]),
                x.encode().unwrap(),
            )
            .await;
            let y = seal_on(&a, tree(), BTreeSet::from([x_id]), y.encode().unwrap()).await;
            let view = fold(tree(), vec![opened.clone(), x.clone(), y.clone()]).unwrap();
            assert_eq!(
                fold(tree(), vec![y, x, opened]).unwrap(),
                view,
                "a cycle folds alike from either order"
            );
            let expected = if x_id < y_id { ["x", "y"] } else { ["y", "x"] };
            assert_eq!(
                view.notes(),
                expected.map(|text| (key(&a), String::from(text))),
                "the cycle is broken at its smaller commit id"
            );
        });
    }

    #[test]
    fn a_view_prints_one_line_per_fact()
    {
        let (author, member) = (key(&owner()), key(&other()));
        let refused = CommitId::new([7; 32]);
        let bound = CommitId::new([8; 32]);
        let elsewhere = elsewhere_key().tree();
        let presented = CommitId::new([6; 32]);
        let direct = endpoint(&a_secret(), Port(5));
        let reached = format!("{direct}@https://relay.example.org/")
            .parse::<Endpoint>()
            .unwrap();
        let view = View {
            owner: author,
            members: BTreeSet::from([member]),
            notes: vec![
                (author, String::from("plain text")),
                (member, String::from("two\nlines, a \\ and a bell\u{7}")),
            ],
            bindings: BTreeMap::from([
                (
                    "a b/c".parse::<Path>().unwrap(),
                    (author, Target::Datum(String::from("one\nline, spaced"))),
                ),
                (
                    "x".parse::<Path>().unwrap(),
                    (member, Target::Anchor(Anchor::commit(elsewhere, bound))),
                ),
                (
                    "y".parse::<Path>().unwrap(),
                    (
                        author,
                        Target::Anchor(Anchor::Path {
                            authority: Authority::Label("my friend".parse().unwrap()),
                            path: "line\none".parse().unwrap(),
                        }),
                    ),
                ),
            ]),
            claims: BTreeSet::from([
                "example.test".parse().unwrap(),
                "a.example.test".parse().unwrap(),
            ]),
            introductions: BTreeMap::from([
                ("my friend".parse::<Label>().unwrap(), (member, elsewhere)),
                ("b".parse::<Label>().unwrap(), (author, tree())),
            ]),
            book: BTreeMap::from([(author, Presence::new(reached.clone(), presented))]),
            attestations: Vec::new(),
            indexes: BTreeMap::new(),
            task: Task::new(),
            plays: BTreeMap::new(),
            admitted: BTreeSet::new(),
            refused: vec![(refused, Refusal::NoAuthority)],
        };
        let (mine, theirs) = (tree(), elsewhere);
        assert_eq!(
            view.to_string(),
            format!(
                "owner {author}\nmember {member}\nnote {author} plain text\nnote {member} \
                 two\\nlines, a \\\\ and a bell\\u{{7}}\nbind a\\u{{20}}b/c datum \
                 one\\nline, spaced\nbind x anchor domhringr://{theirs}/.commit/{bound}\nbind y \
                 anchor domhringr://my friend/line\\none\nclaim a.example.test\nclaim \
                 example.test\nintroduce b domhringr://{mine}/\nintroduce my\\u{{20}}friend \
                 domhringr://{theirs}/\npresent {author} {reached} {presented}\nrefused \
                 {refused} no authority\n"
            ),
            "one line per fact, control characters escaped, a path's and a label's spaces too"
        );
        assert_eq!(
            reached.to_string(),
            format!("{}@127.0.0.1:5@https://relay.example.org/", direct.key()),
            "the presence line writes the endpoint id and every address"
        );
    }

    #[test]
    fn the_dispatched_seat_reports_on_its_dispatch()
    {
        let (a, s, x) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        let secret = b_secret();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let undispatched = fold(tree(), vec![opened.clone()]).unwrap();
            assert_eq!(
                undispatched.task().current(),
                &Current::Undispatched,
                "a tree with no dispatch is undispatched"
            );
            let stray = commit(&x, tree(), &[&opened], &dispatch(key(&x))).await;
            let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let by_stranger = commit(
                &x,
                tree(),
                &[&dispatched],
                &report(id(&dispatched), "mine".into()),
            )
            .await;
            let presented = commit(
                &s,
                tree(),
                &[&dispatched],
                &present(&secret, Port(9), key(&s)),
            )
            .await;
            let reported = commit(
                &s,
                tree(),
                &[&presented],
                &report(id(&dispatched), "done".into()),
            )
            .await;
            let view = fold(tree(), vec![
                opened,
                stray.clone(),
                dispatched.clone(),
                by_stranger.clone(),
                presented.clone(),
                reported.clone(),
            ])
            .unwrap();
            assert_eq!(view.refused().len(), 2, "{:?}", view.refused());
            assert!(
                view.refused().contains(&(id(&stray), Refusal::NoAuthority)),
                "a dispatch by a non-member is refused for want of authority"
            );
            assert!(
                view.refused()
                    .contains(&(id(&by_stranger), Refusal::NotHolder)),
                "a report by a key not dispatched is refused by name"
            );
            assert_eq!(
                view.book().get(&key(&s)),
                Some(&Presence::new(endpoint(&secret, Port(9)), id(&presented))),
                "the dispatched seat presents in the task's book"
            );
            let attempt = attempt(&view);
            assert_eq!(
                (attempt.dispatch(), attempt.slot(), attempt.answer()),
                (
                    id(&dispatched),
                    Slot::Held(key(&s)),
                    Answer::Reported(id(&reported))
                ),
                "the seat's report answers the current attempt"
            );
            assert_eq!(
                view.task().steps(),
                &[
                    (id(&dispatched), Step::Dispatch {
                        edition: crate::Edition::ONE,
                        seat: key(&s),
                        brief: brief(),
                    }),
                    (id(&reported), Step::Report {
                        dispatch: id(&dispatched),
                        author: key(&s),
                        content: evidence("done".into()),
                        summary: "done".parse().unwrap(),
                    }),
                ],
                "the admitted seat receipts are the task's steps"
            );
        });
    }

    #[test]
    fn editionless_dispatches_keep_edition_one_refusals()
    {
        let (a, s) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let blob = crate::testing::editionless_dispatch(tree(), key(&s));
            let dispatched = seal(&a, tree(), &[&opened], blob.clone()).await;
            let d = id(&dispatched);
            let paused = commit(&s, tree(), &[&dispatched], &Receipt::pause(tree(), d).unwrap()).await;
            let early = commit(&s, tree(), &[&paused], &Receipt::retire(tree(), d).unwrap()).await;
            let reported = commit(&s, tree(), &[&early], &report(d, "done".into())).await;
            let retired = commit(&s, tree(), &[&reported], &Receipt::retire(tree(), d).unwrap()).await;
            let late = commit(&s, tree(), &[&retired], &report(d, "late".into())).await;
            let view = fold(tree(), vec![opened, dispatched.clone(), paused.clone(), early.clone(), reported.clone(), retired.clone(), late.clone()]).unwrap();
            assert_eq!(dispatched.blob(), &blob);
            assert_eq!(attempt(&view).edition(), crate::Edition::ONE);
            assert_eq!(attempt(&view).answer(), Answer::Reported(id(&reported)));
            assert_eq!(attempt(&view).slot(), Slot::Retired { by: key(&s), at: id(&retired) });
            assert_eq!(view.refused().iter().map(|&(commit, _)| commit).collect::<BTreeSet<_>>(), BTreeSet::from([id(&paused), id(&early), id(&late)]));
            for refusal in view.refused().iter().map(|refused| &refused.1) {
                assert!(matches!(refusal, Refusal::Protocol(reason) if reason.edition == crate::Edition::ONE && matches!(reason.reason, domhringr_arena_session::Reason::Replay(_))));
            }
        });
    }

    #[test]
    fn dispatch_editions_govern_each_attempt()
    {
        let (a, s) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let early = commit(&s, tree(), &[&opened], &report(CommitId::new([7; 32]), "early".into())).await;
            let mut commits = vec![opened, early.clone()];
            let mut expected = vec![(id(&early), Refusal::NotCurrent)];
            for edition in [crate::Edition::ONE, crate::Edition::TWO, crate::Edition::from(99)] {
                let receipt = Receipt::dispatch(tree(), key(&s), edition, brief()).unwrap();
                let dispatched = commit(&a, tree(), &[commits.last().unwrap()], &receipt).await;
                let d = id(&dispatched);
                let prefix = fold(tree(), commits.iter().cloned().chain([dispatched.clone()]).collect()).unwrap();
                assert!(matches!(prefix.transport(CommitId::new([0; 32]), edition), Err(super::PlayTransportError::Missing(_))));
                if edition == crate::Edition::ONE {
                    assert!(matches!(prefix.transport(d, edition), Err(super::PlayTransportError::Arena(domhringr_arena_session::ArenaError::Transport(gandr_core_session::certified::TransportError::Replay(gandr_core_session::ReplayError::IncompleteRun { .. }))))));
                }
                let paused = commit(&s, tree(), &[&dispatched], &Receipt::pause(tree(), d).unwrap()).await;
                let reported = commit(&s, tree(), &[&paused], &report(d, "done".into())).await;
                let retired = commit(&s, tree(), &[&reported], &Receipt::retire(tree(), d).unwrap()).await;
                let known = edition == crate::Edition::ONE || (cfg!(feature = "edition-2") && edition == crate::Edition::TWO);
                let moves = [(id(&dispatched), domhringr_arena_session::Movement::Dispatch), (id(&paused), domhringr_arena_session::Movement::Pause), (id(&reported), domhringr_arena_session::Movement::Report), (id(&retired), domhringr_arena_session::Movement::Retire)];
                commits.extend([dispatched, paused, reported.clone(), retired.clone()]);
                let view = fold(tree(), commits.clone()).unwrap();
                if known {
                    assert_eq!(attempt(&view).edition(), edition);
                    let target = if cfg!(feature = "edition-2") { crate::Edition::TWO } else { crate::Edition::ONE };
                    let transported = view.transport(d, target).unwrap();
                    assert_eq!(transported.moves(), view.plays[&d].1.moves());
                    assert_eq!(attempt(&view).answer(), Answer::Reported(id(&reported)));
                    assert_eq!(attempt(&view).slot(), Slot::Retired { by: key(&s), at: id(&retired) });
                    if edition == crate::Edition::ONE {
                        let &(pause, ref refusal) = view.refused().last().unwrap();
                        assert_eq!(pause, moves[1].0);
                        assert!(matches!(refusal, Refusal::Protocol(reason) if reason.edition == edition && reason.movement == domhringr_arena_session::Movement::Pause && matches!(reason.reason, domhringr_arena_session::Reason::Replay(gandr_core_session::ReplayError::Refused { reason: gandr_core_session::Refusal::WrongLabel, .. }))));
                        expected.push((pause, refusal.clone()));
                    }
                } else {
                    assert!(matches!(view.transport(d, crate::Edition::ONE), Err(super::PlayTransportError::Arena(domhringr_arena_session::ArenaError::Unknown(domhringr_arena_session::UnknownEdition(named)))) if named == edition));
                    for (commit, movement) in moves {
                        expected.push((commit, Refusal::Protocol(Box::new(domhringr_arena_session::Refusal { edition, movement, reason: domhringr_arena_session::Reason::Unknown(domhringr_arena_session::UnknownEdition(edition)) }))));
                    }
                }
                assert_eq!(view.refused(), expected);
            }
        });
    }

    #[test]
    fn a_handoff_before_report_is_a_named_protocol_refusal()
    {
        let (a, s, t) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let d = id(&dispatched);
            let early = commit(&t, tree(), &[&dispatched], &report(d, "early".into())).await;
            let handoff = Receipt::handoff(tree(), d, key(&t)).unwrap();
            let handed = commit(&s, tree(), &[&dispatched], &handoff).await;
            let by_former = commit(&s, tree(), &[&handed], &report(d, "late".into())).await;
            let seize = Receipt::handoff(tree(), d, key(&a)).unwrap();
            let by_owner = commit(&a, tree(), &[&handed], &seize).await;
            let reported = commit(&t, tree(), &[&handed], &report(d, "done".into())).await;
            let view = fold(tree(), vec![
                opened,
                dispatched,
                early.clone(),
                handed.clone(),
                by_former.clone(),
                by_owner.clone(),
                reported.clone(),
            ])
            .unwrap();
            let mut refused: BTreeMap<_, _> = view.refused().iter().cloned().collect();
            assert!(matches!(refused.remove(&id(&handed)), Some(Refusal::Protocol(reason))
                if reason.movement == domhringr_arena_session::Movement::Handoff
                && matches!(reason.reason, domhringr_arena_session::Reason::Replay(gandr_core_session::ReplayError::Refused { at: gandr_core_session::MoveIndex(1), reason: gandr_core_session::Refusal::WrongLabel, .. }))));
            assert!(matches!(refused.remove(&id(&by_owner)), Some(Refusal::NotHolder | Refusal::Protocol(_))));
            assert_eq!(refused, BTreeMap::from([
                (id(&early), Refusal::NotHolder),
                (id(&reported), Refusal::NotHolder),
            ]));
            let attempt = attempt(&view);
            assert_eq!((attempt.slot(), attempt.answer()),
                (Slot::Held(key(&s)), Answer::Reported(id(&by_former))),
                "refused handoff leaves the original holder able to report");
            assert!(!view.task().steps().iter().any(|&(commit, _)| commit == id(&handed)));
        });
    }

    #[test]
    fn handoff_closes_the_play_instead_of_permitting_a_second_handoff()
    {
        let (a, s, t) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let d = id(&dispatched);
            let reported = commit(&s, tree(), &[&dispatched], &report(d, "done".into())).await;
            let handed = commit(&s, tree(), &[&reported], &Receipt::handoff(tree(), d, key(&t)).unwrap()).await;
            let repeated = commit(&t, tree(), &[&handed], &Receipt::handoff(tree(), d, key(&s)).unwrap()).await;
            let late = commit(&t, tree(), &[&repeated], &report(d, "late".into())).await;
            let retired = commit(&t, tree(), &[&late], &Receipt::retire(tree(), d).unwrap()).await;
            let view = fold(tree(), vec![opened, dispatched, reported.clone(), handed.clone(), repeated.clone(), late.clone(), retired.clone()]).unwrap();
            let expected = [
                (id(&repeated), domhringr_arena_session::Movement::Handoff),
                (id(&late), domhringr_arena_session::Movement::Report),
                (id(&retired), domhringr_arena_session::Movement::Retire),
            ];
            for ((commit, movement), &(actual, ref refusal)) in expected.into_iter().zip(view.refused()) {
                assert_eq!(actual, commit);
                assert!(matches!(*refusal, Refusal::Protocol(ref reason) if reason.movement == movement
                    && matches!(reason.reason, domhringr_arena_session::Reason::Replay(gandr_core_session::ReplayError::Refused { expected: gandr_core_session::Action::End, reason: gandr_core_session::Refusal::ResumeAfterEnd, .. }))));
            }
            assert_eq!(view.refused().len(), expected.len());
            assert_eq!((attempt(&view).slot(), attempt(&view).answer()), (Slot::Held(key(&t)), Answer::Reported(id(&reported))));
            assert!(view.task().steps().iter().any(|&(commit, _)| commit == id(&handed)));
        });
    }

    #[test]
    fn retirement_before_report_is_refused_without_relinquishing_the_slot()
    {
        let (a, s) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let d = id(&dispatched);
            let retirement = Receipt::retire(tree(), d).unwrap();
            let retired = commit(&s, tree(), &[&dispatched], &retirement).await;
            let late = commit(&s, tree(), &[&retired], &report(d, "late".into())).await;
            let view = fold(tree(), vec![
                opened,
                dispatched,
                retired.clone(),
                late.clone(),
            ])
            .unwrap();
            assert!(matches!(view.refused(), [(commit, Refusal::Protocol(reason))]
                if *commit == id(&retired) && reason.movement == domhringr_arena_session::Movement::Retire
                && matches!(reason.reason, domhringr_arena_session::Reason::Replay(gandr_core_session::ReplayError::Refused { at: gandr_core_session::MoveIndex(1), reason: gandr_core_session::Refusal::WrongLabel, .. }))));
            let attempt = attempt(&view);
            assert_eq!((attempt.slot(), attempt.answer(), attempt.seat()),
                (Slot::Held(key(&s)), Answer::Reported(id(&late)), key(&s)),
                "refused abandonment leaves the slot open for its first report");
        });
    }

    #[test]
    fn a_report_on_a_superseded_dispatch_is_refused()
    {
        let (a, s, t) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let first = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let second = commit(&a, tree(), &[&first], &dispatch(key(&t))).await;
            let stale = commit(&s, tree(), &[&second], &report(id(&first), "stale".into())).await;
            let nowhere = CommitId::new([9; 32]);
            let unknown = commit(&s, tree(), &[&first], &report(nowhere, "unknown".into())).await;
            let concurrent = commit(
                &s,
                tree(),
                &[&first],
                &report(id(&first), "concurrent".into()),
            )
            .await;
            let view = fold(tree(), vec![
                opened,
                first.clone(),
                second.clone(),
                stale.clone(),
                unknown.clone(),
                concurrent.clone(),
            ])
            .unwrap();
            let mut refused: BTreeMap<_, _> = view.refused().iter().cloned().collect();
            assert_eq!(refused.remove(&id(&unknown)), Some(Refusal::NotCurrent));
            assert_eq!(
                refused,
                BTreeMap::from([(id(&stale), Refusal::NotCurrent)]),
                "superseded dispatches retain their independent causal authority refusal"
            );
            assert!(
                view.task()
                    .steps()
                    .contains(&(id(&concurrent), Step::Report {
                        dispatch: id(&first),
                        author: key(&s),
                        content: evidence("concurrent".into()),
                        summary: "concurrent".parse().unwrap(),
                    })),
                "a report concurrent with the later dispatch is admitted as a step"
            );
            let attempt = attempt(&view);
            assert_eq!(
                (attempt.dispatch(), attempt.slot(), attempt.answer()),
                (id(&second), Slot::Held(key(&t)), Answer::Awaited),
                "the later dispatch is the current attempt, its report awaited"
            );
        });
    }

    #[test]
    fn a_judge_rules_on_the_current_dispatch()
    {
        let (a, s) = (owner(), other());
        let (j, stranger) = (
            MemorySigner::from_bytes(&[5; 32]),
            MemorySigner::from_bytes(&[7; 32]),
        );
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let d = id(&dispatched);
            let judged = commit(&j, tree(), &[&dispatched], &verdict(d, key(&j))).await;
            let forged = commit(&stranger, tree(), &[&dispatched], &verdict(d, key(&j))).await;
            let by_owner = commit(&a, tree(), &[&dispatched], &verdict(d, key(&j))).await;
            let retirement = Receipt::retire(tree(), d).unwrap();
            let retired = commit(&s, tree(), &[&judged], &retirement).await;
            let own = verdict(d, key(&stranger));
            let after = commit(&stranger, tree(), &[&retired], &own).await;
            let view = fold(tree(), vec![
                opened,
                dispatched,
                judged.clone(),
                forged.clone(),
                by_owner.clone(),
                retired.clone(),
                after.clone(),
            ])
            .unwrap();
            let mut refused: BTreeMap<_, _> = view.refused().iter().cloned().collect();
            assert!(matches!(refused.remove(&id(&retired)), Some(Refusal::Protocol(reason))
                if reason.movement == domhringr_arena_session::Movement::Retire
                && matches!(reason.reason, domhringr_arena_session::Reason::Replay(gandr_core_session::ReplayError::Refused { at: gandr_core_session::MoveIndex(1), reason: gandr_core_session::Refusal::WrongLabel, .. }))));
            assert_eq!(
                refused,
                BTreeMap::from([
                    (id(&forged), Refusal::NotJudge),
                    (id(&by_owner), Refusal::NotJudge),
                ]),
                "a verdict signed by any key but its judge's, the owner's among them, is refused"
            );
            let ruled = |judge: PeerKey| Step::Verdict {
                dispatch: d,
                judge,
                rubric: content("rubric".into()),
                transcript: evidence("transcript".into()),
                answers: answers(),
            };
            assert_eq!(
                view.task()
                    .steps()
                    .iter()
                    .filter(|entry| matches!(entry.1, Step::Verdict { .. }))
                    .cloned()
                    .collect::<Vec<_>>(),
                [
                    (id(&judged), ruled(key(&j))),
                    (id(&after), ruled(key(&stranger)))
                ],
                "judges can rule while the report is still owed, even after a refused retirement"
            );
            let attempt = attempt(&view);
            assert_eq!(
                (attempt.slot(), attempt.answer()),
                (Slot::Held(key(&s)), Answer::Awaited),
                "a verdict moves no slot and answers no attempt"
            );
        });
    }

    #[test]
    fn a_verdict_on_a_superseded_dispatch_is_refused()
    {
        let (a, s, j) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let early = commit(
                &j,
                tree(),
                &[&opened],
                &verdict(CommitId::new([9; 32]), key(&j)),
            )
            .await;
            let first = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let second = commit(&a, tree(), &[&first], &dispatch(key(&s))).await;
            let stale = commit(&j, tree(), &[&second], &verdict(id(&first), key(&j))).await;
            let forged = commit(&s, tree(), &[&second], &verdict(id(&first), key(&j))).await;
            let concurrent = commit(&j, tree(), &[&first], &verdict(id(&first), key(&j))).await;
            let view = fold(tree(), vec![
                opened,
                early.clone(),
                first.clone(),
                second,
                stale.clone(),
                forged.clone(),
                concurrent.clone(),
            ])
            .unwrap();
            let refused: BTreeMap<_, _> = view.refused().iter().cloned().collect();
            assert_eq!(
                refused,
                BTreeMap::from([
                    (id(&early), Refusal::NotCurrent),
                    (id(&stale), Refusal::NotCurrent),
                    (id(&forged), Refusal::NotJudge),
                ]),
                "a verdict naming a dispatch never made or superseded in its past is not \
                 current, and one its judge did not sign is refused for that first"
            );
            assert!(
                view.admitted.contains(&id(&concurrent)),
                "a verdict concurrent with the later dispatch is admitted"
            );
        });
    }

    #[test]
    fn a_runner_verifies_on_the_current_dispatch()
    {
        let (a, s) = (owner(), other());
        let (r, stranger) = (
            MemorySigner::from_bytes(&[5; 32]),
            MemorySigner::from_bytes(&[7; 32]),
        );
        runtime().block_on(async {
            let (passing, failing) = (Code::from(0_i32), Code::from(1_i32));
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let first = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let d = id(&first);
            let passed = commit(&r, tree(), &[&first], &verified(d, key(&r), passing)).await;
            let forged = commit(&stranger, tree(), &[&first], &verified(d, key(&r), passing)).await;
            let by_owner = commit(&a, tree(), &[&first], &verified(d, key(&r), passing)).await;
            let retirement = Receipt::retire(tree(), d).unwrap();
            let retired = commit(&s, tree(), &[&passed], &retirement).await;
            let failed = commit(&r, tree(), &[&retired], &verified(d, key(&r), failing)).await;
            let second = commit(&a, tree(), &[&failed], &dispatch(key(&s))).await;
            let stale = commit(&r, tree(), &[&second], &verified(d, key(&r), passing)).await;
            let view = fold(tree(), vec![
                opened,
                first,
                passed.clone(),
                forged.clone(),
                by_owner.clone(),
                retired.clone(),
                failed.clone(),
                second,
                stale.clone(),
            ])
            .unwrap();
            let mut refused: BTreeMap<_, _> = view.refused().iter().cloned().collect();
            assert!(matches!(refused.remove(&id(&retired)), Some(Refusal::Protocol(reason))
                if reason.movement == domhringr_arena_session::Movement::Retire
                && matches!(reason.reason, domhringr_arena_session::Reason::Replay(gandr_core_session::ReplayError::Refused { at: gandr_core_session::MoveIndex(1), reason: gandr_core_session::Refusal::WrongLabel, .. }))));
            assert_eq!(
                refused,
                BTreeMap::from([
                    (id(&forged), Refusal::NotRunner),
                    (id(&by_owner), Refusal::NotRunner),
                    (id(&stale), Refusal::NotCurrent),
                ]),
                "a verification signed by any key but its runner's, the owner's among them, \
                 and one on a superseded dispatch are refused"
            );
            let ran = |code: Code| Step::Verified {
                dispatch: d,
                runner: key(&r),
                playbook: content("playbook".into()),
                step: "test".parse().unwrap(),
                output: evidence("output".into()),
                status: Status::Exited(code),
            };
            assert_eq!(
                view.task()
                    .steps()
                    .iter()
                    .filter(|entry| matches!(entry.1, Step::Verified { .. }))
                    .cloned()
                    .collect::<Vec<_>>(),
                [(id(&passed), ran(passing)), (id(&failed), ran(failing))],
                "verifications before and after a refused retirement retain their exit status"
            );
        });
    }

    #[test]
    fn a_verdicts_judge_grades_its_answers()
    {
        let (a, s) = (owner(), other());
        let (j, stranger) = (
            MemorySigner::from_bytes(&[5; 32]),
            MemorySigner::from_bytes(&[7; 32]),
        );
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let d = id(&dispatched);
            let judged = commit(&j, tree(), &[&dispatched], &verdict(d, key(&j))).await;
            let ruled = id(&judged);
            let answered = vec![Grade::Met, Grade::Refused];
            let grading = graded(ruled, answered.clone());
            let admitted = commit(&j, tree(), &[&judged], &grading).await;
            let forged = graded(ruled, answered.clone());
            let forged = commit(&stranger, tree(), &[&judged], &forged).await;
            let unknown = graded(CommitId::new([9; 32]), answered.clone());
            let unknown = commit(&j, tree(), &[&judged], &unknown).await;
            let concurrent = graded(ruled, answered.clone());
            let concurrent = commit(&j, tree(), &[&dispatched], &concurrent).await;
            let short = commit(&j, tree(), &[&judged], &graded(ruled, vec![Grade::Met])).await;
            let read_refused = graded(ruled, vec![Grade::Refused, Grade::Refused]);
            let read_refused = commit(&j, tree(), &[&judged], &read_refused).await;
            let unread_met = graded(ruled, vec![Grade::Met, Grade::Met]);
            let unread_met = commit(&j, tree(), &[&judged], &unread_met).await;
            let second = commit(&a, tree(), &[&judged], &dispatch(key(&s))).await;
            let stale = commit(&j, tree(), &[&second], &graded(ruled, answered)).await;
            let view = fold(tree(), vec![
                opened,
                dispatched,
                judged,
                admitted.clone(),
                forged.clone(),
                unknown.clone(),
                concurrent.clone(),
                short.clone(),
                read_refused.clone(),
                unread_met.clone(),
                second,
                stale.clone(),
            ])
            .unwrap();
            for candidate in [&unknown, &concurrent] {
                protocol_refusal(
                    &view,
                    id(candidate),
                    domhringr_arena_session::Movement::Graded,
                    gandr_core_session::Refusal::WrongPayloadIdentity,
                );
            }
            let refused: BTreeMap<_, _> = view
                .refused()
                .iter()
                .filter(|entry| entry.0 != id(&unknown) && entry.0 != id(&concurrent))
                .cloned()
                .collect();
            assert_eq!(
                refused,
                BTreeMap::from([
                    (id(&forged), Refusal::NotJudge),
                    (id(&short), Refusal::Misgraded),
                    (id(&read_refused), Refusal::Misgraded),
                    (id(&unread_met), Refusal::Misgraded),
                    (id(&stale), Refusal::NotCurrent),
                ]),
                "a grading by a key but the verdict's judge, of a verdict not in its past, \
                 whose grades do not answer the verdict's, or after a later dispatch is \
                 refused"
            );
            assert_eq!(
                view.task()
                    .steps()
                    .iter()
                    .filter(|entry| matches!(entry.1, Step::Graded { .. }))
                    .cloned()
                    .collect::<Vec<_>>(),
                [(id(&admitted), Step::Graded {
                    dispatch: d,
                    verdict: ruled,
                    rubric: content("rubric".into()),
                    grades: vec![
                        (content("read".into()), Grade::Met),
                        (content("unread".into()), Grade::Refused),
                    ],
                    composed: Grade::Refused,
                })],
                "the judge's grading is a step naming its verdict's dispatch, rubric and \
                 questions"
            );
        });
    }

    /// Assert a receipt's named, independently produced monitor refusal.
    ///
    /// # Specification
    /// trivial.
    fn protocol_refusal(
        view: &View,
        commit: CommitId,
        movement: domhringr_arena_session::Movement,
        reason: gandr_core_session::Refusal,
    )
    {
        let refusal = &view
            .refused()
            .iter()
            .find(|entry| entry.0 == commit)
            .unwrap()
            .1;
        let Refusal::Protocol(ref refusal) = *refusal
        else {
            panic!("expected protocol refusal, got {refusal:?}");
        };
        assert_eq!(
            (refusal.edition, refusal.movement),
            (crate::Edition::ONE, movement)
        );
        assert!(
            matches!(refusal.reason, domhringr_arena_session::Reason::Replay(gandr_core_session::ReplayError::Refused { reason: actual, .. }) if actual == reason)
        );
    }

    #[test]
    fn task_channels_refuse_second_choices()
    {
        let (a, s) = (owner(), other());
        let j = MemorySigner::from_bytes(&[5; 32]);
        runtime().block_on(async {
            for concurrent in [false, true] {
                let opened = commit(&a, tree(), &[], &open(&a)).await;
                let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
                let d = id(&dispatched);
                let judged = commit(&j, tree(), &[&dispatched], &verdict(d, key(&j))).await;
                let first_grade = commit(
                    &j,
                    tree(),
                    &[&judged],
                    &graded(id(&judged), vec![Grade::Met, Grade::Refused]),
                )
                .await;
                let second_grade = commit(
                    &j,
                    tree(),
                    &[if concurrent { &judged } else { &first_grade }],
                    &graded(id(&judged), vec![Grade::Met, Grade::Refused]),
                )
                .await;
                let first_decision = commit(
                    &a,
                    tree(),
                    &[&first_grade, &second_grade],
                    &decide(d, &a, Decision::Land),
                )
                .await;
                let concurrent_parents = [&first_grade, &second_grade];
                let causal_parents = [&first_decision];
                let second_decision = commit(
                    &a,
                    tree(),
                    if concurrent {
                        concurrent_parents.as_slice()
                    }
                    else {
                        causal_parents.as_slice()
                    },
                    &decide(d, &a, Decision::Land),
                )
                .await;
                let decided = if concurrent && id(&second_decision) < id(&first_decision) {
                    &second_decision
                }
                else {
                    &first_decision
                };
                let first_landing = commit(
                    &a,
                    tree(),
                    &[&first_decision, &second_decision],
                    &landed(id(decided)),
                )
                .await;
                let concurrent_parents = [&first_decision, &second_decision];
                let causal_parents = [&first_landing];
                let second_landing = commit(
                    &a,
                    tree(),
                    if concurrent {
                        concurrent_parents.as_slice()
                    }
                    else {
                        causal_parents.as_slice()
                    },
                    &landed(id(decided)),
                )
                .await;
                let grade_refused = if concurrent {
                    id(&first_grade).max(id(&second_grade))
                }
                else {
                    id(&second_grade)
                };
                let decision_refused = if concurrent {
                    id(&first_decision).max(id(&second_decision))
                }
                else {
                    id(&second_decision)
                };
                let landing_refused = if concurrent {
                    id(&first_landing).max(id(&second_landing))
                }
                else {
                    id(&second_landing)
                };
                let held = vec![
                    opened,
                    dispatched,
                    judged,
                    first_grade,
                    second_grade,
                    first_decision,
                    second_decision,
                    first_landing,
                    second_landing,
                ];
                let view = fold(tree(), held.clone()).unwrap();
                assert_eq!(view.refused().len(), 3);
                protocol_refusal(
                    &view,
                    grade_refused,
                    domhringr_arena_session::Movement::Graded,
                    gandr_core_session::Refusal::ResumeAfterEnd,
                );
                protocol_refusal(
                    &view,
                    decision_refused,
                    domhringr_arena_session::Movement::Decide(
                        domhringr_arena_session::Choice::Land,
                    ),
                    gandr_core_session::Refusal::WrongDirection,
                );
                protocol_refusal(
                    &view,
                    landing_refused,
                    domhringr_arena_session::Movement::Landed,
                    gandr_core_session::Refusal::ResumeAfterEnd,
                );
                let reversed = fold(tree(), held.into_iter().rev().collect()).unwrap();
                assert_eq!(reversed.refused(), view.refused());
                assert_eq!(reversed.task(), view.task());
            }
        });
    }

    #[test]
    fn a_gradings_composition_is_checked_before_it_advances_the_task()
    {
        use Grade::Met;
        use Grade::Refused;
        use Grade::Undecided;
        use Grade::Unmet;
        let (a, s, j) = (owner(), other(), MemorySigner::from_bytes(&[5; 32]));
        runtime().block_on(async {
            for (grades, expected) in [
                (vec![], Met),
                (vec![Met], Met),
                (vec![Unmet], Unmet),
                (vec![Undecided], Undecided),
                (vec![Refused], Refused),
                (vec![Met, Refused], Refused),
                (vec![Refused, Undecided, Unmet], Unmet),
            ] {
                let opened = commit(&a, tree(), &[], &open(&a)).await;
                let dispatched = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
                let d = id(&dispatched);
                let answers = grades
                    .iter()
                    .enumerate()
                    .map(|(index, &grade)| {
                        let ruling = if grade == Refused {
                            Ruling::Unread(Unread::NoLetter)
                        }
                        else {
                            Ruling::Read(
                                Readout::new(
                                    vec![
                                        Probability::try_from(0.75_f64).unwrap(),
                                        Probability::try_from(0.25_f64).unwrap(),
                                    ],
                                    Probability::try_from(0.0_f64).unwrap(),
                                )
                                .unwrap(),
                            )
                        };
                        (content(index.to_string()), ruling)
                    })
                    .collect();
                let receipt = Receipt::verdict(
                    tree(),
                    d,
                    key(&j),
                    content("rubric".into()),
                    evidence("transcript".into()),
                    answers,
                )
                .unwrap();
                let judged = commit(&j, tree(), &[&dispatched], &receipt).await;
                let verdict = id(&judged);
                let mut commits = vec![opened, dispatched, judged.clone()];
                let mut parent = judged;
                let mut refused = BTreeMap::new();
                for composed in [Met, Unmet, Undecided, Refused]
                    .into_iter()
                    .filter(|&grade| grade != expected)
                {
                    let receipt =
                        Receipt::graded(tree(), verdict, grades.clone(), composed).unwrap();
                    let misstated = commit(&j, tree(), &[&parent], &receipt).await;
                    let _previous = refused.insert(id(&misstated), Refusal::Miscomposed);
                    commits.push(misstated.clone());
                    parent = misstated;
                }
                let view = fold(tree(), commits.clone()).unwrap();
                assert_eq!(
                    view.refused().iter().cloned().collect::<BTreeMap<_, _>>(),
                    refused,
                    "{grades:?}"
                );
                assert_eq!(attempt(&view).progress(), &Progress::Unchecked);
                assert!(
                    !view
                        .task()
                        .steps()
                        .iter()
                        .any(|entry| matches!(entry.1, Step::Graded { .. }))
                );
                let receipt = Receipt::graded(tree(), verdict, grades, expected).unwrap();
                let admitted = commit(&j, tree(), &[&parent], &receipt).await;
                let grading = id(&admitted);
                commits.push(admitted);
                let view = fold(tree(), commits).unwrap();
                assert_eq!(
                    view.refused().iter().cloned().collect::<BTreeMap<_, _>>(),
                    refused
                );
                assert_eq!(attempt(&view).progress(), &Progress::Graded {
                    grading,
                    composed: expected
                });
            }
        });
    }

    #[test]
    fn an_operator_decides_on_the_current_dispatch()
    {
        let (a, s) = (owner(), other());
        let (m, stranger) = (
            MemorySigner::from_bytes(&[5; 32]),
            MemorySigner::from_bytes(&[7; 32]),
        );
        runtime().block_on(async {
            for operator in [&a, &m] {
                let opened = commit(&a, tree(), &[], &open(&a)).await;
                let granted = commit(&a, tree(), &[&opened], &grant(&m)).await;
                let dispatched = commit(&a, tree(), &[&granted], &dispatch(key(&s))).await;
                let d = id(&dispatched);
                let admitted = commit(
                    operator,
                    tree(),
                    &[&dispatched],
                    &decide(d, operator, Decision::Land),
                )
                .await;
                let by_seat =
                    commit(&s, tree(), &[&dispatched], &decide(d, &s, Decision::Land)).await;
                let by_stranger = commit(
                    &stranger,
                    tree(),
                    &[&dispatched],
                    &decide(d, &stranger, Decision::Abandon),
                )
                .await;
                let forged =
                    commit(&m, tree(), &[&dispatched], &decide(d, &a, Decision::Land)).await;
                let unknown = commit(
                    &a,
                    tree(),
                    &[&dispatched],
                    &decide(CommitId::new([9; 32]), &a, Decision::Land),
                )
                .await;
                let second = commit(&a, tree(), &[&admitted], &dispatch(key(&s))).await;
                let stale = commit(&a, tree(), &[&second], &decide(d, &a, Decision::Abandon)).await;
                let view = fold(tree(), vec![
                    opened,
                    granted,
                    dispatched,
                    admitted.clone(),
                    by_seat.clone(),
                    by_stranger.clone(),
                    forged.clone(),
                    unknown.clone(),
                    second,
                    stale.clone(),
                ])
                .unwrap();
                assert_eq!(
                    view.refused().iter().cloned().collect::<BTreeMap<_, _>>(),
                    BTreeMap::from([
                        (id(&by_seat), Refusal::NoAuthority),
                        (id(&by_stranger), Refusal::NoAuthority),
                        (id(&forged), Refusal::NotOperator),
                        (id(&unknown), Refusal::NotCurrent),
                        (id(&stale), Refusal::NotCurrent),
                    ])
                );
                assert_eq!(
                    view.task()
                        .steps()
                        .iter()
                        .filter(|entry| matches!(entry.1, Step::Decide { .. }))
                        .cloned()
                        .collect::<Vec<_>>(),
                    vec![(id(&admitted), Step::Decide {
                        dispatch: d,
                        operator: key(operator),
                        decision: Decision::Land
                    })]
                );
            }
        });
    }

    #[test]
    fn a_landing_carries_out_a_decision_to_land()
    {
        let (a, s) = (owner(), other());
        let m = MemorySigner::from_bytes(&[5; 32]);
        runtime().block_on(async {
            for choice in [Decision::Land, rework(), Decision::Abandon] {
                let opened = commit(&a, tree(), &[], &open(&a)).await;
                let granted = commit(&a, tree(), &[&opened], &grant(&m)).await;
                let dispatched = commit(&a, tree(), &[&granted], &dispatch(key(&s))).await;
                let d = id(&dispatched);
                let decided =
                    commit(&a, tree(), &[&dispatched], &decide(d, &a, choice.clone())).await;
                let landing = commit(&a, tree(), &[&decided], &landed(id(&decided))).await;
                let by_seat = commit(&s, tree(), &[&decided], &landed(id(&decided))).await;
                let by_member = commit(&m, tree(), &[&decided], &landed(id(&decided))).await;
                let undecided =
                    commit(&a, tree(), &[&dispatched], &landed(CommitId::new([9; 32]))).await;
                let concurrent = commit(&a, tree(), &[&dispatched], &landed(id(&decided))).await;
                let second = commit(&a, tree(), &[&landing], &dispatch(key(&s))).await;
                let stale = commit(&a, tree(), &[&second], &landed(id(&decided))).await;
                let view = fold(tree(), vec![
                    opened,
                    granted,
                    dispatched,
                    decided.clone(),
                    landing.clone(),
                    by_seat.clone(),
                    by_member.clone(),
                    undecided.clone(),
                    concurrent.clone(),
                    second,
                    stale.clone(),
                ])
                .unwrap();
                for candidate in [&undecided, &concurrent] {
                    protocol_refusal(
                        &view,
                        id(candidate),
                        domhringr_arena_session::Movement::Landed,
                        gandr_core_session::Refusal::WrongDirection,
                    );
                }
                let expected = BTreeMap::from([
                    (id(&by_seat), Refusal::NotOperator),
                    (id(&by_member), Refusal::NotOperator),
                    (id(&stale), Refusal::NotCurrent),
                ]);
                let landings = view
                    .task()
                    .steps()
                    .iter()
                    .filter(|entry| matches!(entry.1, Step::Landed { .. }))
                    .cloned()
                    .collect::<Vec<_>>();
                if choice == Decision::Land {
                    assert_eq!(landings, vec![(id(&landing), Step::Landed {
                        dispatch: d,
                        decided: id(&decided),
                        operator: key(&a),
                        merge: revision()
                    })]);
                }
                else {
                    protocol_refusal(
                        &view,
                        id(&landing),
                        domhringr_arena_session::Movement::Landed,
                        gandr_core_session::Refusal::ResumeAfterEnd,
                    );
                    assert!(landings.is_empty());
                }
                assert_eq!(
                    view.refused()
                        .iter()
                        .filter(|entry| entry.0 != id(&undecided)
                            && entry.0 != id(&concurrent)
                            && entry.0 != id(&landing))
                        .cloned()
                        .collect::<BTreeMap<_, _>>(),
                    expected
                );
            }
        });
    }

    #[test]
    fn an_attempt_advances_through_its_lifecycle()
    {
        let (a, s) = (owner(), other());
        let j = MemorySigner::from_bytes(&[5; 32]);
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open(&a)).await;
            let first = commit(&a, tree(), &[&opened], &dispatch(key(&s))).await;
            let d = id(&first);
            let reported = commit(&s, tree(), &[&first], &report(d, "done".into())).await;
            let passing = verified(d, key(&j), Code::from(0_i32));
            let verifying = commit(&j, tree(), &[&reported], &passing).await;
            let judged = commit(&j, tree(), &[&verifying], &verdict(d, key(&j))).await;
            let grading = graded(id(&judged), vec![Grade::Met, Grade::Refused]);
            let grading = commit(&j, tree(), &[&judged], &grading).await;
            let failing = verified(d, key(&j), Code::from(1_i32));
            let reverifying = commit(&j, tree(), &[&grading], &failing).await;
            let reworked = commit(&a, tree(), &[&reverifying], &decide(d, &a, rework())).await;
            let next = commit(&a, tree(), &[&reworked], &dispatch(key(&s))).await;
            let land = commit(&a, tree(), &[&next], &decide(id(&next), &a, Decision::Land)).await;
            let landing = commit(&a, tree(), &[&land], &landed(id(&land))).await;
            let steps = [
                (first.clone(), Progress::Unchecked, "a dispatch"),
                (reported.clone(), Progress::Unchecked, "its report"),
                (
                    verifying.clone(),
                    Progress::Verified(id(&verifying)),
                    "a verification",
                ),
                (
                    judged.clone(),
                    Progress::Verified(id(&verifying)),
                    "a verdict, which moves nothing",
                ),
                (
                    grading.clone(),
                    Progress::Graded {
                        grading: id(&grading),
                        composed: Grade::Refused,
                    },
                    "its grading",
                ),
                (
                    reverifying.clone(),
                    Progress::Graded {
                        grading: id(&grading),
                        composed: Grade::Refused,
                    },
                    "a later verification, which ranks below the grading",
                ),
                (
                    reworked.clone(),
                    Progress::Decided {
                        decide: id(&reworked),
                        decision: rework(),
                    },
                    "a decision to rework",
                ),
                (next, Progress::Unchecked, "a fresh dispatch after rework"),
                (
                    land.clone(),
                    Progress::Decided {
                        decide: id(&land),
                        decision: Decision::Land,
                    },
                    "the new dispatch decision to land",
                ),
                (
                    landing.clone(),
                    Progress::Landed {
                        landed: id(&landing),
                        merge: revision(),
                    },
                    "the landing",
                ),
            ];
            let mut held = vec![opened];
            for (added, progress, case) in steps {
                held.push(added);
                let view = fold(tree(), held.clone()).unwrap();
                assert!(view.refused().is_empty(), "{case} is admitted");
                assert_eq!(attempt(&view).progress(), &progress, "after {case}");
            }
            let view = fold(tree(), held).unwrap();
            assert_eq!(
                view.task().evidence().collect::<Vec<_>>(),
                [
                    (key(&s), evidence("done".into())),
                    (key(&j), evidence("output".into())),
                    (key(&j), evidence("transcript".into())),
                    (key(&j), evidence("output".into())),
                ],
                "the report's, each verification's and the verdict's evidence, in order, \
                 each with its author"
            );
        });
    }

    #[test]
    fn a_task_prints_one_line_per_step_and_its_standing()
    {
        let (s, t) = (key(&other()), key(&MemorySigner::from_bytes(&[5; 32])));
        let [
            first,
            handed,
            reported,
            retired,
            judged,
            verifying,
            grading,
            reworked,
            decided,
            landing,
            abandoning,
            second,
            abandoned,
        ] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13].map(|byte| CommitId::new([byte; 32]));
        let merge = "0123456789abcdef0123456789abcdef01234567"
            .parse::<Revision>()
            .unwrap();
        let hash = content("brief".into());
        let named = evidence("evidence".into());
        let anchored = Brief::Anchor(Anchor::Path {
            authority: Authority::Key(tree()),
            path: "a\\b".parse().unwrap(),
        });
        let mut task = Task::new();
        assert_eq!(task.to_string(), "undispatched\n", "no dispatch");
        task.dispatch(first, s, crate::Edition::ONE, anchored);
        let dispatch_line = format!(
            "dispatch {first} {s} edition 1 anchor domhringr://{}/a\\\\b\n",
            tree()
        );
        assert_eq!(
            task.to_string(),
            format!("{dispatch_line}dispatched {first} {s}\n"),
            "a held, unreported dispatch"
        );
        task.answer(handed, Step::Handoff {
            dispatch: first,
            from: s,
            to: t,
        });
        task.answer(reported, Step::Report {
            dispatch: first,
            author: t,
            content: named,
            summary: "done \\ ok".parse().unwrap(),
        });
        task.answer(retired, Step::Retire {
            dispatch: first,
            author: t,
        });
        let probability = |value: f64| Probability::try_from(value).unwrap();
        let readout = Readout::new(
            vec![probability(0.25_f64), probability(0.75_f64)],
            probability(0.0_f64),
        )
        .unwrap();
        task.answer(judged, Step::Verdict {
            dispatch: first,
            judge: s,
            rubric: hash,
            transcript: named,
            answers: vec![
                (hash, Ruling::Read(readout)),
                (hash, Ruling::Unread(Unread::Tied)),
            ],
        });
        let answered = format!(
            "{dispatch_line}handoff {handed} {first} {s} {t}\nreport {reported} {first} {t} \
             {named} done \\\\ ok\nretire {retired} {first} {t}\nverdict {judged} {first} {s} \
             {hash} {named}\nruling {judged} {hash} read B A=0.25 B=0.75 outside=0\nruling \
             {judged} {hash} unread tied\n"
        );
        assert_eq!(
            task.to_string(),
            format!("{answered}reported {first} {reported}\n"),
            "a reported dispatch stays reported after its slot is retired and a verdict on it"
        );
        task.answer(verifying, Step::Verified {
            dispatch: first,
            runner: t,
            playbook: hash,
            step: "lint".parse().unwrap(),
            output: named,
            status: Status::Signalled(Signal::from(9_i32)),
        });
        let answered =
            format!("{answered}verified {verifying} {first} {t} {hash} lint {named} signal 9\n");
        assert_eq!(
            task.to_string(),
            format!("{answered}verified {first} {verifying}\n"),
            "a verified dispatch"
        );
        task.answer(grading, Step::Graded {
            dispatch: first,
            verdict: judged,
            rubric: hash,
            grades: vec![(hash, Grade::Met), (hash, Grade::Refused)],
            composed: Grade::Refused,
        });
        let answered = format!(
            "{answered}graded {grading} {first} {judged} {hash} refused\ngrade {grading} {hash} \
             met\ngrade {grading} {hash} refused\n"
        );
        assert_eq!(
            task.to_string(),
            format!("{answered}graded {first} {grading} refused\n"),
            "a graded dispatch"
        );
        task.answer(reworked, Step::Decide {
            dispatch: first,
            operator: s,
            decision: Decision::Rework {
                reason: "lint \\ red".parse().unwrap(),
            },
        });
        let answered = format!("{answered}decide {reworked} {first} {s} rework lint \\\\ red\n");
        assert_eq!(
            task.to_string(),
            format!("{answered}decided {first} {reworked} rework lint \\\\ red\n"),
            "a dispatch decided for rework, the reason's backslash escaped"
        );
        task.answer(decided, Step::Decide {
            dispatch: first,
            operator: s,
            decision: Decision::Land,
        });
        task.answer(landing, Step::Landed {
            dispatch: first,
            decided,
            operator: s,
            merge,
        });
        task.answer(abandoning, Step::Decide {
            dispatch: first,
            operator: s,
            decision: Decision::Abandon,
        });
        let answered = format!(
            "{answered}decide {decided} {first} {s} land\nlanded {landing} {first} {decided} {s} \
             {merge}\ndecide {abandoning} {first} {s} abandon\n"
        );
        assert_eq!(
            task.to_string(),
            format!("{answered}landed {first} {landing} {merge}\n"),
            "a landed dispatch stays landed after a later decision"
        );
        task.dispatch(second, s, crate::Edition::ONE, Brief::Content(hash));
        task.answer(abandoned, Step::Retire {
            dispatch: second,
            author: s,
        });
        assert_eq!(
            task.to_string(),
            format!(
                "{answered}dispatch {second} {s} edition 1 content {hash}\nretire {abandoned} {second} \
                 {s}\nstalled {second} {abandoned}\n"
            ),
            "a later dispatch by content, retired from unreported, is stalled"
        );
    }
}
