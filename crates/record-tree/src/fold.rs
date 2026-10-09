//! The fold: what a peer makes of a tree's commits.
//!
//! Every peer holding the same commits computes the same [`View`]. The
//! commits are placed in one canonical order — a topological order of the
//! DAG that, among the commits whose parents are all placed, places the
//! smallest commit id next — and each receipt is admitted or refused by rules
//! that read only the receipt, its verified author, and its causal past.
//! Refused commits stay in the DAG and sync like any other; the fold is what
//! gives them no meaning.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::Entry;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::fmt::Write as _;

use gandr_storage_values::ValueError;
use sedimentree_core::loose_commit::LooseCommit;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::peer::id::PeerId;
use subduction_crypto::verified_meta::VerifiedMeta;

use crate::anchor::Anchor;
use crate::anchor::Path;
use crate::anchor::Resolution;
use crate::anchor::Target;
use crate::id::CommitPrefix;
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

/// What a peer makes of a tree.
///
/// Its owner, the peers granted write authority, the admitted notes, the paths
/// bound, the DNS names claimed, the trees introduced, the book of who is
/// reachable at which endpoint, the commits admitted, and the commits refused.
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
    /// The admitted commits' ids.
    admitted: BTreeSet<CommitId>,
    /// The refused commits and why, in canonical order.
    refused: Vec<(CommitId, Refusal)>,
}

impl View
{
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
    /// an ancestor of the receipt.
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
            | Self::Undecodable(_) => "undecodable",
            | Self::WrongTree { .. } => "wrong tree",
            | Self::Duplicate { .. } => "duplicate operation",
            | Self::NoAuthority => "no authority",
            | Self::BadProof => "bad proof",
            | Self::NotOwner => "not owner",
            | Self::SecondOpen => "second open",
            | Self::ForeignEndpoint => "foreign endpoint",
            | Self::ForeignPresence => "foreign presence",
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

/// A commit awaiting its place in the canonical order.
struct Node
{
    /// The commit's id.
    commit: CommitId,
    /// The commit's verified signer.
    author: PeerKey,
    /// The receipt the commit's blob carries, or why it carries none.
    receipt: Result<Receipt, ValueError>,
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
    /// The peers named by admitted grants in the commit's causal past, the
    /// commit itself included.
    grantees: BTreeSet<PeerKey>,
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
///   is the owner, or it is a grant, a note, a bind or an introduction whose
///   author is the owner or has an admitted grant among its ancestors, or it is
///   a presence by such an author whose proof verifies under the presented
///   endpoint's key for its author ([`EndpointProof::verify`]), or it is a
///   withdrawal whose author is the owner, or has an admitted grant among its
///   ancestors and withdraws its own presence.
/// - ensures: a refused commit is listed with the first refusal that holds,
///   checked in this order: [`Refusal::Undecodable`], [`Refusal::WrongTree`],
///   [`Refusal::Duplicate`] (an admitted commit earlier in canonical order
///   carries the same operation), then for an Open [`Refusal::BadProof`] when
///   its proof fails and [`Refusal::SecondOpen`] when it is not the tree's,
///   [`Refusal::NotOwner`] for a claim, [`Refusal::NoAuthority`] for a grant, a
///   note, a bind, an introduction, a presence or a withdrawal by an author
///   neither the owner nor granted, then [`Refusal::ForeignEndpoint`] for a
///   presence whose proof fails and [`Refusal::ForeignPresence`] for a member's
///   withdrawal of another's presence.
/// - ensures: each path's binding is the admitted bind of that path last in
///   canonical order, each label's introduction the admitted introduction of
///   that label last in canonical order, the claims the domains of every
///   admitted claim, each author's presence in the book its admitted presence
///   last in canonical order unless an admitted withdrawal of it comes later,
///   whose `since` is that presence's commit, and the admitted commits the ids
///   of every commit admitted.
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
///   and a member's of its own, a member's withdrawal of the owner's refused,
///   an unopened tree and a parent cycle are each pinned by a case of their
///   own.
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
///
/// [`OpenProof::verify`]: crate::receipt::OpenProof::verify
/// [`EndpointProof::verify`]: crate::receipt::EndpointProof::verify
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
        let proof = match receipt {
            | Ok(ref receipt) if receipt.tree() == tree => match *receipt.kind() {
                | Kind::Open { proof } => Some(proof.verify(tree, author)),
                | Kind::Grant { .. }
                | Kind::Note { .. }
                | Kind::Bind { .. }
                | Kind::Claim { .. }
                | Kind::Introduce { .. }
                | Kind::Present { .. }
                | Kind::Withdraw { .. } => None,
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
    loop {
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
        let mut grantees = inherit(&mut carries, &node.parents, position);
        let refusal = match node.receipt {
            | Err(failure) => Some(Refusal::Undecodable(failure)),
            | Ok(receipt) => {
                let (named, operation, kind) = receipt.into_parts();
                let authorized = node.author == owner || grantees.contains(&node.author);
                if named != tree {
                    Some(Refusal::WrongTree { named })
                }
                else if let Some(first) = admitted.get(&operation) {
                    Some(Refusal::Duplicate { first: *first })
                }
                else {
                    let refusal = match kind {
                        | Kind::Open { .. } if bad_proofs.contains(&position) => {
                            Some(Refusal::BadProof)
                        },
                        | Kind::Open { .. } => (position != open).then_some(Refusal::SecondOpen),
                        | Kind::Grant { to } if authorized => {
                            let _was_member = view.members.insert(to);
                            let _was_granted = grantees.insert(to);
                            None
                        },
                        | Kind::Note { text } if authorized => {
                            view.notes.push((node.author, text));
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
                        | Kind::Present { endpoint, proof } if authorized => {
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
                            if node.author == owner || (authorized && of == node.author) =>
                        {
                            let _withdrawn = view.book.remove(&of);
                            None
                        },
                        | Kind::Withdraw { .. } if authorized => Some(Refusal::ForeignPresence),
                        | Kind::Grant { .. }
                        | Kind::Note { .. }
                        | Kind::Bind { .. }
                        | Kind::Introduce { .. }
                        | Kind::Present { .. }
                        | Kind::Withdraw { .. } => Some(Refusal::NoAuthority),
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
            },
        }
        let readers: BTreeSet<Position> = node
            .children
            .iter()
            .copied()
            .filter(|child| nodes.contains_key(child))
            .collect();
        if !readers.is_empty() {
            drop(carries.insert(position, Carry { grantees, readers }));
        }
    }
    Ok(view)
}

/// The canonical order of two commits: by commit id, then by signed bytes.
///
/// # Specification
/// - ensures: a total order on stored commits that two peers compute alike; it
///   ties only commits with identical signed bytes, which are one commit.
/// - panics: none.
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

/// The grantees in the causal past of the commit at `reader`, read from its
/// placed `parents`.
///
/// # Specification
/// - ensures: returns the union of the placed parents' carries; a parent not
///   placed yet (a cycle) contributes nothing. Each carry is read once per
///   reader and dropped after its last reader, moved rather than copied when it
///   is.
/// - panics: none.
fn inherit(
    carries: &mut BTreeMap<Position, Carry>,
    parents: &[Position],
    reader: Position,
) -> BTreeSet<PeerKey>
{
    let mut grantees = BTreeSet::new();
    for parent in parents {
        let Entry::Occupied(mut slot) = carries.entry(*parent)
        else {
            continue;
        };
        let _was_reader = slot.get_mut().readers.remove(&reader);
        if slot.get().readers.is_empty() {
            let carry = slot.remove();
            if grantees.is_empty() {
                grantees = carry.grantees;
            }
            else {
                grantees.extend(carry.grantees);
            }
        }
        else {
            grantees.extend(slot.get().grantees.iter().copied());
        }
    }
    grantees
}

/// Record that `commit` admitted `operation`.
///
/// # Specification
/// - requires: no admitted commit carries `operation` yet.
/// - ensures: later receipts carrying `operation` are duplicates of `commit`.
/// - panics: none.
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
}
