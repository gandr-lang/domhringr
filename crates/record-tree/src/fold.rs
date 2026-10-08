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

use sedimentree_core::loose_commit::LooseCommit;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::peer::id::PeerId;
use subduction_crypto::verified_meta::VerifiedMeta;

use crate::id::PeerKey;
use crate::id::TreeId;
use crate::receipt::DecodeError;
use crate::receipt::Kind;
use crate::receipt::Operation;
use crate::receipt::Receipt;

/// What a peer makes of a tree: its owner, the peers granted write authority,
/// the admitted notes, and the commits refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View
{
    /// The author of the tree's Open.
    owner: PeerKey,
    /// The peers an admitted grant names.
    members: BTreeSet<PeerKey>,
    /// The admitted notes and their authors, in canonical order.
    notes: Vec<(PeerKey, String)>,
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
    /// in key order, one `note <key> <text>` per note and one
    /// `refused <commit> <reason>` per refusal, both in canonical order.
    ///
    /// # Specification
    /// - ensures: every line ends in a newline, and each note stays one line: a
    ///   backslash in its text is written `\\` and a control character as its
    ///   Rust escape (`\n`, `\u{7}`), so equal views print equal bytes and
    ///   distinct notes print distinct lines.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a view with a member, notes, a multi-line note and a
    ///   refusal is printed and compared line for line.
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
            for character in text.chars() {
                if character == '\\' || character.is_control() {
                    write!(f, "{}", character.escape_default())?;
                }
                else {
                    f.write_char(character)?;
                }
            }
            writeln!(f)?;
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
    Undecodable(DecodeError),
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
    /// An Open that is not the tree's.
    SecondOpen,
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
            | Self::SecondOpen => "second open",
        })
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
    receipt: Result<Receipt, DecodeError>,
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
///   parents whose receipt is an Open of `tree`, the first in canonical order,
///   whose author is the owner — or its author is the owner, or an admitted
///   grant to its author is among its ancestors.
/// - ensures: a refused commit is listed with the first refusal that holds,
///   checked in this order: [`Refusal::Undecodable`], [`Refusal::WrongTree`],
///   [`Refusal::Duplicate`] (an admitted commit earlier in canonical order
///   carries the same operation), then [`Refusal::SecondOpen`] for an Open and
///   [`Refusal::NoAuthority`] for a grant or a note.
/// - fails: [`Unopened`] when no commit is the tree's Open.
/// - panics: none.
/// - intension: when parents claim a cycle no topological order exists; the
///   smallest unplaced commit is then placed next, and authority flows only
///   from parents already placed. The fold is O(n log n) in the commits and
///   holds authority sets only for placed commits with unplaced children.
///
/// # Errors
/// - [`Unopened`]: no root Open names `tree`.
///
/// # Adequacy
/// - hypothesis: L3 — one DAG with concurrent branches, a refused note, a grant
///   and a merge is folded from three arrival orders and compared exactly; each
///   refusal reason, the causal reading of a grant, the first-wins duplicate,
///   the smallest-root Open, an unopened tree and a parent cycle are each
///   pinned by a case of their own.
/// - witness: `fold::tests::a_view_is_the_same_whatever_order_commits_arrive_in`
/// - witness: `fold::tests::a_note_by_a_non_member_is_refused`
/// - witness: `fold::tests::a_note_by_a_peer_granted_in_its_causal_past_is_admitted`
/// - witness: `fold::tests::a_duplicate_operation_keeps_the_first`
/// - witness: `fold::tests::a_receipt_under_the_wrong_tree_is_refused`
/// - witness: `fold::tests::the_smallest_root_open_names_the_owner`
/// - witness: `fold::tests::an_undecodable_blob_is_refused_and_an_unopened_tree_has_no_view`
/// - witness: `fold::tests::a_parent_cycle_is_placed_in_commit_id_order`
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
    let mut nodes = BTreeMap::new();
    for (index, (commit, parents)) in commits.into_iter().zip(parents).enumerate() {
        let position = Position(index);
        let author = PeerKey::new(PeerId::from(commit.issuer()));
        let receipt = Receipt::decode(commit.blob());
        let opens = commit.payload().parents().is_empty()
            && receipt
                .as_ref()
                .is_ok_and(|receipt| receipt.tree() == tree && *receipt.kind() == Kind::Open);
        if opens && open.is_none() {
            open = Some((position, author));
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
                        | Kind::Open => (position != open).then_some(Refusal::SecondOpen),
                        | Kind::Grant { to } if authorized => {
                            let _was_member = view.members.insert(to);
                            let _was_granted = grantees.insert(to);
                            None
                        },
                        | Kind::Note { text } if authorized => {
                            view.notes.push((node.author, text));
                            None
                        },
                        | Kind::Grant { .. } | Kind::Note { .. } => Some(Refusal::NoAuthority),
                    };
                    if refusal.is_none() {
                        admit(&mut admitted, operation, node.commit);
                    }
                    refusal
                }
            },
        };
        if let Some(refusal) = refusal {
            view.refused.push((node.commit, refusal));
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
    use alloc::collections::BTreeSet;
    use alloc::string::String;
    use alloc::vec::Vec;

    use sedimentree_core::blob::Blob;
    use sedimentree_core::loose_commit::id::CommitId;
    use subduction_crypto::signer::memory::MemorySigner;

    use super::Refusal;
    use super::Unopened;
    use super::View;
    use super::fold;
    use crate::id::TreeId;
    use crate::receipt::DecodeError;
    use crate::receipt::Kind;
    use crate::receipt::Operation;
    use crate::receipt::Receipt;
    use crate::testing::commit;
    use crate::testing::digest;
    use crate::testing::id;
    use crate::testing::key;
    use crate::testing::other;
    use crate::testing::owner;
    use crate::testing::runtime;
    use crate::testing::seal;
    use crate::testing::seal_on;

    /// The tree every test folds.
    const TREE: &str = "666f6c64666f6c64666f6c64666f6c64666f6c64666f6c64666f6c64666f6c64";

    /// Another tree, which a misplaced receipt names.
    const ELSEWHERE: &str = "656c7365656c7365656c7365656c7365656c7365656c7365656c7365656c7365";

    /// The tree every test folds.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        TREE.parse().unwrap()
    }

    /// A fresh Open of the tree.
    ///
    /// # Specification
    /// trivial.
    fn open() -> Receipt
    {
        Receipt::open(tree()).unwrap()
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

    #[test]
    fn a_view_is_the_same_whatever_order_commits_arrive_in()
    {
        let (a, b) = (owner(), other());
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open()).await;
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
            let opened = commit(&a, tree(), &[], &open()).await;
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
            let opened = commit(&a, tree(), &[], &open()).await;
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
            let opened = commit(&a, tree(), &[], &open()).await;
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
        let elsewhere = ELSEWHERE.parse::<TreeId>().unwrap();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open()).await;
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
            let by_a = commit(&a, tree(), &[], &open()).await;
            let by_b = commit(&b, tree(), &[], &open()).await;
            let reopened = commit(&a, tree(), &[&by_a], &open()).await;
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
                    "every other Open, root or not, is a second Open"
                );
            }
        });
    }

    #[test]
    fn an_undecodable_blob_is_refused_and_an_unopened_tree_has_no_view()
    {
        let a = owner();
        let elsewhere = ELSEWHERE.parse::<TreeId>().unwrap();
        runtime().block_on(async {
            let opened = commit(&a, tree(), &[], &open()).await;
            let garbage = Blob::new(b"not a receipt".to_vec());
            let garbage = seal(&a, tree(), &[&opened], garbage).await;
            let view = fold(tree(), vec![opened, garbage.clone()]).unwrap();
            assert_eq!(
                view.refused(),
                [(
                    id(&garbage),
                    Refusal::Undecodable(DecodeError::Version { found: b'n' })
                )],
                "a blob that is not a receipt is refused with the decoder's reason"
            );

            let foreign = Receipt::open(elsewhere).unwrap();
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
            let opened = commit(&a, tree(), &[], &open()).await;
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
        let view = View {
            owner: author,
            members: BTreeSet::from([member]),
            notes: vec![
                (author, String::from("plain text")),
                (member, String::from("two\nlines, a \\ and a bell\u{7}")),
            ],
            refused: vec![(refused, Refusal::NoAuthority)],
        };
        assert_eq!(
            view.to_string(),
            format!(
                "owner {author}\nmember {member}\nnote {author} plain text\nnote {member} \
                 two\\nlines, a \\\\ and a bell\\u{{7}}\nrefused {refused} no authority\n"
            ),
            "one line per fact, a note's control characters escaped"
        );
    }
}
