//! Task bindings, their standings, and the parts a task is in the project
//! store.
//!
//! A project's direct `tasks/<name>` tree bindings are its tasks. A held
//! task is a `Task` part with its name, the kind of its standing and the
//! heads it was derived at. Its refused commits are `Refusal` parts, each
//! with its displayed reason, in fold order. Its attempts are `Attempt`
//! parts and its moves `Move` parts ([`crate::dialogue`]). A task without a
//! held Open is a `Task` part standing `unheld`, with no heads, attempts or
//! refusals.
//!
//! Standings are exactly the states reachable in the receipt fold:
//! undispatched, dispatched, stalled, reported, verified, graded, decided
//! and landed. A retirement before a report is a refused play, never a
//! standing. The whole standing isn't stored; it is recomputed from the
//! last attempt ([`crate::prove::current`]).

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use core::fmt;
use core::str::FromStr;

use anodized::spec;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::Authority;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Current;
use domhringr_record_tree::Heads;
use domhringr_record_tree::Path;
use domhringr_record_tree::Target;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;
use gandr_storage_schema::AttributeValue;
use gandr_storage_schema::PartKey;
use gandr_storage_schema::Refusal;
use gandr_storage_schema::Row;
use gandr_storage_schema::Store;
use gandr_storage_values::ValueError;
use gandr_storage_values::encode_flat;

use crate::AttemptNumber;
use crate::dialogue::Dialogue;
use crate::keyed;
use crate::keyed::Keyed;
use crate::keyed::Number;
use crate::keyed::Standing;
use crate::keyed::Text;
use crate::provenance;
use crate::provenance::Naming;

/// One path segment beneath a project's `tasks/` binding family.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TaskName(Path);

/// A task name is empty, reserved, or contains more than one path segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a task name is one nonempty path segment")]
pub struct NameError;

impl FromStr for TaskName
{
    type Err = NameError;

    /// Validate a task name using the record plane's path language.
    ///
    /// # Specification
    /// - ensures: the name is one nonempty, unreserved segment, unchanged.
    /// - fails: an invalid path or a slash is refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`NameError`]: invalid name.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the binding family selects names, not nested paths.
    /// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |name| name.to_string() == text))]
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.contains('/') {
            return Err(NameError);
        }
        text.parse::<Path>().map(Self).map_err(|_path| NameError)
    }
}

impl AsRef<str> for TaskName
{
    /// Borrow the exact task name.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &str
    {
        self.0.as_ref()
    }
}

impl fmt::Display for TaskName
{
    /// Write the task name without its project prefix.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(self.as_ref())
    }
}

/// A refused commit and the fold's exact explanation at the derived frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused
{
    /// The commit rejected by the fold.
    pub commit: CommitId,
    /// The display observation retained for an index-only listing.
    reason: String,
}

impl Refused
{
    /// A refusal as a store holds it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(
        commit: CommitId,
        reason: String,
    ) -> Self
    {
        Self { commit, reason }
    }
}

impl From<&(CommitId, domhringr_record_tree::Refusal)> for Refused
{
    /// Retain a refusal without reinterpreting its explanation.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(value: &(CommitId, domhringr_record_tree::Refusal)) -> Self
    {
        Self {
            commit: value.0,
            reason: value.1.to_string(),
        }
    }
}

impl fmt::Display for Refused
{
    /// Write the fold's refusal explanation unchanged.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(&self.reason)
    }
}

/// A task's fold at named heads, or an explicit unheld binding, as the
/// deriver holds it.
///
/// The tree is the project's binding, not a stored field.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "entries normally hold a standing; boxing would allocate per task to compact only unheld bindings"
)]
pub enum TaskEntry
{
    /// The deriving peer held and folded the task.
    Held
    {
        /// The bound task tree.
        tree: TreeId,
        /// The frontier this entry is derived at.
        heads: Heads,
        /// The complete typed standing at that frontier.
        current: Current,
        /// The number of admitted dispatches.
        attempts: AttemptNumber,
        /// Refused commits in the fold's order, including their explanations.
        refused: Vec<Refused>,
    },
    /// The project binds the tree, but the deriver does not hold its Open.
    Unheld
    {
        /// The bound task tree.
        tree: TreeId,
    },
}

impl TaskEntry
{
    /// The tree this task binding names.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn tree(&self) -> TreeId
    {
        match *self {
            Self::Held { tree, .. } | Self::Unheld { tree } => tree,
        }
    }

    /// The kind of standing `task_standing` holds for this entry.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn standing(&self) -> Standing
    {
        match *self {
            Self::Held { ref current, .. } => Standing::of(current),
            Self::Unheld { .. } => Standing::Unheld,
        }
    }
}

/// Select the same one-segment task bindings the operator lists.
///
/// # Specification
/// - ensures: only `tasks/<name>` bound to bare keyed tree anchors are
///   selected, in name order; deeper paths, other families and other targets
///   are absent.
/// - panics: none.
/// - executable: none — the returned iterator is lazy and not cloneable through
///   its declared type; mixed bindings distinguish the selected family.
///
/// # Adequacy
/// - hypothesis: L3 — mixed bindings separate names, nested paths and targets.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[inline]
pub fn bindings(view: &View) -> impl Iterator<Item = (TaskName, TreeId)> + '_
{
    view.bindings()
        .iter()
        .filter_map(|(path, &(_author, ref target))| {
            let name = path.as_ref().strip_prefix("tasks/")?;
            let &Target::Anchor(Anchor::Tree(Authority::Key(tree))) = target
            else {
                return None;
            };
            let name = name.parse().ok()?;
            Some((name, tree))
        })
}

/// Why a task's parts can't be written to or removed from the store.
#[derive(Debug, thiserror::Error)]
pub enum ProjectError
{
    /// A move's value could not be encoded.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// The store refused an edit.
    #[error(transparent)]
    Refused(#[from] Refusal),
}

/// The live subjects of a store, by their `subject_digest`.
#[derive(Debug, Default)]
#[repr(transparent)]
pub(crate) struct Subjects(BTreeMap<AttributeValue, PartKey>);

impl Subjects
{
    /// Every live subject of a store.
    ///
    /// # Specification
    /// - ensures: one entry per live `Subject` part.
    /// - fails: the store refuses a read.
    /// - panics: none.
    /// - executable: none — the map mirrors the table; the refresh witness
    ///   compares a refreshed store with one derived whole.
    ///
    /// # Errors
    /// - [`Refusal`]: a read is refused.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — a refreshed store reuses a subject named before.
    /// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
    pub(crate) fn of(
        store: &Store,
        keyed: &Keyed,
    ) -> Result<Self, Refusal>
    {
        let mut subjects = BTreeMap::new();
        for subject in store.parts(keyed.subject)? {
            let _previous =
                subjects.insert(store.value(keyed.subject_digest, subject)?.clone(), subject);
        }
        Ok(Self(subjects))
    }
}

/// Every live task of a held store, by name.
///
/// # Specification
/// - ensures: one entry per live task.
/// - fails: a refused read, a name that isn't a task name, or two tasks of one
///   name.
/// - panics: none.
/// - executable: none — the map mirrors the table; the check witness reads a
///   forged store through it.
///
/// # Errors
/// - [`crate::prove::ProveError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2/L3 — a refreshed store lists the bound names; a forged
///   extra task is found.
/// - witness: `check::tests::a_forged_entry_is_found_by_re_derivation`
#[inline]
pub fn names(
    store: &Store,
    keyed: &Keyed,
) -> Result<BTreeMap<TaskName, PartKey>, crate::prove::ProveError>
{
    let mut names = BTreeMap::new();
    for task in store
        .parts(keyed.task)
        .map_err(gandr_storage_schema::StoreError::Refused)?
    {
        let name = store
            .value(keyed.task_name, task)
            .map_err(gandr_storage_schema::StoreError::Refused)?;
        let name = keyed::read_text(name)?
            .0
            .parse::<TaskName>()
            .map_err(|_name| keyed::ValueFault::Text)?;
        if let Some(_previous) = names.insert(name.clone(), task) {
            return Err(crate::prove::ProveError::Duplicate(name));
        }
    }
    Ok(names)
}

/// Whether a task carries its tree's namings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Carrier
{
    /// The first name of its tree in name order: it names its moves'
    /// subjects.
    Owner,
    /// A later name of a tree whose namings the owner carries.
    Alias,
}

/// Add a task's parts: the task, its refusals, attempts and moves, and,
/// when it carries its tree's provenance, its namings.
///
/// # Specification
/// - requires: `dialogue` is the task's own, empty when `entry` is unheld, and
///   no live task carries `name`.
/// - ensures: on success one task named `name`, standing as `entry`, its
///   refusals in order, attempts one to n and every move at its place; each
///   naming move named once by an owner, none by an alias.
/// - fails: the store refuses an edit; parts added before the refusal stay.
/// - panics: none.
/// - executable: none — the parts are read back through the readers, which are
///   the witnesses' oracle.
///
/// # Errors
/// - [`ProjectError`]: encoding or an edit is refused.
///
/// # Adequacy
/// - hypothesis: L2 — every reachable standing reads back as the fold holds it.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
pub(crate) fn add(
    store: &mut Store,
    keyed: &Keyed,
    name: &TaskName,
    entry: &TaskEntry,
    dialogue: &Dialogue,
    carrier: Carrier,
    subjects: &mut Subjects,
) -> Result<PartKey, ProjectError>
{
    let heads = match *entry {
        TaskEntry::Held { ref heads, .. } => keyed::heads(heads),
        TaskEntry::Unheld { .. } => keyed::heads(&Heads::from_iter([])),
    };
    let task = store.add_part(
        keyed.task,
        &Row::new()
            .value(keyed.task_name, keyed::text(Text(name.as_ref())))
            .value(keyed.task_standing, entry.standing().value())
            .value(keyed.task_heads, heads),
    )?;
    if let TaskEntry::Held { ref refused, .. } = *entry {
        for refusal in refused {
            let _refusal = store.add_part(
                keyed.refusal,
                &Row::new()
                    .arrow(keyed.refusal_task, task)
                    .value(keyed.refusal_commit, keyed::commit(refusal.commit))
                    .value(keyed.refusal_reason, keyed::text(Text(&refusal.reason))),
            )?;
        }
    }
    let mut attempt = None;
    for &(key, ref value) in &dialogue.moves {
        let (number, seq) = key.coordinates();
        let part = match attempt {
            Some((held, part)) if held == number => part,
            _ => {
                let part = store.add_part(
                    keyed.attempt,
                    &Row::new()
                        .arrow(keyed.attempt_task, task)
                        .value(keyed.attempt_number, keyed::number(Number::from(number))),
                )?;
                attempt = Some((number, part));
                part
            },
        };
        let movement = store.add_part(
            keyed.movement,
            &Row::new()
                .arrow(keyed.move_attempt, part)
                .value(keyed.move_seq, keyed::number(Number::from(seq)))
                .value(
                    keyed.move_receipt,
                    AttributeValue::from(encode_flat(value)?.as_ref()),
                ),
        )?;
        if carrier == Carrier::Owner {
            name_move(store, keyed, task, movement, value, subjects)?;
        }
    }
    Ok(task)
}

/// Add the naming a move makes, if it names a subject.
///
/// # Specification
/// - ensures: on success one naming of the move's subject in its field, the
///   subject minted when no live one carries its digest; nothing for a move
///   naming nothing.
/// - fails: the store refuses an edit, or the move's receipt is malformed.
/// - panics: none.
/// - executable: none — namings are read back through the provenance reader,
///   which the witness compares with the fold.
///
/// # Errors
/// - [`ProjectError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — every naming of the fixture reads back as the fold's
///   evidence and landings.
/// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
pub(crate) fn name_move(
    store: &mut Store,
    keyed: &Keyed,
    task: PartKey,
    movement: PartKey,
    value: &crate::dialogue::MoveValue<'_>,
    subjects: &mut Subjects,
) -> Result<(), ProjectError>
{
    let Naming::Named(subject, attribution) = provenance::naming(value.author, &value.receipt()?)
    else {
        return Ok(());
    };
    let digest = subject.value();
    let subject = if let Some(&subject) = subjects.0.get(&digest) {
        subject
    }
    else {
        let subject = store.add_part(
            keyed.subject,
            &Row::new().value(keyed.subject_digest, digest.clone()),
        )?;
        let _previous = subjects.0.insert(digest, subject);
        subject
    };
    let _naming = store.add_part(
        keyed.naming,
        &Row::new()
            .arrow(keyed.naming_move, movement)
            .arrow(keyed.naming_subject, subject)
            .arrow(keyed.naming_task, task)
            .value(keyed.naming_role, attribution.field.value()),
    )?;
    Ok(())
}

/// Remove a task and everything referring to it.
///
/// # Specification
/// - requires: `task` is a live task.
/// - ensures: on success the task, its namings, moves, attempts and refusals
///   are dead; subjects stay, for [`prune`].
/// - fails: the store refuses a delete.
/// - panics: none.
/// - executable: none — the refresh witness compares the edited store with one
///   derived whole.
///
/// # Errors
/// - [`Refusal`]: a delete or read is refused.
///
/// # Adequacy
/// - hypothesis: L2 — a refreshed store reads as one derived whole after every
///   kind of change.
/// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
pub(crate) fn remove(
    store: &mut Store,
    keyed: &Keyed,
    task: PartKey,
) -> Result<(), Refusal>
{
    unname(store, keyed, task)?;
    for attempt in store.preimage(keyed.attempt_task, task)?.to_vec() {
        for movement in store.preimage(keyed.move_attempt, attempt)?.to_vec() {
            store.delete_part(keyed.movement, movement)?;
        }
        store.delete_part(keyed.attempt, attempt)?;
    }
    for refusal in store.preimage(keyed.refusal_task, task)?.to_vec() {
        store.delete_part(keyed.refusal, refusal)?;
    }
    store.delete_part(keyed.task, task)
}

/// Remove a task's namings, leaving its moves.
///
/// # Specification
/// - ensures: on success no naming refers to the task.
/// - fails: the store refuses a delete.
/// - panics: none.
/// - executable: none — the alias witness reads provenance back.
///
/// # Errors
/// - [`Refusal`]: a delete or read is refused.
///
/// # Adequacy
/// - hypothesis: L2 — a refreshed store reads as one derived whole.
/// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
pub(crate) fn unname(
    store: &mut Store,
    keyed: &Keyed,
    task: PartKey,
) -> Result<(), Refusal>
{
    for naming in store.preimage(keyed.naming_task, task)?.to_vec() {
        store.delete_part(keyed.naming, naming)?;
    }
    Ok(())
}

/// Name every naming move of a task that carries its tree's provenance.
///
/// # Specification
/// - requires: the task has no namings.
/// - ensures: on success each naming move of the task named once.
/// - fails: the store refuses an edit, or a move's value is malformed.
/// - panics: none.
/// - executable: none — the alias witness reads provenance back.
///
/// # Errors
/// - [`ProjectError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — a refreshed store reads as one derived whole.
/// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
pub(crate) fn rename(
    store: &mut Store,
    keyed: &Keyed,
    task: PartKey,
    subjects: &mut Subjects,
) -> Result<(), ProjectError>
{
    let mut moves = Vec::new();
    for attempt in store.preimage(keyed.attempt_task, task)?.to_vec() {
        for movement in store.preimage(keyed.move_attempt, attempt)? {
            let value = store.value(keyed.move_receipt, *movement)?;
            let value = gandr_storage_values::decode_flat::<crate::dialogue::MoveValue<'_>>(
                gandr_storage_values::TokenBody::from(value.as_ref()),
            )?;
            moves.push((*movement, crate::dialogue::MoveValue {
                author: value.author,
                blob: alloc::borrow::Cow::Owned(value.blob.into_owned()),
            }));
        }
    }
    for (movement, value) in moves {
        name_move(store, keyed, task, movement, &value, subjects)?;
    }
    Ok(())
}

/// Delete every subject no naming refers to.
///
/// # Specification
/// - ensures: on success every live subject has a naming.
/// - fails: the store refuses a delete.
/// - panics: none.
/// - executable: none — the refresh witness compares the edited store with one
///   derived whole, which mints no unnamed subject.
///
/// # Errors
/// - [`Refusal`]: a delete or read is refused.
///
/// # Adequacy
/// - hypothesis: L2 — a refreshed store reads as one derived whole.
/// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
pub(crate) fn prune(
    store: &mut Store,
    keyed: &Keyed,
) -> Result<(), Refusal>
{
    let subjects: Vec<_> = store.parts(keyed.subject)?.collect();
    for subject in subjects {
        if store.preimage(keyed.naming_subject, subject)?.is_empty() {
            store.delete_part(keyed.subject, subject)?;
        }
    }
    Ok(())
}
