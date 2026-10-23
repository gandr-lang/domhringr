//! Compare an attested project store with independent folds at its named
//! frontiers.
//!
//! An owner's or granted member's `Indexed` receipt attests a store root.
//! Its parents name the project frontier used by derivation; each task
//! names its own frontier in its heads. A proof establishes what the store
//! holds, not that it agrees with the fold. Checking rebuilds each held task
//! at its own heads and the bindings at the attestation's parents, and
//! compares contents, not roots: a refreshed store's root depends on its
//! history ([`crate::derive`]). Later receipts don't make a true historical
//! claim disagree.

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use core::fmt;

use domhringr_record_tree::IndexAttestation;
use domhringr_record_tree::Peer;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::ViewAtError;
use domhringr_record_tree::ViewError;
use gandr_storage_schema::AttributeValue;
use gandr_storage_schema::SchemaError;
use gandr_storage_values::ValueError;
use gandr_storage_values::encode_flat;

use crate::MoveKey;
use crate::derive;
use crate::dialogue;
use crate::dialogue::Dialogue;
use crate::dialogue::DialogueError;
use crate::keyed::Keyed;
use crate::keyed::Standing;
use crate::project;
use crate::project::Refused;
use crate::project::TaskName;
use crate::prove;
use crate::prove::Local;
use crate::prove::Move;
use crate::prove::ProveError;
use crate::provenance;
use crate::provenance::Field as Role;
use crate::provenance::Naming;

/// The independently checked field which disagrees with a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field
{
    /// A task is missing or extra.
    Binding,
    /// The standing differs from the fold at its heads.
    Current,
    /// The number of admitted dispatches differs.
    Attempts,
    /// The admitted original moves differ.
    Dialogue,
    /// Refused commits or their explanations differ from the fold.
    Refusals,
    /// The task's namings of evidence and revisions differ.
    Provenance,
}

impl fmt::Display for Field
{
    /// Write the stable finding field name.
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
            Self::Binding => "binding",
            Self::Current => "current",
            Self::Attempts => "attempts",
            Self::Dialogue => "dialogue",
            Self::Refusals => "refusals",
            Self::Provenance => "provenance",
        })
    }
}

/// A disagreement or a task whose claimed frontier cannot be checked locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding
{
    /// Independent derivation refutes this task field.
    Disagrees
    {
        /// The project's bound task name.
        task: TaskName,
        /// The field refuted by the fold.
        field: Field,
    },
    /// The task's claimed frontier is not held locally, or the claim is unheld.
    Unchecked(TaskName),
    /// The store holds a subject no naming refers to.
    Project,
}

impl fmt::Display for Finding
{
    /// Write one finding in the peer command's stable form.
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
            Self::Disagrees { ref task, field } => write!(f, "disagrees {task} {field}"),
            Self::Unchecked(ref task) => write!(f, "unchecked {task}"),
            Self::Project => f.write_str("disagrees project subjects"),
        }
    }
}

/// Independent findings; an empty report means every claimed field agrees.
#[derive(Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Report(pub Vec<Finding>);

impl fmt::Display for Report
{
    /// Write agreement or each finding on its own line.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        if self.0.is_empty() {
            return writeln!(f, "agrees");
        }
        for finding in &self.0 {
            writeln!(f, "{finding}")?;
        }
        Ok(())
    }
}

/// The checker lacks a required project input or cannot read the store.
#[derive(Debug, thiserror::Error)]
pub enum CheckError
{
    /// The supplied store is not the attested root.
    #[error("supplied store is not the attested root")]
    Identity,
    /// A required historical project view cannot be read.
    #[error(transparent)]
    View(#[from] ViewAtError),
    /// A move's canonical value can't be encoded.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// Rebuilding admitted moves failed.
    #[error(transparent)]
    Dialogue(#[from] DialogueError),
    /// The claimed store can't be read.
    #[error(transparent)]
    Read(#[from] ProveError),
    /// The keyed schema didn't resolve.
    #[error(transparent)]
    Schema(#[from] SchemaError),
}

/// The moves a dialogue holds, as a reader decodes them.
///
/// # Specification
/// - ensures: one play per attempt, each move as [`prove::read_move`] reads its
///   stored value.
/// - fails: a move value that doesn't encode or decode.
/// - panics: none.
/// - executable: none — the decoder is the oracle; the forged-entry witness
///   compares claimed and derived plays.
///
/// # Errors
/// - [`CheckError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — an authentic store's plays equal the fold's.
/// - witness: `check::tests::a_forged_entry_is_found_by_re_derivation`
fn plays(dialogue: &Dialogue) -> Result<Vec<Vec<(MoveKey, Move)>>, CheckError>
{
    let mut plays: Vec<Vec<(MoveKey, Move)>> = Vec::new();
    for &(key, ref value) in &dialogue.moves {
        let movement = prove::read_move(&AttributeValue::from(encode_flat(value)?.as_ref()))?;
        match plays.last_mut() {
            Some(play)
                if play
                    .first()
                    .is_some_and(|first| first.0.coordinates().0 == key.coordinates().0) =>
            {
                play.push((key, movement));
            },
            _ => plays.push(vec![(key, movement)]),
        }
    }
    Ok(plays)
}

/// The namings a dialogue's moves make, as the store sorts them.
///
/// # Specification
/// trivial.
fn namings(plays: &[Vec<(MoveKey, Move)>]) -> Vec<(AttributeValue, MoveKey, Role)>
{
    let mut namings: Vec<_> = plays
        .iter()
        .flatten()
        .filter_map(|&(key, ref movement)| {
            match provenance::naming(movement.author, &movement.receipt) {
                Naming::Named(subject, attribution) => {
                    Some((subject.value(), key, attribution.field))
                },
                Naming::None => None,
            }
        })
        .collect();
    namings.sort_unstable();
    namings
}

/// Check the claim at its project parents and each task's own heads.
///
/// # Specification
/// - ensures: later receipts can't stale a true claim; each held task's
///   standing, refusals, attempts, moves and namings are independently
///   re-derived; a missing local frontier is unchecked, never agreement.
/// - fails: a store of another root, a missing project past or a store that
///   doesn't read.
/// - panics: none.
/// - executable: none — historical folds require storage I/O; the checker is
///   its own specification, with forged and older authentic claims as
///   independent oracles.
///
/// # Errors
/// - [`CheckError`]: a required input cannot be interpreted.
///
/// # Adequacy
/// - hypothesis: L2 — a false standing is refuted while an older true claim
///   agrees.
/// - witness: `check::tests::a_forged_entry_is_found_by_re_derivation`
#[inline]
pub async fn check(
    peer: &Peer,
    project: TreeId,
    attestation: &IndexAttestation,
    claimed: &gandr_storage_schema::Store,
) -> Result<Report, CheckError>
{
    if claimed.root() != derive::root(attestation.index) {
        return Err(CheckError::Identity);
    }
    let keyed = Keyed::shared()?;
    let view = peer.view_at(project, &attestation.parents).await?;
    let mut bindings: BTreeMap<_, _> = project::bindings(&view).collect();
    let names = project::names(claimed, keyed)?;
    let mut local = Local(claimed);
    let contents = prove::contents(&mut local, keyed, names.into_keys()).await?;
    let mut report = Report::default();
    let mut owners = BTreeSet::new();
    let mut subjects = BTreeSet::new();
    let owned: BTreeMap<TaskName, bool> = bindings
        .iter()
        .map(|(name, &tree)| (name.clone(), owners.insert(tree)))
        .collect();
    for (name, claim) in contents.0 {
        subjects.extend(claim.namings.iter().map(|naming| naming.0.clone()));
        let Some(tree) = bindings.remove(&name)
        else {
            report.0.push(Finding::Disagrees {
                task: name,
                field: Field::Binding,
            });
            continue;
        };
        if claim.standing == Standing::Unheld {
            report.0.push(Finding::Unchecked(name));
            continue;
        }
        let view = match peer.view_at(tree, &claim.heads).await {
            Ok(view) => view,
            Err(ViewAtError::Missing(_) | ViewAtError::View(ViewError::Unopened(_))) => {
                report.0.push(Finding::Unchecked(name));
                continue;
            },
            Err(failure) => return Err(failure.into()),
        };
        let dialogue = dialogue::derive(view.task())?;
        let derived = plays(&dialogue)?;
        let expected = if owned.get(&name).copied().unwrap_or_default() {
            namings(&derived)
        }
        else {
            Vec::new()
        };
        let refusals_differ = claim.refused.len() != view.refused().len()
            || claim
                .refused
                .iter()
                .zip(view.refused())
                .any(|(held, viewed)| *held != Refused::from(viewed));
        let attempts = usize::try_from(dialogue.attempts.0).ok();
        let fields = [
            (
                Field::Current,
                claim.standing != Standing::of(view.task().current()),
            ),
            (Field::Attempts, Some(claim.plays.len()) != attempts),
            (Field::Dialogue, claim.plays != derived),
            (Field::Refusals, refusals_differ),
            (Field::Provenance, claim.namings != expected),
        ];
        for (field, differs) in fields {
            if differs {
                report.0.push(Finding::Disagrees {
                    task: name.clone(),
                    field,
                });
            }
        }
    }
    for (task, _tree) in bindings {
        report.0.push(Finding::Disagrees {
            task,
            field: Field::Binding,
        });
    }
    let held = claimed
        .live_count(keyed.subject)
        .map_err(|refusal| ProveError::Store(gandr_storage_schema::StoreError::Refused(refusal)))?;
    if usize::try_from(u64::from(held)).ok() != Some(subjects.len()) {
        report.0.push(Finding::Project);
    }
    Ok(report)
}
