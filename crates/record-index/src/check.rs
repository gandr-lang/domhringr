//! Compare an attested project with independent folds at its named frontiers.

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use core::fmt;

use domhringr_record_tree::IndexAttestation;
use domhringr_record_tree::Peer;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::ViewAtError;
use domhringr_record_tree::ViewError;
use gandr_storage_records::RecordTreeError;
use gandr_storage_values::TokenBody;
use gandr_storage_values::ValueError;
use gandr_storage_values::decode_flat;

use crate::Index;
use crate::IndexKind;
use crate::WireError;
use crate::dialogue;
use crate::dialogue::DialogueError;
use crate::project;
use crate::project::ProjectError;
use crate::project::Refused;
use crate::project::TaskEntry;
use crate::project::TaskName;
use crate::provenance;
use crate::provenance::ProvenanceError;

/// The independently checked field which disagrees with a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field
{
    /// A task entry is missing, extra, or names a different bound tree.
    Binding,
    /// The typed standing differs from the fold at its heads.
    Current,
    /// The number of admitted dispatches differs.
    Attempts,
    /// The admitted original moves derive another dialogue identity.
    Dialogue,
    /// Refused commits or their explanations differ from the fold.
    Refusals,
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
            | Self::Binding => "binding",
            | Self::Current => "current",
            | Self::Attempts => "attempts",
            | Self::Dialogue => "dialogue",
            | Self::Refusals => "refusals",
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
    /// Project framing or its reserved family differs from the supported
    /// layout.
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
            | Self::Disagrees { ref task, field } => write!(f, "disagrees {task} {field}"),
            | Self::Unchecked(ref task) => write!(f, "unchecked {task}"),
            | Self::Project => f.write_str("disagrees project manifest"),
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

/// The checker lacks a required project input or cannot interpret its records.
#[derive(Debug, thiserror::Error)]
pub enum CheckError
{
    /// The supplied tree does not carry the attested project identity.
    #[error("supplied index is not the attested project")]
    Identity,
    /// A required historical project view cannot be read.
    #[error(transparent)]
    View(#[from] ViewAtError),
    /// A task entry's canonical value is malformed.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// Rebuilding admitted moves failed.
    #[error(transparent)]
    Dialogue(#[from] DialogueError),
    /// Rebuilding project records failed.
    #[error(transparent)]
    Project(#[from] ProjectError),
    /// Manifest encoding failed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A dialogue cannot supply its provenance records.
    #[error(transparent)]
    Provenance(#[from] ProvenanceError),
    /// Rebuilding provenance records failed.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
}

/// Check the claim at its project parents and each entry's own task heads.
///
/// # Specification
/// - ensures: later receipts cannot stale a true claim; each held task's
///   standing, refusals, attempt count, dialogue and provenance are
///   independently re-derived; a missing local frontier is unchecked, never
///   agreement.
/// - fails: wrong project identity, missing project past or malformed values.
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
    index: &Index,
) -> Result<Report, CheckError>
{
    let digest = index.manifest.identity()?;
    if index.manifest.kind() != IndexKind::Project || digest != attestation.index {
        return Err(CheckError::Identity);
    }
    let view = peer.view_at(project, &attestation.parents).await?;
    let mut bindings: BTreeMap<_, _> = project::bindings(&view).collect();
    let mut report = Report::default();
    let mut rebuilt = BTreeMap::new();
    let mut provenance = provenance::Records::default();
    for record in index.tree.records() {
        let key = record.key();
        if key.as_ref() == [0, u8::from(IndexKind::Provenance)] {
            continue;
        }
        let Some((&1, name)) = key.as_ref().split_first()
        else {
            report.0.push(Finding::Project);
            continue;
        };
        let Some(name) = core::str::from_utf8(name)
            .ok()
            .and_then(|name| name.parse::<TaskName>().ok())
        else {
            report.0.push(Finding::Project);
            continue;
        };
        let claimed = decode_flat::<TaskEntry>(TokenBody::from(record.value().as_ref()))?;
        if bindings.remove(&name) != Some(claimed.tree()) {
            report.0.push(Finding::Disagrees {
                task: name,
                field: Field::Binding,
            });
            continue;
        }
        let TaskEntry::Held {
            ref tree,
            ref heads,
            ref current,
            ref attempts,
            ref dialogue,
            ref refused,
        } = claimed
        else {
            report.0.push(Finding::Unchecked(name));
            continue;
        };
        let view = match peer.view_at(*tree, heads).await {
            | Ok(view) => view,
            | Err(ViewAtError::Missing(_) | ViewAtError::View(ViewError::Unopened(_))) => {
                report.0.push(Finding::Unchecked(name));
                continue;
            },
            | Err(failure) => return Err(failure.into()),
        };
        let derived = dialogue::derive(view.task())?;
        let identity = derived.index.manifest.identity()?;
        let refusals: Vec<_> = view.refused().iter().map(Refused::from).collect();
        provenance.extend(*tree, &derived.index)?;
        let fields = [
            (Field::Current, current != view.task().current()),
            (Field::Attempts, *attempts != derived.attempts),
            (Field::Dialogue, *dialogue != identity),
            (Field::Refusals, *refused != refusals),
        ];
        for (field, differs) in fields {
            if differs {
                report.0.push(Finding::Disagrees {
                    task: name.clone(),
                    field,
                });
            }
        }
        let entry = TaskEntry::Held {
            tree: *tree,
            heads: heads.clone(),
            current: view.task().current().clone(),
            attempts: derived.attempts,
            dialogue: identity,
            refused: refusals,
        };
        let _previous = rebuilt.insert(name, entry);
    }
    for (task, _tree) in bindings {
        report.0.push(Finding::Disagrees {
            task,
            field: Field::Binding,
        });
    }
    if report.0.is_empty() {
        let provenance = provenance.build()?;
        let digest = provenance.manifest.identity()?;
        let nested = BTreeMap::from([(IndexKind::Provenance, digest)]);
        let rebuilt = project::build(&rebuilt, &nested)?;
        if rebuilt.manifest != index.manifest {
            report.0.push(Finding::Project);
        }
    }
    Ok(report)
}
