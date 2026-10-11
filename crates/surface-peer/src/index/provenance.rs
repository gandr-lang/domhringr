//! Prove subject naming through the project, provenance and dialogue roots.

use alloc::collections::BTreeMap;
use core::fmt::Write as _;

use anodized::spec;
use domhringr_record_index::IndexKind;
use domhringr_record_index::project;
use domhringr_record_index::project::Nested;
use domhringr_record_index::project::TaskEntry;
use domhringr_record_index::prove;
use domhringr_record_index::prove::Query;
use domhringr_record_index::prove::Verified;
use domhringr_record_index::provenance::Attribution;
use domhringr_record_index::provenance::Naming;
use domhringr_record_index::provenance::Reference;
use domhringr_record_index::provenance::Subject;
use domhringr_record_index::provenance::naming;
use domhringr_record_index::stream::Request;
use domhringr_record_tree::Aim;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::At;
use domhringr_record_tree::IndexAttestation;
use domhringr_record_tree::Revision;
use gandr_storage_values::ManifestDigest;
use gandr_storage_values::TokenBody;
use gandr_storage_values::decode_flat;

use super::Action;
use super::Command;
use super::IndexError;
use super::ParseError;
use super::Reader;
use super::render;
use crate::Operand;
use crate::UsageError;
use crate::Verb;

/// Read a subject and the same attester/routing options as other proof verbs.
///
/// # Specification
/// - ensures: forty hex digits select a SHA-1 revision; sixty-four select both
///   evidence and SHA-256 revision families, whose text languages overlap.
/// - fails: malformed subjects, endpoints, keys and surplus operands fail.
/// - panics: none.
/// - executable: none — the consuming operand parser is its own specification;
///   malformed subjects and project-only proof queries provide the oracle.
///
/// # Errors
/// - [`UsageError`]: a lexical or subject-language refusal.
///
/// # Adequacy
/// - hypothesis: L1/L3 — a project-only process proves a transcript and refuses
///   malformed subject operands without importing task trees.
/// - witness: `index::tests::a_transcript_resolves_to_its_verdict_by_proof`
pub fn parse_provenance(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let mut operands = Vec::new();
    let mut by = Aim::Owner;
    let mut at = At::Book;
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Value(value) => operands.push(value),
            | lexopt::Arg::Long("by") => {
                let value = arguments.value()?;
                by = Aim::Peer(crate::read_id(&value, Operand::Peer)?);
            },
            | lexopt::Arg::Long("at") => {
                let value = arguments.value()?;
                at = At::Given(crate::read_id(&value, Operand::At)?);
            },
            | argument => return Err(argument.unexpected().into()),
        }
    }
    let [ref project, ref subject] = *operands.as_slice()
    else {
        return Err(UsageError::Operands(Verb::Provenance));
    };
    let project = crate::read_tree(project)?;
    let text = subject.to_str().ok_or(ParseError::Subject)?;
    let revision = text
        .parse::<Revision>()
        .map_err(|_revision| ParseError::Subject)?;
    let subjects = match revision {
        | Revision::Sha1(_) => vec![Subject::Revision(revision)],
        | Revision::Sha256(bytes) => vec![
            Subject::Evidence(ManifestDigest::from(bytes)),
            Subject::Revision(revision),
        ],
    };
    Ok(Command {
        project,
        action: Action::Provenance { subjects, by, at },
    })
}

/// Authenticate every edge before publishing any part of the answer.
///
/// # Specification
/// - requires: a Tokio runtime with time and I/O is active.
/// - ensures: subject ranges are proved under the project's nested root; each
///   task entry names the proved dialogue; its original move agrees with the
///   subject, field and holder. Task aliases do not duplicate the answer.
/// - fails: missing or malformed links and disagreeing attributions fail; no
///   task receipt tree is fetched to supply a missing link.
/// - panics: none.
///
/// # Errors
/// - [`IndexError`]: project inputs, proof, move, transport or formatting
///   failure.
///
/// # Adequacy
/// - hypothesis: L1 — a separate process holding only the project verifies a
///   transcript through every root to the verdict's original receipt.
/// - witness: `index::tests::a_transcript_resolves_to_its_verdict_by_proof`
#[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
pub(super) async fn answer(
    reader: Reader,
    attestation: &IndexAttestation,
    subjects: Vec<Subject>,
) -> Result<(Reader, String), IndexError>
{
    let view = reader
        .peer()
        .view_at(reader.project, &attestation.parents)
        .await?;
    let names: BTreeMap<_, _> = project::bindings(&view)
        .map(|(name, tree)| (tree, name))
        .collect();
    let digest = attestation.index;
    let request = Request {
        digest,
        query: Query::Key([0, u8::from(IndexKind::Provenance)].as_slice().into()),
    };
    let (mut reader, proof) = reader.ask(&request, IndexKind::Project).await?;
    let Verified::Present(value) = proof.verify(digest, IndexKind::Project, &request.query)?
    else {
        return Err(IndexError::Shape);
    };
    let Nested(provenance) = decode_flat(TokenBody::from(value.as_ref()))?;
    let mut output = format!("proved {digest} {}\n", reader.author);
    for subject in subjects {
        let range = subject.range()?;
        let request = Request {
            digest: provenance,
            query: Query::Range(range),
        };
        let (next, proof) = reader.ask(&request, IndexKind::Provenance).await?;
        reader = next;
        let Verified::Range(records) =
            proof.verify(provenance, IndexKind::Provenance, &request.query)?
        else {
            return Err(IndexError::Shape);
        };
        writeln!(output, "proved {provenance} {}", reader.author)?;
        for record in &records {
            let reference = Reference::try_from(record.key().as_ref())?;
            if reference.subject != subject {
                return Err(IndexError::Shape);
            }
            let attribution = decode_flat::<Attribution>(TokenBody::from(record.value().as_ref()))?;
            let name = names.get(&reference.tree).ok_or(IndexError::Shape)?;
            let request = Request {
                digest,
                query: Query::Key(name.key()),
            };
            let (next, proof) = reader.ask(&request, IndexKind::Project).await?;
            reader = next;
            let Verified::Present(value) =
                proof.verify(digest, IndexKind::Project, &request.query)?
            else {
                return Err(IndexError::Shape);
            };
            let TaskEntry::Held { tree, dialogue, .. } =
                decode_flat::<TaskEntry>(TokenBody::from(value.as_ref()))?
            else {
                return Err(IndexError::Unheld(reference.tree));
            };
            if tree != reference.tree {
                return Err(IndexError::Shape);
            }
            let request = Request {
                digest: dialogue,
                query: Query::Key(reference.position.owned()),
            };
            let (next, proof) = reader.ask(&request, IndexKind::Dialogue).await?;
            reader = next;
            let Verified::Present(value) =
                proof.verify(dialogue, IndexKind::Dialogue, &request.query)?
            else {
                return Err(IndexError::Shape);
            };
            let movement = prove::read_move(tree, value)?;
            if naming(movement.author, &movement.receipt) != Naming::Named(subject, attribution) {
                return Err(IndexError::Shape);
            }
            let (attempt, sequence) = reference.position.coordinates();
            writeln!(
                output,
                "provenance {} {attempt}.{sequence} {} {}",
                Anchor::commit(tree, movement.commit),
                attribution.field,
                attribution.holder
            )?;
            writeln!(output, "proved {dialogue} {}", reader.author)?;
            (reader, output) =
                render::movement(reader, tree, dialogue, reference.position, movement, output)
                    .await?;
        }
    }
    Ok((reader, output))
}
