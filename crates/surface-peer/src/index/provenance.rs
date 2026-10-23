//! Prove the moves naming a subject, with their task and attempt.

use core::fmt::Write as _;

use anodized::spec;
use domhringr_record_index::keyed::Keyed;
use domhringr_record_index::prove;
use domhringr_record_index::provenance::Subject;
use domhringr_record_tree::Aim;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::At;
use domhringr_record_tree::Kind;
use domhringr_record_tree::Revision;
use gandr_storage_values::ManifestDigest;

use super::Action;
use super::Command;
use super::Found;
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
            lexopt::Arg::Value(value) => operands.push(value),
            lexopt::Arg::Long("by") => {
                let value = arguments.value()?;
                by = Aim::Peer(crate::read_id(&value, Operand::Peer)?);
            },
            lexopt::Arg::Long("at") => {
                let value = arguments.value()?;
                at = At::Given(crate::read_id(&value, Operand::At)?);
            },
            argument @ (lexopt::Arg::Short(_) | lexopt::Arg::Long(_)) => {
                return Err(argument.unexpected().into());
            },
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
        Revision::Sha1(_) => vec![Subject::Revision(revision)],
        Revision::Sha256(bytes) => vec![
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
/// - ensures: each subject's namings are proved under the attested root; each
///   names a move of its task whose receipt names the subject, field and
///   holder. Task aliases do not duplicate the answer.
/// - fails: missing or malformed links and disagreeing attributions fail; no
///   task receipt tree is fetched to supply a missing link.
/// - panics: none.
///
/// # Errors
/// - [`IndexError`]: proof, move, transport or formatting failure.
///
/// # Adequacy
/// - hypothesis: L1 — a separate process holding only the project verifies a
///   transcript through the store to the verdict's original receipt.
/// - witness: `index::tests::a_transcript_resolves_to_its_verdict_by_proof`
#[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
pub(super) async fn answer(
    mut reader: Reader,
    subjects: Vec<Subject>,
) -> Result<(Reader, String), IndexError>
{
    let keyed = Keyed::shared()?;
    let mut output = format!("proved {} {}\n", reader.root, reader.author);
    for subject in subjects {
        let namings = prove::named(&mut reader, keyed, subject).await?;
        for named in namings {
            let tree = named.movement.receipt.tree();
            let (attempt, sequence) = named.key.coordinates();
            writeln!(
                output,
                "provenance {} {attempt}.{sequence} {} {}",
                Anchor::commit(tree, named.movement.commit),
                named.field,
                named.holder
            )?;
            let play = if matches!(
                named.movement.receipt.kind(),
                Kind::Graded { .. } | Kind::Landed { .. }
            ) {
                let task = prove::task(&mut reader, keyed, &named.task).await?;
                let claim = prove::claim(&mut reader, keyed, task).await?;
                render::play(&mut reader, &Found { tree, claim }, named.key).await?
            }
            else {
                Vec::new()
            };
            render::emit_with(&mut output, &named.movement, &play)?;
        }
    }
    Ok((reader, output))
}
