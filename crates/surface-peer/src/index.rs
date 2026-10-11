//! Derive, attest, prove, check and measure the keyed plane.

mod render;

use core::fmt::Write as _;
use std::ffi::OsStr;

use anodized::spec;
use domhringr_record_index::AttemptNumber;
use domhringr_record_index::Index;
use domhringr_record_index::IndexKind;
use domhringr_record_index::MoveKey;
use domhringr_record_index::SequenceNumber;
use domhringr_record_index::check;
use domhringr_record_index::derive::Deriver;
use domhringr_record_index::measure;
use domhringr_record_index::project::TaskEntry;
use domhringr_record_index::project::TaskName;
use domhringr_record_index::prove;
use domhringr_record_index::prove::Answer;
use domhringr_record_index::prove::Query;
use domhringr_record_index::prove::Verified;
use domhringr_record_index::store::Store;
use domhringr_record_index::store::StoreError;
use domhringr_record_index::stream;
use domhringr_record_index::stream::Request;
use domhringr_record_tree::Aim;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::At;
use domhringr_record_tree::BindPort;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::Node;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Route;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::TreeId;
use gandr_storage_records::KeyRange;
use gandr_storage_records::OwnedKeyRange;
use gandr_storage_records::Record;
use gandr_storage_records::RecordTree;
use gandr_storage_records::TreeParams;
use gandr_storage_values::TokenBody;
use gandr_storage_values::decode_flat;

use crate::Completion;
use crate::Operand;
use crate::RunError;
use crate::UsageError;
use crate::Verb;

/// A keyed-plane command with its project frontier supplied by local receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command
{
    /// The project carrying task bindings and attestations.
    project: TreeId,
    /// The operation over its derived indexes.
    action: Action,
}

/// The operations whose permissions and inputs differ.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Action
{
    /// Derive current task frontiers and publish only a changed own claim.
    Derive,
    /// Answer a root-checkable question, without syncing any task tree.
    Prove
    {
        /// The authenticated task or dialogue coordinate.
        question: Question,
        /// The project attester whose manifest is authoritative.
        by: Aim,
        /// The routing choice used on a local index miss.
        at: At,
    },
    /// Compare the chosen claim with historical receipt folds.
    Check(Aim),
    /// Measure the owner's project and its nested dialogue indexes.
    Measure,
}

/// A task entry or a coordinate in that entry's dialogue.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Question
{
    /// The named project entry, including its full standing.
    Task(TaskName),
    /// Exactly this move coordinate.
    Move(TaskName, MoveKey),
    /// Every move of this attempt.
    Play(TaskName, AttemptNumber),
    /// Whether the next attempt begins, or the dialogue has ended.
    After(TaskName, AttemptNumber),
}

impl Question
{
    /// The project name every question must authenticate first.
    ///
    /// # Specification
    /// trivial.
    fn name(&self) -> &TaskName
    {
        match *self {
            | Self::Task(ref name)
            | Self::Move(ref name, _)
            | Self::Play(ref name, _)
            | Self::After(ref name, _) => name,
        }
    }
}

/// An invalid keyed command operand.
#[derive(Debug, thiserror::Error)]
pub enum ParseError
{
    /// A name is not a single task path segment.
    #[error(transparent)]
    Name(#[from] domhringr_record_index::project::NameError),
    /// A coordinate component is not an unsigned 32-bit integer.
    #[error("invalid index coordinate: {0}")]
    Number(#[from] core::num::ParseIntError),
    /// A move coordinate has no separating period.
    #[error("expected a move coordinate <attempt>.<seq>")]
    Coordinate,
}

/// Parse the index verbs, refusing irrelevant options rather than ignoring
/// them.
///
/// # Specification
/// - ensures: derive and measure take only a project; check permits by; the
///   four proving verbs also permit at and take exactly their named
///   coordinates.
/// - fails: malformed names, coordinates, endpoints and extra operands fail.
/// - panics: none.
/// - executable: none — the function is its own specification; process
///   witnesses exercise the accepted commands and their refused operands.
///
/// # Errors
/// - [`UsageError`]: lexical, operand or keyed-language refusal.
///
/// # Adequacy
/// - hypothesis: L1 — real processes invoke every proving and checking verb.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
/// - witness: `index::tests::a_peer_holding_the_trees_checks_the_attestation`
pub fn parse(arguments: &mut lexopt::Parser) -> Result<Command, UsageError>
{
    let action = arguments.value()?;
    let action = action.to_str().ok_or(UsageError::Operands(Verb::Index))?;
    if !matches!(
        action,
        "derive" | "task" | "move" | "play" | "after" | "check" | "measure"
    ) {
        return Err(UsageError::Operands(Verb::Index));
    }
    let proving = matches!(action, "task" | "move" | "play" | "after");
    let mut operands = Vec::new();
    let mut by = Aim::Owner;
    let mut at = At::Book;
    while let Some(argument) = arguments.next()? {
        match argument {
            | lexopt::Arg::Value(value) => operands.push(value),
            | lexopt::Arg::Long("by") if proving || action == "check" => {
                let value = arguments.value()?;
                let peer = crate::read_id(&value, Operand::Peer)?;
                by = Aim::Peer(peer);
            },
            | lexopt::Arg::Long("at") if proving => {
                let value = arguments.value()?;
                let endpoint = crate::read_id(&value, Operand::At)?;
                at = At::Given(endpoint);
            },
            | argument => return Err(argument.unexpected().into()),
        }
    }
    let (project, operands) = operands
        .split_first()
        .ok_or(UsageError::Operands(Verb::Index))?;
    let project = crate::read_tree(project)?;
    let action = match (action, operands) {
        | ("derive", &[]) => Action::Derive,
        | ("measure", &[]) => Action::Measure,
        | ("check", &[]) => Action::Check(by),
        | ("task", &[ref name]) => {
            let name = read_name(name)?;
            Action::Prove {
                question: Question::Task(name),
                by,
                at,
            }
        },
        | ("move", &[ref name, ref coordinate]) => {
            let name = read_name(name)?;
            let coordinate = coordinate
                .to_str()
                .ok_or(UsageError::Operands(Verb::Index))?;
            let (attempt, seq) = coordinate.split_once('.').ok_or(ParseError::Coordinate)?;
            let attempt = attempt.parse().map_err(ParseError::from)?;
            let seq = seq.parse().map_err(ParseError::from)?;
            Action::Prove {
                question: Question::Move(
                    name,
                    MoveKey::new(AttemptNumber(attempt), SequenceNumber(seq)),
                ),
                by,
                at,
            }
        },
        | ("play" | "after", &[ref name, ref attempt]) => {
            let name = read_name(name)?;
            let attempt = attempt.to_str().ok_or(UsageError::Operands(Verb::Index))?;
            let attempt = attempt.parse().map_err(ParseError::from)?;
            let attempt = AttemptNumber(attempt);
            let question = if action == "play" {
                Question::Play(name, attempt)
            }
            else {
                Question::After(name, attempt)
            };
            Action::Prove { question, by, at }
        },
        | _arity => return Err(UsageError::Operands(Verb::Index)),
    };
    Ok(Command { project, action })
}

/// Read a single task-name operand without lossy text conversion.
///
/// # Specification
/// trivial.
fn read_name(name: &OsStr) -> Result<TaskName, UsageError>
{
    let name = name.to_str().ok_or(UsageError::Operands(Verb::Index))?;
    name.parse()
        .map_err(ParseError::from)
        .map_err(UsageError::from)
}

/// A keyed-plane runtime refusal, preserving its source boundary.
#[derive(Debug, thiserror::Error)]
pub enum IndexError
{
    /// The chosen author has not attested an index.
    #[error("unindexed {0}")]
    Unindexed(PeerKey),
    /// Only an operator may publish an attestation.
    #[error("no authority to attest this project")]
    Authority,
    /// A proved task name is absent from the project.
    #[error("absent task {0}")]
    Absent(TaskName),
    /// The attested entry explicitly has no held task.
    #[error("unheld task {0}")]
    Unheld(TreeId),
    /// A proved coordinate is absent.
    #[error("absent move {0}.{1}")]
    MoveAbsent(AttemptNumber, SequenceNumber),
    /// Proof contents do not match the requested semantic shape.
    #[error("index answer does not describe the requested move or entry")]
    Shape,
    /// Receipt folds cannot be read.
    #[error(transparent)]
    View(#[from] domhringr_record_tree::ViewError),
    /// Historical receipt folds cannot be read.
    #[error(transparent)]
    Historical(#[from] domhringr_record_tree::ViewAtError),
    /// A frontier cannot be read.
    #[error(transparent)]
    Heads(#[from] domhringr_record_tree::HeadsError),
    /// Receipt construction cannot draw a fence.
    #[error(transparent)]
    Random(#[from] domhringr_record_tree::RandomError),
    /// An attestation cannot be committed.
    #[error(transparent)]
    Commit(#[from] domhringr_record_tree::CommitError),
    /// The endpoint cannot be bound.
    #[error(transparent)]
    Bind(#[from] domhringr_record_tree::BindError),
    /// The attester cannot be located.
    #[error(transparent)]
    Route(#[from] domhringr_record_tree::RouteError),
    /// The attester's proof endpoint cannot be reached.
    #[error(transparent)]
    Dial(#[from] domhringr_record_tree::DialError),
    /// Derivation failed at the record or value boundary.
    #[error(transparent)]
    Derive(#[from] domhringr_record_index::derive::DeriveError),
    /// Local immutable index files could not be read or written.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Manifest framing or identity failed.
    #[error(transparent)]
    Manifest(#[from] domhringr_record_index::ManifestError),
    /// Index wire framing cannot be represented.
    #[error(transparent)]
    Wire(#[from] domhringr_record_index::WireError),
    /// Proof construction or verification failed.
    #[error(transparent)]
    Proof(#[from] prove::ProveError),
    /// Transport, framing or the answer cap failed.
    #[error(transparent)]
    Stream(#[from] stream::StreamError),
    /// A canonical value could not be read.
    #[error(transparent)]
    Value(#[from] gandr_storage_values::ValueError),
    /// The record tree or its range was refused.
    #[error(transparent)]
    Records(#[from] gandr_storage_records::RecordTreeError),
    /// The coordinate cannot be advanced.
    #[error(transparent)]
    Key(#[from] domhringr_record_index::key::KeyError),
    /// Re-derivation could not check the historical claim.
    #[error(transparent)]
    Check(#[from] check::CheckError),
    /// Exact answer extents could not be measured.
    #[error(transparent)]
    Measure(#[from] measure::MeasureError),
    /// Text output could not be formatted.
    #[error(transparent)]
    Format(#[from] core::fmt::Error),
}

/// Network resources exist only after a local manifest miss.
enum Link
{
    /// A local-only reader retains the unopened routing choice.
    Local
    {
        /// Receipt store retained before the first remote query.
        peer: Peer,
        /// The attester route selected by the command.
        at: At,
    },
    /// Dependent proof questions share this one QUIC connection.
    Remote
    {
        /// Bound peer retaining the same receipt store.
        node: Node,
        /// The reusable proof-only transport.
        connection: iroh::endpoint::Connection,
    },
}

/// One command's receipt authority, node files and optional live proof link.
struct Reader
{
    /// The project whose book supplies the attester's endpoint.
    project: TreeId,
    /// The selected attester, never changed by a holder's answer.
    author: PeerKey,
    /// Immutable manifests and authenticated nodes.
    store: Store,
    /// The local peer or its lazily opened proof link.
    link: Link,
}

impl Reader
{
    /// The receipt store held in either connection state.
    ///
    /// # Specification
    /// trivial.
    fn peer(&self) -> &Peer
    {
        match self.link {
            | Link::Local { ref peer, .. } => peer,
            | Link::Remote { ref node, .. } => node.peer(),
        }
    }

    /// Read local proof material first, dialing once only when its manifest
    /// lacks.
    ///
    /// # Specification
    /// - ensures: answers remain untrusted until the caller verifies; a remote
    ///   connection is reused and no receipt tree is synced.
    /// - fails: local corruption, missing route, transport and framing fail.
    /// - panics: none.
    /// - executable: none — connection reuse and receipt-store isolation are
    ///   external effects; the project-only process witness observes them.
    ///
    /// # Errors
    /// - [`IndexError`]: store, route or stream refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L1 — a project-only reader proves without acquiring tasks.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    async fn ask(
        mut self,
        request: &Request,
        kind: IndexKind,
    ) -> Result<(Self, Answer), IndexError>
    {
        match self.store.load(request.digest) {
            | Ok(index) => {
                let answer = prove::answer(&index, &request.query)?;
                return Ok((self, answer));
            },
            | Err(StoreError::Unheld(_digest)) => {},
            | Err(failure) => return Err(failure.into()),
        }
        let (node, connection) = match self.link {
            | Link::Local { peer, at } => {
                let route = peer.route(self.project, Aim::Peer(self.author), at).await?;
                let remote = match route {
                    | Route::Itself => return Err(StoreError::Unheld(request.digest).into()),
                    | Route::Book { remote, .. } | Route::Given { remote } => remote,
                };
                let node = peer.bind(BindPort::Ephemeral, &[]).await?;
                let connection = node.open(remote.endpoint(), stream::PROTOCOL).await?;
                (node, connection)
            },
            | Link::Remote { node, connection } => (node, connection),
        };
        let answer = stream::ask(&connection, request, kind).await?;
        self.link = Link::Remote { node, connection };
        Ok((self, answer))
    }

    /// Hydrate a complete authenticated index, never inferring it from a claim.
    ///
    /// # Specification
    /// - ensures: the returned tree rebuilds exactly the selected manifest.
    /// - fails: incomplete ranges, foreign roots and over-cap answers fail.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`IndexError`]: storage, proof, framing or identity refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the tree-holding reader checks the served
    ///   attestation.
    /// - witness: `index::tests::a_peer_holding_the_trees_checks_the_attestation`
    #[spec(ensures: |ref output| output.as_ref().map_or(true, |loaded| loaded.1.manifest.identity().is_ok_and(|identity| identity == digest)))]
    async fn load(
        self,
        digest: IndexDigest,
        kind: IndexKind,
    ) -> Result<(Self, Index), IndexError>
    {
        match self.store.load(digest) {
            | Ok(index) if index.manifest.kind() == kind => return Ok((self, index)),
            | Ok(_foreign) => return Err(IndexError::Shape),
            | Err(StoreError::Unheld(_digest)) => {},
            | Err(failure) => return Err(failure.into()),
        }
        let query = Query::Range(OwnedKeyRange::from_range(KeyRange::all()));
        let request = Request { digest, query };
        let (reader, answer) = self.ask(&request, kind).await?;
        let Verified::Range(records) = answer.verify(digest, kind, &request.query)?
        else {
            return Err(IndexError::Shape);
        };
        let records: Vec<_> = records.iter().map(Record::as_record_ref).collect();
        let tree = RecordTree::build(&records, TreeParams::current())?;
        let index = Index::new(kind, tree);
        if index.manifest != answer.manifest {
            return Err(IndexError::Shape);
        }
        let _digest = reader.store.keep(&index)?;
        Ok((reader, index))
    }

    /// Close the command's proof connection before releasing the receipt store.
    ///
    /// # Specification
    /// trivial.
    async fn close(self)
    {
        if let Link::Remote { node, connection } = self.link {
            connection.close(iroh::endpoint::VarInt::from_u32(0), b"questions complete");
            node.close().await;
        }
    }
}

/// Run one keyed command and print only authenticated or independently derived
/// output.
///
/// # Specification
/// - ensures: derive captures its project frontier before publishing; proving
///   reads no task tree; check returns status three for any finding.
/// - fails: unavailable authority, inputs, proofs and output fail explicitly.
/// - panics: none.
/// - executable: none — receipt publication, network reads and standard output
///   are external effects; the two-process witnesses observe them.
///
/// # Errors
/// - [`RunError`]: keyed operation or output refusal.
///
/// # Adequacy
/// - hypothesis: L1 — the two-process witness exercises the complete command
///   path.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
/// - witness: `index::tests::a_peer_holding_the_trees_checks_the_attestation`
#[expect(
    clippy::large_futures,
    reason = "the one-shot CLI keeps its bounded nonrecursive request future inline instead of allocating at each layer"
)]
pub async fn run(
    peer: Peer,
    state: &StateDir,
    command: Command,
) -> Result<Completion, RunError>
{
    let (completion, output) = execute(peer, Store::open(state), command).await?;
    crate::emit(&output)?;
    Ok(completion)
}

/// Execute against the exclusively held local receipt store.
///
/// # Specification
/// trivial.
#[expect(
    clippy::large_futures,
    reason = "the one-shot CLI keeps its bounded nonrecursive request future inline instead of allocating at each layer"
)]
async fn execute(
    peer: Peer,
    store: Store,
    command: Command,
) -> Result<(Completion, String), IndexError>
{
    let Command { project, action } = command;
    let heads = peer.heads(project).await?;
    let view = peer.view_at(project, &heads).await?;
    if action == Action::Derive {
        let author = peer.identity().peer_key();
        if author != view.owner() && !view.members().contains(&author) {
            return Err(IndexError::Authority);
        }
        let derived = Deriver::default().project(&peer, &view, &store).await?;
        let digest = derived.index.manifest.identity()?;
        if view
            .indexes()
            .get(&author)
            .is_some_and(|attestation| attestation.index == digest)
        {
            return Ok((Completion::Success, format!("unchanged {digest}\n")));
        }
        // No node is bound and the process holds redb exclusively: these heads
        // remain the commit's parents throughout task derivation.
        let receipt = Receipt::indexed(project, digest)?;
        let commit = peer.commit(project, receipt).await?;
        return Ok((Completion::Success, format!("indexed {commit} {digest}\n")));
    }
    let (by, at) = match action {
        | Action::Prove { by, ref at, .. } => (by, at.clone()),
        | Action::Check(by) => (by, At::Book),
        | Action::Measure | Action::Derive => (Aim::Owner, At::Book),
    };
    let author = match by {
        | Aim::Owner => view.owner(),
        | Aim::Peer(author) => author,
    };
    let attestation = view
        .indexes()
        .get(&author)
        .ok_or(IndexError::Unindexed(author))?;
    let reader = Reader {
        project,
        author,
        store,
        link: Link::Local { peer, at },
    };
    match action {
        | Action::Prove { question, .. } => {
            let (reader, output) = answer(reader, attestation.index, question).await?;
            reader.close().await;
            Ok((Completion::Success, output))
        },
        | Action::Check(_by) => {
            let (reader, index) = reader.load(attestation.index, IndexKind::Project).await?;
            let report = check::check(reader.peer(), project, attestation, &index).await?;
            let completion = if report.0.is_empty() {
                Completion::Success
            }
            else {
                Completion::IndexFinding
            };
            reader.close().await;
            Ok((completion, report.to_string()))
        },
        | Action::Measure => {
            let (reader, output) = measurements(reader, attestation.index).await?;
            reader.close().await;
            Ok((Completion::Success, output))
        },
        | Action::Derive => {
            drop(reader);
            Err(IndexError::Shape)
        },
    }
}

/// Authenticate the task entry before reading any coordinate of its dialogue.
///
/// # Specification
/// trivial.
#[expect(
    clippy::large_futures,
    reason = "the one-shot CLI keeps its bounded nonrecursive request future inline instead of allocating at each layer"
)]
async fn answer(
    reader: Reader,
    digest: IndexDigest,
    question: Question,
) -> Result<(Reader, String), IndexError>
{
    let request = Request {
        digest,
        query: Query::Key(question.name().key()),
    };
    let (reader, answer) = reader.ask(&request, IndexKind::Project).await?;
    let verified = answer.verify(digest, IndexKind::Project, &request.query)?;
    let entry = match verified {
        | Verified::Present(value) => decode_flat::<TaskEntry>(TokenBody::from(value.as_ref()))?,
        | Verified::Absent(_evidence) => return Err(IndexError::Absent(question.name().clone())),
        | Verified::Range(_records) => return Err(IndexError::Shape),
    };
    let mut output = format!("proved {digest} {}\n", reader.author);
    if matches!(&question, Question::Task(_name)) {
        match entry {
            | TaskEntry::Held { tree, current, .. } => {
                writeln!(output, "task {} {current}", Anchor::key(tree))?;
            },
            | TaskEntry::Unheld { tree } => writeln!(output, "task {} unheld", Anchor::key(tree))?,
        }
        return Ok((reader, output));
    }
    let TaskEntry::Held { tree, dialogue, .. } = entry
    else {
        return Err(IndexError::Unheld(entry.tree()));
    };
    render::question(reader, tree, dialogue, question, output).await
}

/// Measure each distinct index named by a project, preserving alias-free
/// output.
///
/// # Specification
/// trivial.
async fn measurements(
    reader: Reader,
    digest: IndexDigest,
) -> Result<(Reader, String), IndexError>
{
    let (mut reader, index) = reader.load(digest, IndexKind::Project).await?;
    let mut output = String::new();
    measurement(&mut output, digest, &index)?;
    let mut dialogues = alloc::collections::BTreeSet::new();
    for record in index.tree.records() {
        if record.key().as_ref().first() != Some(&1) {
            continue;
        }
        let entry = decode_flat::<TaskEntry>(TokenBody::from(record.value().as_ref()))?;
        if let TaskEntry::Held { dialogue, .. } = entry {
            let _inserted = dialogues.insert(dialogue);
        }
    }
    for digest in dialogues {
        let (next, index) = reader.load(digest, IndexKind::Dialogue).await?;
        reader = next;
        measurement(&mut output, digest, &index)?;
    }
    Ok((reader, output))
}

/// Write one index's exact extents and root-to-leaf crossing signal.
///
/// # Specification
/// trivial.
fn measurement(
    output: &mut String,
    digest: IndexDigest,
    index: &Index,
) -> Result<(), IndexError>
{
    let measured = measure::measure(index)?;
    let kind = match index.manifest.kind() {
        | IndexKind::Dialogue => "dialogue",
        | IndexKind::Project => "project",
        | IndexKind::Provenance => "provenance",
    };
    let levels = match measured.levels {
        | measure::Levels::Closed => "closed",
        | measure::Levels::Open => "open",
    };
    writeln!(
        output,
        "index {kind} {digest} records {} children {} root {} leaf {} proof {} levels {levels}",
        measured.records, measured.children.0, measured.root, measured.leaf, measured.proof
    )?;
    Ok(())
}
