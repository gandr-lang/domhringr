//! Derive, attest, prove, check and measure the keyed plane.
//!
//! # Keyed indexes
//!
//! The index plane, `domhringr-record-index`, derives a project's tasks, their
//! attempts and admitted moves, their refusals, and the evidence and
//! revisions those moves name into one keyed store, without changing receipt
//! admission. A project includes direct `tasks/<name>` bindings; each held
//! task holds its frontier, the kind of its standing, its refusals and its
//! play. An `Indexed` receipt attests the store's root.
//!
//! Run these commands after `domhringr-peer --state <dir>`:
//!
//! | Command | Result |
//! | ------- | ------ |
//! | `index derive <project>` | `indexed <commit-id> <root>`, or `unchanged <root>` for the same own claim |
//! | `index task <project> <name>` | `task <anchor> <standing>`, or an explicit unheld task |
//! | `index move <project> <name> <attempt>.<seq>` | One authenticated move in the replay language |
//! | `index play <project> <name> <attempt>` | Every move in that attempt, in canonical order |
//! | `index replay <project> <name>` | Every attempt replayed under its dispatch's protocol; the standing checked against the task's |
//! | `index after <project> <name> <attempt>` | `after <n> none` or `after <n> <dispatch-id>` |
//! | `index check <project> [--by <peer-id>]` | `agrees`, or findings with exit status 3 |
//! | `index measure <project>` | The store's root, then one line per table |
//! | `provenance <project> <digest\|revision>` | Every move naming the subject, proved with its task and attempt |
//!
//! The proving verbs accept `--by <peer-id>` and `--at <endpoint>`. They select
//! the owner's latest attestation unless `--by` names another author, read
//! the attested store when it is held locally, and otherwise reach that
//! attester through the project's book or `--at`. They print `proved <root>
//! <peer-id>` before the answer. Every question shares one connection; no
//! task tree is synced. A task's anchor comes from the project's binding at
//! the attestation's parents. A task's standing is recomputed from its last
//! attempt and checked against the kind the store holds. A grading or
//! landing also proves its attempt's play before rendering the verdict or
//! decision fields it refers to.
//!
//! `index play` proves membership without checking protocol conformance. `index
//! replay` checks every proved attempt through the arena monitor without
//! syncing task receipts. It prints the moves and `replayed <attempt>
//! <standing>` for each attempt, then `current <standing>`. A protocol refusal
//! exits 1 and names the movement and its `<attempt>.<seq>`; a standing
//! whose kind differs from the task's names both. An omitted move can still
//! conform, so agreement with the receipt fold remains `index check`'s
//! responsibility.
//!
//! `provenance` accepts 40 hexadecimal digits for a SHA-1 revision, or 64 for
//! both an evidence digest and a SHA-256 revision. The 64-digit form searches
//! both families, retaining both kinds of match. Each answer prints `provenance
//! <commit-anchor> <attempt>.<seq> <field> <holder>` followed by the
//! authenticated move in replay form; a proved empty preimage shows that the
//! store names no such subject.
//!
//! A proof authenticates the attester's claim, not its agreement with the fold.
//! `index check` re-derives at the attestation's project parents and each
//! task's heads: `disagrees <task> <field>` identifies a false field, and
//! `unchecked <task>` identifies an unavailable task frontier. Later receipts
//! do not make a true historical claim disagree. Check and measure fetch an
//! unheld store's manifest and nodes from the attester, each authenticated
//! by its hash; they do not sync receipts.
//!
//! `index measure` prints `store <root>`, then `table <name> records <n>
//! children <n> root <bytes> leaf <bytes> proof <bytes> levels closed|open`
//! per table. Proof bytes are the largest framed answer to a question about
//! the table; `levels open` means an internal root is at least as large as
//! its largest leaf.
//!
//! Run derive before serve: both hold the receipt store exclusively. `serve`
//! binds `domhringr/index/0` beside sync, wakes and evidence, printing `proved
//! <count>` when an index connection closes and reporting failed streams on
//! standard error.

mod provenance;
mod render;
mod replay;

use core::fmt::Write as _;
use std::ffi::OsStr;

use anodized::spec;
use domhringr_record_index::AttemptNumber;
use domhringr_record_index::MoveKey;
use domhringr_record_index::SequenceNumber;
use domhringr_record_index::check;
use domhringr_record_index::derive;
use domhringr_record_index::derive::Deriver;
use domhringr_record_index::keyed::Keyed;
use domhringr_record_index::keyed::Standing;
use domhringr_record_index::measure;
use domhringr_record_index::project;
use domhringr_record_index::project::TaskName;
use domhringr_record_index::prove;
use domhringr_record_index::prove::Ask;
use domhringr_record_index::prove::Local;
use domhringr_record_index::prove::ProveError;
use domhringr_record_index::store::Store;
use domhringr_record_index::store::StoreError;
use domhringr_record_index::stream;
use domhringr_record_index::stream::Remote;
use domhringr_record_index::stream::StreamError;
use domhringr_record_tree::Aim;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::At;
use domhringr_record_tree::BindPort;
use domhringr_record_tree::IndexAttestation;
use domhringr_record_tree::Node;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Route;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::TreeId;
use gandr_storage_schema::Answer;
use gandr_storage_schema::Question as StoreQuestion;
use gandr_storage_schema::StoreRoot;
pub use provenance::parse_provenance;

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
    /// Trace evidence or revision subjects to their original naming moves.
    Provenance
    {
        /// Both families when a 256-bit subject is textually ambiguous.
        subjects: Vec<domhringr_record_index::provenance::Subject>,
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
    /// Replay every attested attempt and check the entry's standing.
    Replay(TaskName),
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
            Self::Task(ref name)
            | Self::Replay(ref name)
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
    /// A subject is neither a manifest digest nor a Git revision.
    #[error("expected a lowercase 40- or 64-digit digest or revision")]
    Subject,
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
        "derive" | "task" | "move" | "play" | "replay" | "after" | "check" | "measure"
    ) {
        return Err(UsageError::Operands(Verb::Index));
    }
    let proving = matches!(action, "task" | "move" | "play" | "replay" | "after");
    let mut operands = Vec::new();
    let mut by = Aim::Owner;
    let mut at = At::Book;
    while let Some(argument) = arguments.next()? {
        match argument {
            lexopt::Arg::Value(value) => operands.push(value),
            lexopt::Arg::Long("by") if proving || action == "check" => {
                let value = arguments.value()?;
                let peer = crate::read_id(&value, Operand::Peer)?;
                by = Aim::Peer(peer);
            },
            lexopt::Arg::Long("at") if proving => {
                let value = arguments.value()?;
                let endpoint = crate::read_id(&value, Operand::At)?;
                at = At::Given(endpoint);
            },
            argument @ (lexopt::Arg::Short(_) | lexopt::Arg::Long(_)) => {
                return Err(argument.unexpected().into());
            },
        }
    }
    let (project, operands) = operands
        .split_first()
        .ok_or(UsageError::Operands(Verb::Index))?;
    let project = crate::read_tree(project)?;
    let action = match (action, operands) {
        ("derive", &[]) => Action::Derive,
        ("measure", &[]) => Action::Measure,
        ("check", &[]) => Action::Check(by),
        ("replay", &[ref name]) => {
            let name = read_name(name)?;
            Action::Prove {
                question: Question::Replay(name),
                by,
                at,
            }
        },
        ("task", &[ref name]) => {
            let name = read_name(name)?;
            Action::Prove {
                question: Question::Task(name),
                by,
                at,
            }
        },
        ("move", &[ref name, ref coordinate]) => {
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
        ("play" | "after", &[ref name, ref attempt]) => {
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
        _arity => return Err(UsageError::Operands(Verb::Index)),
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
    /// The attested task explicitly has no held task.
    #[error("unheld task {0}")]
    Unheld(TreeId),
    /// A proved coordinate is absent.
    #[error("absent move {0}.{1}")]
    MoveAbsent(AttemptNumber, SequenceNumber),
    /// Proof contents do not match the requested semantic shape.
    #[error("index answer does not describe the requested move or task")]
    Shape,
    /// An attested play fails its dispatch's protocol.
    #[error(transparent)]
    Replay(#[from] domhringr_record_index::replay::ReplayError),
    /// The replayed standing's kind differs from the task's.
    #[error("current mismatch: task {claimed}; replay {replayed:?}")]
    Standing
    {
        /// The kind the store holds for the task.
        claimed: Standing,
        /// The standing independently reached by replay.
        replayed: Box<domhringr_record_tree::Current>,
    },
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
    /// The keyed schema didn't resolve.
    #[error(transparent)]
    Schema(#[from] gandr_storage_schema::SchemaError),
    /// A proof didn't verify, or the store refused a question.
    #[error(transparent)]
    Proof(#[from] ProveError),
    /// Transport, framing or the answer cap failed.
    #[error(transparent)]
    Stream(#[from] StreamError),
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

/// Network resources exist only when the attested store isn't held.
enum Link
{
    /// A local-only reader retains the unopened routing choice.
    Local
    {
        /// Receipt store retained before the first remote question.
        peer: Peer,
        /// The attester route selected by the command.
        at: At,
    },
    /// Every question shares this one QUIC connection.
    Remote
    {
        /// Bound peer retaining the same receipt store.
        node: Node,
        /// The reusable proof-only transport.
        connection: iroh::endpoint::Connection,
    },
}

/// Whether this peer holds the attested store.
enum Attested
{
    /// The store isn't held here: answers are proofs from the attester.
    Unheld,
    /// The store, held locally or fetched from the attester.
    Held(Box<gandr_storage_schema::Store>),
}

/// One command's receipt authority, store files and optional live proof link.
struct Reader
{
    /// The project whose book supplies the attester's endpoint.
    project: TreeId,
    /// The selected attester, never changed by a holder's answer.
    author: PeerKey,
    /// The attested root every answer is about.
    root: StoreRoot,
    /// Committed manifests and authenticated nodes.
    store: Store,
    /// The attested store, when held.
    attested: Attested,
    /// The local peer or its opened proof link.
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
            Link::Local { ref peer, .. } => peer,
            Link::Remote { ref node, .. } => node.peer(),
        }
    }

    /// Read the attested store locally when held, dialing the attester once
    /// only when it isn't.
    ///
    /// # Specification
    /// - ensures: on success the reader answers every question from the held
    ///   store or over one connection; no receipt tree is synced.
    /// - fails: local corruption, missing route or transport failure.
    /// - panics: none.
    /// - executable: none — connection reuse and receipt-store isolation are
    ///   external effects; the project-only process witness observes them.
    ///
    /// # Errors
    /// - [`IndexError`]: store, route or dial refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L1 — a project-only reader proves without acquiring tasks.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    async fn open(mut self) -> Result<Self, IndexError>
    {
        let loaded = self.store.load(Keyed::shared()?, self.root);
        match loaded {
            Ok(held) => {
                self.attested = Attested::Held(Box::new(held));
                return Ok(self);
            },
            Err(StoreError::Unheld(_root)) => {},
            Err(failure) => return Err(failure.into()),
        }
        if let Link::Local { peer, at } = self.link {
            let route = peer.route(self.project, Aim::Peer(self.author), at).await?;
            let remote = match route {
                Route::Itself => return Err(StoreError::Unheld(self.root).into()),
                Route::Book { remote, .. } | Route::Given { remote } => remote,
            };
            let node = peer.bind(BindPort::Ephemeral, &[]).await?;
            let connection = node.open(remote.endpoint(), stream::PROTOCOL).await?;
            self.link = Link::Remote { node, connection };
        }
        Ok(self)
    }

    /// Hold the whole attested store, fetching it when it isn't held.
    ///
    /// # Specification
    /// - requires: the reader is open.
    /// - ensures: the returned store's root is the attested one.
    /// - fails: a manifest or node that doesn't authenticate, transport, or a
    ///   store that doesn't reopen.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`IndexError`]: storage, stream or identity refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the tree-holding reader checks the served
    ///   attestation.
    /// - witness: `index::tests::a_peer_holding_the_trees_checks_the_attestation`
    #[spec(ensures: |ref output| output.as_ref().map_or(true, |held| held.root() == self.root))]
    async fn load(&mut self) -> Result<gandr_storage_schema::Store, IndexError>
    {
        if let Attested::Held(ref held) = self.attested {
            return Ok((**held).clone());
        }
        let Link::Remote { ref connection, .. } = self.link
        else {
            return Err(StoreError::Unheld(self.root).into());
        };
        let held = stream::fetch(connection, &self.store, self.root).await?;
        self.attested = Attested::Held(Box::new(held.clone()));
        Ok(held)
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

impl Ask for Reader
{
    /// Answer from the held store, or by a proof verified against the
    /// attested root.
    ///
    /// # Specification
    /// - requires: the reader is open.
    /// - ensures: as [`Local`] or [`Remote`].
    /// - fails: as they do.
    /// - panics: none.
    /// - executable: none — the answer is checked by the reader it is forwarded
    ///   to; the project-only witness observes both.
    ///
    /// # Errors
    /// - [`ProveError`]: as [`Local`] or [`Remote`].
    ///
    /// # Adequacy
    /// - hypothesis: L1 — a project-only reader proves without acquiring tasks.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    async fn ask(
        &mut self,
        question: &StoreQuestion,
    ) -> Result<Answer, ProveError>
    {
        if let Attested::Held(ref held) = self.attested {
            return Local(held).ask(question).await;
        }
        match self.link {
            Link::Remote { ref connection, .. } => {
                Remote {
                    connection,
                    root: self.root,
                }
                .ask(question)
                .await
            },
            Link::Local { .. } => Err(StreamError::Unheld(self.root).into()),
        }
    }
}

/// A bound task, found in the attested store.
struct Found
{
    /// The tree the project binds the name to.
    tree: TreeId,
    /// What the store claims about the task.
    claim: prove::Claim,
}

/// Find a task by name and read its claim.
///
/// # Specification
/// - ensures: the tree is the project's binding at the attestation's parents;
///   the claim is the store's.
/// - fails: a name unbound at those parents or without a task, or a claim that
///   doesn't read.
/// - panics: none.
/// - executable: none — the reads are proofs; the project-only witness observes
///   them.
///
/// # Errors
/// - [`IndexError`]: as above.
///
/// # Adequacy
/// - hypothesis: L1 — a project-only reader finds every task.
/// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
async fn find(
    reader: &mut Reader,
    attestation: &IndexAttestation,
    name: &TaskName,
) -> Result<Found, IndexError>
{
    let view = reader
        .peer()
        .view_at(reader.project, &attestation.parents)
        .await?;
    let tree = project::bindings(&view)
        .find_map(|(bound, tree)| (&bound == name).then_some(tree))
        .ok_or_else(|| IndexError::Absent(name.clone()))?;
    let keyed = Keyed::shared()?;
    let task = prove::task(reader, keyed, name).await.map_err(|failure| {
        if let ProveError::Absent(absent) = failure {
            IndexError::Absent(absent)
        }
        else {
            IndexError::Proof(failure)
        }
    })?;
    let claim = prove::claim(reader, keyed, task).await?;
    Ok(Found { tree, claim })
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
        let mut deriver = Deriver::owned(&peer, project, &view, &store)?;
        let derived = deriver.project(&peer, project, &view, &store).await?;
        let root = derived.root();
        let digest = derive::digest(root);
        if view
            .indexes()
            .get(&author)
            .is_some_and(|attestation| attestation.index == digest)
        {
            return Ok((Completion::Success, format!("unchanged {root}\n")));
        }
        // No node is bound and the process holds redb exclusively: these heads
        // remain the commit's parents throughout task derivation.
        let receipt = Receipt::indexed(project, digest)?;
        let commit = peer.commit(project, receipt).await?;
        return Ok((Completion::Success, format!("indexed {commit} {root}\n")));
    }
    let (by, at) = match action {
        Action::Prove { by, ref at, .. } | Action::Provenance { by, ref at, .. } => {
            (by, at.clone())
        },
        Action::Check(by) => (by, At::Book),
        Action::Measure | Action::Derive => (Aim::Owner, At::Book),
    };
    let author = match by {
        Aim::Owner => view.owner(),
        Aim::Peer(author) => author,
    };
    let attestation = view
        .indexes()
        .get(&author)
        .ok_or(IndexError::Unindexed(author))?;
    let reader = Reader {
        project,
        author,
        root: derive::root(attestation.index),
        store,
        attested: Attested::Unheld,
        link: Link::Local { peer, at },
    }
    .open()
    .await?;
    match action {
        Action::Provenance { subjects, .. } => {
            let (reader, output) = provenance::answer(reader, subjects).await?;
            reader.close().await;
            Ok((Completion::Success, output))
        },
        Action::Prove { question, .. } => {
            let (reader, output) = answer(reader, attestation, question).await?;
            reader.close().await;
            Ok((Completion::Success, output))
        },
        Action::Check(_by) => {
            let mut reader = reader;
            let held = reader.load().await?;
            let report = check::check(reader.peer(), project, attestation, &held).await?;
            let completion = if report.0.is_empty() {
                Completion::Success
            }
            else {
                Completion::IndexFinding
            };
            reader.close().await;
            Ok((completion, report.to_string()))
        },
        Action::Measure => {
            let mut reader = reader;
            let held = reader.load().await?;
            let output = measurements(&held)?;
            reader.close().await;
            Ok((Completion::Success, output))
        },
        Action::Derive => {
            drop(reader);
            Err(IndexError::Shape)
        },
    }
}

/// Find the task before reading any coordinate of its play.
///
/// # Specification
/// trivial.
async fn answer(
    mut reader: Reader,
    attestation: &IndexAttestation,
    question: Question,
) -> Result<(Reader, String), IndexError>
{
    let found = find(&mut reader, attestation, question.name()).await?;
    let mut output = format!("proved {} {}\n", reader.root, reader.author);
    if found.claim.standing == Standing::Unheld {
        if matches!(&question, Question::Task(_name)) {
            writeln!(output, "task {} unheld", Anchor::key(found.tree))?;
            return Ok((reader, output));
        }
        return Err(IndexError::Unheld(found.tree));
    }
    match question {
        Question::Replay(_name) => replay::answer(reader, found, output).await,
        Question::Task(_name) => {
            let current = prove::current(&mut reader, Keyed::shared()?, &found.claim).await?;
            writeln!(output, "task {} {current}", Anchor::key(found.tree))?;
            Ok((reader, output))
        },
        question @ (Question::Move(..) | Question::Play(..) | Question::After(..)) => {
            render::question(reader, &found, question, output).await
        },
    }
}

/// Measure each table of the attested store.
///
/// # Specification
/// trivial.
fn measurements(held: &gandr_storage_schema::Store) -> Result<String, IndexError>
{
    let mut output = format!("store {}\n", held.root());
    for measured in measure::measure(held)? {
        let levels = match measured.levels {
            measure::Levels::Closed => "closed",
            measure::Levels::Open => "open",
        };
        writeln!(
            output,
            "table {} records {} children {} root {} leaf {} proof {} levels {levels}",
            measured.table.as_ref(),
            measured.records,
            measured.children.0,
            measured.root,
            measured.leaf,
            measured.proof
        )?;
    }
    Ok(output)
}
