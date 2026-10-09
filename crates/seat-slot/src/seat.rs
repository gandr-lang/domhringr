//! The seat: a node serving wakes, acting on the dispatches it holds through
//! a command surface, and reporting.
//!
//! [`serve`] accepts on a node bound with [`PROTOCOL`]: a linked peer is
//! announced, and each wake is answered on a task of its own. Answering pulls
//! the task from the operator, folds it, and replies woken only when the
//! wake's dispatch is the task's current attempt and this seat holds its
//! slot; the seat presents itself in the task first when the task's book
//! lacks it, so the operator reaches it through the book from then on. A
//! woken dispatch not yet reported on is acted on: the surface's program runs
//! with the brief, and its standard output becomes the report — the content
//! by its BLAKE3 hash, the first line as the summary. On start the seat
//! resumes every dispatch it holds unreported in the trees its store holds,
//! so a seat restarted mid-work finishes it.

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;

use domhringr_record_tree::AcceptError;
use domhringr_record_tree::Accepted;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::Answer;
use domhringr_record_tree::Attempt;
use domhringr_record_tree::Brief;
use domhringr_record_tree::CommitError;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Content;
use domhringr_record_tree::ContentHash;
use domhringr_record_tree::Current;
use domhringr_record_tree::Incoming;
use domhringr_record_tree::Node;
use domhringr_record_tree::ParseSummaryError;
use domhringr_record_tree::PresentError;
use domhringr_record_tree::RandomError;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Slot;
use domhringr_record_tree::Summary;
use domhringr_record_tree::SyncError;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::TreesError;
use domhringr_record_tree::ViewError;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::wake::Decline;
use crate::wake::LINE_BYTES;
use crate::wake::Line;
use crate::wake::PROTOCOL;
use crate::wake::ParseWakeError;
use crate::wake::Reply;
use crate::wake::Wake;

/// How long a seat that replied waits for the operator to read the reply and
/// close the connection before it lets the connection go.
const LINGER: core::time::Duration = core::time::Duration::from_secs(10);

/// The environment variable naming the task to the surface's program.
const TASK: &str = "DOMHRINGR_TASK";

/// The environment variable naming the dispatch to the surface's program.
const DISPATCH: &str = "DOMHRINGR_DISPATCH";

/// What a seat acts through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Surface
{
    /// Nothing: the seat holds its slots and never reports.
    Hold,
    /// This program, run as `<program> anchor <anchor>` or `<program> content
    /// <hash>` with the task's and the dispatch's anchors in
    /// `DOMHRINGR_TASK` and `DOMHRINGR_DISPATCH`; its standard output is the
    /// report.
    Program(PathBuf),
}

/// What a serving seat did, for its surface to tell.
#[derive(Debug)]
pub enum Event
{
    /// A peer linked to this seat.
    Accepted(Accepted),
    /// A connection was not admitted.
    Unaccepted(AcceptError),
    /// The seat replied woken to a wake of `dispatch` in `tree`.
    Woken
    {
        /// The task.
        tree: TreeId,
        /// The dispatch.
        dispatch: CommitId,
    },
    /// The seat declined a wake.
    Declined(Declined),
    /// A wake's stream failed before its reply was written.
    Unanswered(AnswerError),
    /// The seat reported on a dispatch in `tree`: `report` is the report's
    /// commit.
    Reported
    {
        /// The task.
        tree: TreeId,
        /// The report's commit.
        report: CommitId,
    },
    /// The seat acted on `dispatch` in `tree` and committed no report.
    Unreported
    {
        /// The task.
        tree: TreeId,
        /// The dispatch.
        dispatch: CommitId,
        /// Why.
        failure: ActError,
    },
    /// The seat could not read what to resume.
    Unresumed(ResumeError),
    /// The endpoint closed: no connection will arrive again.
    Closed,
}

/// A serving seat's state, shared by its accept loop, its answers and its
/// acts.
struct Seat
{
    /// The node the seat serves on.
    node: Arc<Node>,
    /// What the seat acts through.
    surface: Surface,
    /// The dispatches being acted on now, so a wake during an act starts no
    /// second one.
    acting: Mutex<BTreeSet<CommitId>>,
    /// Where events go.
    events: mpsc::UnboundedSender<Event>,
}

/// Serve wakes on `node` as a seat acting through `surface`, and resume the
/// dispatches it holds.
///
/// # Specification
/// - requires: called within a Tokio runtime; `node` was bound with
///   [`PROTOCOL`] among its protocols.
/// - ensures: returns at once with the receiver of the seat's events, the
///   serving running on tasks of its own. Each accepted link is an
///   [`Event::Accepted`] and each refused connection an [`Event::Unaccepted`];
///   each wake is answered as [`answer`] states; every dispatch whose slot this
///   seat holds, unreported, in a tree its store holds is acted on as [`act`]
///   states. Once the endpoint closes the last event is [`Event::Closed`].
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — an operator wakes a seat serving in-process: the seat
///   announces the link, replies woken, presents itself, acts through a program
///   and reports; a wake to a dispatch it no longer holds is declined; a seat
///   started over a store that holds a dispatch to it, unreported, acts on it
///   and reports unwoken.
/// - witness: `seat::tests::a_woken_seat_presents_acts_and_reports`
/// - witness: `seat::tests::a_seat_resumes_on_start_what_it_holds`
#[inline]
#[must_use]
pub fn serve(
    node: Arc<Node>,
    surface: Surface,
) -> mpsc::UnboundedReceiver<Event>
{
    let (events, heard) = mpsc::unbounded_channel();
    let seat = Arc::new(Seat {
        node,
        surface,
        acting: Mutex::new(BTreeSet::new()),
        events,
    });
    drop(tokio::spawn(resume(Arc::clone(&seat))));
    drop(tokio::spawn(accept(seat)));
    heard
}

/// Accept connections until the endpoint closes, answering each wake on a
/// task of its own.
///
/// # Specification
/// - ensures: as [`serve`] states for links, refusals and wakes; a connection
///   under another protocol the node accepts is closed and told as
///   [`AcceptError::Protocol`]. Ends after telling [`Event::Closed`].
/// - panics: none.
async fn accept(seat: Arc<Seat>)
{
    loop {
        match seat.node.accept().await {
            | Ok(Incoming::Peer(accepted)) => seat.tell(Event::Accepted(accepted)),
            | Ok(Incoming::Protocol {
                protocol,
                connection,
            }) if protocol == PROTOCOL => {
                drop(tokio::spawn(answer(Arc::clone(&seat), connection)));
            },
            | Ok(Incoming::Protocol { connection, .. }) => {
                connection.close(iroh::endpoint::VarInt::from_u32(0), b"unknown protocol");
                seat.tell(Event::Unaccepted(AcceptError::Protocol));
            },
            | Err(AcceptError::Closed) => {
                seat.tell(Event::Closed);
                return;
            },
            | Err(failure) => seat.tell(Event::Unaccepted(failure)),
        }
    }
}

/// Answer the wake `connection` carries, then act on its dispatch when it is
/// held and unreported.
///
/// # Specification
/// - ensures: reads one wake line from the stream the operator opens, considers
///   it ([`Seat::consider`]), writes the reply line and finishes, then waits up
///   to [`LINGER`] for the operator to close the connection. Tells
///   [`Event::Woken`] and acts on the dispatch ([`act`]) when its answer is
///   awaited; tells [`Event::Declined`] for a decline, its reason the one the
///   reply names; tells [`Event::Unanswered`] when the stream fails.
/// - panics: none.
async fn answer(
    seat: Arc<Seat>,
    connection: iroh::endpoint::Connection,
)
{
    let answered = seat.converse(&connection).await;
    let _closed = tokio::time::timeout(LINGER, connection.closed()).await;
    match answered {
        | Err(failure) => seat.tell(Event::Unanswered(failure)),
        | Ok(Err(declined)) => seat.tell(Event::Declined(declined)),
        | Ok(Ok((tree, attempt))) => {
            seat.tell(Event::Woken {
                tree,
                dispatch: attempt.dispatch(),
            });
            if attempt.answer() == Answer::Awaited {
                act(seat, tree, attempt).await;
            }
        },
    }
}

/// Resume every dispatch this seat holds unreported in the trees its store
/// holds.
///
/// # Specification
/// - ensures: for each tree the store holds ([`Peer::trees`]) whose current
///   attempt's slot this seat holds and whose answer is awaited, acts on it
///   ([`act`]) on a task of its own. A tree that cannot be folded is told as
///   [`Event::Unresumed`] and the rest are resumed.
/// - panics: none.
///
/// [`Peer::trees`]: domhringr_record_tree::Peer::trees
async fn resume(seat: Arc<Seat>)
{
    let trees = match seat.node.peer().trees().await {
        | Ok(trees) => trees,
        | Err(failure) => {
            seat.tell(Event::Unresumed(ResumeError::Trees(failure)));
            return;
        },
    };
    let me = seat.node.peer().identity().peer_key();
    for tree in trees {
        let view = match seat.node.peer().view(tree).await {
            | Ok(view) => view,
            | Err(failure) => {
                seat.tell(Event::Unresumed(ResumeError::View { tree, failure }));
                continue;
            },
        };
        if let Current::Attempt(ref attempt) = *view.task().current()
            && attempt.slot() == Slot::Held(me)
            && attempt.answer() == Answer::Awaited
        {
            drop(tokio::spawn(act(Arc::clone(&seat), tree, attempt.clone())));
        }
    }
}

/// Act on `attempt` in `tree` through the seat's surface, once.
///
/// # Specification
/// - ensures: with [`Surface::Hold`], nothing. With [`Surface::Program`], when
///   no act on the same dispatch is running, runs the program as
///   [`Surface::Program`] states and, when it exits 0 with a first line
///   [`Summary`] admits, commits a report on the dispatch: the BLAKE3 hash of
///   its whole standard output, and that line. Tells [`Event::Reported`] with
///   the report's commit, or [`Event::Unreported`] with why none was committed;
///   the slot stays held either way.
/// - panics: none.
async fn act(
    seat: Arc<Seat>,
    tree: TreeId,
    attempt: Attempt,
)
{
    let Surface::Program(ref program) = seat.surface
    else {
        return;
    };
    let dispatch = attempt.dispatch();
    if !seat.acting.lock().await.insert(dispatch) {
        return;
    }
    let reported = seat.report(tree, &attempt, program.clone()).await;
    let _was_acting = seat.acting.lock().await.remove(&dispatch);
    seat.tell(match reported {
        | Ok(report) => Event::Reported { tree, report },
        | Err(failure) => Event::Unreported {
            tree,
            dispatch,
            failure,
        },
    });
}

impl Seat
{
    /// Tell the surface `event`.
    ///
    /// # Specification
    /// - ensures: the event is queued for the receiver [`serve`] returned; once
    ///   that receiver is dropped no one listens, and the event is dropped with
    ///   it.
    /// - panics: none.
    fn tell(
        &self,
        event: Event,
    )
    {
        if let Err(unheard) = self.events.send(event) {
            drop(unheard);
        }
    }

    /// Read the wake on `connection`'s first stream, consider it, and write
    /// the reply.
    ///
    /// # Specification
    /// - ensures: on success the reply line — `woken` for a held dispatch, or
    ///   the decline's reason — is written and the stream finished; returns the
    ///   task and its current attempt, or why the wake was declined.
    /// - fails: [`AnswerError`] when the stream cannot be accepted, read,
    ///   written or finished.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`AnswerError`]: the stream failed.
    async fn converse(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> Result<Result<(TreeId, Attempt), Declined>, AnswerError>
    {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(AnswerError::Stream)?;
        let asked = recv
            .read_to_end(LINE_BYTES)
            .await
            .map_err(AnswerError::Receive)?;
        let read = Line::try_from(asked).and_then(|line| line.as_ref().parse::<Wake>());
        let considered = match read {
            | Ok(wake) => self.consider(&wake).await,
            | Err(malformed) => Err(Declined::Malformed(malformed)),
        };
        let reply = match considered {
            | Ok(_) => Reply::Woken,
            | Err(ref declined) => Reply::Declined(declined.decline()),
        };
        let line = format!("{reply}\n");
        send.write_all(line.as_bytes())
            .await
            .map_err(AnswerError::Send)?;
        send.finish().map_err(AnswerError::Finish)?;
        Ok(considered)
    }

    /// Pull `wake`'s task from its operator, fold it, and decide.
    ///
    /// # Specification
    /// - requires: the operator holds a link to this node, as [`wake`] makes
    ///   before it opens the wake's connection.
    /// - ensures: on success the wake's dispatch is the task's current attempt,
    ///   this seat holds its slot, and the task's book holds this seat's
    ///   presence — committed now ([`Node::present`]) when it lacked one;
    ///   returns the task and the attempt.
    /// - fails: [`Declined::Unsynced`] when the pull fails,
    ///   [`Declined::Unfolded`] when the task cannot be folded,
    ///   [`Declined::NotCurrent`] when the dispatch is not the current attempt,
    ///   [`Declined::NotHeld`] when the slot is with another seat or retired,
    ///   and [`Declined::Unpresented`] when the presence cannot be committed.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Declined`]: as listed above.
    ///
    /// [`wake`]: crate::wake::wake
    async fn consider(
        &self,
        wake: &Wake,
    ) -> Result<(TreeId, Attempt), Declined>
    {
        let tree = wake.tree();
        let _heads = self
            .node
            .pull(wake.operator(), tree)
            .await
            .map_err(Declined::Unsynced)?;
        let view = self
            .node
            .peer()
            .view(tree)
            .await
            .map_err(Declined::Unfolded)?;
        let me = self.node.peer().identity().peer_key();
        let attempt = match *view.task().current() {
            | Current::Attempt(ref attempt) if attempt.dispatch() == wake.dispatch() => attempt,
            | Current::Attempt(_) | Current::Undispatched => return Err(Declined::NotCurrent),
        };
        if attempt.slot() != Slot::Held(me) {
            return Err(Declined::NotHeld);
        }
        if !view.book().contains_key(&me) {
            let _presented = self
                .node
                .present(tree)
                .await
                .map_err(Declined::Unpresented)?;
        }
        Ok((tree, attempt.clone()))
    }

    /// Run `program` on `attempt`'s brief and commit its output as the
    /// report.
    ///
    /// # Specification
    /// - ensures: as [`act`] states for one run: on success the report is
    ///   committed and its commit returned.
    /// - fails: [`ActError::Join`] when the run's task fails,
    ///   [`ActError::Spawn`] when the program cannot run, [`ActError::Exit`]
    ///   when it exits other than 0, [`ActError::Text`] and
    ///   [`ActError::Summary`] when its first line is no summary,
    ///   [`ActError::Random`] when no fence can be drawn, and
    ///   [`ActError::Commit`] when the report cannot be committed.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ActError`]: as listed above.
    async fn report(
        &self,
        tree: TreeId,
        attempt: &Attempt,
        program: PathBuf,
    ) -> Result<CommitId, ActError>
    {
        let dispatch = attempt.dispatch();
        let (kind, brief) = match *attempt.brief() {
            | Brief::Anchor(ref anchor) => ("anchor", anchor.to_string()),
            | Brief::Content(content) => ("content", content.to_string()),
        };
        let task = Anchor::key(tree).to_string();
        let named = Anchor::commit(tree, dispatch).to_string();
        let output = tokio::task::spawn_blocking(move || {
            Command::new(program)
                .args([kind, brief.as_str()])
                .env(TASK, task)
                .env(DISPATCH, named)
                .stdin(Stdio::null())
                .stderr(Stdio::inherit())
                .output()
        })
        .await
        .map_err(ActError::Join)?
        .map_err(ActError::Spawn)?;
        if !output.status.success() {
            return Err(ActError::Exit(output.status));
        }
        let first = output
            .stdout
            .split(|&byte| byte == b'\n')
            .next()
            .unwrap_or_default();
        let summary = core::str::from_utf8(first)
            .map_err(|_not_utf8| ActError::Text)?
            .parse::<Summary>()
            .map_err(ActError::Summary)?;
        let content = ContentHash::of(&Content::from(output.stdout));
        let receipt = Receipt::report(tree, dispatch, content, summary)?;
        Ok(self.node.peer().commit(tree, receipt).await?)
    }
}

/// Why a seat declined a wake.
#[derive(Debug, thiserror::Error)]
pub enum Declined
{
    /// The wake is malformed.
    #[error("the wake is malformed")]
    Malformed(#[source] ParseWakeError),
    /// The task cannot be pulled from the operator.
    #[error("cannot pull the task from the operator")]
    Unsynced(#[source] SyncError),
    /// The task cannot be folded.
    #[error("cannot fold the task")]
    Unfolded(#[source] ViewError),
    /// The dispatch is not the task's current attempt.
    #[error("the dispatch is not the task's current attempt")]
    NotCurrent,
    /// This seat does not hold the dispatch's slot.
    #[error("this seat does not hold the dispatch's slot")]
    NotHeld,
    /// This seat cannot present itself in the task.
    #[error("cannot present this seat in the task")]
    Unpresented(#[source] PresentError),
}

impl Declined
{
    /// The reason the reply names.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn decline(&self) -> Decline
    {
        match *self {
            | Self::Malformed(_) => Decline::Malformed,
            | Self::Unsynced(_) => Decline::Unsynced,
            | Self::Unfolded(_) => Decline::Unfolded,
            | Self::NotCurrent => Decline::NotCurrent,
            | Self::NotHeld => Decline::NotHeld,
            | Self::Unpresented(_) => Decline::Unpresented,
        }
    }
}

/// Why a wake's stream failed on the seat's side.
#[derive(Debug, thiserror::Error)]
pub enum AnswerError
{
    /// The operator opened no stream.
    #[error("no wake stream opened")]
    Stream(#[source] iroh::endpoint::ConnectionError),
    /// The wake cannot be read.
    #[error("cannot read the wake")]
    Receive(#[source] iroh::endpoint::ReadToEndError),
    /// The reply cannot be written.
    #[error("cannot write the reply")]
    Send(#[source] iroh::endpoint::WriteError),
    /// The reply's stream cannot be finished.
    #[error("cannot finish the reply's stream")]
    Finish(#[source] iroh::endpoint::ClosedStream),
}

/// Why an act committed no report.
#[derive(Debug, thiserror::Error)]
pub enum ActError
{
    /// The task running the program failed.
    #[error("the surface's task failed")]
    Join(#[source] tokio::task::JoinError),
    /// The program cannot run.
    #[error("cannot run the surface's program")]
    Spawn(#[source] std::io::Error),
    /// The program exited other than 0.
    #[error("the surface's program exited with {0}")]
    Exit(ExitStatus),
    /// The program's first line is not UTF-8.
    #[error("the surface's first line is not UTF-8")]
    Text,
    /// The program's first line is no summary.
    #[error("the surface's first line is no summary")]
    Summary(#[source] ParseSummaryError),
    /// No operation fence can be drawn for the report.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// The report cannot be committed.
    #[error(transparent)]
    Commit(#[from] CommitError),
}

/// Why a seat could not read what to resume.
#[derive(Debug, thiserror::Error)]
pub enum ResumeError
{
    /// The store's trees cannot be listed.
    #[error(transparent)]
    Trees(#[from] TreesError),
    /// A tree cannot be folded.
    #[error("cannot fold the tree {tree} to resume it")]
    View
    {
        /// The tree.
        tree: TreeId,
        /// Why.
        #[source]
        failure: ViewError,
    },
}

#[cfg(test)]
mod tests
{
    use alloc::sync::Arc;
    use core::time::Duration;
    use std::path::PathBuf;

    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::Answer;
    use domhringr_record_tree::Authority;
    use domhringr_record_tree::BindPort;
    use domhringr_record_tree::Brief;
    use domhringr_record_tree::Content;
    use domhringr_record_tree::ContentHash;
    use domhringr_record_tree::Current;
    use domhringr_record_tree::Endpoint;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::Peer;
    use domhringr_record_tree::Receipt;
    use domhringr_record_tree::RemotePeer;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::Step;
    use domhringr_record_tree::TreeKey;
    use domhringr_record_tree::UdpPort;
    use tokio::sync::mpsc;

    use super::Event;
    use super::Surface;
    use super::serve;
    use crate::wake::Decline;
    use crate::wake::PROTOCOL;
    use crate::wake::Wake;
    use crate::wake::WakeError;
    use crate::wake::wake;

    /// How long a test waits for the seat's next event.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// The seat's next event, within [`DEADLINE`].
    ///
    /// # Specification
    /// trivial.
    async fn next(events: &mut mpsc::UnboundedReceiver<Event>) -> Event
    {
        tokio::time::timeout(DEADLINE, events.recv())
            .await
            .unwrap()
            .unwrap()
    }

    /// A UDP port free on this host now.
    ///
    /// # Specification
    /// trivial.
    fn free_port() -> UdpPort
    {
        let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        port.to_string().parse().unwrap()
    }

    #[test]
    fn a_woken_seat_presents_acts_and_reports()
    {
        let (operator_root, seat_root) =
            (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let operator_state = StateDir::from(operator_root.path().to_path_buf());
            let identity = Identity::load_or_create(&operator_state).unwrap();
            let me = identity.peer_key();
            let operator = Peer::open(&operator_state, identity)
                .unwrap()
                .bind(BindPort::Ephemeral, &[])
                .await
                .unwrap();
            let key = TreeKey::mint(&operator_state).unwrap();
            let tree = key.tree();
            let _opened = operator
                .peer()
                .commit(tree, Receipt::open(&key, me).unwrap())
                .await
                .unwrap();

            let seat_state = StateDir::from(seat_root.path().to_path_buf());
            let identity = Identity::load_or_create(&seat_state).unwrap();
            let seat_key = identity.peer_key();
            let port = free_port();
            let seat = Arc::new(
                Peer::open(&seat_state, identity)
                    .unwrap()
                    .bind(BindPort::Fixed(port), &[PROTOCOL])
                    .await
                    .unwrap(),
            );
            let mut events = serve(Arc::clone(&seat), Surface::Program(PathBuf::from("echo")));
            let reached = format!("{}@127.0.0.1:{port}", seat.endpoint_key())
                .parse::<Endpoint>()
                .unwrap();
            let remote = RemotePeer::new(reached, seat_key);

            let anchor = Anchor::Path {
                authority: Authority::Key(tree),
                path: "briefs/one".parse().unwrap(),
            };
            let receipt = Receipt::dispatch(tree, seat_key, Brief::Anchor(anchor.clone())).unwrap();
            let dispatch = operator.peer().commit(tree, receipt).await.unwrap();
            wake(&operator, &remote, &Wake::new(tree, dispatch, me))
                .await
                .unwrap();
            assert!(
                matches!(next(&mut events).await, Event::Accepted(ref linked) if linked.peer() == me),
                "the seat admits the operator's link"
            );
            assert!(
                matches!(
                    next(&mut events).await,
                    Event::Woken { tree: woken, dispatch: answered }
                        if woken == tree && answered == dispatch
                ),
                "the seat replies woken to the dispatch it holds"
            );
            let Event::Reported { report, .. } = next(&mut events).await
            else {
                panic!("the seat acts on the dispatch and reports");
            };
            assert!(
                operator
                    .peer()
                    .view(tree)
                    .await
                    .unwrap()
                    .book()
                    .contains_key(&seat_key),
                "the woken operator holds the seat's presence"
            );

            let _synced = operator.sync(&remote, tree).await.unwrap();
            assert!(matches!(next(&mut events).await, Event::Accepted(_)));
            let view = operator.peer().view(tree).await.unwrap();
            let summary = format!("anchor {anchor}");
            let output = format!("{summary}\n").into_bytes();
            assert!(
                view.task().steps().contains(&(report, Step::Report {
                    dispatch,
                    author: seat_key,
                    content: ContentHash::of(&Content::from(output)),
                    summary: summary.parse().unwrap(),
                })),
                "the report hashes the program's whole output and summarizes its first line"
            );
            assert!(
                matches!(
                    *view.task().current(),
                    Current::Attempt(ref attempt) if attempt.answer() == Answer::Reported(report)
                ),
                "the report answers the current attempt"
            );

            let receipt = Receipt::dispatch(tree, me, Brief::Anchor(anchor)).unwrap();
            let elsewhere = operator.peer().commit(tree, receipt).await.unwrap();
            let declined = wake(&operator, &remote, &Wake::new(tree, elsewhere, me)).await;
            assert!(
                matches!(declined, Err(WakeError::Declined(Decline::NotHeld))),
                "a seat declines a dispatch to another seat by name: {declined:?}"
            );
            assert!(matches!(next(&mut events).await, Event::Accepted(_)));
            assert!(
                matches!(next(&mut events).await, Event::Declined(ref declined) if declined.decline() == Decline::NotHeld),
                "the seat tells its decline"
            );
            operator.close().await;
            drop(operator);
            seat.close().await;
            drop(seat);
        });
    }

    #[test]
    fn a_seat_resumes_on_start_what_it_holds()
    {
        let root = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let state = StateDir::from(root.path().to_path_buf());
            let identity = Identity::load_or_create(&state).unwrap();
            let me = identity.peer_key();
            let seat = Arc::new(
                Peer::open(&state, identity)
                    .unwrap()
                    .bind(BindPort::Ephemeral, &[PROTOCOL])
                    .await
                    .unwrap(),
            );
            let key = TreeKey::mint(&state).unwrap();
            let tree = key.tree();
            let _opened = seat
                .peer()
                .commit(tree, Receipt::open(&key, me).unwrap())
                .await
                .unwrap();
            let brief = Brief::Content(ContentHash::of(&Content::from(b"brief".to_vec())));
            let receipt = Receipt::dispatch(tree, me, brief).unwrap();
            let dispatch = seat.peer().commit(tree, receipt).await.unwrap();

            let mut events = serve(Arc::clone(&seat), Surface::Program(PathBuf::from("echo")));
            let Event::Reported {
                tree: reported_in,
                report,
            } = next(&mut events).await
            else {
                panic!("the seat resumes the dispatch it holds and reports");
            };
            assert_eq!(reported_in, tree);
            let view = seat.peer().view(tree).await.unwrap();
            assert!(
                matches!(
                    *view.task().current(),
                    Current::Attempt(ref attempt)
                        if attempt.dispatch() == dispatch
                            && attempt.answer() == Answer::Reported(report)
                ),
                "the report answers the dispatch the seat held"
            );
            seat.close().await;
            drop(seat);
        });
    }
}
