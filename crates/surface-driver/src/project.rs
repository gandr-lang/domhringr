//! The project: where the operator's tasks are bound and its seats present.
//!
//! A project is a tree the operator holds. Each task is a tree of its own,
//! bound in the project at `tasks/<name>` to the task tree's anchor; the
//! project's book says where each seat is reached. A task tree's own book
//! names its seat once the seat has presented itself there, so a seat is
//! reached through the task's book first and the project's after.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use domhringr_record_evidence::Evidence;
use domhringr_record_tree::Aim;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::Answer;
use domhringr_record_tree::At;
use domhringr_record_tree::Authority;
use domhringr_record_tree::BindPort;
use domhringr_record_tree::Brief;
use domhringr_record_tree::Current;
use domhringr_record_tree::Node;
use domhringr_record_tree::ParseAnchorError;
use domhringr_record_tree::Path;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::RemotePeer;
use domhringr_record_tree::Route;
use domhringr_record_tree::RouteError;
use domhringr_record_tree::Slot;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::SyncError;
use domhringr_record_tree::Target;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::TreeKey;
use domhringr_record_tree::View;
use domhringr_record_tree::ViewError;
use domhringr_seat_slot::Wake;
use gandr_storage_values::ManifestDigest;

use crate::RunError;
use crate::change;
use crate::emit;
use crate::report;

/// The segment every task's path in its project begins with.
const TASKS: &str = "tasks";

/// A task as the command line names it: its path `tasks/<name>` in a
/// project, and the project, when its anchor names one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskName
{
    /// The project the task's anchor names, if any.
    within: Within,
    /// The task's path in its project.
    path: Path,
}

/// Which project a task's name holds for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Within
{
    /// Any: the name was given bare.
    Any,
    /// This one: the name was given as an anchor in it.
    Project(TreeId),
}

impl TaskName
{
    /// The task's path in its project: `tasks/<name>`.
    ///
    /// # Specification
    /// trivial.
    pub const fn path(&self) -> &Path
    {
        &self.path
    }

    /// Check that the name holds for `project`.
    ///
    /// # Specification
    /// - ensures: `Ok` for a bare name, and for an anchor in `project`.
    /// - fails: [`RunError::OtherProject`] for an anchor in another project.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RunError::OtherProject`]: the anchor names another project.
    fn within(
        &self,
        project: TreeId,
    ) -> Result<(), RunError>
    {
        match self.within {
            | Within::Project(named) if named != project => Err(RunError::OtherProject(named)),
            | Within::Any | Within::Project(_) => Ok(()),
        }
    }
}

impl FromStr for TaskName
{
    type Err = ParseTaskError;

    /// Read a task's name, or the anchor of its path in its project.
    ///
    /// # Specification
    /// - ensures: text beginning `domhringr://` is read as an anchor, which
    ///   must name the path `tasks/<name>` in a tree named by its key; any
    ///   other text is the name itself. A name is one or more ASCII letters,
    ///   digits, `-`, `_` and `.`, not beginning with `.`.
    /// - fails: [`ParseTaskError::Anchor`] for an anchor that does not read,
    ///   [`ParseTaskError::NotTask`] for one naming the tree, a commit, another
    ///   path, or its tree by a DNS name or a label, and
    ///   [`ParseTaskError::Name`] for a name that is not one.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseTaskError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a bare name and a task anchor read to the same path;
    ///   a name holding a slash, a path anchor outside `tasks/` and a project
    ///   anchor in a task's place are refused.
    /// - witness: `tests::every_verb_reads_its_options`
    /// - witness: `tests::a_malformed_command_line_is_refused`
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let task_path = |name: &str| {
            let named = !name.is_empty()
                && !name.starts_with('.')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
            if !named {
                return Err(ParseTaskError::Name);
            }
            format!("{TASKS}/{name}")
                .parse::<Path>()
                .map_err(|_reserved: ParseAnchorError| ParseTaskError::Name)
        };
        if !text.starts_with("domhringr://") {
            return Ok(Self {
                within: Within::Any,
                path: task_path(text)?,
            });
        }
        let Anchor::Path {
            authority: Authority::Key(project),
            path,
        } = text.parse::<Anchor>().map_err(ParseTaskError::Anchor)?
        else {
            return Err(ParseTaskError::NotTask);
        };
        let name = path
            .as_ref()
            .strip_prefix(TASKS)
            .and_then(|rest| rest.strip_prefix('/'))
            .ok_or(ParseTaskError::NotTask)?;
        Ok(Self {
            within: Within::Project(project),
            path: task_path(name)?,
        })
    }
}

impl fmt::Display for TaskName
{
    /// Write the task's path in its project.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Display::fmt(&self.path, f)
    }
}

/// Why a text names no task.
#[derive(Debug, thiserror::Error)]
pub enum ParseTaskError
{
    /// The name holds a character a task's name does not.
    #[error("a task's name is ASCII letters, digits, `-`, `_` and `.`, not beginning with `.`")]
    Name,
    /// The text begins as an anchor and is none.
    #[error("cannot read the task's anchor")]
    Anchor(#[source] ParseAnchorError),
    /// The anchor names no task's path in a tree named by its key.
    #[error("a task's anchor is domhringr://<project-id>/tasks/<name>")]
    NotTask,
}

/// What the project binds a task's path to.
enum Found
{
    /// This task tree.
    Tree(TreeId),
    /// Nothing.
    Unbound,
}

/// The tree the project binds `task` to.
///
/// # Specification
/// - ensures: yields the tree the binding of the task's path in the project's
///   view names.
/// - fails: as [`find`], and [`RunError::Unbound`] when the path is unbound.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests verify, decide and land tasks by name
///   after a dispatch bound them.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
async fn task(
    peer: &Peer,
    project: TreeId,
    task: &TaskName,
) -> Result<TreeId, RunError>
{
    match find(peer, project, task).await? {
        | Found::Tree(tree) => Ok(tree),
        | Found::Unbound => Err(RunError::Unbound(task.path().clone())),
    }
}

/// What `project` binds `task`'s path to, as the local store folds it.
///
/// # Specification
/// - ensures: [`Found::Tree`] when the path's binding is a tree's bare anchor
///   in the key form, [`Found::Unbound`] when the path is unbound.
/// - fails: [`RunError::OtherProject`] when the task's anchor names another
///   project, [`RunError::View`] when the project cannot be folded, and
///   [`RunError::NotTask`] when the path is bound to anything else.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
async fn find(
    peer: &Peer,
    project: TreeId,
    task: &TaskName,
) -> Result<Found, RunError>
{
    task.within(project)?;
    let view = peer.view(project).await?;
    match view.bindings().get(task.path()) {
        | Some(&(_, Target::Anchor(Anchor::Tree(Authority::Key(tree))))) => Ok(Found::Tree(tree)),
        | Some(_) => Err(RunError::NotTask(task.path().clone())),
        | None => Ok(Found::Unbound),
    }
}

/// The tasks `view`, a project's, binds: each path `tasks/<name>` bound to a
/// tree's bare anchor in the key form, with that tree, in path order.
///
/// # Specification
/// trivial.
fn tasks(view: &View) -> Vec<(Path, TreeId)>
{
    view.bindings()
        .iter()
        .filter_map(|(path, bound)| {
            let name = path.as_ref().strip_prefix(TASKS)?.strip_prefix('/')?;
            match bound.1 {
                | Target::Anchor(Anchor::Tree(Authority::Key(tree))) if !name.contains('/') => {
                    Some((path.clone(), tree))
                },
                | Target::Anchor(_) | Target::Endpoint(_) | Target::Datum(_) => None,
            }
        })
        .collect()
}

/// Where a dispatch is committed: the state directory a new task's key is
/// minted beneath, the operator, and the project.
#[derive(Clone, Copy)]
pub struct Dispatching<'state>
{
    /// The state directory.
    pub state: &'state StateDir,
    /// This peer: the operator.
    pub operator: PeerKey,
    /// The project.
    pub project: TreeId,
}

/// Dispatch `seat` to `brief` on `task` and wake it, as `on` names.
///
/// # Specification
/// - ensures: a task the project does not bind is minted first: a tree under a
///   fresh key, opened by the operator, and bound at the task's path in the
///   project. The seat is reached as [`reach`] reaches it before anything is
///   dispatched, so a seat no endpoint names gets no dispatch. When the task's
///   current attempt puts `seat` in its slot, held, to `brief`, that dispatch
///   is re-sent; otherwise a dispatch of `seat` to `brief` is committed. Writes
///   `dispatch <commit-anchor>` at once, binds an ephemeral endpoint, wakes the
///   seat ([`domhringr_seat_slot::wake`]), closes the endpoint, and writes
///   `woken`.
/// - fails: as [`find`] and [`reach`], [`RunError::Identity`] when the task's
///   key cannot be minted, [`RunError::Random`] and [`RunError::Commit`] when a
///   receipt cannot be committed, [`RunError::View`] when the task cannot be
///   folded, [`RunError::Bind`] when the endpoint cannot bind,
///   [`RunError::Wake`] when the seat is not woken — the dispatch stays
///   committed, to be re-sent — and [`RunError::Output`] when standard output
///   cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests dispatch two seats to two new tasks
///   through the project's book, each seat woken and reporting, and the tasks
///   listed by `open` with their dispatches.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
/// - witness: `operator::tests::open_lists_every_seat_and_task`
pub async fn dispatch(
    peer: Peer,
    on: Dispatching<'_>,
    task: &TaskName,
    seat: PeerKey,
    brief: Brief,
    at: At,
) -> Result<(), RunError>
{
    let tree = match find(&peer, on.project, task).await? {
        | Found::Tree(tree) => tree,
        | Found::Unbound => {
            let key = TreeKey::mint(on.state)?;
            let tree = key.tree();
            peer.commit(tree, Receipt::open(&key, on.operator)?).await?;
            let bound = Receipt::bind(
                on.project,
                task.path().clone(),
                Target::Anchor(Anchor::key(tree)),
            )?;
            peer.commit(on.project, bound).await?;
            tree
        },
    };
    let remote = reach(&peer, on.project, tree, seat, at).await?;
    let view = peer.view(tree).await?;
    let resent = match *view.task().current() {
        | Current::Attempt(ref attempt)
            if attempt.slot() == Slot::Held(seat) && *attempt.brief() == brief =>
        {
            Some(attempt.dispatch())
        },
        | Current::Attempt(_) | Current::Undispatched => None,
    };
    let dispatch = match resent {
        | Some(dispatch) => dispatch,
        | None => {
            let receipt = Receipt::dispatch(tree, seat, brief)?;
            peer.commit(tree, receipt).await?
        },
    };
    emit(&format_args!(
        "dispatch {}\n",
        Anchor::commit(tree, dispatch)
    ))?;
    let node = peer.bind(BindPort::Ephemeral, &[]).await?;
    let woken =
        domhringr_seat_slot::wake(&node, &remote, &Wake::new(tree, dispatch, on.operator)).await;
    node.close().await;
    drop(node);
    woken?;
    emit(&"woken\n")
}

/// Why a seat cannot be reached, or a task synced from it.
#[derive(Debug, thiserror::Error)]
pub enum Unreached
{
    /// Neither book names the seat, or a tree cannot be folded.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// The seat is this peer.
    #[error("the seat is this peer: no one to reach")]
    Itself,
    /// The sync failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
}

/// The remote at which `seat` is reached for the task `tree` of `project`.
///
/// # Specification
/// - ensures: routes to `seat` for `tree` as `at` says ([`Peer::route`]); when
///   the task's book holds no presence of it, routes through the project's book
///   instead.
/// - fails: [`Unreached::Route`] when neither book names the seat, or a tree
///   cannot be folded, and [`Unreached::Itself`] when the seat is this peer.
/// - panics: none.
///
/// # Errors
/// - [`Unreached`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — a first dispatch reaches its seat through the project's
///   book, the task's holding none, and a later sync of the task reaches it
///   through the task's.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
async fn reach(
    peer: &Peer,
    project: TreeId,
    tree: TreeId,
    seat: PeerKey,
    at: At,
) -> Result<RemotePeer, Unreached>
{
    let route = match peer.route(tree, Aim::Peer(seat), at).await {
        | Err(RouteError::Unreachable { .. }) => {
            peer.route(project, Aim::Peer(seat), At::Book).await?
        },
        | routed => routed?,
    };
    match route {
        | Route::Itself => Err(Unreached::Itself),
        | Route::Book { remote, .. } | Route::Given { remote } => Ok(remote),
    }
}

/// Whose report a task awaits.
enum Awaiting
{
    /// This seat holds the current dispatch's slot and has not reported.
    Seat(PeerKey),
    /// No one: the task has no dispatch, its dispatch is reported on or
    /// retired from, or the store does not hold the task.
    Nothing,
}

/// Whose report the task `tree` awaits, as the local store folds it.
///
/// # Specification
/// trivial.
async fn awaited(
    peer: &Peer,
    tree: TreeId,
) -> Result<Awaiting, RunError>
{
    let view = match peer.view(tree).await {
        | Ok(view) => view,
        | Err(ViewError::Unopened(_)) => return Ok(Awaiting::Nothing),
        | Err(failure) => return Err(RunError::View(failure)),
    };
    Ok(match *view.task().current() {
        | Current::Attempt(ref attempt) => match (attempt.slot(), attempt.answer()) {
            | (Slot::Held(seat), Answer::Awaited) => Awaiting::Seat(seat),
            | (Slot::Held(_) | Slot::Retired { .. }, _) => Awaiting::Nothing,
        },
        | Current::Undispatched => Awaiting::Nothing,
    })
}

/// Sync the task `tree` of `project` from `seat` over `node`.
///
/// # Specification
/// - ensures: reaches the seat as [`reach`] does, through the books, and syncs
///   the task with it ([`Node::sync`]).
/// - fails: as [`reach`], and [`Unreached::Sync`] when the sync fails.
/// - panics: none.
///
/// # Errors
/// - [`Unreached`]: as listed above.
async fn catch_up(
    node: &Node,
    project: TreeId,
    tree: TreeId,
    seat: PeerKey,
) -> Result<(), Unreached>
{
    let remote = reach(node.peer(), project, tree, seat, At::Book).await?;
    let _synced = node.sync(&remote, tree).await?;
    Ok(())
}

/// The operator's store: bound to an endpoint when a command had to dial.
pub enum Store
{
    /// The store alone.
    Local(Peer),
    /// The store, bound.
    Bound(Node),
}

impl Store
{
    /// The store.
    ///
    /// # Specification
    /// trivial.
    pub const fn peer(&self) -> &Peer
    {
        match *self {
            | Self::Local(ref peer) => peer,
            | Self::Bound(ref node) => node.peer(),
        }
    }

    /// Close the endpoint, when bound; the store closes when dropped.
    ///
    /// # Specification
    /// trivial.
    pub async fn close(&self)
    {
        if let Self::Bound(ref node) = *self {
            node.close().await;
        }
    }
}

/// Whose report's content the evidence store lacks.
enum Unheld
{
    /// The current attempt's report names content not held whole.
    Report
    {
        /// The seat that reported, which holds the content.
        author: PeerKey,
        /// The content.
        content: ManifestDigest,
    },
    /// Nothing to fetch: the store holds the content whole, or the task has
    /// no report on its current dispatch to act on.
    Nothing,
}

/// Whose report's content on the task `tree` `evidence` lacks, as the local
/// store folds it.
///
/// # Specification
/// trivial.
async fn unheld(
    peer: &Peer,
    tree: TreeId,
    evidence: &Evidence,
) -> Result<Unheld, RunError>
{
    let view = match peer.view(tree).await {
        | Ok(view) => view,
        | Err(ViewError::Unopened(_)) => return Ok(Unheld::Nothing),
        | Err(failure) => return Err(RunError::View(failure)),
    };
    Ok(match change::reported(&view) {
        | Ok(reported) if evidence.read(reported.content).is_err() => Unheld::Report {
            author: reported.author,
            content: reported.content,
        },
        | Ok(_) | Err(_) => Unheld::Nothing,
    })
}

/// Fetch the report `content` of the task `tree` of `project` from its
/// `author` over `node`, into `evidence`.
///
/// # Specification
/// - ensures: reaches the author as [`reach`] does, through the books, and
///   fetches the content ([`domhringr_record_evidence::fetch`]): every chunk of
///   its closure checked and the value kept before this returns.
/// - fails: [`RunError::Reach`] as [`reach`] fails, and [`RunError::Fetch`] as
///   the fetch refuses.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
async fn fetch(
    node: &Node,
    project: TreeId,
    tree: TreeId,
    (author, content): (PeerKey, ManifestDigest),
    evidence: &Evidence,
) -> Result<(), RunError>
{
    let remote = reach(node.peer(), project, tree, author, At::Book).await?;
    let _content =
        domhringr_record_evidence::fetch(node, remote.endpoint(), content, evidence).await?;
    Ok(())
}

/// The task `name` names in `project`, and the store holding its current
/// report and the report's content: the task synced from its seat first
/// when the attempt awaits a report, and the content fetched from the
/// report's author when `evidence` lacks it.
///
/// # Specification
/// - ensures: names the task's tree as [`task`] does. When the current
///   dispatch's seat holds the slot without a report, binds an ephemeral
///   endpoint and syncs the task from that seat ([`catch_up`]). Then, when the
///   current attempt's report names content `evidence` does not hold whole,
///   binds an ephemeral endpoint unless bound and fetches the content from the
///   report's author ([`fetch`]). Returns the tree, and the store bound when it
///   dialed and alone otherwise; a task with no report on its current dispatch
///   to act on is returned as it stands, for the command to refuse.
/// - fails: as [`task`], [`RunError::View`] when the task cannot be folded,
///   [`RunError::Bind`] when the endpoint cannot bind, and as [`catch_up`] and
///   [`fetch`], the endpoint closed first.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — the process tests verify, decide and land tasks by name
///   after a dispatch bound them; verify a change the operator learns of only
///   by this sync, the seat having reported after its wake; and verify and
///   decide changes whose reports the operator holds only by this fetch, the
///   listing having synced the reports alone.
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
/// - witness: `operator::tests::a_refused_merge_commits_nothing`
pub async fn caught_up(
    peer: Peer,
    project: TreeId,
    name: &TaskName,
    evidence: &Evidence,
) -> Result<(TreeId, Store), RunError>
{
    let tree = task(&peer, project, name).await?;
    let awaiting = awaited(&peer, tree).await?;
    let store = match awaiting {
        | Awaiting::Nothing => Store::Local(peer),
        | Awaiting::Seat(seat) => {
            let node = peer.bind(BindPort::Ephemeral, &[]).await?;
            if let Err(failure) = catch_up(&node, project, tree, seat).await {
                node.close().await;
                drop(node);
                return Err(RunError::Reach(failure));
            }
            Store::Bound(node)
        },
    };
    holding(store, project, tree, evidence)
        .await
        .map(|store| (tree, store))
}

/// `store`, holding the content of the report on `tree`'s current dispatch:
/// fetched from the report's author when `evidence` lacks it.
///
/// # Specification
/// - ensures: when the current attempt's report names content `evidence` does
///   not hold whole ([`unheld`]), binds an ephemeral endpoint unless bound and
///   fetches the content from the report's author ([`fetch`]), returning the
///   store bound; otherwise returns `store` as it was.
/// - fails: [`RunError::View`] when the task cannot be folded,
///   [`RunError::Bind`] when the endpoint cannot bind, and as [`fetch`], the
///   endpoint closed first.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
async fn holding(
    store: Store,
    project: TreeId,
    tree: TreeId,
    evidence: &Evidence,
) -> Result<Store, RunError>
{
    let lacking = match unheld(store.peer(), tree, evidence).await {
        | Ok(Unheld::Report { author, content }) => (author, content),
        | Ok(Unheld::Nothing) => return Ok(store),
        | Err(failure) => {
            store.close().await;
            return Err(failure);
        },
    };
    let node = match store {
        | Store::Local(peer) => peer.bind(BindPort::Ephemeral, &[]).await?,
        | Store::Bound(node) => node,
    };
    if let Err(failure) = fetch(&node, project, tree, lacking, evidence).await {
        node.close().await;
        drop(node);
        return Err(failure);
    }
    Ok(Store::Bound(node))
}

/// List the seats and the tasks of `project`, as `operator`.
///
/// # Specification
/// - ensures: syncs each task whose seat holds its slot without a report from
///   that seat ([`catch_up`]) over one ephemeral endpoint, writing a sync that
///   fails to standard error as `cannot sync the task <anchor>` and its cause
///   and going on; then writes `project <anchor>`, `seat <peer-id> <endpoint>
///   <commit-id>` for each presence in the project's book but the operator's,
///   in key order, and `task <anchor> <standing>` for each task in path order,
///   the standing as [`Current`]'s display writes it, or `unheld` for a task
///   tree the store does not hold.
/// - fails: [`RunError::View`] when a tree cannot be folded, [`RunError::Bind`]
///   when the endpoint cannot bind, [`RunError::Diagnostics`] when standard
///   error cannot be written, and [`RunError::Output`] when standard output
///   cannot be written.
/// - panics: none.
///
/// # Errors
/// - [`RunError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — a project of two present seats and two dispatched tasks
///   lists both seats and both tasks with their standings, after the seats
///   reported, as the process test reads them.
/// - witness: `operator::tests::open_lists_every_seat_and_task`
/// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
pub async fn open(
    peer: Peer,
    operator: PeerKey,
    project: TreeId,
) -> Result<(), RunError>
{
    let view = peer.view(project).await?;
    let tasks = tasks(&view);
    let mut awaiting = Vec::new();
    for &(ref path, tree) in &tasks {
        if let Awaiting::Seat(seat) = awaited(&peer, tree).await? {
            awaiting.push((path, tree, seat));
        }
    }
    let store = if awaiting.is_empty() {
        Store::Local(peer)
    }
    else {
        Store::Bound(peer.bind(BindPort::Ephemeral, &[]).await?)
    };
    let mut reported = Ok(());
    if let Store::Bound(ref node) = store {
        for (path, tree, seat) in awaiting {
            if let Err(failure) = catch_up(node, project, tree, seat).await {
                let unsynced = RunError::Unsynced {
                    task: in_project(project, path),
                    cause: Box::new(failure),
                };
                reported = reported.and_then(|()| report(&unsynced));
            }
        }
    }
    let listed = listing(store.peer(), operator, project, &view, &tasks).await;
    store.close().await;
    drop(store);
    reported.map_err(RunError::Diagnostics)?;
    emit(&listed?)
}

/// The anchor of `path` in `project`.
///
/// # Specification
/// trivial.
fn in_project(
    project: TreeId,
    path: &Path,
) -> Anchor
{
    Anchor::Path {
        authority: Authority::Key(project),
        path: path.clone(),
    }
}

/// The lines `open` writes for `project`, whose view is `view` and whose
/// tasks are `tasks`, as `operator`.
///
/// # Specification
/// - ensures: as [`open`] writes them.
/// - fails: [`RunError::View`] when a task tree the store holds cannot be
///   folded.
/// - panics: none.
///
/// # Errors
/// - [`RunError::View`]: a task cannot be folded.
async fn listing(
    peer: &Peer,
    operator: PeerKey,
    project: TreeId,
    view: &View,
    tasks: &[(Path, TreeId)],
) -> Result<String, RunError>
{
    let mut lines = vec![format!("project {}\n", Anchor::key(project))];
    for (seat, presence) in view.book() {
        if *seat != operator {
            lines.push(format!("seat {seat} {presence}\n"));
        }
    }
    for &(ref path, tree) in tasks {
        let standing = match peer.view(tree).await {
            | Ok(task) => task.task().current().to_string(),
            | Err(ViewError::Unopened(_)) => String::from("unheld"),
            | Err(failure) => return Err(RunError::View(failure)),
        };
        lines.push(format!("task {} {standing}\n", in_project(project, path)));
    }
    Ok(lines.concat())
}
