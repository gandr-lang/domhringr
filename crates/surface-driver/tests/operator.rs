//! The operator's loop, exercised as processes: two seats serve in-process
//! through a script that commits a change to a throwaway git repository and
//! reports it, and the driver binary dispatches them, verifies, decides and
//! lands their changes — fetching each report from its seat as evidence — and
//! lists the project, from its own state directory.

extern crate alloc;

#[cfg(test)]
mod tests
{
    use alloc::sync::Arc;
    use core::fmt;
    use core::net::Ipv4Addr;
    use core::net::SocketAddr;
    use core::time::Duration;
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;
    use std::process::Stdio;

    use domhringr_record_evidence::Evidence;
    use domhringr_record_evidence::ParsedDigest;
    use domhringr_record_tree::AcceptError;
    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::BindPort;
    use domhringr_record_tree::CommitId;
    use domhringr_record_tree::Endpoint;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::Node;
    use domhringr_record_tree::Peer;
    use domhringr_record_tree::PeerKey;
    use domhringr_record_tree::Receipt;
    use domhringr_record_tree::RemotePeer;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::TreeId;
    use domhringr_record_tree::TreeKey;
    use domhringr_record_tree::UdpPort;
    use domhringr_seat_slot::Event;
    use domhringr_seat_slot::PROTOCOL;
    use domhringr_seat_slot::Surface;
    use domhringr_seat_slot::serve;
    use tokio::sync::mpsc;

    /// How long a test waits for a seat's next event.
    const DEADLINE: Duration = Duration::from_secs(60);

    /// The brief every dispatch names, by content hash.
    const BRIEF: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    /// A playbook of one verifier, which passes only in a checkout holding
    /// the change's file: the repository's own branch has none.
    const PLAYBOOK: &str = r#"name = "check"

[[steps]]
id = "content"
why = "The change writes its content."
verifier = { command = "sh", args = ["-c", "test -s change.txt"] }
"#;

    /// A rubric of one question over the state `decide` writes.
    const RUBRIC: &str = r#"name = "change"
state = ["change.diff", "commits.txt"]

[band]
low = 0.2
high = 0.8

[questions.scoped]
instructions = "Read the diff. Does it change change.txt alone?"
criteria.true = "The diff changes change.txt alone."
criteria.false = "The diff changes another file."
"#;

    /// What a seat's script writes to `change.txt`.
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    struct Written(&'static str);

    /// A task's name in the project.
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    struct Task(&'static str);

    impl AsRef<OsStr> for Task
    {
        /// The name, as an operand.
        ///
        /// # Specification
        /// trivial.
        fn as_ref(&self) -> &OsStr
        {
            OsStr::new(self.0)
        }
    }

    impl fmt::Display for Task
    {
        /// Write the name.
        ///
        /// # Specification
        /// trivial.
        fn fmt(
            &self,
            f: &mut fmt::Formatter<'_>,
        ) -> fmt::Result
        {
            f.write_str(self.0)
        }
    }

    /// Which of the world's two seats.
    #[derive(Clone, Copy)]
    enum Which
    {
        /// The first made.
        First,
        /// The second made.
        Second,
    }

    /// How the driver is expected to exit.
    #[derive(Clone, Copy, Debug)]
    enum Exit
    {
        /// 0: the command did what it says.
        Success,
        /// 3: `decide` decided nothing.
        Undecided,
    }

    /// The ruling a table records for the rubric's question.
    #[derive(Clone, Copy)]
    enum Ruled
    {
        /// The criterion holds, above the band.
        Holds,
        /// The criterion fails, below the band.
        Fails,
    }

    impl fmt::Display for Ruled
    {
        /// Write the ruling as a table line spells it.
        ///
        /// # Specification
        /// trivial.
        fn fmt(
            &self,
            f: &mut fmt::Formatter<'_>,
        ) -> fmt::Result
        {
            f.write_str(match *self {
                Self::Holds => "read A A=0.9 B=0.1 outside=0",
                Self::Fails => "read B A=0.1 B=0.9 outside=0",
            })
        }
    }

    /// A seat serving in-process.
    struct Seat
    {
        /// Its peer id.
        key: PeerKey,
        /// What it did.
        events: mpsc::UnboundedReceiver<Event>,
        /// The commit that presented it in the project.
        presence: CommitId,
    }

    /// An operator's state directory holding a project, two seats present in
    /// it and serving, and a git repository on `main`.
    struct World
    {
        /// The runtime the seats serve on.
        runtime: tokio::runtime::Runtime,
        /// The seats, in the order made.
        seats: Vec<Seat>,
        /// The project.
        project: TreeId,
        /// The repository.
        repository: PathBuf,
        /// The playbook.
        playbook: PathBuf,
        /// The rubric.
        rubric: PathBuf,
        /// The judge's table.
        table: PathBuf,
        /// Every directory and file the world holds.
        root: tempfile::TempDir,
    }

    /// A UDP port free on this host now, and its loopback address.
    ///
    /// # Specification
    /// trivial.
    fn free_port() -> (UdpPort, SocketAddr)
    {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let number = socket.local_addr().unwrap().port();
        (
            number.to_string().parse().unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, number)),
        )
    }

    /// `node`, bound at `address`'s port, as reached at `address`.
    ///
    /// # Specification
    /// trivial.
    fn direct(
        node: &Node,
        address: SocketAddr,
    ) -> Endpoint
    {
        format!("{}@{address}", node.endpoint_key())
            .parse()
            .unwrap()
    }

    /// git in `directory`, configured by `root`'s empty file alone, as the
    /// operator.
    ///
    /// # Specification
    /// trivial.
    fn git(
        root: &Path,
        directory: &Path,
    ) -> Command
    {
        let mut command = Command::new("git");
        let _configured = command
            .current_dir(directory)
            .env("GIT_CONFIG_GLOBAL", root.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "operator")
            .env("GIT_AUTHOR_EMAIL", "operator@example.invalid")
            .env("GIT_COMMITTER_NAME", "operator")
            .env("GIT_COMMITTER_EMAIL", "operator@example.invalid")
            .stdin(Stdio::null());
        command
    }

    /// Run `command` and return what it printed, trimmed.
    ///
    /// # Specification
    /// - panics: unless it exits 0.
    /// - executable: none — the helper is its own specification: a process
    ///   assertion whose oracle is the caller's observed repository state.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the operator lands one change and reworks another.
    /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
    fn read(command: &mut Command) -> String
    {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// Run the driver as `command` and return the lines it printed.
    ///
    /// # Specification
    /// - panics: unless it exits as `exit` says.
    /// - executable: none — the helper is its own specification: a process exit
    ///   assertion, exercised by decided and undecided outcomes.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — refused grading exits undecided; met grading decides.
    /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
    fn ended(
        command: &mut Command,
        exit: Exit,
    ) -> Vec<String>
    {
        let output = command.output().unwrap();
        let expected = match exit {
            Exit::Success => 0_i32,
            Exit::Undecided => 3_i32,
        };
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{command:?} exits {exit:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Run the driver as `command`, which fails, and return what it wrote to
    /// standard error.
    ///
    /// # Specification
    /// - panics: unless it exits 1 having printed no landing.
    /// - executable: none — the helper is its own specification: it asserts the
    ///   failed child's exit and absence of a landing.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a conflicting merge leaves the branch unchanged.
    /// - witness: `operator::tests::a_refused_merge_commits_nothing`
    fn refused(command: &mut Command) -> String
    {
        let output = command.output().unwrap();
        let printed = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            output.status.code(),
            Some(1_i32),
            "{command:?} fails: {printed}"
        );
        assert!(
            !printed.lines().any(|line| line.starts_with("landed ")),
            "a refusal prints no landing: {printed}"
        );
        String::from_utf8(output.stderr).unwrap()
    }

    /// The script a seat acts through: it clones the repository, commits
    /// `written` to `change.txt` on a branch named for the dispatch, pushes
    /// the branch, and reports `<branch> <commit>`.
    ///
    /// # Specification
    /// trivial.
    fn script(
        root: &Path,
        written: Written,
    ) -> String
    {
        format!(
            r#"#!/bin/sh
set -eu
export GIT_CONFIG_GLOBAL='{config}' GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=seat GIT_AUTHOR_EMAIL=seat@example.invalid
export GIT_COMMITTER_NAME=seat GIT_COMMITTER_EMAIL=seat@example.invalid
dispatch=${{DOMHRINGR_DISPATCH##*/}}
branch=seat/$(printf %.12s "$dispatch")
work=$(mktemp -d)
git clone --quiet '{repository}' "$work"
cd "$work"
git switch --quiet --create "$branch"
printf '%s\n' '{content}' > change.txt
git add change.txt
git commit --quiet --message 'Write the change'
git push --quiet origin "$branch"
printf '%s %s\n' "$branch" "$(git rev-parse HEAD)"
cd /
rm -rf "$work"
"#,
            config = root.join("gitconfig").display(),
            repository = root.join("repo").display(),
            content = written.0,
        )
    }

    impl World
    {
        /// A world whose two seats commit `written`, one each.
        ///
        /// # Specification
        /// - ensures: the repository holds one commit on `main`; the operator
        ///   owns the project and granted both seats, which hold it and
        ///   presented themselves in it, and its store holds both presences;
        ///   the operator's store is closed, so the driver can open it.
        /// - panics: when any of it cannot be made.
        /// - executable: none — fixture setup creates processes and durable
        ///   stores; the operator loop observes the resulting project and
        ///   seats.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — both seats report into the operator's project.
        /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
        fn new(written: [Written; 2]) -> Self
        {
            let root = tempfile::tempdir().unwrap();
            let path = root.path();
            std::fs::write(path.join("gitconfig"), "").unwrap();
            let repository = path.join("repo");
            std::fs::create_dir_all(&repository).unwrap();
            let _init =
                read(git(path, &repository).args(["init", "--quiet", "--initial-branch=main"]));
            std::fs::write(repository.join("README.md"), "# fixture\n").unwrap();
            let _added = read(git(path, &repository).args(["add", "README.md"]));
            let _committed =
                read(git(path, &repository).args(["commit", "--quiet", "--message", "Start"]));
            let (playbook, rubric, table) = (
                path.join("playbook.toml"),
                path.join("rubric.toml"),
                path.join("table"),
            );
            std::fs::write(&playbook, PLAYBOOK).unwrap();
            std::fs::write(&rubric, RUBRIC).unwrap();
            std::fs::write(&table, "").unwrap();
            let scripts = written.map(|written| {
                let file = path.join(format!("seat-{}.sh", written.0));
                std::fs::write(&file, script(path, written)).unwrap();
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
                file
            });
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let (project, seats) = runtime.block_on(Self::populate(path, scripts));
            Self {
                runtime,
                seats,
                project,
                repository,
                playbook,
                rubric,
                table,
                root,
            }
        }

        /// Open the project in the operator's state under `root`, and make,
        /// grant, start and present a seat per script.
        ///
        /// # Specification
        /// trivial.
        async fn populate(
            root: &Path,
            scripts: [PathBuf; 2],
        ) -> (TreeId, Vec<Seat>)
        {
            let operator_state = StateDir::from(root.join("operator"));
            let identity = Identity::load_or_create(&operator_state).unwrap();
            let me = identity.peer_key();
            let (port, address) = free_port();
            let operator = Arc::new(
                Peer::open(&operator_state, identity)
                    .unwrap()
                    .with_relay(domhringr_record_tree::Relay::Off)
                    .bind(BindPort::Fixed(port), &[])
                    .await
                    .unwrap(),
            );
            let accepting = {
                let operator = Arc::clone(&operator);
                tokio::spawn(async move {
                    while !matches!(operator.accept().await, Err(AcceptError::Closed)) {}
                })
            };
            let key = TreeKey::mint(&operator_state).unwrap();
            let project = key.tree();
            let _opened = operator
                .peer()
                .commit(project, Receipt::open(&key, me).unwrap())
                .await
                .unwrap();
            let reached = RemotePeer::new(direct(&operator, address), me);
            let mut seats = Vec::new();
            for (state, script) in ["seat-first", "seat-second"].into_iter().zip(scripts) {
                let state = StateDir::from(root.join(state));
                let identity = Identity::load_or_create(&state).unwrap();
                let key = identity.peer_key();
                let _granted = operator
                    .peer()
                    .commit(project, Receipt::grant(project, key).unwrap())
                    .await
                    .unwrap();
                let (port, address) = free_port();
                let node = Arc::new(
                    Peer::open(&state, identity)
                        .unwrap()
                        .with_relay(domhringr_record_tree::Relay::Off)
                        .bind(BindPort::Fixed(port), &[
                            PROTOCOL,
                            domhringr_record_evidence::PROTOCOL,
                            domhringr_record_index::stream::PROTOCOL,
                        ])
                        .await
                        .unwrap(),
                );
                let events = serve(
                    Arc::clone(&node),
                    Surface::Program(script),
                    Evidence::open(&state),
                    domhringr_record_index::store::Store::open(&state),
                );
                let _held = node.sync(&reached, project).await.unwrap();
                let presence = node.present(project).await.unwrap();
                let seat = RemotePeer::new(direct(&node, address), key);
                drop(node);
                let _pulled = operator.sync(&seat, project).await.unwrap();
                seats.push(Seat {
                    key,
                    events,
                    presence,
                });
            }
            operator.close().await;
            accepting.await.unwrap();
            drop(operator);
            (project, seats)
        }

        /// The driver, run as the operator.
        ///
        /// # Specification
        /// trivial.
        fn driver(&self) -> Command
        {
            let root = self.root.path();
            let mut command = Command::new(env!("CARGO_BIN_EXE_domhringr"));
            let _configured = command
                .env("DOMHRINGR_STATE", root.join("operator"))
                .env("DOMHRINGR_PROJECT", Anchor::key(self.project).to_string())
                .env("DOMHRINGR_RELAY", "off")
                .env("GIT_CONFIG_GLOBAL", root.join("gitconfig"))
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "operator")
                .env("GIT_AUTHOR_EMAIL", "operator@example.invalid")
                .env("GIT_COMMITTER_NAME", "operator")
                .env("GIT_COMMITTER_EMAIL", "operator@example.invalid")
                .stdin(Stdio::null());
            command
        }

        /// git in the repository.
        ///
        /// # Specification
        /// trivial.
        fn git(&self) -> Command
        {
            git(self.root.path(), &self.repository)
        }

        /// Where `main` stands.
        ///
        /// # Specification
        /// trivial.
        fn main(&self) -> String
        {
            read(self.git().args(["rev-parse", "main"]))
        }

        /// Dispatch the seat `which` names to `task` and wait for its report.
        ///
        /// # Specification
        /// - ensures: returns the dispatch's commit id as the driver's
        ///   `dispatch` line spells it, and the report's, read from the seat's
        ///   event.
        /// - panics: unless the driver prints the dispatch's anchor and
        ///   `woken`, and the seat reports within [`DEADLINE`].
        /// - executable: none — dispatch and report events cross process
        ///   boundaries; the loop witness verifies the admitted dispatch and
        ///   report.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — verification acts on the dispatched seat's
        ///   report.
        /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
        fn dispatch(
            &mut self,
            task: Task,
            which: Which,
        ) -> (String, CommitId)
        {
            let index = match which {
                Which::First => 0,
                Which::Second => 1,
            };
            let lines = ended(
                self.driver()
                    .arg("dispatch")
                    .arg(task)
                    .arg("--seat")
                    .arg(self.seats[index].key.to_string())
                    .args(["--brief", BRIEF]),
                Exit::Success,
            );
            let [ref dispatched, ref woken] = *lines.as_slice()
            else {
                panic!("dispatch prints its anchor and woken: {lines:?}");
            };
            assert_eq!(woken, "woken", "the seat is woken");
            let (_tree, dispatch) = dispatched
                .strip_prefix("dispatch domhringr://")
                .and_then(|anchor| anchor.split_once("/.commit/"))
                .unwrap();
            let (runtime, events) = (&self.runtime, &mut self.seats[index].events);
            let report = runtime.block_on(async {
                loop {
                    match tokio::time::timeout(DEADLINE, events.recv()).await.unwrap() {
                        Some(Event::Reported { report, .. }) => return report,
                        Some(Event::Unreported { failure, .. }) => {
                            panic!("the seat's script fails: {failure}")
                        },
                        Some(_) => {},
                        None => panic!("the seat stopped serving"),
                    }
                }
            });
            (dispatch.to_owned(), report)
        }

        /// Where `task` stands, as `open` lists it.
        ///
        /// # Specification
        /// - panics: unless `open` lists the task.
        /// - executable: none — the helper is its own specification; the loop
        ///   compares the selected standing with expected receipt anchors.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — each loop transition changes the listed standing.
        /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
        fn standing(
            &self,
            task: Task,
        ) -> String
        {
            let listed = format!("task {}tasks/{task} ", Anchor::key(self.project));
            let lines = ended(self.driver().arg("open"), Exit::Success);
            lines
                .iter()
                .find_map(|line| line.strip_prefix(&listed))
                .unwrap_or_else(|| panic!("open lists {task}: {lines:?}"))
                .to_owned()
        }

        /// Verify `task` by the world's playbook.
        ///
        /// # Specification
        /// - panics: unless the driver exits 0.
        /// - executable: none — the helper is its own specification; it
        ///   delegates the command exit assertion to `ended`.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — verification records the change's verifier
        ///   output.
        /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
        fn verify(
            &self,
            task: Task,
        ) -> Vec<String>
        {
            ended(
                self.driver()
                    .arg("verify")
                    .arg(task)
                    .arg("--playbook")
                    .arg(&self.playbook)
                    .arg("--repo")
                    .arg(&self.repository),
                Exit::Success,
            )
        }

        /// Decide `task` from the rubric with the world's table, ending as
        /// `exit` says.
        ///
        /// # Specification
        /// trivial.
        fn decide(
            &self,
            task: Task,
            exit: Exit,
        ) -> Vec<String>
        {
            ended(
                self.driver()
                    .arg("decide")
                    .arg(task)
                    .arg("--rubric")
                    .arg(&self.rubric)
                    .arg("--repo")
                    .arg(&self.repository)
                    .arg("--static")
                    .arg(&self.table),
                exit,
            )
        }

        /// The driver landing `task` in the repository.
        ///
        /// # Specification
        /// trivial.
        fn land(
            &self,
            task: Task,
        ) -> Command
        {
            let mut command = self.driver();
            let _land = command
                .arg("land")
                .arg(task)
                .arg("--repo")
                .arg(&self.repository);
            command
        }

        /// Decide `task` from an empty table, which refuses every question,
        /// and add the table's row for its question about the transcript
        /// that run printed, ruled as `ruled` says.
        ///
        /// # Specification
        /// - ensures: the task's standing is graded refused, nothing decided.
        /// - panics: unless the run printed one transcript and one question and
        ///   composed refused.
        /// - executable: none — seeding updates a table after a child process
        ///   runs; the loop then observes the seeded ruling and resulting
        ///   decision.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — the seeded table distinguishes met and unmet
        ///   changes.
        /// - witness: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one`
        fn seed(
            &self,
            task: Task,
            ruled: Ruled,
        )
        {
            let seeded = std::fs::read_to_string(&self.table).unwrap();
            std::fs::write(&self.table, "").unwrap();
            let lines = self.decide(task, Exit::Undecided);
            let word = |prefix| {
                lines
                    .iter()
                    .find_map(|line| line.strip_prefix(prefix))
                    .and_then(|rest| rest.split(' ').next())
                    .unwrap()
                    .to_owned()
            };
            let (transcript, question) = (word("transcript "), word("ruling "));
            assert_eq!(
                lines.last().map(String::as_str),
                Some("composed refused"),
                "a refused question decides nothing: {lines:?}"
            );
            std::fs::write(
                &self.table,
                format!("{seeded}{question} {transcript} {ruled}\n"),
            )
            .unwrap();
        }
    }

    #[test]
    fn the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one()
    {
        let mut world = World::new([Written("met"), Written("unmet")]);
        let (first, second) = (Task("first"), Task("second"));
        let mut standings = Vec::new();

        let (dispatch, report) = world.dispatch(first, Which::First);
        std::fs::write(world.repository.join("NOTES.md"), "notes\n").unwrap();
        let _added = read(world.git().args(["add", "NOTES.md"]));
        let _committed = read(
            world
                .git()
                .args(["commit", "--quiet", "--message", "Note on main"]),
        );
        let noted = world.main();
        standings.push(world.standing(first));
        let verified = world.verify(first);
        let [ref change, ref report_line, ref named, ref ran] = *verified.as_slice()
        else {
            panic!(
                "verify prints the change, the report, the playbook and one verification: \
                 {verified:?}"
            );
        };
        let (branch, commit) = change
            .strip_prefix("change ")
            .and_then(|rest| rest.split_once(' '))
            .map(|(branch, commit)| (branch.to_owned(), commit.to_owned()))
            .unwrap();
        assert!(branch.starts_with("seat/"), "the seat's branch: {change}");
        assert!(
            named.starts_with("playbook ") && named.ends_with(" check"),
            "{named}"
        );
        let words = ran.split(' ').collect::<Vec<_>>();
        assert!(
            matches!(*words.as_slice(), [
                "verified",
                _,
                "content",
                _,
                "exit",
                "0"
            ]),
            "the verifier passes in the change's checkout: {ran}"
        );
        let held = |line: &str, prefix: &str| {
            let digest = line
                .strip_prefix(prefix)
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or_else(|| panic!("a digest after {prefix:?}: {line:?}"))
                .parse::<ParsedDigest>()
                .unwrap();
            Evidence::open(&StateDir::from(world.root.path().join("operator")))
                .read(digest.into())
                .unwrap_or_else(|refused| panic!("the operator holds {line:?}: {refused}"))
        };
        assert_eq!(
            held(report_line, "report ").as_ref(),
            format!("{branch} {commit}\n").as_bytes(),
            "the operator holds the seat's report, fetched from the seat"
        );
        let output = words.get(3).copied().unwrap_or_default();
        assert!(
            held(output, "").as_ref().is_empty(),
            "the operator holds the verifier's output, which is empty"
        );
        assert_eq!(
            read(world.git().args(["worktree", "list", "--porcelain"]))
                .matches("worktree ")
                .count(),
            1,
            "the checkout is removed"
        );
        standings.push(world.standing(first));
        world.seed(first, Ruled::Holds);
        standings.push(world.standing(first));
        let decided = world.decide(first, Exit::Success);
        assert!(
            decided.contains(&String::from("step content exit 0")),
            "the verification counts: {decided:?}"
        );
        assert_eq!(
            decided.iter().rev().nth(1).map(String::as_str),
            Some("composed met"),
            "{decided:?}"
        );
        let decide = decided
            .last()
            .and_then(|line| line.strip_prefix("decide "))
            .and_then(|rest| rest.strip_suffix(" land"))
            .unwrap()
            .to_owned();
        standings.push(world.standing(first));
        let landed = ended(&mut world.land(first), Exit::Success);
        let [ref landing_change, ref landing_report, ref landing] = *landed.as_slice()
        else {
            panic!("land prints the change, the report and the landing: {landed:?}");
        };
        assert_eq!(
            [landing_change, landing_report],
            [change, report_line],
            "land names the change it merges and the report it read"
        );
        let (landing, merge) = landing
            .strip_prefix("landed ")
            .and_then(|rest| rest.split_once(' '))
            .unwrap();
        assert_eq!(world.main(), merge, "the landing names where main stands");
        assert_eq!(
            (
                read(world.git().args(["rev-parse", "main^1"])),
                read(world.git().args(["rev-parse", "main^2"])),
            ),
            (noted, commit),
            "main moved past the change's base, so the change merges by a merge commit"
        );
        assert_eq!(
            read(world.git().args(["log", "-1", "--format=%s", "main"])),
            format!("Merge branch '{branch}'"),
            "the merge commit names the seat's branch"
        );
        standings.push(world.standing(first));
        let [
            ref reported,
            ref verified_at,
            ref graded,
            ref decided_at,
            ref landed_at,
        ] = *standings.as_slice()
        else {
            panic!("one standing per step: {standings:?}");
        };
        assert_eq!(
            *reported,
            format!("reported {dispatch} {report}"),
            "the seat's report, synced"
        );
        assert!(
            verified_at.starts_with(&format!("verified {dispatch} ")),
            "then verified: {verified_at}"
        );
        assert!(
            graded.starts_with(&format!("graded {dispatch} ")) && graded.ends_with(" refused"),
            "then graded refused by the empty table: {graded}"
        );
        assert_eq!(
            *decided_at,
            format!("decided {dispatch} {decide} land"),
            "then decided to land"
        );
        assert_eq!(
            *landed_at,
            format!("landed {dispatch} {landing} {merge}"),
            "then landed at the merge"
        );
        let merged = world.main();

        let (dispatch, _report) = world.dispatch(second, Which::Second);
        let _verified = world.verify(second);
        world.seed(second, Ruled::Fails);
        let decided = world.decide(second, Exit::Success);
        let (decide, decision) = decided
            .last()
            .and_then(|line| line.strip_prefix("decide "))
            .and_then(|rest| rest.split_once(' '))
            .unwrap();
        assert_eq!(
            decision, "rework question change/scoped unmet",
            "an unmet question reworks the change, naming it"
        );
        assert_eq!(
            world.standing(second),
            format!("decided {dispatch} {decide} {decision}"),
            "the rework is the attempt's progress"
        );
        let refusal = refused(&mut world.land(second));
        assert!(refusal.contains("not land"), "{refusal}");
        assert_eq!(world.main(), merged, "a reworked change does not land");
    }

    #[test]
    fn open_names_unknown_protocol_refusals()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let (project, task, dispatch, pause) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let identity = Identity::load_or_create(&state).unwrap();
                let me = identity.peer_key();
                let peer = Peer::open(&state, identity).unwrap();
                let project = TreeKey::mint(&state).unwrap();
                let task = TreeKey::mint(&state).unwrap();
                for key in [&project, &task] {
                    peer.commit(key.tree(), Receipt::open(key, me).unwrap())
                        .await
                        .unwrap();
                }
                let (project, task) = (project.tree(), task.tree());
                peer.commit(
                    project,
                    Receipt::bind(
                        project,
                        "tasks/unknown".parse().unwrap(),
                        domhringr_record_tree::Target::Anchor(Anchor::key(task)),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
                let dispatch = peer
                    .commit(
                        task,
                        Receipt::dispatch(
                            task,
                            me,
                            domhringr_record_tree::Edition::from(99),
                            domhringr_record_tree::Brief::Anchor(Anchor::key(project)),
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let pause = peer
                    .commit(task, Receipt::pause(task, dispatch).unwrap())
                    .await
                    .unwrap();
                drop(peer);
                (project, task, dispatch, pause)
            });
        let lines = ended(
            Command::new(env!("CARGO_BIN_EXE_domhringr"))
                .env("DOMHRINGR_STATE", root.path())
                .env("DOMHRINGR_PROJECT", Anchor::key(project).to_string())
                .arg("open"),
            Exit::Success,
        );
        assert_eq!(lines, [
            format!("project {}", Anchor::key(project)),
            format!(
                "refused {} protocol edition 99 dispatch: unknown edition 99",
                Anchor::commit(task, dispatch)
            ),
            format!(
                "refused {} protocol edition 99 pause: unknown edition 99",
                Anchor::commit(task, pause)
            ),
            format!("task {}tasks/unknown undispatched", Anchor::key(project)),
        ]);
    }

    #[test]
    fn open_lists_every_seat_and_task()
    {
        let mut world = World::new([Written("one"), Written("two")]);
        let (first, first_report) = world.dispatch(Task("alpha"), Which::First);
        let (second, second_report) = world.dispatch(Task("beta"), Which::Second);
        let lines = ended(world.driver().arg("open"), Exit::Success);
        let project = Anchor::key(world.project);
        let mut seats = world
            .seats
            .iter()
            .map(|seat| (seat.key, seat.presence))
            .collect::<Vec<_>>();
        seats.sort_by_key(|&(key, _presence)| key.to_string());
        let [ref named, ref seat_one, ref seat_two, ref alpha, ref beta] = *lines.as_slice()
        else {
            panic!("open prints the project, two seats and two tasks: {lines:?}");
        };
        assert_eq!(*named, format!("project {project}"), "the project first");
        for (line, &(key, presence)) in [seat_one, seat_two].into_iter().zip(&seats) {
            assert!(
                line.starts_with(&format!("seat {key} "))
                    && line.ends_with(&format!(" {presence}")),
                "each seat at its presence, in key order: {line}"
            );
        }
        assert_eq!(
            *alpha,
            format!("task {project}tasks/alpha reported {first} {first_report}"),
            "a task by its anchor, synced to its seat's report"
        );
        assert_eq!(
            *beta,
            format!("task {project}tasks/beta reported {second} {second_report}"),
            "every task in path order"
        );
        assert_eq!(
            ended(world.driver().arg("open"), Exit::Success),
            lines,
            "a second listing, from the store alone, reads the same"
        );
    }

    #[test]
    fn a_refused_merge_commits_nothing()
    {
        let mut world = World::new([Written("left"), Written("right")]);
        let (left, right) = (Task("left"), Task("right"));
        let _left = world.dispatch(left, Which::First);
        let (dispatch, _report) = world.dispatch(right, Which::Second);
        for task in [left, right] {
            world.seed(task, Ruled::Holds);
            let decided = world.decide(task, Exit::Success);
            assert!(
                decided.last().is_some_and(|line| line.ends_with(" land")),
                "{decided:?}"
            );
        }
        std::fs::write(world.repository.join("README.md"), "# changed by hand\n").unwrap();
        let refusal = refused(&mut world.land(left));
        assert!(refusal.contains("uncommitted changes"), "{refusal}");
        let _restored = read(world.git().args(["checkout", "--", "README.md"]));
        let landed = ended(&mut world.land(left), Exit::Success);
        let [ref change, ref report, ref landing] = *landed.as_slice()
        else {
            panic!("land prints the change, the report and the landing: {landed:?}");
        };
        assert!(report.starts_with("report "), "{landed:?}");
        let main = world.main();
        assert!(
            change.ends_with(&format!(" {main}")) && landing.ends_with(&format!(" {main}")),
            "a change on main's tip fast-forwards it: {landed:?}"
        );
        let decided = world.standing(right);
        assert!(
            decided.starts_with(&format!("decided {dispatch} ")),
            "{decided}"
        );

        let refusal = refused(&mut world.land(right));
        assert!(
            refusal.contains("git refused to merge the change"),
            "both changes write change.txt: {refusal}"
        );
        assert_eq!(world.main(), main, "main stays");
        assert_eq!(
            read(world.git().args(["status", "--porcelain"])),
            "",
            "the merge is aborted, the tree as it was"
        );
        assert_eq!(
            world.standing(right),
            decided,
            "a refused merge commits no landing"
        );
    }

    /// List the record directly, independently of the keyed-plane reader.
    ///
    /// # Specification
    /// trivial.
    async fn folding_listing(
        peer: &Peer,
        project: TreeId,
    ) -> Vec<String>
    {
        use domhringr_record_tree::Authority;
        use domhringr_record_tree::Target;
        use domhringr_record_tree::ViewError;
        let view = peer.view(project).await.unwrap();
        let mut lines = vec![format!("project {}", Anchor::key(project))];
        for (seat, presence) in view.book() {
            if *seat != peer.identity().peer_key() {
                lines.push(format!("seat {seat} {presence}"));
            }
        }
        for (path, binding) in view.bindings() {
            let Some(name) = path.as_ref().strip_prefix("tasks/")
            else {
                continue;
            };
            let Target::Anchor(Anchor::Tree(Authority::Key(tree))) = binding.1
            else {
                continue;
            };
            if name.contains('/') {
                continue;
            }
            let standing = match peer.view(tree).await {
                Ok(task) => {
                    for &(commit, ref refusal) in task.refused() {
                        lines.push(format!(
                            "refused {} {refusal}",
                            Anchor::commit(tree, commit)
                        ));
                    }
                    task.task().current().to_string()
                },
                Err(ViewError::Unopened(_)) => String::from("unheld"),
                Err(failure) => panic!("fold task: {failure}"),
            };
            lines.push(format!("task {}{path} {standing}", Anchor::key(project)));
        }
        lines
    }

    /// A separate runtime releases the tree engine before the next process.
    ///
    /// # Specification
    /// trivial.
    fn local_runtime() -> tokio::runtime::Runtime
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn open_reads_the_index_as_the_fold_reads_the_trees()
    {
        use domhringr_record_tree::Brief;
        use domhringr_record_tree::Code;
        use domhringr_record_tree::Current;
        use domhringr_record_tree::Decision;
        use domhringr_record_tree::Edition;
        use domhringr_record_tree::Grade;
        use domhringr_record_tree::Revision;
        use domhringr_record_tree::Ruling;
        use domhringr_record_tree::Status;
        use domhringr_record_tree::Target;
        use domhringr_record_tree::Unread;
        use gandr_storage_values::ManifestDigest;
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let (project, task) = local_runtime().block_on(async {
            let identity = Identity::load_or_create(&state).unwrap();
            let me = identity.peer_key();
            let peer = Peer::open(&state, identity).unwrap();
            let project = TreeKey::mint(&state).unwrap();
            let task = TreeKey::mint(&state).unwrap();
            let absent = TreeKey::mint(&state).unwrap();
            for key in [&project, &task] {
                peer.commit(key.tree(), Receipt::open(key, me).unwrap())
                    .await
                    .unwrap();
            }
            for (name, tree) in [
                ("alpha", task.tree()),
                ("unheld", absent.tree()),
                ("zeta", task.tree()),
            ] {
                peer.commit(
                    project.tree(),
                    Receipt::bind(
                        project.tree(),
                        format!("tasks/{name}").parse().unwrap(),
                        Target::Anchor(Anchor::key(tree)),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            }
            drop(peer);
            (project.tree(), task.tree())
        });
        let stages = [
            "undispatched",
            "dispatched",
            "reported",
            "verified",
            "graded",
            "decided",
            "landed",
            "refused",
        ];
        // The listing line of `tasks/alpha` up to its standing.
        let alpha = format!("task {}tasks/alpha ", Anchor::key(project));
        for stage in stages {
            let (reference, heads) = local_runtime().block_on(async {
                let identity = Identity::load_or_create(&state).unwrap();
                let me = identity.peer_key();
                let peer = Peer::open(&state, identity).unwrap();
                let view = peer.view(task).await.unwrap();
                let dispatch = match *view.task().current() {
                    Current::Attempt(ref attempt) => Some(attempt.dispatch()),
                    Current::Undispatched => None,
                };
                let hash = BRIEF.parse().unwrap();
                let value = ManifestDigest::from([42; 32]);
                match stage {
                    "undispatched" => {},
                    "dispatched" => {
                        peer.commit(
                            task,
                            Receipt::dispatch(task, me, Edition::CURRENT, Brief::Content(hash))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    },
                    "reported" => {
                        peer.commit(
                            task,
                            Receipt::report(
                                task,
                                dispatch.unwrap(),
                                value,
                                "report".parse().unwrap(),
                            )
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                    },
                    "verified" => {
                        peer.commit(
                            task,
                            Receipt::verified(
                                task,
                                dispatch.unwrap(),
                                me,
                                hash,
                                "check".parse().unwrap(),
                                value,
                                Status::Exited(Code::from(0_i32)),
                            )
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                    },
                    "graded" => {
                        let verdict = peer
                            .commit(
                                task,
                                Receipt::verdict(task, dispatch.unwrap(), me, hash, value, vec![(
                                    hash,
                                    Ruling::Unread(Unread::Tied),
                                )])
                                .unwrap(),
                            )
                            .await
                            .unwrap();
                        peer.commit(
                            task,
                            Receipt::graded(task, verdict, vec![Grade::Refused], Grade::Refused)
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    },
                    "decided" => {
                        peer.commit(
                            task,
                            Receipt::decide(task, dispatch.unwrap(), me, Decision::Land).unwrap(),
                        )
                        .await
                        .unwrap();
                    },
                    "landed" => {
                        let Current::Attempt(ref attempt) = *view.task().current()
                        else {
                            panic!("attempt");
                        };
                        let &domhringr_record_tree::Progress::Decided { decide, .. } =
                            attempt.progress()
                        else {
                            panic!("decided");
                        };
                        peer.commit(
                            task,
                            Receipt::landed(task, decide, Revision::Sha1([9; 20])).unwrap(),
                        )
                        .await
                        .unwrap();
                    },
                    "refused" => {
                        peer.commit(
                            task,
                            Receipt::dispatch(task, me, Edition::from(99), Brief::Content(hash))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    },
                    _ => panic!("unknown fixture stage"),
                }
                let reference = folding_listing(&peer, project).await;
                if stage == "refused" {
                    assert!(
                        reference.iter().any(|line| line.starts_with("refused ")
                            && line.ends_with("unknown edition 99"))
                    );
                }
                else {
                    assert!(reference.iter().any(|line| {
                        line.strip_prefix(alpha.as_str())
                            .is_some_and(|standing| standing.starts_with(stage))
                    }));
                }
                (reference, peer.heads(project).await.unwrap())
            });
            for _read in 0_u8 .. 2 {
                let actual = ended(
                    Command::new(env!("CARGO_BIN_EXE_domhringr"))
                        .env("DOMHRINGR_STATE", root.path())
                        .env("DOMHRINGR_PROJECT", Anchor::key(project).to_string())
                        .arg("open"),
                    Exit::Success,
                );
                assert_eq!(
                    actual, reference,
                    "{stage}: cold or refreshed, then unchanged"
                );
            }
            local_runtime().block_on(async {
                let identity = Identity::load_or_create(&state).unwrap();
                let peer = Peer::open(&state, identity).unwrap();
                assert_eq!(
                    peer.heads(project).await.unwrap(),
                    heads,
                    "open never attests"
                );
                drop(peer);
            });
        }
    }

    /// Own claims in the actual store, checked against a whole derivation.
    ///
    /// # Specification
    /// trivial.
    fn attested(world: &World) -> Vec<CommitId>
    {
        local_runtime().block_on(async {
            let state = StateDir::from(world.root.path().join("operator"));
            let identity = Identity::load_or_create(&state).unwrap();
            let author = identity.peer_key();
            let peer = Peer::open(&state, identity).unwrap();
            let view = peer.view(world.project).await.unwrap();
            let claims: Vec<_> = view
                .attestations()
                .iter()
                .filter(|entry| entry.0 == author)
                .map(|entry| entry.1.commit)
                .collect();
            let claim = &view.indexes()[&author];
            let keyed = domhringr_record_index::keyed::Keyed::shared().unwrap();
            let store = domhringr_record_index::store::Store::open(&state);
            let attested = store
                .load(keyed, domhringr_record_index::derive::root(claim.index))
                .unwrap();
            assert!(
                domhringr_record_index::check::check(&peer, world.project, claim, &attested)
                    .await
                    .unwrap()
                    .0
                    .is_empty()
            );
            let whole = domhringr_record_index::derive::Deriver::default()
                .project(&peer, world.project, &view, &store)
                .await
                .unwrap();
            drop(peer);
            let names: Vec<_> = whole.entries.keys().cloned().collect();
            let mut contents = Vec::new();
            for held in [&attested, &whole.store] {
                let mut local = domhringr_record_index::prove::Local(held);
                contents.push(
                    domhringr_record_index::prove::contents(&mut local, keyed, names.clone())
                        .await
                        .unwrap(),
                );
            }
            assert_eq!(
                contents[0], contents[1],
                "attestation describes the command's resulting store"
            );
            claims
        })
    }

    #[test]
    fn a_committing_command_attests_a_changed_index_once()
    {
        let mut world = World::new([Written("attested"), Written("unused")]);
        let task = Task("change");
        let (dispatch, _) = world.dispatch(task, Which::First);
        let first = attested(&world);
        assert_eq!(first.len(), 1);
        let resent = ended(
            world
                .driver()
                .arg("dispatch")
                .arg(task)
                .arg("--seat")
                .arg(world.seats[0].key.to_string())
                .args(["--brief", BRIEF]),
            Exit::Success,
        );
        assert!(resent[0].ends_with(&dispatch));
        local_runtime().block_on(async {
            let state = StateDir::from(world.root.path().join("operator"));
            let identity = Identity::load_or_create(&state).unwrap();
            let author = identity.peer_key();
            let peer = Peer::open(&state, identity).unwrap();
            let view = peer.view(world.project).await.unwrap();
            drop(peer);
            let claims: Vec<_> = view
                .attestations()
                .iter()
                .filter(|entry| entry.0 == author)
                .map(|entry| entry.1.commit)
                .collect();
            assert_eq!(
                claims, first,
                "a re-sent dispatch attests nothing, even if its wake syncs a report"
            );
        });
        let _verified = world.verify(task);
        assert_eq!(attested(&world).len(), 2);
        world.seed(task, Ruled::Holds);
        assert_eq!(attested(&world).len(), 3);
        let _decided = world.decide(task, Exit::Success);
        assert_eq!(attested(&world).len(), 4);
        let _landed = ended(&mut world.land(task), Exit::Success);
        assert_eq!(attested(&world).len(), 5);
    }
}
