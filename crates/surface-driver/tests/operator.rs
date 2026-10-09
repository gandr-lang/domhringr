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
                | Self::Holds => "read A A=0.9 B=0.1 outside=0",
                | Self::Fails => "read B A=0.1 B=0.9 outside=0",
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
    fn ended(
        command: &mut Command,
        exit: Exit,
    ) -> Vec<String>
    {
        let output = command.output().unwrap();
        let expected = match exit {
            | Exit::Success => 0_i32,
            | Exit::Undecided => 3_i32,
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
                        .bind(BindPort::Fixed(port), &[
                            PROTOCOL,
                            domhringr_record_evidence::PROTOCOL,
                        ])
                        .await
                        .unwrap(),
                );
                let events = serve(
                    Arc::clone(&node),
                    Surface::Program(script),
                    Evidence::open(&state),
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
        fn dispatch(
            &mut self,
            task: Task,
            which: Which,
        ) -> (String, CommitId)
        {
            let index = match which {
                | Which::First => 0,
                | Which::Second => 1,
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
                        | Some(Event::Reported { report, .. }) => return report,
                        | Some(Event::Unreported { failure, .. }) => {
                            panic!("the seat's script fails: {failure}")
                        },
                        | Some(_) => {},
                        | None => panic!("the seat stopped serving"),
                    }
                }
            });
            (dispatch.to_owned(), report)
        }

        /// Where `task` stands, as `open` lists it.
        ///
        /// # Specification
        /// - panics: unless `open` lists the task.
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
}
