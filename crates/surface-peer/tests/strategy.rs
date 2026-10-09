//! The peer binary's playbook and rubric contract, exercised as processes:
//! the documents validate or are refused by file and field, a playbook's
//! verifiers run in the task's state directory and its questions are graded
//! against the rubric's band, every receipt lands on the task's current
//! dispatch, and the replay shows them. The rubric set under `rubrics/` is
//! graded the same way: every rubric validates and grades its fixture pair.

#[cfg(test)]
mod tests
{
    use core::time::Duration;
    use std::io::BufRead as _;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Child;
    use std::process::Command;
    use std::process::Output;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Instant;

    use domhringr_strategy_document::Loaded;
    use domhringr_strategy_document::Rubric;

    /// How long one command may run, or a running process may take to print a
    /// line.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// How often a running command is polled for its exit.
    const POLL: Duration = Duration::from_millis(20);

    /// The brief the task's dispatch names, by content hash.
    const BRIEF: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    /// The rubric set: the workspace's `rubrics/` directory.
    const SET: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rubrics");

    /// The ruling a table records for a criterion holding: above the rubric
    /// set's band.
    const HOLDS: &str = "read A A=0.9 B=0.1 outside=0";

    /// The ruling a table records for a criterion failing: below the rubric
    /// set's band.
    const FAILS: &str = "read B A=0.1 B=0.9 outside=0";

    /// A rubric of three questions over one state file.
    const RUBRIC: &str = r#"name = "landing"
state = ["note.txt"]

[band]
low = 0.25
high = 0.75

[questions.landed]
instructions = "Does the note say the change landed?"
criteria.true = "The note says the change landed."
criteria.false = "The note says the change did not land."

[questions.passed]
instructions = "Does the note say every check passed?"
criteria.true = "The note says every check passed."
criteria.false = "The note says a check failed."

[questions.tested]
instructions = "Does the note say the change was tested?"
criteria.true = "The note says the change was tested."
criteria.false = "The note says the change was not tested."
"#;

    /// A playbook of a passing and a failing verifier and the rubric's three
    /// questions; the passing verifier leaves a mark in the task's state.
    const PLAYBOOK: &str = r#"name = "landing"

[[steps]]
id = "note"
why = "The note is in the task's state."
verifier = { command = "sh", args = ["-c", "cat note.txt; echo ran >> runs.txt"] }

[[steps]]
id = "failing"
why = "A failing check is recorded, not fatal."
verifier = { command = "sh", args = ["-c", "echo failing >&2; exit 3"] }

[[steps]]
id = "landed"
why = "The change landed."
question = { rubric = "rubric.toml", question = "landed" }

[[steps]]
id = "passed"
why = "Every check passed."
question = { rubric = "rubric.toml", question = "passed" }

[[steps]]
id = "tested"
why = "The change was tested."
question = { rubric = "rubric.toml", question = "tested" }
"#;

    /// The peer binary on the state directory `state`.
    ///
    /// # Specification
    /// trivial.
    fn peer(state: &Path) -> Command
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_domhringr-peer"));
        let _command = command.arg("--state").arg(state);
        command
    }

    /// Run `command` to completion and return its output.
    ///
    /// # Specification
    /// - ensures: the command exited within [`DEADLINE`].
    /// - panics: when it cannot start or outlives the deadline (it is killed
    ///   first).
    fn run(command: &mut Command) -> Output
    {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > DEADLINE {
                child.kill().unwrap();
                panic!("{command:?} outlived {DEADLINE:?}");
            }
            std::thread::sleep(POLL);
        }
        child.wait_with_output().unwrap()
    }

    /// The lines `output`'s standard output holds.
    ///
    /// # Specification
    /// - panics: unless the standard output is UTF-8.
    fn printed(output: &Output) -> Vec<String>
    {
        String::from_utf8(output.stdout.clone())
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    /// The lines `output`'s standard error holds.
    ///
    /// # Specification
    /// - panics: unless the standard error is UTF-8.
    fn diagnosed(output: &Output) -> Vec<String>
    {
        String::from_utf8(output.stderr.clone())
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Run `command` to completion and return the lines it printed.
    ///
    /// # Specification
    /// - ensures: the command exited 0 within [`DEADLINE`].
    /// - panics: as [`run`], or when it exits non-zero (its standard error is
    ///   shown) or prints anything but UTF-8.
    fn finish(command: &mut Command) -> Vec<String>
    {
        let output = run(command);
        assert!(
            output.status.success(),
            "{command:?}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        printed(&output)
    }

    /// Run `command` to completion, expecting it to fail, and return the one
    /// line it wrote to standard error.
    ///
    /// # Specification
    /// - ensures: the command exited 1 within [`DEADLINE`] and printed nothing.
    /// - panics: as [`run`], or when it exits otherwise, prints anything, or
    ///   writes other than one line to standard error.
    fn refused(command: &mut Command) -> String
    {
        let output = run(command);
        assert_eq!(output.status.code(), Some(1_i32), "{command:?}: {output:?}");
        assert!(printed(&output).is_empty(), "{command:?} prints nothing");
        let diagnostics = diagnosed(&output);
        let [ref line] = *diagnostics.as_slice()
        else {
            panic!("{command:?} names one cause: {diagnostics:?}");
        };
        line.clone()
    }

    /// A UDP port in the ephemeral range that nothing on this host holds, as
    /// its decimal text.
    ///
    /// # Specification
    /// trivial.
    fn free_port() -> String
    {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        socket.local_addr().unwrap().port().to_string()
    }

    /// The rubric files of the set: every `*.toml` directly in [`SET`], in
    /// name order.
    ///
    /// # Specification
    /// - ensures: at least one file, sorted by path.
    /// - panics: when the set's directory cannot be read or holds no rubric.
    fn rubric_files() -> Vec<PathBuf>
    {
        let mut files = std::fs::read_dir(SET)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "toml")
            })
            .collect::<Vec<_>>();
        files.sort();
        assert!(!files.is_empty(), "{SET} holds the rubric set");
        files
    }

    /// A question of a rubric, as `rubric validate` prints it.
    struct Asked
    {
        /// The question's name in its rubric.
        name: String,
        /// The hash a table names the question by.
        hash: String,
    }

    /// A rubric file of the set, as `rubric validate` prints it.
    struct Validated
    {
        /// The rubric's name, its file's stem.
        name: String,
        /// The hash of the rubric file's bytes.
        hash: String,
        /// Its questions, in the order printed.
        questions: Vec<Asked>,
    }

    /// Validate the rubric `file` with the peer of state `state`.
    ///
    /// # Specification
    /// - ensures: `rubric validate` exited 0 and printed `rubric <hash>
    ///   <name>`, `<name>` the file's stem, then one `question <question>
    ///   <hash>` line per question, at least one.
    /// - provides: the rubric's name, its hash, and each question in the order
    ///   printed.
    /// - panics: when the command fails or prints other lines, or the rubric is
    ///   not named for its file.
    fn validate(
        state: &Path,
        file: &Path,
    ) -> Validated
    {
        let name = file
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_else(|| panic!("a rubric file is named in UTF-8: {file:?}"))
            .to_owned();
        let lines = finish(peer(state).args(["rubric", "validate"]).arg(file));
        let (first, listed) = lines
            .split_first()
            .unwrap_or_else(|| panic!("{name}: a rubric prints itself"));
        let hash = first
            .strip_prefix("rubric ")
            .and_then(|rest| rest.strip_suffix(name.as_str()))
            .and_then(|rest| rest.strip_suffix(' '))
            .unwrap_or_else(|| panic!("{name}: the rubric is named for its file: {first:?}"))
            .to_owned();
        let questions = listed
            .iter()
            .map(|line| {
                let fields = line.split(' ').collect::<Vec<_>>();
                let ["question", question, hash] = *fields.as_slice()
                else {
                    panic!("{name}: a question line: {line:?}");
                };
                Asked {
                    name: question.to_owned(),
                    hash: hash.to_owned(),
                }
            })
            .collect::<Vec<_>>();
        assert!(!questions.is_empty(), "{name} holds questions");
        Validated {
            name,
            hash,
            questions,
        }
    }

    /// The question a fixture pair isolates: the name its `isolates` file
    /// holds.
    ///
    /// # Specification
    /// - ensures: the file's text without its final line break.
    /// - panics: when the file cannot be read.
    fn isolated(pair: &Path) -> String
    {
        std::fs::read_to_string(pair.join("isolates"))
            .unwrap_or_else(|error| panic!("{pair:?} names the question it isolates: {error}"))
            .trim_end()
            .to_owned()
    }

    /// A task opened by one peer and dispatched to another, for gradings to
    /// land on.
    struct Dispatched
    {
        /// The opening peer's id: the judge of every grading it commits.
        judge: String,
        /// The dispatched seat's peer id.
        seat: String,
        /// The task's tree.
        tree: String,
        /// The dispatch's commit id.
        dispatch: String,
    }

    impl Dispatched
    {
        /// Open a task with the peer of state `o` and dispatch it to the peer
        /// of state `s`.
        ///
        /// # Specification
        /// - ensures: O owns a fresh tree whose current dispatch names S and
        ///   the brief [`BRIEF`]; the dispatching process is gone once the
        ///   dispatch is committed.
        /// - panics: when a command fails or prints other than its contract.
        fn open(
            o: &Path,
            s: &Path,
        ) -> Self
        {
            let judge = finish(peer(o).arg("id"))[1].clone();
            let s_id = finish(peer(s).arg("id"));
            let (endpoint, seat) = (s_id[0].clone(), s_id[1].clone());
            let tree = finish(peer(o).arg("open"))[0].clone();
            let contact = format!("{endpoint}@127.0.0.1:{}", free_port());
            let dialing = Running::spawn(peer(o).args([
                "dispatch",
                tree.as_str(),
                seat.as_str(),
                "content",
                BRIEF,
                "--at",
                contact.as_str(),
            ]));
            let dispatch = dialing.line();
            drop(dialing);
            Self {
                judge,
                seat,
                tree,
                dispatch,
            }
        }
    }

    /// A running process and its standard output, read as it arrives.
    ///
    /// The process is killed when the value drops, so a failing test leaves
    /// no process behind, and a test kills one by dropping it.
    struct Running
    {
        /// The process.
        child: Child,
        /// Its standard output, one line per message, from a reader thread.
        lines: mpsc::Receiver<String>,
    }

    impl Running
    {
        /// Start `command` and read its standard output line by line.
        ///
        /// # Specification
        /// - ensures: the process is running and its standard output is read
        ///   line by line; its standard error passes through to the test's.
        /// - panics: when the process cannot start.
        fn spawn(command: &mut Command) -> Self
        {
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
            let (sender, lines) = mpsc::channel();
            drop(std::thread::spawn(move || {
                for line in stdout.lines() {
                    if sender.send(line.unwrap()).is_err() {
                        break;
                    }
                }
            }));
            Self { child, lines }
        }

        /// The next line the process prints.
        ///
        /// # Specification
        /// - panics: when no line arrives within [`DEADLINE`], or the process's
        ///   output ends.
        fn line(&self) -> String
        {
            self.lines.recv_timeout(DEADLINE).unwrap_or_else(|error| {
                panic!("the process printed no line within {DEADLINE:?}: {error}")
            })
        }
    }

    impl Drop for Running
    {
        /// Kill the process and reap it.
        ///
        /// # Specification
        /// - ensures: the process has exited and been reaped.
        /// - panics: when the process cannot be killed or reaped.
        fn drop(&mut self)
        {
            self.child.kill().unwrap();
            let _status = self.child.wait().unwrap();
        }
    }

    /// A playbook and its rubric validate, a broken one is refused by file
    /// and field, and a run on the task's current dispatch commits each
    /// verification and grading, which the replay shows.
    ///
    /// # Specification
    /// - ensures: `rubric validate` on rubric R (questions `landed`, `passed`,
    ///   `tested`) prints `rubric r landing` and one `question <name> <hash>`
    ///   line per question in the names' order; `playbook validate` on playbook
    ///   P prints `playbook p landing`, `step note verifier`, `step failing
    ///   verifier` and `step <id> question r <id> <hash>` per question step,
    ///   the hashes those R printed. A playbook whose step lacks `why` exits 1
    ///   naming `<file>: steps[0].why: missing field`, and a rubric whose band
    ///   is inverted names `<file>: band: …`. O's run of P on its open task,
    ///   which has no dispatch, fails before any verifier runs. Once O
    ///   dispatches S, O's grading of R from an empty table prints the rubric,
    ///   the transcript t, three unread rulings, the verdict V₁, three
    ///   `refused` grades and `graded G₁ refused`. O's run of P from a table
    ///   reading `landed` met and `passed` undecided prints the playbook,
    ///   `verified <commit> note <output> exit 0` and `verified <commit>
    ///   failing <output> exit 3` with distinct outputs, then the grading lines
    ///   ending `graded G₂ refused`; the passing verifier ran once, in the
    ///   task's state. With `tested` read as unmet, R grades `graded G₃ unmet`.
    ///   O's local replay prints the dispatch, each verdict with its rulings,
    ///   each grading with its grades, each verification with O as runner and p
    ///   as playbook, `graded D G₃ unmet`, and `evidence <digest> held` for t
    ///   and each output in the order first named: each kept on O's side.
    /// - panics: on any contract violation.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one contract walked end to end, each step depending on the last"
    )]
    fn a_playbook_runs_its_checks_and_replay_shows_the_receipts()
    {
        let (o, s, files, task) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let (o, s, files, task) = (o.path(), s.path(), files.path(), task.path());
        // The last word of a line that begins with the prefix and a space.
        let last = |line: &str, prefix: &str| {
            assert!(
                line.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(' ')),
                "{line:?} begins with {prefix:?}"
            );
            line.rsplit(' ').next().unwrap().to_owned()
        };
        // A BLAKE3 hash or a commit id: 64 hex digits.
        let hashed =
            |word: &str| word.len() == 64 && word.bytes().all(|byte| byte.is_ascii_hexdigit());
        let o_peer = finish(peer(o).arg("id"))[1].clone();
        let s_id = finish(peer(s).arg("id"));
        let (s_endpoint, s_peer) = (s_id[0].clone(), s_id[1].clone());
        let (rubric_file, playbook_file) = (files.join("rubric.toml"), files.join("playbook.toml"));
        std::fs::write(&rubric_file, RUBRIC).unwrap();
        std::fs::write(&playbook_file, PLAYBOOK).unwrap();
        std::fs::write(
            task.join("note.txt"),
            "The change landed, and every check passed.\n",
        )
        .unwrap();

        let rubric_lines = finish(peer(o).args(["rubric", "validate"]).arg(&rubric_file));
        let [
            ref rubric_line,
            ref landed_line,
            ref passed_line,
            ref tested_line,
        ] = *rubric_lines.as_slice()
        else {
            panic!("a rubric prints itself and each question: {rubric_lines:?}");
        };
        let rubric = rubric_line
            .strip_prefix("rubric ")
            .and_then(|rest| rest.strip_suffix(" landing"))
            .unwrap_or_else(|| panic!("the rubric line: {rubric_line:?}"))
            .to_owned();
        let (landed, passed, tested) = (
            last(landed_line, "question landed"),
            last(passed_line, "question passed"),
            last(tested_line, "question tested"),
        );
        for hash in [&rubric, &landed, &passed, &tested] {
            assert!(hashed(hash), "named by its hash: {hash:?}");
        }
        let playbook_lines = finish(peer(o).args(["playbook", "validate"]).arg(&playbook_file));
        let playbook = playbook_lines
            .first()
            .and_then(|line| line.strip_prefix("playbook "))
            .and_then(|rest| rest.strip_suffix(" landing"))
            .unwrap_or_else(|| panic!("the playbook line: {playbook_lines:?}"))
            .to_owned();
        assert!(hashed(&playbook), "named by its hash: {playbook:?}");
        assert_eq!(
            playbook_lines,
            [
                format!("playbook {playbook} landing"),
                "step note verifier".to_owned(),
                "step failing verifier".to_owned(),
                format!("step landed question {rubric} landed {landed}"),
                format!("step passed question {rubric} passed {passed}"),
                format!("step tested question {rubric} tested {tested}"),
            ],
            "a playbook prints each step, its questions by the rubric's hashes"
        );

        let (broken, inverted) = (files.join("broken.toml"), files.join("inverted.toml"));
        std::fs::write(
            &broken,
            "name = \"broken\"\n\n[[steps]]\nid = \"note\"\nverifier = { command = \"sh\" }\n",
        )
        .unwrap();
        std::fs::write(&inverted, RUBRIC.replace("low = 0.25", "low = 0.9")).unwrap();
        assert_eq!(
            refused(peer(o).args(["playbook", "validate"]).arg(&broken)),
            format!(
                "domhringr-peer: {}: steps[0].why: missing field",
                broken.display()
            )
        );
        assert_eq!(
            refused(peer(o).args(["rubric", "validate"]).arg(&inverted)),
            format!(
                "domhringr-peer: {}: band: the band's low bound is not below its high bound",
                inverted.display()
            )
        );

        let tree = finish(peer(o).arg("open"))[0].clone();
        let (empty, table) = (files.join("empty"), files.join("table"));
        std::fs::write(&empty, "").unwrap();
        let checks = |document: &str, file: &Path, answers: &Path| {
            let mut command = peer(o);
            let _command = command
                .arg(document)
                .arg(if document == "playbook" {
                    "run"
                }
                else {
                    "grade"
                })
                .arg(file)
                .arg(&tree)
                .arg("--task-state")
                .arg(task)
                .arg("--static")
                .arg(answers);
            command
        };
        assert_eq!(
            refused(&mut checks("playbook", &playbook_file, &empty)),
            "domhringr-peer: the task has no dispatch: nothing to report on, hand off, retire \
             from or rule on"
        );
        assert!(
            !task.join("runs.txt").exists(),
            "a task with no dispatch is refused before any verifier runs"
        );

        let contact = format!("{s_endpoint}@127.0.0.1:{}", free_port());
        let dialing = Running::spawn(peer(o).args([
            "dispatch",
            tree.as_str(),
            s_peer.as_str(),
            "content",
            BRIEF,
            "--at",
            contact.as_str(),
        ]));
        let dispatch = dialing.line();
        drop(dialing);

        let unlisted = run(&mut checks("rubric", &rubric_file, &empty));
        assert!(
            unlisted.status.success(),
            "a refused grade still succeeds: {unlisted:?}"
        );
        assert_eq!(diagnosed(&unlisted).len(), 3, "one cause per unread ruling");
        let lines = printed(&unlisted);
        let [_, ref transcript_line, .., ref first_graded] = *lines.as_slice()
        else {
            panic!("a grading prints its receipts: {lines:?}");
        };
        let transcript = last(transcript_line, "transcript");
        let verdict_line = lines.get(5).cloned().unwrap_or_default();
        let first_verdict = last(&verdict_line, "verdict");
        let first_grading = first_graded
            .strip_prefix("graded ")
            .and_then(|rest| rest.strip_suffix(" refused"))
            .unwrap_or_else(|| panic!("the grading line: {first_graded:?}"))
            .to_owned();
        assert_eq!(
            lines,
            [
                format!("rubric {rubric} landing"),
                format!("transcript {transcript}"),
                format!("ruling {landed} unread malformed"),
                format!("ruling {passed} unread malformed"),
                format!("ruling {tested} unread malformed"),
                format!("verdict {first_verdict}"),
                format!("grade {landed} refused"),
                format!("grade {passed} refused"),
                format!("grade {tested} refused"),
                format!("graded {first_grading} refused"),
            ],
            "every question unread grades refused, and the rubric with them"
        );

        let (met, undecided, unmet) = (
            "read A A=0.9 B=0.1 outside=0",
            "read A A=0.6 B=0.4 outside=0",
            "read B A=0.1 B=0.9 outside=0",
        );
        std::fs::write(
            &table,
            format!("{landed} {transcript} {met}\n{passed} {transcript} {undecided}\n"),
        )
        .unwrap();
        let ran = finish(&mut checks("playbook", &playbook_file, &table));
        let [_, ref note_line, ref failing_line, ..] = *ran.as_slice()
        else {
            panic!("a run prints its receipts: {ran:?}");
        };
        let note_fields = note_line.split(' ').collect::<Vec<_>>();
        let ["verified", note_commit, "note", note_output, "exit", "0"] = *note_fields.as_slice()
        else {
            panic!("the passing verifier exits 0: {note_line:?}");
        };
        let failing_fields = failing_line.split(' ').collect::<Vec<_>>();
        let [
            "verified",
            failing_commit,
            "failing",
            failing_output,
            "exit",
            "3",
        ] = *failing_fields.as_slice()
        else {
            panic!("the failing verifier's code is recorded: {failing_line:?}");
        };
        for name in [note_commit, note_output, failing_commit, failing_output] {
            assert!(hashed(name), "named by 64 hex digits: {name:?}");
        }
        assert_ne!(note_output, failing_output, "each output by its own digest");
        assert_eq!(
            std::fs::read_to_string(task.join("runs.txt")).unwrap(),
            "ran\n",
            "the verifier ran once, in the task's state"
        );
        let second_verdict = last(&ran.get(8).cloned().unwrap_or_default(), "verdict");
        let second_grading = ran
            .last()
            .and_then(|line| line.strip_prefix("graded "))
            .and_then(|rest| rest.strip_suffix(" refused"))
            .unwrap_or_else(|| panic!("an unread question refuses the rubric: {ran:?}"))
            .to_owned();
        assert_eq!(
            ran,
            [
                format!("playbook {playbook} landing"),
                note_line.clone(),
                failing_line.clone(),
                format!("rubric {rubric} landing"),
                format!("transcript {transcript}"),
                format!("ruling {landed} {met}"),
                format!("ruling {passed} {undecided}"),
                format!("ruling {tested} unread malformed"),
                format!("verdict {second_verdict}"),
                format!("grade {landed} met"),
                format!("grade {passed} undecided"),
                format!("grade {tested} refused"),
                format!("graded {second_grading} refused"),
            ],
            "the band grades each ruling, and a refusal outranks the undecided"
        );

        std::fs::write(
            &table,
            format!(
                "{landed} {transcript} {met}\n{passed} {transcript} {undecided}\n{tested} \
                 {transcript} {unmet}\n"
            ),
        )
        .unwrap();
        let graded = finish(&mut checks("rubric", &rubric_file, &table));
        let third_verdict = last(&graded.get(5).cloned().unwrap_or_default(), "verdict");
        let third_grading = graded
            .last()
            .and_then(|line| line.strip_prefix("graded "))
            .and_then(|rest| rest.strip_suffix(" unmet"))
            .unwrap_or_else(|| panic!("an unmet question fails the rubric: {graded:?}"))
            .to_owned();
        assert_eq!(graded[6 .. 9], [
            format!("grade {landed} met"),
            format!("grade {passed} undecided"),
            format!("grade {tested} unmet"),
        ]);

        let mut replayed = vec![format!("dispatch {dispatch} {s_peer} content {BRIEF}")];
        let gradings = [
            (
                &first_verdict,
                &first_grading,
                ["unread malformed"; 3],
                ["refused"; 3],
                "refused",
            ),
            (
                &second_verdict,
                &second_grading,
                [met, undecided, "unread malformed"],
                ["met", "undecided", "refused"],
                "refused",
            ),
            (
                &third_verdict,
                &third_grading,
                [met, undecided, unmet],
                ["met", "undecided", "unmet"],
                "unmet",
            ),
        ];
        for (index, (verdict, grading, rulings, grades, composed)) in
            gradings.into_iter().enumerate()
        {
            if index == 1 {
                replayed.push(format!(
                    "verified {note_commit} {dispatch} {o_peer} {playbook} note {note_output} \
                     exit 0"
                ));
                replayed.push(format!(
                    "verified {failing_commit} {dispatch} {o_peer} {playbook} failing \
                     {failing_output} exit 3"
                ));
            }
            replayed.push(format!(
                "verdict {verdict} {dispatch} {o_peer} {rubric} {transcript}"
            ));
            for (question, ruling) in [&landed, &passed, &tested].into_iter().zip(rulings) {
                replayed.push(format!("ruling {verdict} {question} {ruling}"));
            }
            replayed.push(format!(
                "graded {grading} {dispatch} {verdict} {rubric} {composed}"
            ));
            for (question, grade) in [&landed, &passed, &tested].into_iter().zip(grades) {
                replayed.push(format!("grade {grading} {question} {grade}"));
            }
        }
        replayed.push(format!("graded {dispatch} {third_grading} unmet"));
        replayed.extend([
            format!("evidence {transcript} held"),
            format!("evidence {note_output} held"),
            format!("evidence {failing_output} held"),
        ]);
        assert_eq!(
            finish(peer(o).args(["replay", tree.as_str(), "--local"])),
            replayed,
            "the replay shows every verification and grading on the dispatch, and the attempt \
             graded as the last grading composed"
        );
    }

    /// Every rubric of the set validates and grades its fixture pair: met
    /// over its `met` state, and unmet over its `unmet` state with the
    /// question the pair isolates unmet; the replay holds each grading naming
    /// the rubric and every question.
    ///
    /// # Specification
    /// - ensures: for each `<name>.toml` in [`SET`], in name order, `rubric
    ///   validate` prints `rubric r <name>` and its questions; the transcripts
    ///   of the state directories `fixtures/<name>/met` and
    ///   `fixtures/<name>/unmet` differ, and `fixtures/<name>/isolates` names
    ///   one of the questions. From a table reading every question [`HOLDS`]
    ///   about the `met` transcript, and about the `unmet` one the isolated
    ///   question [`FAILS`] and every other [`HOLDS`], O's grading over `met`
    ///   prints the rubric, the transcript t, each ruling, the verdict V, every
    ///   grade `met` and `graded G met`; over `unmet` it prints the isolated
    ///   question's grade `unmet`, every other `met`, and `graded G unmet`. O's
    ///   local replay prints the dispatch D; per grading, the verdict naming D,
    ///   O, r and t with each question's ruling, and the grading naming D, V, r
    ///   and the composition with each question's grade; then `dispatched D S`
    ///   and `evidence t held` per transcript in the order first named.
    /// - panics: on any contract violation.
    #[test]
    fn every_rubric_in_the_set_grades_its_fixture_pair()
    {
        let (o, s, files) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let (o, s, files) = (o.path(), s.path(), files.path());
        let task = Dispatched::open(o, s);
        let mut replayed = vec![format!(
            "dispatch {} {} content {BRIEF}",
            task.dispatch, task.seat
        )];
        let mut standing = format!("dispatched {} {}", task.dispatch, task.seat);
        let mut held = Vec::new();
        for file in rubric_files() {
            let Validated {
                name,
                hash: rubric,
                questions,
            } = validate(o, &file);
            let pair = Path::new(SET).join("fixtures").join(&name);
            let isolated = isolated(&pair);
            assert!(
                questions.iter().any(|asked| asked.name == isolated),
                "{name}: its pair isolates a question it holds, not {isolated:?}"
            );
            let loaded = Loaded::<Rubric>::read(&file).unwrap();
            let transcript = |member: &str| {
                loaded
                    .document()
                    .transcript(&pair.join(member))
                    .unwrap_or_else(|error| panic!("{name}: its {member} state reads: {error}"))
                    .digest()
                    .to_string()
            };
            let (met, unmet) = (transcript("met"), transcript("unmet"));
            assert_ne!(met, unmet, "{name}: the members of its pair differ");
            let members = [("met", met, "met"), ("unmet", unmet, "unmet")];
            // Each question's ruling and grade over a member: every criterion
            // holds over `met`, and over `unmet` all but the isolated one.
            let answer = |member: &str, question: &str| {
                if member == "unmet" && question == isolated {
                    (FAILS, "unmet")
                }
                else {
                    (HOLDS, "met")
                }
            };
            let table = members
                .iter()
                .flat_map(|&(member, ref transcript, _)| {
                    questions.iter().map(move |asked| {
                        let (ruling, _) = answer(member, &asked.name);
                        format!("{} {transcript} {ruling}\n", asked.hash)
                    })
                })
                .collect::<String>();
            let answers = files.join(&name);
            std::fs::write(&answers, table).unwrap();

            for &(member, ref transcript, composed) in &members {
                let answered = questions
                    .iter()
                    .map(|asked| (asked.hash.as_str(), answer(member, &asked.name)))
                    .collect::<Vec<_>>();
                let graded = finish(
                    peer(o)
                        .args(["rubric", "grade"])
                        .arg(&file)
                        .arg(&task.tree)
                        .arg("--task-state")
                        .arg(pair.join(member))
                        .arg("--static")
                        .arg(&answers),
                );
                let verdict = graded
                    .get(questions.len().saturating_add(2))
                    .and_then(|line| line.strip_prefix("verdict "))
                    .unwrap_or_else(|| {
                        panic!("{name} over its {member} state commits a verdict: {graded:?}")
                    })
                    .to_owned();
                let grading = graded
                    .last()
                    .and_then(|line| line.strip_prefix("graded "))
                    .and_then(|rest| rest.split(' ').next())
                    .unwrap_or_else(|| {
                        panic!("{name} is graded over its {member} state: {graded:?}")
                    })
                    .to_owned();
                let mut expected = vec![
                    format!("rubric {rubric} {name}"),
                    format!("transcript {transcript}"),
                ];
                expected.extend(
                    answered
                        .iter()
                        .map(|&(hash, (ruling, _))| format!("ruling {hash} {ruling}")),
                );
                expected.push(format!("verdict {verdict}"));
                expected.extend(
                    answered
                        .iter()
                        .map(|&(hash, (_, grade))| format!("grade {hash} {grade}")),
                );
                expected.push(format!("graded {grading} {composed}"));
                assert_eq!(
                    graded, expected,
                    "{name} grades {composed} over its {member} state"
                );

                replayed.push(format!(
                    "verdict {verdict} {} {} {rubric} {transcript}",
                    task.dispatch, task.judge
                ));
                replayed.extend(
                    answered
                        .iter()
                        .map(|&(hash, (ruling, _))| format!("ruling {verdict} {hash} {ruling}")),
                );
                replayed.push(format!(
                    "graded {grading} {} {verdict} {rubric} {composed}",
                    task.dispatch
                ));
                replayed.extend(
                    answered
                        .iter()
                        .map(|&(hash, (_, grade))| format!("grade {grading} {hash} {grade}")),
                );
                standing = format!("graded {} {grading} {composed}", task.dispatch);
                let line = format!("evidence {transcript} held");
                if !held.contains(&line) {
                    held.push(line);
                }
            }
        }
        replayed.push(standing);
        replayed.extend(held);
        assert_eq!(
            finish(peer(o).args(["replay", task.tree.as_str(), "--local"])),
            replayed,
            "the replay holds every grading, naming its rubric and every question"
        );
    }

    /// A fixture pair of the set graded by the judge the environment
    /// configures: `stable-refs` is met over its `met` state, and unmet over
    /// its `unmet` state on the question the pair isolates.
    ///
    /// # Specification
    /// - ensures: O, having dispatched S, grades `stable-refs` over its `met`
    ///   state to `graded G met`, and over its `unmet` state to `graded G
    ///   unmet` with the isolated question's grade `unmet`.
    /// - panics: on any contract violation, a judge the environment does not
    ///   configure among them.
    #[test]
    #[ignore = "asks the judge the environment configures: run with --ignored where \
                DOMHRINGR_JUDGE_ENDPOINT and DOMHRINGR_JUDGE_MODEL name one"]
    fn a_configured_judge_grades_a_fixture_pair_of_the_set()
    {
        let (o, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (o, s) = (o.path(), s.path());
        let task = Dispatched::open(o, s);
        let (file, pair) = (
            Path::new(SET).join("stable-refs.toml"),
            Path::new(SET).join("fixtures").join("stable-refs"),
        );
        let Validated { questions, .. } = validate(o, &file);
        let isolated = isolated(&pair);
        let hash = questions
            .iter()
            .find(|asked| asked.name == isolated)
            .map_or_else(
                || panic!("the pair isolates a question the rubric holds"),
                |asked| asked.hash.clone(),
            );
        for (member, composed) in [("met", "met"), ("unmet", "unmet")] {
            // A model may take longer than the deadline to answer, so the
            // command runs to its end.
            let output = peer(o)
                .args(["rubric", "grade"])
                .arg(&file)
                .arg(&task.tree)
                .arg("--task-state")
                .arg(pair.join(member))
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "the grading runs: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let graded = printed(&output);
            assert!(
                graded
                    .last()
                    .is_some_and(|line| line.starts_with("graded ")
                        && line.ends_with(&format!(" {composed}"))),
                "the judge grades stable-refs {composed} over its {member} state: {graded:?}"
            );
            assert!(
                member == "met" || graded.contains(&format!("grade {hash} unmet")),
                "the judge fails the question the pair isolates: {graded:?}"
            );
        }
    }
}
