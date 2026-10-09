//! The peer binary's judge contract, exercised as processes: a judge asks
//! lettered questions about a transcript, answered from a table file or from
//! an endpoint that cannot answer, and rules on a task's current dispatch;
//! every refusal is recorded as an unread ruling, never a default letter, and
//! the replay shows the verdict.

#[cfg(test)]
mod tests
{
    use core::time::Duration;
    use std::ffi::OsString;
    use std::io::BufRead as _;
    use std::path::Path;
    use std::process::Child;
    use std::process::Command;
    use std::process::Output;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Instant;

    /// How long one command may run, or a running process may take to print a
    /// line.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// How often a running command is polled for its exit.
    const POLL: Duration = Duration::from_millis(20);

    /// The brief the task's dispatch names, by content hash.
    const BRIEF: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    /// The rubric the verdict's questions come from, by content hash.
    const RUBRIC: &str = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";

    /// The environment that configures the judge's endpoint.
    const VARIABLES: [&str; 4] = [
        "DOMHRINGR_JUDGE_ENDPOINT",
        "DOMHRINGR_JUDGE_MODEL",
        "DOMHRINGR_JUDGE_KEY",
        "DOMHRINGR_JUDGE_CEILING",
    ];

    /// The peer binary on the state directory `state`, with no judge endpoint
    /// configured.
    ///
    /// # Specification
    /// trivial.
    fn peer(state: &Path) -> Command
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_domhringr-peer"));
        command.arg("--state").arg(state);
        for variable in VARIABLES {
            let _command = command.env_remove(variable);
        }
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

    /// Run `command` to completion and return the one line it printed.
    ///
    /// # Specification
    /// - panics: as [`finish`], or unless exactly one line was printed.
    fn only(command: &mut Command) -> String
    {
        let lines = finish(command);
        let [ref line] = *lines.as_slice()
        else {
            panic!("{command:?} prints one line: {lines:?}");
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

    /// A URL on the loopback address where nothing listens.
    ///
    /// # Specification
    /// trivial.
    fn nowhere() -> String
    {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("http://127.0.0.1:{port}/v1")
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

    /// A judge reads the letter a table records for a question about a
    /// transcript, records every refusal as unread, and commits its rulings as
    /// a verdict on the task's current dispatch, which the replay shows.
    ///
    /// # Specification
    /// - ensures: O asks question Q (`yes`, `no`) about the transcript file T
    ///   from an empty table: it prints `transcript t` and `ruling q unread
    ///   malformed`, exits 0, and names the cause on standard error. From a
    ///   table recording `read A A=0.9 B=0.1 outside=0` for q about t, the same
    ///   ask by T's file prints that ruling, whose letter is `A` and whose
    ///   option probabilities sum to one; by t alone, before anything keeps it,
    ///   the ask exits 1 with nothing printed, naming `evidence t is not held`.
    ///   With the endpoint configured at a loopback address where nothing
    ///   listens, the ask prints `ruling q unread endpoint` and exits 0; with
    ///   no endpoint configured, it fails naming the missing configuration. A
    ///   verdict on O's open task, which has no dispatch, fails before asking
    ///   anything. Once O dispatches S, O's verdict on Q and on R (`main`,
    ///   `other`), which the table does not hold, prints the transcript line,
    ///   `ruling q read A …`, `ruling r unread malformed` and its commit V, and
    ///   keeps t: the ask by t alone then prints the same ruling. O's local
    ///   replay prints `dispatch D S content <brief>`, `verdict V D O <rubric>
    ///   t`, the two ruling lines under V, `dispatched D S` — the verdict
    ///   answers no attempt — and `evidence t held`.
    /// - panics: on any contract violation.
    #[test]
    fn a_judge_rules_on_a_transcript_and_replay_shows_the_verdict()
    {
        let (o, s, files) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let (o, s, files) = (o.path(), s.path(), files.path());
        let o_peer = finish(peer(o).arg("id"))[1].clone();
        let s_id = finish(peer(s).arg("id"));
        let (s_endpoint, s_peer) = (s_id[0].clone(), s_id[1].clone());
        let (transcript_file, empty, table) = (
            files.join("transcript"),
            files.join("empty"),
            files.join("table"),
        );
        std::fs::write(
            &transcript_file,
            "The seat merged the branch, and every check passed.\n",
        )
        .unwrap();
        std::fs::write(&empty, "").unwrap();
        let asked = [
            "--question",
            "Did every check pass?",
            "--option",
            "yes",
            "--option",
            "no",
        ];
        let other = [
            "--question",
            "Which branch?",
            "--option",
            "main",
            "--option",
            "other",
        ];
        let ask = |transcript: &[OsString], judging: &[OsString]| {
            let mut command = peer(o);
            let _command = command
                .args(["judge", "ask"])
                .args(asked)
                .args(transcript)
                .args(judging);
            command
        };
        let from_file = [
            OsString::from("--transcript-file"),
            OsString::from(&transcript_file),
        ];
        let from_table = |file: &Path| [OsString::from("--static"), OsString::from(file)];

        let unlisted = run(&mut ask(&from_file, &from_table(&empty)));
        assert!(unlisted.status.success(), "a refusal still succeeds");
        let lines = printed(&unlisted);
        let [ref transcript_line, ref ruling_line] = *lines.as_slice()
        else {
            panic!("an ask prints the transcript and the ruling: {lines:?}");
        };
        let transcript = transcript_line
            .strip_prefix("transcript ")
            .unwrap_or_else(|| panic!("the transcript line: {transcript_line:?}"))
            .to_owned();
        let fields = ruling_line.split(' ').collect::<Vec<_>>();
        let ["ruling", question, "unread", "malformed"] = *fields.as_slice()
        else {
            panic!("an empty table records an unread ruling: {ruling_line:?}");
        };
        let question = question.to_owned();
        for hash in [&transcript, &question] {
            assert!(
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "named by its hash: {hash:?}"
            );
        }
        let diagnostics = diagnosed(&unlisted);
        assert!(
            matches!(*diagnostics.as_slice(), [ref cause] if cause.starts_with("domhringr-peer: ")),
            "the refusal's cause is on standard error: {diagnostics:?}"
        );

        let read = "read A A=0.9 B=0.1 outside=0";
        std::fs::write(&table, format!("{question} {transcript} {read}\n")).unwrap();
        let ruled = [
            format!("transcript {transcript}"),
            format!("ruling {question} {read}"),
        ];
        assert_eq!(
            finish(&mut ask(&from_file, &from_table(&table))),
            ruled,
            "the table answers the question about the transcript"
        );
        let named = [OsString::from("--transcript"), OsString::from(&transcript)];
        let unheld = run(&mut ask(&named, &from_table(&table)));
        assert!(!unheld.status.success(), "{unheld:?}");
        assert!(
            printed(&unheld).is_empty(),
            "an unheld transcript is refused before any question is asked"
        );
        assert_eq!(
            diagnosed(&unheld),
            [format!("domhringr-peer: evidence {transcript} is not held")],
            "a transcript named by its digest is read from the evidence store"
        );
        let fields = read.split(' ').collect::<Vec<_>>();
        let ["read", "A", ref options @ .., outside] = *fields.as_slice()
        else {
            panic!("a read ruling names its letter: {read:?}");
        };
        let sum = options
            .iter()
            .map(|&option| option.split_once('=').unwrap().1.parse::<f64>().unwrap())
            .sum::<f64>();
        assert!(
            (sum - 1.0_f64).abs() < 1.0e-9_f64,
            "the option probabilities sum to one: {sum}"
        );
        assert_eq!(outside, "outside=0");

        let mut unreachable = ask(&from_file, &[]);
        let _unreachable = unreachable
            .env("DOMHRINGR_JUDGE_ENDPOINT", nowhere())
            .env("DOMHRINGR_JUDGE_MODEL", "judge");
        assert_eq!(
            finish(&mut unreachable),
            [
                format!("transcript {transcript}"),
                format!("ruling {question} unread endpoint")
            ],
            "an endpoint that cannot answer records an unread ruling"
        );
        let unconfigured = run(&mut ask(&from_file, &[]));
        assert!(!unconfigured.status.success());
        assert_eq!(printed(&unconfigured), [format!("transcript {transcript}")]);
        let diagnostics = diagnosed(&unconfigured);
        assert!(
            matches!(
                *diagnostics.as_slice(),
                [ref cause] if cause.starts_with("domhringr-peer: no judge endpoint configured")
            ),
            "with no endpoint configured the judge asks no one: {diagnostics:?}"
        );

        let tree = only(peer(o).arg("open"));
        let verdict = || {
            let mut command = peer(o);
            let _command = command
                .args(["judge", "verdict", tree.as_str(), "--rubric", RUBRIC])
                .args(&from_file)
                .args(asked)
                .args(other)
                .args(from_table(&table));
            command
        };
        let undispatched = run(&mut verdict());
        assert!(!undispatched.status.success());
        assert!(
            printed(&undispatched).is_empty(),
            "a task with no dispatch is refused before any question is asked"
        );
        assert_eq!(diagnosed(&undispatched), [
            "domhringr-peer: the task has no dispatch: nothing to report on, hand off, \
              retire from or rule on"
        ]);

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

        let ruling = run(&mut verdict());
        assert!(ruling.status.success(), "{ruling:?}");
        let lines = printed(&ruling);
        let [ref transcript_line, ref first, ref second, ref commit] = *lines.as_slice()
        else {
            panic!("a verdict prints the transcript, each ruling and its commit: {lines:?}");
        };
        let (other_line, other_question) = (
            second.clone(),
            second
                .strip_prefix("ruling ")
                .and_then(|rest| rest.strip_suffix(" unread malformed"))
                .unwrap_or_else(|| panic!("the unlisted question is unread: {second:?}"))
                .to_owned(),
        );
        assert_eq!(
            [transcript_line, first],
            [&ruled[0], &ruled[1]],
            "the verdict asks each question in order"
        );
        assert_eq!(diagnosed(&ruling).len(), 1, "one refusal, one cause");
        assert_eq!(
            other_line,
            format!("ruling {other_question} unread malformed")
        );
        assert_eq!(
            finish(&mut ask(&named, &from_table(&table))),
            ruled,
            "the verdict kept the transcript, so its digest names the same transcript"
        );
        assert_eq!(
            finish(peer(o).args(["replay", tree.as_str(), "--local"])),
            [
                format!("dispatch {dispatch} {s_peer} content {BRIEF}"),
                format!("verdict {commit} {dispatch} {o_peer} {RUBRIC} {transcript}"),
                format!("ruling {commit} {question} {read}"),
                format!("ruling {commit} {other_question} unread malformed"),
                format!("dispatched {dispatch} {s_peer}"),
                format!("evidence {transcript} held"),
            ],
            "the replay shows the verdict, which answers no attempt, and its transcript held"
        );
    }
}
