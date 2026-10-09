//! The peer binary's evidence contract, exercised as processes: a seat
//! reports a value of many chunks, an operator replaying the task fetches it
//! through the book, a reader holding nothing fetches it from the seat by
//! name, and once the seat has lost a chunk a reader is refused naming that
//! chunk, printing nothing and keeping nothing.

#[cfg(test)]
mod tests
{
    use core::time::Duration;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::io::BufRead as _;
    use std::os::unix::fs::PermissionsExt as _;
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

    /// The brief the operator dispatches, by content hash.
    const BRIEF: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    /// The first line the seat's program prints: the report's summary.
    const SUMMARY: &str = "the checks ran";

    /// The body the seat's program prints after its summary: a test run's
    /// output from the evidence corpus, long enough to span many chunks.
    const BODY: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../record-evidence/tests/corpus/output-nextest"
    );

    /// The peer binary on the state directory `state`.
    ///
    /// # Specification
    /// trivial.
    fn peer(state: &Path) -> Command
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_domhringr-peer"));
        command.arg("--state").arg(state);
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

    /// Run `command` to completion and return its output, having exited 0.
    ///
    /// # Specification
    /// - ensures: the command exited 0 within [`DEADLINE`].
    /// - panics: as [`run`], or when it exits non-zero (its standard error is
    ///   shown).
    fn succeeded(command: &mut Command) -> Output
    {
        let output = run(command);
        assert!(
            output.status.success(),
            "{command:?}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Run `command` to completion and return the lines it printed.
    ///
    /// # Specification
    /// - panics: as [`succeeded`], or when it prints anything but UTF-8.
    fn finish(command: &mut Command) -> Vec<String>
    {
        String::from_utf8(succeeded(command).stdout)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
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

    /// The names of the files in the evidence store's directory `path`, in
    /// name order; none when the directory does not exist.
    ///
    /// # Specification
    /// - panics: when the directory exists but cannot be listed.
    fn stored(path: &Path) -> Vec<String>
    {
        if !path.exists() {
            return Vec::new();
        }
        let mut names = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    /// A running process and its standard output, read as it arrives.
    ///
    /// The process is killed when the value drops, so a failing test leaves
    /// no process behind.
    struct Running
    {
        /// The process.
        child: Child,
        /// Its standard output, one line per message, from a reader thread.
        lines: mpsc::Receiver<String>,
    }

    impl Running
    {
        /// Start `serve` on `state` at the fixed `port`, acting through the
        /// program `surface`, and read its announcement.
        ///
        /// # Specification
        /// - ensures: the process is running and its standard output is read
        ///   line by line, its standard error passing through to the test's; it
        ///   has announced `ids` and `listening`.
        /// - panics: when the process cannot start or its announcement is not
        ///   `ids` and `listening`.
        fn serve(
            state: &Path,
            port: &OsStr,
            surface: &Path,
            ids: &[String],
        ) -> Self
        {
            let mut child = peer(state)
                .args(["serve", "--port"])
                .arg(port)
                .arg("--surface")
                .arg(surface)
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
            let server = Self { child, lines };
            let mut announced = ids.to_vec();
            announced.push("listening".into());
            assert_eq!(
                core::iter::repeat_with(|| server.line())
                    .take(3)
                    .collect::<Vec<_>>(),
                announced,
                "serve announces its ids"
            );
            server
        }

        /// Assert the server admitted the peer `dialer` and printed the path
        /// its connection took.
        ///
        /// # Specification
        /// - panics: unless the next line is `accepted` with `dialer` and the
        ///   one after is a path line for it, each within [`DEADLINE`].
        fn admitted(
            &self,
            dialer: &OsStr,
        )
        {
            let dialer = dialer.to_string_lossy();
            assert_eq!(
                self.line(),
                format!("accepted {dialer}"),
                "the server admits the dialer"
            );
            let path = self.line();
            assert!(
                path.starts_with(&format!("path {dialer} ")),
                "a path line for the dialer: {path:?}"
            );
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

    /// A seat's report is evidence another process dereferences over the
    /// fetch stream, whole or not at all.
    ///
    /// # Specification
    /// - ensures: S serves acting through a program printing [`SUMMARY`] and
    ///   then [`BODY`], the report bytes P; O opens a task and dispatches S to
    ///   [`BRIEF`] at S's endpoint, and S prints `woken <tree> D` and `reported
    ///   <tree> R`, its store holding P in more than one chunk. O's replay
    ///   through the book prints `report R D S <digest> <summary>` and ends
    ///   `evidence <digest> held`, S printing `served <digest>`; O's local
    ///   `evidence` then prints P byte for byte. B, holding no tree and no
    ///   evidence, names S and its endpoint and prints P byte for byte, S
    ///   printing `served <digest>` again. With one chunk C removed from S's
    ///   store, R, holding nothing, exits 1 with nothing on standard output,
    ///   standard error reading `domhringr-peer: evidence <digest> is refused:
    ///   no chunk is stored under C`, and no manifest kept; S still serves what
    ///   it holds and prints `served <digest>`.
    /// - panics: on any contract violation.
    #[test]
    fn a_reader_fetches_a_seats_report_and_refuses_a_missing_chunk()
    {
        let (o, s, b, r, files) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let (o, s, b, r, files) = (o.path(), s.path(), b.path(), r.path(), files.path());
        let (o_id, s_id) = (finish(peer(o).arg("id")), finish(peer(s).arg("id")));
        let o_peer = OsString::from(&o_id[1]);
        let (s_endpoint, s_peer) = (s_id[0].clone(), s_id[1].clone());
        let port = free_port();
        let contact = format!("{s_endpoint}@127.0.0.1:{port}");
        let tree = only(peer(o).arg("open"));

        let surface = files.join("surface");
        std::fs::write(
            &surface,
            format!("#!/bin/sh\nprintf '%s\\n' '{SUMMARY}'\ncat '{BODY}'\n"),
        )
        .unwrap();
        std::fs::set_permissions(&surface, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut printed = format!("{SUMMARY}\n").into_bytes();
        printed.extend(std::fs::read(BODY).unwrap());

        let seat = Running::serve(s, OsStr::new(&port), &surface, &s_id);
        let dispatched = finish(peer(o).args([
            "dispatch",
            tree.as_str(),
            s_peer.as_str(),
            "content",
            BRIEF,
            "--at",
            contact.as_str(),
        ]));
        let dispatch = dispatched
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("a dispatch prints its commit: {dispatched:?}"));
        seat.admitted(&o_peer);
        assert_eq!(seat.line(), format!("woken {tree} {dispatch}"));
        let reported = seat.line();
        let report = reported
            .strip_prefix(&format!("reported {tree} "))
            .unwrap_or_else(|| panic!("the seat reports: {reported:?}"))
            .to_owned();
        let chunks = stored(&s.join("evidence").join("chunks"));
        assert!(
            chunks.len() > 1,
            "the report spans more than one chunk: {chunks:?}"
        );

        let replayed = finish(peer(o).args(["replay", tree.as_str()]));
        seat.admitted(&o_peer);
        let report_line = replayed
            .iter()
            .find(|line| line.starts_with(&format!("report {report} ")))
            .unwrap_or_else(|| panic!("the replay holds the report: {replayed:?}"));
        let fields = report_line.split(' ').collect::<Vec<_>>();
        let ["report", _, on, author, digest, ref summary @ ..] = *fields.as_slice()
        else {
            panic!(
                "a report line names its commit, dispatch, author, content and summary: {report_line:?}"
            );
        };
        assert_eq!(
            [on, author, summary.join(" ").as_str()],
            [dispatch.as_str(), s_peer.as_str(), SUMMARY],
            "the seat reports on the dispatch, summarized by the program's first line"
        );
        let digest = digest.to_owned();
        assert_eq!(
            replayed.last(),
            Some(&format!("evidence {digest} held")),
            "the replay fetches the report through the book"
        );
        assert_eq!(seat.line(), format!("served {digest}"));
        assert_eq!(
            succeeded(peer(o).args(["evidence", "--local", tree.as_str(), digest.as_str()])).stdout,
            printed,
            "the operator holds the report byte for byte"
        );

        let fetch = |state: &Path| {
            let mut command = peer(state);
            let _command = command.args([
                "evidence",
                "--peer",
                s_peer.as_str(),
                "--at",
                contact.as_str(),
                tree.as_str(),
                digest.as_str(),
            ]);
            command
        };
        assert_eq!(
            succeeded(&mut fetch(b)).stdout,
            printed,
            "a reader holding nothing fetches the report byte for byte"
        );
        assert_eq!(seat.line(), format!("served {digest}"));

        let missing = chunks.first().cloned().unwrap();
        std::fs::remove_file(s.join("evidence").join("chunks").join(&missing)).unwrap();
        let refused = run(&mut fetch(r));
        assert_eq!(refused.status.code(), Some(1_i32), "{refused:?}");
        assert!(
            refused.stdout.is_empty(),
            "a refused fetch prints nothing: {:?}",
            String::from_utf8_lossy(&refused.stdout)
        );
        assert_eq!(
            String::from_utf8(refused.stderr).unwrap(),
            format!(
                "domhringr-peer: evidence {digest} is refused: no chunk is stored under \
                 {missing}\n"
            ),
            "the refusal names the chunk neither side holds"
        );
        assert!(
            stored(&r.join("evidence").join("manifests")).is_empty(),
            "a refused fetch keeps nothing"
        );
        assert_eq!(
            seat.line(),
            format!("served {digest}"),
            "the seat serves what it holds"
        );
        drop(seat);
    }
}
