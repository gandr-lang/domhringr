//! The peer binary's seat contract, exercised as processes: an operator
//! dispatches a seat to a task and wakes it, the seat acts through the program
//! it serves with and reports, and the operator replays the task through the
//! seat's presence in the book — while each side is killed and started again,
//! holding its state in its store alone.

#[cfg(test)]
mod tests
{
    use core::time::Duration;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::io::BufRead as _;
    use std::path::Path;
    use std::process::Child;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Instant;

    /// How long one command may run, or a running process may take to print a
    /// line.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// How often a running command is polled for its exit.
    const POLL: Duration = Duration::from_millis(20);

    /// The brief the operator dispatches, by content hash. A seat's program
    /// is handed it as two operands, `content` and the hash, so `echo` prints
    /// them back as the report's summary.
    const BRIEF: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

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

    /// Run `command` to completion and return the lines it printed.
    ///
    /// # Specification
    /// - ensures: the command exited 0 within [`DEADLINE`].
    /// - panics: when it cannot start, outlives the deadline (it is killed
    ///   first), exits non-zero (its standard error is shown) or prints
    ///   anything but UTF-8.
    fn finish(command: &mut Command) -> Vec<String>
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
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{command:?}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
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

        /// Start `serve` on `state` at the fixed `port`, acting through the
        /// program `surface`, and read its announcement.
        ///
        /// # Specification
        /// - ensures: as [`Running::spawn`], and the process has announced
        ///   `ids` and `listening`.
        /// - panics: when the process cannot start or its announcement is not
        ///   `ids` and `listening`.
        fn serve(
            state: &Path,
            port: &OsStr,
            surface: &OsStr,
            ids: &[String],
        ) -> Self
        {
            let server = Self::spawn(
                peer(state)
                    .args(["serve", "--port"])
                    .arg(port)
                    .arg("--surface")
                    .arg(surface),
            );
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

    /// A dispatch outlives the operator that sent it and the seat that holds
    /// it: the seat reports on it once started again with a program that
    /// succeeds, and the operator replays the report through the seat's
    /// presence.
    ///
    /// # Specification
    /// - ensures: O opens a task and dispatches S to [`BRIEF`] at S's endpoint
    ///   on the loopback address while S is down; the dispatch prints its
    ///   commit id D, and O is killed while it dials. O's local replay prints
    ///   `dispatch D S content <brief>` and `dispatched D S`. S serves acting
    ///   through `false`; O's same dispatch, sent again, prints D, `source`,
    ///   the tree, `at` and S's endpoint, and `woken`, while S admits O and
    ///   prints `woken <tree> D` and `unreported <tree> D`. O's book then holds
    ///   S's presence, and O's replay, naming no peer and no endpoint, prints
    ///   `source`, the tree, `book` and S's presenting commit, then the two
    ///   lines above. S, killed and served again through `echo`, resumes the
    ///   dispatch it holds and prints `reported <tree> R`; O's replay through
    ///   the book then prints the source line, the dispatch line, `report R D S
    ///   <digest> content <brief>`, `reported D R` and `evidence <digest>
    ///   held`, fetching the report from S, which prints `served <digest>`; O's
    ///   local `evidence` then prints echo's output, `content <brief>`. O's
    ///   dispatch, sent once more through the book, prints D, the source line
    ///   and `woken`; S prints `woken <tree> D` and acts no more: O's replay
    ///   prints the same five lines.
    /// - panics: on any contract violation.
    #[test]
    fn a_dispatched_seat_reports_across_restarts_of_either_side()
    {
        let (o, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (o, s) = (o.path(), s.path());
        let (o_id, s_id) = (finish(peer(o).arg("id")), finish(peer(s).arg("id")));
        let o_peer = OsString::from(&o_id[1]);
        let (s_endpoint, s_peer) = (s_id[0].clone(), s_id[1].clone());
        let port = free_port();
        let contact = format!("{s_endpoint}@127.0.0.1:{port}");
        let tree = only(peer(o).arg("open"));
        let dispatch_to = |at: &[&str]| {
            let mut command = peer(o);
            let _command = command
                .args(["dispatch", tree.as_str(), s_peer.as_str(), "content", BRIEF])
                .args(at);
            command
        };

        let dialing = Running::spawn(&mut dispatch_to(&["--at", contact.as_str()]));
        let dispatch = dialing.line();
        drop(dialing);
        let dispatched = [
            format!("dispatch {dispatch} {s_peer} content {BRIEF}"),
            format!("dispatched {dispatch} {s_peer}"),
        ];
        assert_eq!(
            finish(peer(o).args(["replay", tree.as_str(), "--local"])),
            dispatched,
            "the dispatch outlives the operator that sent it"
        );

        let seat = Running::serve(s, OsStr::new(&port), OsStr::new("false"), &s_id);
        assert_eq!(
            finish(&mut dispatch_to(&["--at", contact.as_str()])),
            [
                dispatch.clone(),
                format!("source {tree} at {contact}"),
                "woken".into()
            ],
            "the dispatch sent again is the same dispatch, and wakes the seat"
        );
        seat.admitted(&o_peer);
        assert_eq!(seat.line(), format!("woken {tree} {dispatch}"));
        assert_eq!(
            seat.line(),
            format!("unreported {tree} {dispatch}"),
            "a failing program reports nothing"
        );
        let book = only(peer(o).args(["book", tree.as_str()]));
        let fields = book.split(' ').collect::<Vec<_>>();
        let [presenter, _endpoint, presented] = *fields.as_slice()
        else {
            panic!("a book line is a peer id, an endpoint and a commit: {book:?}");
        };
        assert_eq!(
            presenter, s_peer,
            "the woken seat presents itself, and the operator pulls the presence"
        );
        let through_book = format!("source {tree} book {presented}");
        let mut awaited = vec![through_book.clone()];
        awaited.extend(dispatched.iter().cloned());
        assert_eq!(
            finish(peer(o).args(["replay", tree.as_str()])),
            awaited,
            "the operator replays the task through the seat's presence"
        );
        seat.admitted(&o_peer);
        drop(seat);

        let seat = Running::serve(s, OsStr::new(&port), OsStr::new("echo"), &s_id);
        let reported = seat.line();
        let report = reported
            .strip_prefix(&format!("reported {tree} "))
            .unwrap_or_else(|| panic!("the restarted seat resumes and reports: {reported:?}"))
            .to_owned();
        let replayed = finish(peer(o).args(["replay", tree.as_str()]));
        seat.admitted(&o_peer);
        let [
            ref source,
            ref dispatch_line,
            ref report_line,
            ref standing,
            ref held,
        ] = *replayed.as_slice()
        else {
            panic!("the replay is a source line, three task lines and the evidence: {replayed:?}");
        };
        assert_eq!(source, &through_book);
        assert_eq!(dispatch_line, &dispatched[0]);
        let fields = report_line.split(' ').collect::<Vec<_>>();
        let ["report", by, on, author, content, "content", summary] = *fields.as_slice()
        else {
            panic!(
                "a report line names its commit, dispatch, author, content and summary: {report_line:?}"
            );
        };
        assert_eq!(
            [by, on, author, summary],
            [report.as_str(), dispatch.as_str(), s_peer.as_str(), BRIEF],
            "the seat reports on the dispatch, summarized by echo's line"
        );
        assert!(
            content.len() == 64 && content.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the content is named by its digest: {content:?}"
        );
        assert_eq!(standing, &format!("reported {dispatch} {report}"));
        assert_eq!(
            held,
            &format!("evidence {content} held"),
            "the replay fetches the report from the seat"
        );
        assert_eq!(seat.line(), format!("served {content}"));
        assert_eq!(
            finish(peer(o).args(["evidence", "--local", tree.as_str(), content])),
            [format!("content {BRIEF}")],
            "the operator holds the report echo printed"
        );

        assert_eq!(
            finish(&mut dispatch_to(&[])),
            [dispatch.clone(), through_book, "woken".into()],
            "an answered dispatch is sent again through the book"
        );
        seat.admitted(&o_peer);
        assert_eq!(seat.line(), format!("woken {tree} {dispatch}"));
        assert_eq!(
            finish(peer(o).args(["replay", tree.as_str()])),
            replayed,
            "the seat does not act on an answered dispatch again"
        );
        seat.admitted(&o_peer);
        drop(seat);
    }
}
