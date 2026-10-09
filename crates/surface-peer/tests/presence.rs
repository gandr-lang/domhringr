//! The peer binary's presence contract, exercised as processes: a peer
//! presents the endpoint it serves at in its tree, another peer reaches it
//! once at an endpoint named by hand, and from then on finds it through the
//! tree's book alone — for `whence` and `sync`, as their source lines say —
//! until the presence is withdrawn, when the book no longer offers it.

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

    /// How long one command may run, or a server may take to print a line.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// How often a running command is polled for its exit.
    const POLL: Duration = Duration::from_millis(20);

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
    fn output(command: &mut Command) -> std::process::Output
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

    /// Run `command` to completion and return the lines it printed.
    ///
    /// # Specification
    /// - ensures: the command exited 0 within [`DEADLINE`].
    /// - panics: as [`output`], or when it exits non-zero (its standard error
    ///   is shown) or prints anything but UTF-8.
    fn finish(command: &mut Command) -> Vec<String>
    {
        let output = output(command);
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

    /// Run `command`, which must fail, and return its diagnostic.
    ///
    /// # Specification
    /// - ensures: the command exited 1 within [`DEADLINE`], printing nothing to
    ///   standard output and one line to standard error.
    /// - panics: as [`output`], or on any other status or output.
    fn refuse(command: &mut Command) -> String
    {
        let output = output(command);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            output.status.code(),
            Some(1_i32),
            "{command:?} fails once read: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{command:?} prints nothing");
        let mut lines = stderr.lines();
        let (Some(line), None) = (lines.next(), lines.next())
        else {
            panic!("{command:?} writes one diagnostic line: {stderr:?}");
        };
        line.into()
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

    /// A running `serve` process and its output, read as it arrives.
    ///
    /// The process is killed when the value drops, so a failing test leaves
    /// no server behind.
    struct Server
    {
        /// The process.
        child: Child,
        /// Its standard output, one line per message, from a reader thread.
        lines: mpsc::Receiver<String>,
    }

    impl Server
    {
        /// Start `serve` on `state` at the fixed `port`, and read its
        /// announcement.
        ///
        /// # Specification
        /// - ensures: the process is running, has announced `ids` and
        ///   `listening`, and its standard output is read line by line; its
        ///   standard error passes through to the test's.
        /// - panics: when the process cannot start or its announcement is not
        ///   `ids` and `listening`.
        fn start(
            state: &Path,
            port: &OsStr,
            ids: &[String],
        ) -> Self
        {
            let mut child = peer(state)
                .arg("serve")
                .arg("--port")
                .arg(port)
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

        /// The next line the server prints.
        ///
        /// # Specification
        /// - panics: when no line arrives within [`DEADLINE`], or the server's
        ///   output ends.
        fn line(&self) -> String
        {
            self.lines.recv_timeout(DEADLINE).unwrap_or_else(|error| {
                panic!("serve printed no line within {DEADLINE:?}: {error}")
            })
        }
    }

    impl Drop for Server
    {
        /// Kill the server and reap it.
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

    /// A peer that presents its endpoint is reached through the book alone
    /// once one sync carried the presence, until it withdraws it.
    ///
    /// # Specification
    /// - ensures: A opens a tree, binds `x` to a note, and presents itself at
    ///   the port it then serves on; `present` prints the presenting commit,
    ///   and A's `book` prints one line, A's peer id, an endpoint beginning
    ///   with A's endpoint id and naming at least one address, and that commit.
    ///   A's own `whence` of `x` reaches no one and prints the resolution
    ///   alone. B syncs once with `--peer` and `--at` A's endpoint at the
    ///   loopback address; then, naming no endpoint and no peer, B's `book`
    ///   prints A's line exactly, B's `whence` of `x` prints `source`, the
    ///   tree, `book` and the presenting commit, then the anchor `x` is bound
    ///   to, and B's `sync` prints the same source line, the heads and a path
    ///   line, each admitted by A. A, stopped, withdraws its presence and its
    ///   `book` prints nothing; serving again, B syncs through the book it
    ///   still holds and takes the withdrawal: B's `book` prints nothing, B's
    ///   `whence` of `x` exits 1 with `domhringr-peer: unreachable <A's peer
    ///   id>: no presence in the book`, and with `--at` A's endpoint it prints
    ///   `source`, the tree, `at` and that endpoint, then the anchor.
    /// - panics: on any contract violation.
    #[test]
    fn a_peer_is_reached_through_the_book_until_it_withdraws()
    {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (a.path(), b.path());
        let (a_id, b_id) = (finish(peer(a).arg("id")), finish(peer(b).arg("id")));
        let (a_endpoint, a_peer) = (a_id[0].clone(), a_id[1].clone());
        let b_peer = OsString::from(&b_id[1]);
        let port = free_port();

        let tree = only(peer(a).arg("open"));
        let x = format!("{tree}x");
        let noted = only(peer(a).args(["note", tree.as_str(), "reached"]));
        let commit = format!("{tree}.commit/{noted}");
        let _bound = only(peer(a).args(["bind", x.as_str(), "anchor", commit.as_str()]));
        let resolved = format!("anchor {commit}");

        let presented = only(peer(a).args(["present", tree.as_str(), "--port", port.as_str()]));
        let book = only(peer(a).args(["book", tree.as_str()]));
        let fields = book.split(' ').collect::<Vec<_>>();
        let [peer_id, endpoint, since] = *fields.as_slice()
        else {
            panic!("a book line is a peer id, an endpoint and a commit: {book:?}");
        };
        assert_eq!(peer_id, a_peer, "the book names the presenting peer");
        assert!(
            endpoint.starts_with(&format!("{a_endpoint}@")),
            "the presence is of A's own endpoint, at an address: {endpoint:?}"
        );
        assert_eq!(since, presented, "the presence holds since its commit");
        assert_eq!(
            only(peer(a).args(["whence", x.as_str()])),
            resolved,
            "the owner resolves its own tree reaching no one"
        );

        let server = Server::start(a, OsStr::new(&port), &a_id);
        let first_contact = format!("{a_endpoint}@127.0.0.1:{port}");
        let synced = finish(peer(b).args([
            "sync",
            tree.as_str(),
            "--peer",
            a_peer.as_str(),
            "--at",
            first_contact.as_str(),
        ]));
        assert_eq!(
            synced.first(),
            Some(&format!("source {tree} at {first_contact}")),
            "first contact names the endpoint by hand"
        );
        server.admitted(&b_peer);

        assert_eq!(
            only(peer(b).args(["book", tree.as_str()])),
            book,
            "one sync carries the book"
        );
        let through_book = format!("source {tree} book {presented}");
        assert_eq!(
            finish(peer(b).args(["whence", x.as_str()])),
            [through_book.clone(), resolved.clone()],
            "whence reaches the owner through the book alone"
        );
        server.admitted(&b_peer);
        let synced = finish(peer(b).args(["sync", tree.as_str()]));
        assert_eq!(
            synced.first(),
            Some(&through_book),
            "sync reaches the owner through the book alone"
        );
        assert!(
            synced
                .last()
                .is_some_and(|path| path.starts_with(&format!("path {a_peer} "))),
            "the sync ends in A's path line: {synced:?}"
        );
        server.admitted(&b_peer);
        drop(server);

        let _withdrawn = only(peer(a).args(["withdraw", tree.as_str()]));
        assert_eq!(
            finish(peer(a).args(["book", tree.as_str()])),
            Vec::<String>::new(),
            "a withdrawn presence leaves the book"
        );
        let server = Server::start(a, OsStr::new(&port), &a_id);
        let synced = finish(peer(b).args(["sync", tree.as_str()]));
        assert_eq!(
            synced.first(),
            Some(&through_book),
            "the book B holds still reaches A, which has not moved"
        );
        server.admitted(&b_peer);
        assert_eq!(
            finish(peer(b).args(["book", tree.as_str()])),
            Vec::<String>::new(),
            "the synced withdrawal leaves B's book empty"
        );
        assert_eq!(
            refuse(peer(b).args(["whence", x.as_str()])),
            format!("domhringr-peer: unreachable {a_peer}: no presence in the book"),
            "a withdrawn presence is not offered"
        );
        assert_eq!(
            finish(peer(b).args(["whence", x.as_str(), "--at", first_contact.as_str()])),
            [format!("source {tree} at {first_contact}"), resolved],
            "an endpoint named by hand still reaches the owner"
        );
        server.admitted(&b_peer);
        drop(server);
    }
}
