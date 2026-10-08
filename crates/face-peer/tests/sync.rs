//! The peer binary's consumer-visible contract, exercised as processes: two
//! peers on one host reach each other by endpoint id and sync one tree to
//! identical heads, and the serving peer's store survives a kill.

#[cfg(test)]
mod tests
{
    use core::time::Duration;
    use std::io::BufRead as _;
    use std::path::Path;
    use std::process::Child;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Instant;

    /// The tree every peer commits to and syncs.
    const TREE: &str = "73796e6373796e6373796e6373796e6373796e6373796e6373796e6373796e63";

    /// How long one command may run, or a server may take to print a line.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// How often a running command is polled for its exit.
    const POLL: Duration = Duration::from_millis(20);

    /// Lines a peer process printed, in order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[repr(transparent)]
    struct Lines(Vec<String>);

    impl Lines
    {
        /// The lines followed by `listening`: what `serve` announces for a
        /// peer whose `id` printed these lines.
        ///
        /// # Specification
        /// trivial.
        fn then_listening(&self) -> Self
        {
            let mut lines = self.0.clone();
            lines.push("listening".into());
            Self(lines)
        }

        /// The line `serve` prints when it admits the peer whose `id` printed
        /// these lines.
        ///
        /// # Specification
        /// trivial.
        fn accepted(&self) -> Self
        {
            Self(vec![format!("accepted {}", self.0[1])])
        }

        /// Assert every line is an id: 64 lowercase hex digits.
        ///
        /// # Specification
        /// - panics: on a line that is not 64 lowercase hex digits.
        fn assert_ids(&self)
        {
            for line in &self.0 {
                assert!(
                    line.len() == 64
                        && line
                            .bytes()
                            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
                    "not an id: {line:?}"
                );
            }
        }
    }

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

    /// Run `command` to completion and return what it printed.
    ///
    /// # Specification
    /// - ensures: the command exited 0 within [`DEADLINE`].
    /// - panics: when it cannot start, outlives the deadline (it is killed
    ///   first), exits non-zero (its standard error is shown), or prints
    ///   anything but UTF-8.
    fn finish(command: &mut Command) -> Lines
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
        Lines(
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(String::from)
                .collect(),
        )
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
        /// Start `serve` on `state`.
        ///
        /// # Specification
        /// - ensures: the process is running with its standard output read line
        ///   by line; its standard error passes through to the test's.
        /// - panics: when the process cannot start.
        fn start(state: &Path) -> Self
        {
            let mut child = peer(state)
                .arg("serve")
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

        /// The server's announcement: its two ids and `listening`.
        ///
        /// # Specification
        /// - panics: when the three lines do not arrive within [`DEADLINE`]
        ///   each.
        fn announcement(&self) -> Lines
        {
            Lines(core::iter::repeat_with(|| self.line()).take(3).collect())
        }

        /// The next line the server prints, as a one-line output.
        ///
        /// # Specification
        /// - panics: when no line arrives within [`DEADLINE`].
        fn next(&self) -> Lines
        {
            Lines(vec![self.line()])
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

    /// Two peers on one host sync a tree by endpoint id to identical heads,
    /// and the serving peer's store survives a kill.
    ///
    /// # Specification
    /// - ensures: A's `id` prints two distinct ids, and A's `serve` announces
    ///   the same two followed by `listening`; A's second commit replaces its
    ///   first as the head; B's `sync` against A by endpoint id prints A's
    ///   heads, B's store then holds them, and A prints B's peer id as
    ///   accepted; after A is killed its store still holds the heads, a
    ///   restarted A announces the same ids, and both B's repeated sync and a
    ///   fresh C's first sync print the same heads.
    /// - panics: on any contract violation.
    #[test]
    fn two_peers_sync_one_tree_to_identical_heads()
    {
        let (a, b, c) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let (a, b, c) = (a.path(), b.path(), c.path());
        let a_id = finish(peer(a).arg("id"));
        assert_eq!(
            a_id.0.len(),
            2,
            "id prints the endpoint id, then the peer id"
        );
        a_id.assert_ids();
        assert_ne!(
            a_id.0[0], a_id.0[1],
            "the endpoint key and the signer are distinct"
        );
        let b_id = finish(peer(b).arg("id"));
        let (endpoint, peer_id) = (&a_id.0[0], &a_id.0[1]);

        // A store is held exclusively by the process that opened it, so A
        // commits before it serves rather than while serving.
        let first = finish(peer(a).args(["commit", TREE, "first"]));
        let second = finish(peer(a).args(["commit", TREE, "second"]));
        first.assert_ids();
        second.assert_ids();
        assert_ne!(first, second, "distinct contents are distinct commits");
        let heads = finish(peer(a).args(["heads", TREE]));
        assert_eq!(
            heads, second,
            "the second commit's parent is the first, so it alone is the head"
        );

        let server = Server::start(a);
        assert_eq!(
            server.announcement(),
            a_id.then_listening(),
            "serve announces the ids id prints"
        );
        let synced = finish(peer(b).args(["sync", endpoint, peer_id, TREE]));
        assert_eq!(synced, heads, "the dialer prints the server's heads");
        assert_eq!(
            server.next(),
            b_id.accepted(),
            "the server admits the dialer"
        );
        assert_eq!(
            finish(peer(b).args(["heads", TREE])),
            heads,
            "the dialer stored the synced tree"
        );
        drop(server);

        assert_eq!(
            finish(peer(a).args(["heads", TREE])),
            heads,
            "the killed server's store survives"
        );
        let server = Server::start(a);
        assert_eq!(
            server.announcement(),
            a_id.then_listening(),
            "a restarted server keeps its ids"
        );
        let resynced = finish(peer(b).args(["sync", endpoint, peer_id, TREE]));
        assert_eq!(resynced, heads, "a second sync leaves the heads unchanged");
        assert_eq!(
            server.next(),
            b_id.accepted(),
            "the restarted server admits the dialer"
        );
        let fresh = finish(peer(c).args(["sync", endpoint, peer_id, TREE]));
        assert_eq!(
            fresh, heads,
            "the restarted server serves the tree from its store"
        );
        drop(server);
    }
}
