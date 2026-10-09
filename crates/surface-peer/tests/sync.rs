//! The peer binary's consumer-visible contract, exercised as processes: two
//! peers on one host reach each other at a direct address and sync one tree to
//! identical heads, the serving peer's store survives a kill, two peers that
//! exchange a tree's commits fold them to byte-identical views in which a note
//! is admitted only under a grant in its causal past, a path bound in a tree
//! resolves alike on both peers through its anchor, a DNS name or a label in
//! an anchor's place resolves only through a claim or an introduction, and a
//! commit resolves through its anchor, by its whole id or a prefix of it, to
//! the fold's verdict on it.

#[cfg(test)]
mod tests
{
    use core::net::SocketAddr;
    use core::time::Duration;
    use std::ffi::OsStr;
    use std::io::BufRead as _;
    use std::path::Path;
    use std::process::Child;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Instant;

    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::Authority;

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

        /// The endpoint id, the first line `id` prints.
        ///
        /// # Specification
        /// trivial.
        fn endpoint(&self) -> &String
        {
            &self.0[0]
        }

        /// The peer id, the second line `id` prints.
        ///
        /// # Specification
        /// trivial.
        fn peer(&self) -> &String
        {
            &self.0[1]
        }

        /// The one line a command printed.
        ///
        /// # Specification
        /// - panics: unless exactly one line was printed.
        fn only(&self) -> &String
        {
            assert_eq!(self.0.len(), 1, "one line expected: {:?}", self.0);
            &self.0[0]
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

    /// A `path <peer-id> <path>` line, read.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum PathLine
    {
        /// A direct UDP path to this address.
        Direct(SocketAddr),
        /// A path through the relay at this URL.
        Relay(String),
        /// No path selected yet.
        Pending,
    }

    impl PathLine
    {
        /// Read `line` as the path line printed for the peer whose `id`
        /// printed `from`.
        ///
        /// # Specification
        /// - panics: unless the line is `path`, the peer id, and one of `direct
        ///   <socket address>`, `relay <http or https URL>` or `pending`,
        ///   separated by single spaces.
        fn read(
            line: &OsStr,
            from: &Lines,
        ) -> Self
        {
            let line = line.to_str().expect("a path line is UTF-8");
            let path = line
                .strip_prefix("path ")
                .and_then(|rest| rest.strip_prefix(from.peer().as_str()))
                .and_then(|rest| rest.strip_prefix(' '))
                .unwrap_or_else(|| panic!("not a path line for {}: {line:?}", from.peer()));
            match path.split_once(' ') {
                | Some(("direct", address)) => Self::Direct(
                    address
                        .parse()
                        .unwrap_or_else(|error| panic!("not a socket address: {line:?}: {error}")),
                ),
                | Some(("relay", url)) if url.starts_with("http") && !url.contains(' ') => {
                    Self::Relay(url.into())
                },
                | None if path == "pending" => Self::Pending,
                | Some(_) | None => panic!("not a path: {line:?}"),
            }
        }
    }

    /// A UDP port a test serves on, as its decimal text.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[repr(transparent)]
    struct Port(String);

    /// A UDP port in the ephemeral range that nothing on this host holds: the
    /// system picks it for a socket that is closed again at once.
    ///
    /// # Specification
    /// trivial.
    fn free_port() -> Port
    {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        Port(socket.local_addr().unwrap().port().to_string())
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

    /// Run `command` to completion and return what it printed.
    ///
    /// # Specification
    /// - ensures: the command exited 0 within [`DEADLINE`].
    /// - panics: as [`output`], or when it exits non-zero (its standard error
    ///   is shown) or prints anything but UTF-8.
    fn finish(command: &mut Command) -> Lines
    {
        let output = output(command);
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

    /// Run `command`, which must fail, and return its diagnostic.
    ///
    /// # Specification
    /// - ensures: the command exited 1, the status of a command line that was
    ///   read but failed, within [`DEADLINE`], printing nothing to standard
    ///   output and one line to standard error.
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

    /// Open a tree on `state` and return the anchor `open` printed.
    ///
    /// # Specification
    /// - panics: as [`finish`], or unless `open` printed one line that parses
    ///   as a bare tree anchor in the key form.
    fn open(state: &Path) -> String
    {
        let anchor = finish(peer(state).arg("open")).only().clone();
        assert!(
            matches!(
                anchor.parse::<Anchor>(),
                Ok(Anchor::Tree(Authority::Key(_)))
            ),
            "open prints a bare tree anchor: {anchor:?}"
        );
        anchor
    }

    /// The tree id the bare key-form anchor `anchor` spells.
    ///
    /// # Specification
    /// - panics: unless `anchor` is a bare anchor in the key form.
    fn tree_id(anchor: &OsStr) -> String
    {
        let text = anchor.to_str().expect("an anchor is UTF-8");
        match text.parse::<Anchor>() {
            | Ok(Anchor::Tree(Authority::Key(tree))) => tree.to_string(),
            | other => panic!("not a bare key-form anchor: {text:?}: {other:?}"),
        }
    }

    /// Sync `tree` on `state` with the peer whose `id` printed `remote`,
    /// serving on this host at `port`.
    ///
    /// # Specification
    /// - ensures: the sync names the remote's peer id and its endpoint at its
    ///   direct address, the loopback address at `port`, and prints that it
    ///   reached the tree there; returns the heads the sync printed and its
    ///   path line, read for `remote`'s peer id.
    /// - panics: as [`finish`], when the first line is not the source line
    ///   naming that endpoint, or when no path line ends the output.
    fn sync(
        state: &Path,
        remote: &Lines,
        tree: &OsStr,
        port: &Port,
    ) -> (Lines, PathLine)
    {
        let at = format!("{}@127.0.0.1:{}", remote.endpoint(), port.0);
        let mut printed = finish(
            peer(state)
                .arg("sync")
                .arg(tree)
                .arg("--peer")
                .arg(remote.peer())
                .arg("--at")
                .arg(&at),
        );
        let path = printed.0.pop().expect("a sync prints its path");
        let source = printed.0.remove(0);
        assert_eq!(
            source,
            format!("source {} at {at}", tree.to_string_lossy()),
            "the sync says it reached the tree at the endpoint named"
        );
        (printed, PathLine::read(OsStr::new(&path), remote))
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
        /// Start `serve` on `state`, with `options` after the verb.
        ///
        /// # Specification
        /// - ensures: the process is running with its standard output read line
        ///   by line; its standard error passes through to the test's.
        /// - panics: when the process cannot start.
        fn start(
            state: &Path,
            options: &[&OsStr],
        ) -> Self
        {
            let mut child = peer(state)
                .arg("serve")
                .args(options)
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

        /// The server's report of one admission: it admitted the peer whose
        /// `id` printed `dialer`, over the path returned.
        ///
        /// # Specification
        /// - panics: unless the next line is `accepted` with `dialer`'s peer id
        ///   and the one after is a path line for the same peer, each within
        ///   [`DEADLINE`].
        fn admitted(
            &self,
            dialer: &Lines,
        ) -> PathLine
        {
            assert_eq!(
                self.line(),
                format!("accepted {}", dialer.peer()),
                "the server admits the dialer"
            );
            PathLine::read(OsStr::new(&self.line()), dialer)
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

    /// Two peers on one host sync a tree at a direct address to identical
    /// heads, and the serving peer's store survives a kill.
    ///
    /// # Specification
    /// - ensures: A's `id` prints two distinct ids, and A's `serve` announces
    ///   the same two followed by `listening`; A's `open` prints a tree anchor
    ///   and A's note replaces the Open as the head; B's `sync` against A at
    ///   its direct address prints A's heads and a path line, B's store then
    ///   holds them, and A prints B's peer id as accepted with a path line;
    ///   after A is killed its store still holds the heads, a restarted A
    ///   announces the same ids, and both B's repeated sync and a fresh C's
    ///   first sync print the same heads.
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
            a_id.endpoint(),
            a_id.peer(),
            "the endpoint key and the signer are distinct"
        );
        let (b_id, c_id) = (finish(peer(b).arg("id")), finish(peer(c).arg("id")));

        // A store is held exclusively by the process that opened it, so A
        // commits before it serves rather than while serving.
        let tree = open(a);
        let noted = finish(peer(a).args(["note", tree.as_str(), "first"]));
        noted.assert_ids();
        let heads = finish(peer(a).args(["heads", tree.as_str()]));
        assert_eq!(
            heads, noted,
            "the note's parent is the Open, so it alone is the head"
        );

        let port = free_port();
        let options = [OsStr::new("--port"), OsStr::new(&port.0)];
        let server = Server::start(a, &options);
        assert_eq!(
            server.announcement(),
            a_id.then_listening(),
            "serve announces the ids id prints"
        );
        let (synced, _path) = sync(b, &a_id, OsStr::new(&tree), &port);
        assert_eq!(synced, heads, "the dialer prints the server's heads");
        let _admitted = server.admitted(&b_id);
        assert_eq!(
            finish(peer(b).args(["heads", tree.as_str()])),
            heads,
            "the dialer stored the synced tree"
        );
        drop(server);

        assert_eq!(
            finish(peer(a).args(["heads", tree.as_str()])),
            heads,
            "the killed server's store survives"
        );
        let server = Server::start(a, &options);
        assert_eq!(
            server.announcement(),
            a_id.then_listening(),
            "a restarted server keeps its ids"
        );
        let (resynced, _path) = sync(b, &a_id, OsStr::new(&tree), &port);
        assert_eq!(resynced, heads, "a second sync leaves the heads unchanged");
        let _admitted = server.admitted(&b_id);
        let (fresh, _path) = sync(c, &a_id, OsStr::new(&tree), &port);
        assert_eq!(
            fresh, heads,
            "the restarted server serves the tree from its store"
        );
        let _admitted = server.admitted(&c_id);
        drop(server);
    }

    /// Serve `state` on the fixed `port` while the peer on `dialer` syncs
    /// `tree` from it at that port, then stop serving.
    ///
    /// # Specification
    /// - ensures: the server announced `server`'s ids, admitted the dialer and
    ///   printed a parseable path line for it; the dialer printed a parseable
    ///   path line naming a selected path: a direct one reaches the server's
    ///   fixed port, a relayed one is accepted and printed, since iroh does not
    ///   promise a direct path even on one host; the server is killed on
    ///   return, freeing the store.
    /// - panics: on any contract violation, a pending path among them.
    fn pull(
        dialer: (&Path, &Lines),
        server: (&Path, &Lines),
        port: &Port,
        tree: &OsStr,
    ) -> Lines
    {
        let options = [OsStr::new("--port"), OsStr::new(&port.0)];
        let serving = Server::start(server.0, &options);
        assert_eq!(
            serving.announcement(),
            server.1.then_listening(),
            "serve announces its ids"
        );
        let (heads, path) = sync(dialer.0, server.1, tree, port);
        match path {
            | PathLine::Direct(address) => assert_eq!(
                address.port().to_string(),
                port.0,
                "the dialer reaches the server at its fixed port"
            ),
            | PathLine::Relay(url) => println!("the dialer stayed on the relay {url}"),
            | PathLine::Pending => {
                panic!("a connection that carried a sync round has a selected path")
            },
        }
        let _admitted = serving.admitted(dialer.1);
        drop(serving);
        heads
    }

    /// Two peers exchange one tree's commits and fold them to byte-identical
    /// views, in which a note is admitted only under a grant in its causal
    /// past.
    ///
    /// # Specification
    /// - ensures: A opens the tree and writes a note; B pulls it and writes a
    ///   note of its own; A pulls B's note, and A's view and B's both show it
    ///   refused for want of authority; A grants B and writes a note; B pulls
    ///   them and writes a second note while A writes a third, concurrently;
    ///   after A and B each pull the other, both views are byte-identical:
    ///   owner A, member B, A's notes and B's second note in canonical order,
    ///   B's first note refused. Every pull serves on a fixed port and reads a
    ///   selected path: direct to that port, or relayed.
    /// - panics: on any contract violation.
    #[test]
    fn two_peers_fold_one_tree_to_identical_views()
    {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (a.path(), b.path());
        let (a_id, b_id) = (finish(peer(a).arg("id")), finish(peer(b).arg("id")));
        let (a_port, b_port) = (free_port(), free_port());
        let tree = open(a);
        let note = |state: &Path, text: &str| {
            let id = finish(peer(state).args(["note", tree.as_str(), text]));
            id.assert_ids();
            id.only().clone()
        };
        let view = |state: &Path| finish(peer(state).args(["view", tree.as_str()]));
        let owner = format!("owner {}", a_id.peer());
        let folded = OsStr::new(&tree);

        let _a1 = note(a, "a1");
        pull((b, &b_id), (a, &a_id), &a_port, folded);
        let b1 = note(b, "b1 before any grant");
        pull((a, &a_id), (b, &b_id), &b_port, folded);
        let refused = format!("refused {b1} no authority");
        let unauthorised = Lines(vec![
            owner.clone(),
            format!("note {} a1", a_id.peer()),
            refused.clone(),
        ]);
        assert_eq!(
            view(a),
            unauthorised,
            "the owner holds the non-member's note and refuses it"
        );
        assert_eq!(
            view(b),
            unauthorised,
            "the non-member folds its own note to the same refusal"
        );

        let granted = finish(peer(a).args(["grant", tree.as_str(), b_id.peer().as_str()]));
        granted.assert_ids();
        let _a2 = note(a, "a2");
        pull((b, &b_id), (a, &a_id), &a_port, folded);
        let b2 = note(b, "b2 under the grant");
        let a3 = note(a, "a3");
        pull((a, &a_id), (b, &b_id), &b_port, folded);
        let heads = pull((b, &b_id), (a, &a_id), &a_port, folded);

        let mut concurrent = [a3, b2.clone()];
        concurrent.sort();
        assert_eq!(heads.0, concurrent, "both peers hold both concurrent notes");
        let line = |id: &str| {
            if id == b2 {
                format!("note {} b2 under the grant", b_id.peer())
            }
            else {
                format!("note {} a3", a_id.peer())
            }
        };
        let expected = Lines(vec![
            owner,
            format!("member {}", b_id.peer()),
            format!("note {} a1", a_id.peer()),
            format!("note {} a2", a_id.peer()),
            line(&concurrent[0]),
            line(&concurrent[1]),
            refused,
        ]);
        let (a_view, b_view) = (view(a), view(b));
        assert_eq!(a_view, b_view, "both peers fold the same view");
        assert_eq!(
            a_view, expected,
            "the grant admits B's later note alone, concurrent notes in commit id order"
        );
    }

    /// A path bound in a tree resolves alike on both peers through its anchor,
    /// to the binding the fold admitted last.
    ///
    /// # Specification
    /// - ensures: A opens a tree, whose printed anchor parses, writes a note
    ///   and binds `x` to the note's commit anchor; B syncs from A and its
    ///   `whence` of `x` prints that anchor. B, not a member, binds `x` on its
    ///   copy; A syncs from B, A's `whence` of `x` is unchanged, and A's view
    ///   lists B's bind as refused for want of authority. A grants B; B syncs
    ///   the grant, writes a note and binds `x` to it; A syncs, resolves `x` to
    ///   B's note, writes a note of its own and re-binds `x` to it; B syncs,
    ///   and both peers' `whence` of `x` print A's target. `whence` of `y`,
    ///   which nobody bound, prints `unbound` on both. Every sync names the
    ///   remote's direct address.
    /// - panics: on any contract violation.
    #[test]
    fn an_anchor_resolves_alike_on_both_peers()
    {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (a.path(), b.path());
        let (a_id, b_id) = (finish(peer(a).arg("id")), finish(peer(b).arg("id")));
        let (a_port, b_port) = (free_port(), free_port());
        let tree = open(a);
        let (x, y) = (format!("{tree}x"), format!("{tree}y"));
        let anchored = OsStr::new(&tree);
        let note = |state: &Path, text: &str| {
            let id = finish(peer(state).args(["note", tree.as_str(), text]));
            id.assert_ids();
            id.only().clone()
        };
        let bind = |state: &Path, commit: &str| {
            let target = format!("{tree}.commit/{commit}");
            let id = finish(peer(state).args(["bind", x.as_str(), "anchor", target.as_str()]));
            id.assert_ids();
            id.only().clone()
        };
        let squat_on = |state: &Path| {
            let id = finish(peer(state).args(["bind", x.as_str(), "datum", "squat"]));
            id.assert_ids();
            id.only().clone()
        };
        let whence = |state: &Path, anchor: &str| {
            finish(peer(state).args(["whence", "--local", anchor]))
                .only()
                .clone()
        };

        let a1 = note(a, "a1");
        let _bound = bind(a, &a1);
        pull((b, &b_id), (a, &a_id), &a_port, anchored);
        let first = format!("anchor {tree}.commit/{a1}");
        assert_eq!(
            whence(b, &x),
            first,
            "the synced bind resolves on the dialer to the same commit anchor"
        );

        let squat = squat_on(b);
        pull((a, &a_id), (b, &b_id), &b_port, anchored);
        assert_eq!(
            whence(a, &x),
            first,
            "a non-member's bind leaves the path as it was"
        );
        let view = finish(peer(a).args(["view", tree.as_str()]));
        assert!(
            view.0.contains(&format!("refused {squat} no authority")),
            "the owner's view lists the non-member's bind as refused: {view:?}"
        );

        let granted = finish(peer(a).args(["grant", tree.as_str(), b_id.peer().as_str()]));
        granted.assert_ids();
        pull((b, &b_id), (a, &a_id), &a_port, anchored);
        let b1 = note(b, "b1");
        let _rebound = bind(b, &b1);
        pull((a, &a_id), (b, &b_id), &b_port, anchored);
        assert_eq!(
            whence(a, &x),
            format!("anchor {tree}.commit/{b1}"),
            "a member's bind under the grant rebinds the path"
        );
        let a2 = note(a, "a2");
        let _rebound = bind(a, &a2);
        pull((b, &b_id), (a, &a_id), &a_port, anchored);
        let last = format!("anchor {tree}.commit/{a2}");
        for state in [a, b] {
            assert_eq!(
                whence(state, &x),
                last,
                "the bind made after the others in its causal past wins on both peers"
            );
            assert_eq!(
                whence(state, &y),
                "unbound",
                "a path nobody bound is unbound"
            );
        }
    }

    /// A DNS name in an anchor's place resolves as the key form of the one
    /// witnessed tree whose root claims it, and a label resolves through the
    /// introductions of the tree it is read in alone.
    ///
    /// # Specification
    /// - ensures: A opens a tree, claims `example.test` for it, writes a note
    ///   and binds `x` to the note's commit anchor; B pulls the tree, and B's
    ///   `whence` of `domhringr://example.test/x`, witnessed by hand by A's
    ///   tree, prints what the key form prints, that anchor, while the bare
    ///   name prints `anchor` and A's anchor, and the name's commit form prints
    ///   the note's commit admitted. B opens a tree of its own, which claims
    ///   nothing; witnessed by it the name exits 1 with `domhringr-peer:
    ///   unclaimed example.test`. A introduces B's tree as `b` in its own, and
    ///   A's `whence` of `domhringr://b/` in A's tree prints `anchor` and B's
    ///   anchor; read in no tree it exits 1. A pulls B's tree; read in it,
    ///   which introduced nothing, `domhringr://b/` exits 1 with
    ///   `domhringr-peer: unintroduced b`. A's view lists the claim and the
    ///   introduction. Every witness is given by hand, so no step asks DNS.
    /// - panics: on any contract violation.
    #[test]
    fn a_named_anchor_resolves_through_its_claim_or_introduction()
    {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (a.path(), b.path());
        let (a_id, b_id) = (finish(peer(a).arg("id")), finish(peer(b).arg("id")));
        let (a_port, b_port) = (free_port(), free_port());
        let tree = open(a);
        let claimed = finish(peer(a).args(["claim", tree.as_str(), "example.test"]));
        claimed.assert_ids();
        let noted = finish(peer(a).args(["note", tree.as_str(), "named"]));
        noted.assert_ids();
        let x = format!("{tree}x");
        let commit = format!("{tree}.commit/{}", noted.only());
        let bound = finish(peer(a).args(["bind", x.as_str(), "anchor", commit.as_str()]));
        bound.assert_ids();
        pull((b, &b_id), (a, &a_id), &a_port, OsStr::new(&tree));

        let witnessed = |anchor: &str, witness: &str| {
            let witness = format!("example.test={}", tree_id(OsStr::new(witness)));
            let mut command = peer(b);
            let _args = command.args(["whence", "--local", anchor, "--witness", witness.as_str()]);
            command
        };
        let by_key = finish(peer(b).args(["whence", "--local", x.as_str()]));
        assert_eq!(
            by_key.only(),
            &format!("anchor {commit}"),
            "the key form resolves to the bound note"
        );
        assert_eq!(
            finish(&mut witnessed("domhringr://example.test/x", &tree)),
            by_key,
            "the DNS form resolves as the key form of the witnessed tree that claims it"
        );
        assert_eq!(
            finish(&mut witnessed("domhringr://example.test/", &tree)).only(),
            &format!("anchor {tree}"),
            "the bare name resolves to the claiming tree"
        );
        let named_commit = format!("domhringr://example.test/.commit/{}", noted.only());
        assert_eq!(
            finish(&mut witnessed(&named_commit, &tree)).only(),
            &format!("commit {} admitted", noted.only()),
            "a commit under the name resolves in the claiming tree to its verdict"
        );
        let fresh = open(b);
        assert_eq!(
            refuse(&mut witnessed("domhringr://example.test/x", &fresh)),
            "domhringr-peer: unclaimed example.test",
            "a witnessed tree that never claimed the name resolves nothing"
        );

        let introduced = finish(peer(a).args(["introduce", tree.as_str(), "b", fresh.as_str()]));
        introduced.assert_ids();
        let label = |scope: &str| {
            let mut command = peer(a);
            let _args = command.args(["whence", "--local", "domhringr://b/", "--in", scope]);
            command
        };
        assert_eq!(
            finish(&mut label(&tree)).only(),
            &format!("anchor {fresh}"),
            "read in the tree that introduced it, the label names the introduced tree"
        );
        assert_eq!(
            refuse(peer(a).args(["whence", "domhringr://b/"])),
            "domhringr-peer: unscoped b",
            "a label read in no tree resolves nothing"
        );
        pull((a, &a_id), (b, &b_id), &b_port, OsStr::new(&fresh));
        assert_eq!(
            refuse(&mut label(&fresh)),
            "domhringr-peer: unintroduced b",
            "read in the introduced tree, which introduced nothing, the label is unknown"
        );
        let view = finish(peer(a).args(["view", tree.as_str()]));
        for fact in [
            "claim example.test".to_owned(),
            format!("introduce b {fresh}"),
        ] {
            assert!(view.0.contains(&fact), "the view lists {fact:?}: {view:?}");
        }
    }

    /// A commit resolves through its anchor to the fold's verdict on it, alike
    /// on both peers, by its whole id or by a prefix of it.
    ///
    /// # Specification
    /// - ensures: A opens a tree and writes a note; B pulls it, and B's
    ///   `whence` of the note's commit anchor, its id abbreviated to 12 digits,
    ///   prints `commit`, the whole id and `admitted`. B, not a member, writes
    ///   a note; A pulls it, and A's `whence` of its anchor prints `commit`,
    ///   its id and `refused no authority`. A binds `x` to its own note's
    ///   commit anchor; B pulls, B's `whence` of `x` prints `anchor` and that
    ///   commit anchor, and B's view lists the bind with it. A commit id of 64
    ///   zeros, which the tree does not hold, prints `unknown`. Every sync
    ///   names the remote's direct address.
    /// - panics: on any contract violation.
    #[test]
    fn a_commit_resolves_to_its_verdict_on_both_peers()
    {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (a.path(), b.path());
        let (a_id, b_id) = (finish(peer(a).arg("id")), finish(peer(b).arg("id")));
        let (a_port, b_port) = (free_port(), free_port());
        let tree = open(a);
        let anchored = OsStr::new(&tree);
        let note = |state: &Path, text: &str| {
            let id = finish(peer(state).args(["note", tree.as_str(), text]));
            id.assert_ids();
            id.only().clone()
        };
        let commit = |digits: &str| format!("{tree}.commit/{digits}");
        let whence = |state: &Path, reference: &str| {
            finish(peer(state).args(["whence", "--local", reference]))
                .only()
                .clone()
        };

        let a1 = note(a, "a1");
        pull((b, &b_id), (a, &a_id), &a_port, anchored);
        let prefix = a1.chars().take(12).collect::<String>();
        assert_eq!(
            whence(b, &commit(&prefix)),
            format!("commit {a1} admitted"),
            "a synced commit resolves by a prefix of its id to its whole id and its verdict"
        );

        let b1 = note(b, "b1 before any grant");
        pull((a, &a_id), (b, &b_id), &b_port, anchored);
        assert_eq!(
            whence(a, &commit(&b1)),
            format!("commit {b1} refused no authority"),
            "a non-member's commit resolves to its refusal with the reason"
        );

        let x = format!("{tree}x");
        let target = commit(&a1);
        let bound = finish(peer(a).args(["bind", x.as_str(), "anchor", target.as_str()]));
        bound.assert_ids();
        pull((b, &b_id), (a, &a_id), &a_port, anchored);
        let resolved = format!("anchor {target}");
        assert_eq!(
            whence(b, &x),
            resolved,
            "a path bound to a commit resolves to its anchor"
        );
        let view = finish(peer(b).args(["view", tree.as_str()]));
        assert!(
            view.0.contains(&format!("bind x {resolved}")),
            "the view lists the bind with its target anchor: {view:?}"
        );
        assert_eq!(
            whence(a, &commit(&"0".repeat(64))),
            "unknown",
            "a commit the tree does not hold is unknown"
        );
    }
}
