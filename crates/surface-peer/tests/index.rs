//! Keyed questions proved by the peer binary without importing task trees.

extern crate alloc;

#[cfg(test)]
mod tests
{
    use core::time::Duration;
    use std::ffi::OsStr;
    use std::io::BufRead as _;
    use std::path::Path;
    use std::process::Child;
    use std::process::Command;
    use std::process::Output;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Instant;

    /// Independently frame a membership answer, including hostile proof nodes.
    ///
    /// # Specification
    /// - ensures: the image carries the manifest and raw proof bytes, not a
    ///   root supplied outside that manifest.
    /// - panics: unless the answer is membership or its fields fit the wire
    ///   width.
    /// - executable: none — the function is its own specification; the process
    ///   witness supplies the output or proof image and checks its
    ///   interpretation.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    fn member_image(
        answer: &domhringr_record_index::prove::Answer
    ) -> domhringr_record_index::WireImage
    {
        use domhringr_record_index::prove::Proof;
        let Proof::Present(ref proof) = answer.proof
        else {
            panic!("membership answer");
        };
        let mut image = domhringr_record_index::WireImage(vec![1]);
        frame(&mut image, answer.manifest.encode().unwrap());
        image.0.push(1);
        frame(&mut image, proof.value());
        image
            .0
            .extend_from_slice(&u32::try_from(proof.nodes().len()).unwrap().to_le_bytes());
        for node in proof.nodes() {
            frame(&mut image, node.bytes());
        }
        image
    }

    /// Append one independently length-prefixed field.
    ///
    /// # Specification
    /// - panics: when a field exceeds the wire width.
    /// - executable: none — the function is its own specification; the process
    ///   witness supplies the output or proof image and checks its
    ///   interpretation.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    fn frame(
        image: &mut domhringr_record_index::WireImage,
        field: impl AsRef<[u8]>,
    )
    {
        let field = field.as_ref();
        image
            .0
            .extend_from_slice(&u32::try_from(field.len()).unwrap().to_le_bytes());
        image.0.extend_from_slice(field);
    }

    /// Serve supplied bytes to a real reader process, then await its refusal.
    ///
    /// # Specification
    /// - ensures: every image answers a separate request on one connection.
    /// - panics: on transport failure or reader timeout.
    /// - executable: none — process, channel or filesystem effects cannot be
    ///   replayed in a predicate; the process witness checks their observable
    ///   results.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    async fn hostile(
        holder: &domhringr_record_tree::Node,
        images: Vec<domhringr_record_index::WireImage>,
        mut command: Command,
    ) -> Output
    {
        let reader = tokio::task::spawn_blocking(move || run(&mut command));
        let domhringr_record_tree::Incoming::Protocol { connection, .. } =
            holder.accept().await.unwrap()
        else {
            panic!("index connection");
        };
        for image in images {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let _request = recv.read_to_end(4096).await.unwrap();
            send.write_all(image.as_ref()).await.unwrap();
            send.finish().unwrap();
        }
        let output = reader.await.unwrap();
        assert_eq!(output.status.code(), Some(1_i32), "{output:?}");
        assert!(
            output.stdout.is_empty(),
            "a refused proof prints no trusted answer: {output:?}"
        );
        output
    }

    /// A hostile holder cannot invent a later attempt or exceed the reader's
    /// cap.
    ///
    /// # Specification
    /// - ensures: a forged dispatch fails against the attested manifest;
    ///   exactly one MiB reaches framing, while an extra byte fails at the read
    ///   boundary.
    /// - panics: on any accepted forgery or incorrect boundary classification.
    /// - executable: none — process, channel or filesystem effects cannot be
    ///   replayed in a predicate; the process witness checks their observable
    ///   results.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    fn hostile_answers_are_refused(fixture: &Fixture)
    {
        use domhringr_record_index::AttemptNumber;
        use domhringr_record_index::Index;
        use domhringr_record_index::IndexKind;
        use domhringr_record_index::MoveKey;
        use domhringr_record_index::SequenceNumber;
        use domhringr_record_index::WireImage;
        use domhringr_record_index::project::TaskEntry;
        use domhringr_record_index::project::TaskName;
        use domhringr_record_index::prove::Query;
        use domhringr_record_index::store::Store;
        use domhringr_record_tree::StateDir;
        use gandr_storage_values::TokenBody;
        use gandr_storage_values::decode_flat;
        use gandr_storage_values::encode_flat;
        let state = StateDir::from(fixture.root.path().join("a"));
        let store = Store::open(&state);
        let project = store.load(fixture.digest.parse().unwrap()).unwrap();
        let name: TaskName = "one".parse().unwrap();
        let query = Query::Key(name.key());
        let answer = domhringr_record_index::prove::answer(&project, &query).unwrap();
        let value = project.tree.lookup(name.key().as_borrowed()).unwrap();
        let TaskEntry::Held { tree, dialogue, .. } =
            decode_flat::<TaskEntry>(TokenBody::from(value.as_ref())).unwrap()
        else {
            panic!("held task");
        };
        let dialogue = store.load(dialogue).unwrap();
        let bid = finish(fixture.reader().arg("id"));
        let stranger = bid[1].parse().unwrap();
        let receipt = domhringr_record_tree::Receipt::dispatch(
            tree,
            stranger,
            domhringr_record_tree::Edition::CURRENT,
            domhringr_record_tree::Brief::Content(BRIEF.parse().unwrap()),
        )
        .unwrap();
        let receipt = encode_flat(&receipt).unwrap();
        let value = encode_flat(&domhringr_record_index::dialogue::MoveValue {
            author: stranger,
            blob: alloc::borrow::Cow::Borrowed(receipt.as_ref()),
        })
        .unwrap();
        let key = MoveKey::new(AttemptNumber(3), SequenceNumber(0));
        let mut records = dialogue.tree.records().to_vec();
        records.push(gandr_storage_records::Record::new(
            key.as_ref(),
            value.as_ref(),
        ));
        let records: Vec<_> = records
            .iter()
            .map(gandr_storage_records::Record::as_record_ref)
            .collect();
        let forged = gandr_storage_records::RecordTree::build(
            &records,
            gandr_storage_records::TreeParams::current(),
        )
        .unwrap();
        let forged = Index::new(IndexKind::Dialogue, forged);
        let mut forged =
            domhringr_record_index::prove::answer(&forged, &Query::Key(key.owned())).unwrap();
        forged.manifest = dialogue.manifest;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let state = StateDir::from(fixture.root.path().join("hostile"));
            let identity = domhringr_record_tree::Identity::load_or_create(&state).unwrap();
            let port = free_port();
            let holder = domhringr_record_tree::Peer::open(&state, identity)
                .unwrap()
                .bind(
                    domhringr_record_tree::BindPort::Fixed(port.parse().unwrap()),
                    &[domhringr_record_index::stream::PROTOCOL],
                )
                .await
                .unwrap();
            let at = format!("{}@127.0.0.1:{port}", holder.endpoint_key());
            let mut command = fixture.reader();
            command.args(["index", "after", &fixture.project, "one", "2", "--at", &at]);
            let refused = hostile(
                &holder,
                vec![member_image(&answer), member_image(&forged)],
                command,
            )
            .await;
            let failure = String::from_utf8(refused.stderr).unwrap();
            assert!(failure.contains("proof"), "{failure}");
            let cap = usize::try_from(domhringr_record_index::stream::ANSWER_CAP.0).unwrap();
            for size in [cap, cap.saturating_add(1)] {
                let mut command = fixture.reader();
                command.args(["index", "task", &fixture.project, "one", "--at", &at]);
                let refused = hostile(&holder, vec![WireImage(vec![0; size])], command).await;
                let failure = String::from_utf8(refused.stderr).unwrap();
                if size == cap {
                    assert!(
                        failure.contains("trailing"),
                        "the whole in-cap answer reaches framing: {failure}"
                    );
                }
                else {
                    assert!(failure.contains("exceeds 1048576 bytes"), "{failure}");
                }
            }
            holder.close().await;
            drop(holder);
        });
    }

    /// Bound each process invocation and server announcement.
    const DEADLINE: Duration = Duration::from_secs(30);
    /// Poll without busy-waiting.
    const POLL: Duration = Duration::from_millis(20);
    /// The brief's content identity.
    const BRIEF: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    /// Select an isolated peer state directory.
    ///
    /// # Specification
    /// trivial.
    fn peer(state: &Path) -> Command
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_domhringr-peer"));
        command.arg("--state").arg(state);
        command
    }

    /// Run a bounded command, retaining both output channels.
    ///
    /// # Specification
    /// - ensures: the child exits within the deadline.
    /// - panics: on process I/O failure or deadline expiry, killing the child
    ///   first.
    /// - executable: none — process, channel or filesystem effects cannot be
    ///   replayed in a predicate; the process witness checks their observable
    ///   results.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
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
                let _status = child.wait().unwrap();
                panic!("{command:?} outlived {DEADLINE:?}");
            }
            std::thread::sleep(POLL);
        }
        child.wait_with_output().unwrap()
    }

    /// Collect the successful command's lines.
    ///
    /// # Specification
    /// - panics: on failure, timeout or non-UTF-8 output.
    /// - executable: none — process, channel or filesystem effects cannot be
    ///   replayed in a predicate; the process witness checks their observable
    ///   results.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    fn finish(command: &mut Command) -> Vec<String>
    {
        let output = run(command);
        assert!(output.status.success(), "{command:?}: {output:?}");
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Collect a command's single output line.
    ///
    /// # Specification
    /// - panics: as `finish`, or unless exactly one line is printed.
    /// - executable: none — the function is its own specification; the process
    ///   witness supplies the output or proof image and checks its
    ///   interpretation.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    fn only(command: &mut Command) -> String
    {
        let mut lines = finish(command);
        assert_eq!(lines.len(), 1, "{command:?}: {lines:?}");
        lines.pop().unwrap()
    }

    /// Reserve an ephemeral UDP port long enough to discover its number.
    ///
    /// # Specification
    /// - panics: if the socket cannot be bound or inspected.
    /// - executable: none — process, channel or filesystem effects cannot be
    ///   replayed in a predicate; the process witness checks their observable
    ///   results.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the process fixture checks the commands, receipts or
    ///   findings this helper supplies.
    /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
    fn free_port() -> String
    {
        let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        socket.local_addr().unwrap().port().to_string()
    }

    /// A server killed and reaped even when a witness fails.
    struct Running
    {
        /// The serving process.
        child: Child,
        /// Drained stdout, so proof responses cannot fill its pipe.
        lines: mpsc::Receiver<String>,
    }

    impl Running
    {
        /// Start the server and await its listening announcement.
        ///
        /// # Specification
        /// - ensures: the server has announced both identities and its
        ///   listener.
        /// - panics: on process failure or a missing announcement.
        /// - executable: none — process, channel or filesystem effects cannot
        ///   be replayed in a predicate; the process witness checks their
        ///   observable results.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — the process fixture checks the commands, receipts
        ///   or findings this helper supplies.
        /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
        fn serve(
            state: &Path,
            port: &OsStr,
        ) -> Self
        {
            let mut child = peer(state)
                .args(["serve", "--port"])
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
            let _endpoint = server.lines.recv_timeout(DEADLINE).unwrap();
            let _peer = server.lines.recv_timeout(DEADLINE).unwrap();
            assert_eq!(server.lines.recv_timeout(DEADLINE).unwrap(), "listening");
            server
        }
    }

    impl Drop for Running
    {
        /// Kill and reap the server.
        ///
        /// # Specification
        /// - ensures: the server no longer holds its state directory.
        /// - panics: on process I/O failure.
        /// - executable: none — process, channel or filesystem effects cannot
        ///   be replayed in a predicate; the process witness checks their
        ///   observable results.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — the process fixture checks the commands, receipts
        ///   or findings this helper supplies.
        /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
        fn drop(&mut self)
        {
            self.child.kill().unwrap();
            let _status = self.child.wait().unwrap();
        }
    }

    /// A real two-attempt task and a reader holding only its project.
    struct Fixture
    {
        /// Files outlive every process using them.
        root: tempfile::TempDir,
        /// Project anchor.
        project: String,
        /// Task anchor.
        task: String,
        /// Owner's peer key.
        owner: String,
        /// Owner's direct endpoint.
        contact: String,
        /// Attested project digest.
        digest: String,
        /// Dispatch identities in attempt order.
        dispatches: Vec<String>,
        /// Report identities in attempt order.
        reports: Vec<String>,
        /// Replay's admitted move lines, used as an independent rendering
        /// oracle.
        replay: Vec<String>,
        /// The owner serving both trees and index proofs.
        server: Running,
    }

    impl Fixture
    {
        /// Drive two attempts, attest their index, and sync the project alone.
        ///
        /// # Specification
        /// - ensures: A holds both trees; B holds the project and no task; the
        ///   first attempt reports then retires, the second reports and stays
        ///   live.
        /// - panics: on any process or semantic contract failure.
        /// - executable: none — process, channel or filesystem effects cannot
        ///   be replayed in a predicate; the process witness checks their
        ///   observable results.
        ///
        /// # Adequacy
        /// - hypothesis: L3 — the process fixture checks the commands, receipts
        ///   or findings this helper supplies.
        /// - witness: `index::tests::a_peer_holding_only_the_project_verifies_every_question`
        fn new() -> Self
        {
            let root = tempfile::tempdir().unwrap();
            let (a, b, seat) = (
                root.path().join("a"),
                root.path().join("b"),
                root.path().join("seat"),
            );
            let aid = finish(peer(&a).arg("id"));
            let sid = finish(peer(&seat).arg("id"));
            let project = only(peer(&a).arg("open"));
            let task = only(peer(&a).arg("open"));
            let _binding =
                only(peer(&a).args(["bind", &format!("{project}tasks/one"), "anchor", &task]));
            let seat_port = free_port();
            let seat_at = format!("{}@127.0.0.1:{seat_port}", sid[0]);
            let file = root.path().join("report");
            std::fs::write(&file, b"a real two-attempt report").unwrap();
            let mut dispatches = Vec::new();
            let mut reports = Vec::new();
            let mut replay = Vec::new();
            for attempt in [1_u32, 2] {
                let server = Running::serve(&seat, OsStr::new(&seat_port));
                let dispatched = finish(peer(&a).args([
                    "dispatch", &task, &sid[1], "content", BRIEF, "--at", &seat_at,
                ]));
                dispatches.push(dispatched[0].clone());
                drop(server);
                reports.push(only(
                    peer(&seat)
                        .args(["report", &task])
                        .arg(&file)
                        .arg(format!("report-{attempt}")),
                ));
                if attempt == 1 {
                    let _retired = only(peer(&seat).args(["retire", &task]));
                }
                let server = Running::serve(&seat, OsStr::new(&seat_port));
                replay =
                    finish(peer(&a).args(["replay", &task, "--peer", &sid[1], "--at", &seat_at]));
                drop(server);
            }
            replay.retain(|line| {
                ["dispatch ", "report ", "retire "]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
            });
            let port = free_port();
            let contact = format!("{}@127.0.0.1:{port}", aid[0]);
            let _present = only(peer(&a).args(["present", &project, "--port", &port]));
            let indexed = only(peer(&a).args(["index", "derive", &project]));
            let fields: Vec<_> = indexed.split_whitespace().collect();
            assert_eq!(fields[0], "indexed");
            let digest = fields[2].to_owned();
            let heads = finish(peer(&a).args(["heads", &project]));
            assert_eq!(
                only(peer(&a).args(["index", "derive", &project])),
                format!("unchanged {digest}")
            );
            assert_eq!(
                finish(peer(&a).args(["heads", &project])),
                heads,
                "an unchanged derivation writes no attestation"
            );
            let server = Running::serve(&a, OsStr::new(&port));
            let _sync =
                finish(peer(&b).args(["sync", &project, "--peer", &aid[1], "--at", &contact]));
            assert!(finish(peer(&b).args(["heads", &task])).is_empty());
            Self {
                root,
                project,
                task,
                owner: aid[1].clone(),
                contact,
                digest,
                dispatches,
                reports,
                replay,
                server,
            }
        }

        /// The reader's binary invocation.
        ///
        /// # Specification
        /// trivial.
        fn reader(&self) -> Command
        {
            peer(&self.root.path().join("b"))
        }
    }

    /// Authentication answers the four questions without transferring a task
    /// tree.
    ///
    /// # Specification
    /// - ensures: B verifies the task standing, original report, first
    ///   attempt's complete play, second dispatch and absence of a third
    ///   attempt; its task store remains empty throughout.
    /// - panics: on any mismatch with A's replay or B's held trees.
    #[test]
    fn a_peer_holding_only_the_project_verifies_every_question()
    {
        let fixture = Fixture::new();
        let standing = finish(fixture.reader().args([
            "index",
            "task",
            &fixture.project,
            "one",
            "--at",
            &fixture.contact,
        ]));
        assert_eq!(
            standing[0],
            format!("proved {} {}", fixture.digest, fixture.owner)
        );
        assert_eq!(
            standing[1],
            format!(
                "task {} reported {} {}",
                fixture.task, fixture.dispatches[1], fixture.reports[1]
            )
        );
        let movement =
            finish(
                fixture
                    .reader()
                    .args(["index", "move", &fixture.project, "one", "2.1"]),
            );
        assert_eq!(movement.last(), fixture.replay.last());
        let play = finish(
            fixture
                .reader()
                .args(["index", "play", &fixture.project, "one", "1"]),
        );
        assert_eq!(&play[2 ..], &fixture.replay[.. 3]);
        let after = finish(
            fixture
                .reader()
                .args(["index", "after", &fixture.project, "one", "1"]),
        );
        assert_eq!(
            after.last(),
            Some(&format!("after 1 {}", fixture.dispatches[1]))
        );
        let after = finish(
            fixture
                .reader()
                .args(["index", "after", &fixture.project, "one", "2"]),
        );
        assert_eq!(after.last(), Some(&"after 2 none".to_owned()));
        hostile_answers_are_refused(&fixture);
        assert!(
            finish(fixture.reader().args(["heads", &fixture.task])).is_empty(),
            "proof questions never import task commits"
        );
        drop(fixture.server);
    }

    /// Held trees permit the stronger fold-based attestation check.
    ///
    /// # Specification
    /// - ensures: B reports an unchecked task before syncing it, agrees after
    ///   syncing, and measures the same project and dialogue as their holder.
    /// - panics: on any status, check or measurement mismatch.
    #[test]
    fn a_peer_holding_the_trees_checks_the_attestation()
    {
        let fixture = Fixture::new();
        let unchecked = run(fixture.reader().args(["index", "check", &fixture.project]));
        assert_eq!(unchecked.status.code(), Some(3_i32));
        assert_eq!(
            String::from_utf8(unchecked.stdout).unwrap().trim(),
            "unchecked one"
        );
        let _sync = finish(fixture.reader().args([
            "sync",
            &fixture.task,
            "--peer",
            &fixture.owner,
            "--at",
            &fixture.contact,
        ]));
        assert_eq!(
            only(fixture.reader().args(["index", "check", &fixture.project])),
            "agrees"
        );
        let measured = finish(
            fixture
                .reader()
                .args(["index", "measure", &fixture.project]),
        );
        assert_eq!(measured.len(), 2);
        assert!(measured[0].starts_with("index project "));
        assert!(measured[1].starts_with("index dialogue "));
        let project = fixture.project.clone();
        let state = fixture.root.path().join("a");
        drop(fixture.server);
        assert_eq!(
            measured,
            finish(peer(&state).args(["index", "measure", &project]))
        );
    }
}
