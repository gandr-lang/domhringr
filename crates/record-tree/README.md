# domhringr-record-tree

The record plane stores signed receipts in sedimentrees, folds them into views, and syncs them over iroh.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Receipts and views](#receipts-and-views)
- [Anchors and witnesses](#anchors-and-witnesses)
- [Presence](#presence)
- [Tasks](#tasks)
- [Networking](#networking)
- [Codec](#codec)
- [Dependencies](#dependencies)
- [License](#license)

## Synopsis

**What.** `domhringr-record-tree` is the record plane's durable, replicated receipt store. It provides one sedimentree per tree, named by the tree's own verifying key, a view of each tree's owner, delegated write authority, admitted notes, bound paths, claimed DNS names, introduced trees, the book of which member is reachable at which endpoint, the task its seat receipts, judges' verdicts, runners' verifications, verdicts' gradings and the operator's decisions and landings make of the tree, and admitted and refused commits, and the resolution against those views of an anchor naming a tree, a path in it, `domhringr://<authority>/<path>`, or a commit in it, `domhringr://<authority>/.commit/<commit-id>`, whose authority takes three forms: the tree's key, a DNS name, or a label.

**Why.** Peers need the same interpretation of signed operations regardless of arrival order. Authority depends on a commit's causal past; retaining refused commits lets peers replicate the same evidence without treating every stored write as authorized.

**How.** Published subduction crates store signed commits in redb and sync them over iroh. This crate supplies identity files, Tokio spawner and timer adapters, the value-plane receipt grammar, a deterministic fold, and a single-batch sync operation.

## References

| Artifact | Use |
| -------- | --- |
| `subduction_core`, [crate documentation](https://docs.rs/subduction_core) | Signed commit storage and batch synchronization. |
| `sedimentree_core`, [crate documentation](https://docs.rs/sedimentree_core) | Causal trees, commit ids, and signed payloads. |
| `subduction_redb_storage`, [crate documentation](https://docs.rs/subduction_redb_storage) | Durable redb storage. |
| `iroh`, [crate documentation](https://docs.rs/iroh) | Endpoint discovery, direct connections, and relays. |
| `tokio`, [crate documentation](https://docs.rs/tokio) | Runtime, task spawning, and timers. |
| `gandr-storage-values`, [crate documentation](https://github.com/gandr-lang/gandr/tree/main/crates/storage-values) | Canonical receipt tokens and flat encoding, and the manifest digest evidence is named by. |
| `getrandom`, [crate documentation](https://docs.rs/getrandom/0.4) | Operating-system randomness for operation fences. |
| `blake3`, [crate documentation](https://docs.rs/blake3) | The hash a brief, a playbook, a rubric and a question are named by. |

## Provided features

- Persistent endpoint and signing identities in a state directory, and one minted key per tree opened.
- Durable commits carrying `Open`, `Grant`, `Note`, `Bind`, `Claim`, `Introduce`, `Present`, `Withdraw`, `Dispatch`, `Report`, `Handoff`, `Retire`, `Verdict`, `Verified`, `Graded`, `Decide` or `Landed` receipts; an `Open` carries the tree key's proof, a `Present` the presented endpoint key's; a report's content, a verdict's transcript and a verification's output are named by their value manifest's digest, and `Task::evidence` lists each with the peer that holds it.
- Canonical views with causal authority checks, path bindings, owner-only name claims, label introductions, a book of each member's own presented endpoint, a task of seat receipts, verdicts, verifications, gradings, decisions and landings with its current attempt and how far it has progressed, and explicit refusals.
- A judge's `Ruling` on a lettered question: read, as the answer `Letter` and each option's `Probability` with the mass outside the options (`Readout`), or unread for a named reason (`Unread`).
- Anchors naming a tree, a path in it, or a commit in it by key, by DNS name, or by label, resolved by fold to a binding, to unbound, to a commit's verdict, to unknown, or to a named refusal; a `Reference` may abbreviate a commit id to a unique prefix of at least eight hex digits.
- A `Witness` trait for a DNS name's candidate trees, with the `Dns` witness over `_domhringr.<domain>` TXT records and the `Static` witness supplied by hand.
- Sorted tree heads, the trees a store holds, and one-round peer synchronization.
- Ephemeral or fixed UDP binding beside other application protocols, presenting the bound endpoint in a tree, routing a dial for a tree through its book or to an endpoint named by hand, dialing an endpoint by its id and any addresses, a link held open for pulls, and selected-path reporting.

## Expected features

- A writable state directory, with exclusive access to its tree store.
- A Tokio runtime when opening a `Peer` and while its engine runs.
- A native target with an operating-system random source.
- For synchronization, network access and the remote's endpoint and signing identities: named by hand at first contact, or read from the tree's book once a sync has carried the remote's presence.
- For a DNS-form anchor, a witness: DNS resolvers reaching the name's `_domhringr.<domain>` TXT records, or a `Static` map.
- For the ignored test `witness::tests::the_dns_witness_reads_a_real_record`, `DOMHRINGR_WITNESS=<domain>=<tree id>` naming a published witness record; the test fails naming the variable when it is unset, and CI does not run it.

## Examples

With `domhringr-record-tree` and Tokio's `rt` and `time` features as dependencies, this program opens a tree in a fresh state directory supplied as its first argument, binds a path in it to a note's commit, claims a DNS name for the tree, resolves the path's anchor by key and by the DNS name under a witness supplied by hand, and resolves the note's commit by a prefix of its id:

```rust
use domhringr_record_tree::{Anchor, Domain, Identity, Peer, Receipt, Reference, Resolution, Scope, StateDir, Static, Target, TreeKey, Verdict};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("expected a fresh state directory")?;
    let state = StateDir::from(std::path::PathBuf::from(path));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let identity = Identity::load_or_create(&state)?;
        let owner = identity.peer_key();
        let peer = Peer::open(&state, identity)?;
        let key = TreeKey::mint(&state)?;
        let tree = key.tree();
        peer.commit(tree, Receipt::open(&key, owner)?).await?;
        let note = peer.commit(tree, Receipt::note(tree, "hello".into())?).await?;
        let target = Target::Anchor(Anchor::commit(tree, note));
        let bind = Receipt::bind(tree, "greeting".parse()?, target.clone())?;
        peer.commit(tree, bind).await?;
        let domain: Domain = "example.test".parse()?;
        peer.commit(tree, Receipt::claim(tree, domain.clone())?).await?;
        let witness: Static = [(domain, tree)].into_iter().collect();
        let bound = Resolution::Bound(owner, target);
        for text in [format!("{}greeting", Anchor::key(tree)), "domhringr://example.test/greeting".into()] {
            let reference: Reference = text.parse()?;
            assert_eq!(peer.whence(&reference, &witness, Scope::Unscoped).await?, bound);
        }
        let prefix: String = note.to_string().chars().take(12).collect();
        let commit: Reference = format!("{}.commit/{prefix}", Anchor::key(tree)).parse()?;
        let located = Resolution::Commit { id: note, verdict: Verdict::Admitted };
        assert_eq!(peer.whence(&commit, &witness, Scope::Unscoped).await?, located);
        Ok(())
    })
}
```

The tree id is the tree key's verifying key, written in an anchor as 52 z-base-32 characters; it selects a sedimentree and is not a commit digest. The [`domhringr-peer` binary](../surface-peer/README.md) names trees by anchor and peer, endpoint and commit ids in hex.

Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-record-tree
```

## Receipts and views

A peer is a state directory holding two ed25519 keys, one for the iroh endpoint and one for subduction's signer, the key of every tree it opened, and the tree store. Every commit carries a receipt: the format version, the tree it belongs to, a 16-byte operation fence drawn at random, and its kind — `Open { proof }` (the tree's root; its author owns the tree, and the proof is the tree key's signature naming that author), `Grant { to }` (write authority delegated to a peer), `Note { text }`, `Bind { path, target }` (a path in the tree bound to an anchor — a tree, a path, or a commit, in this tree or another — to an endpoint, or to an opaque datum), `Claim { domain }` (a DNS name claimed for the tree), `Introduce { tree, label }` (another tree introduced by a label in this one), `Present { endpoint, proof }` (the author's iroh endpoint and the addresses it is reached at; the proof is the endpoint key's signature naming the author), or `Withdraw { of }` (the withdrawal of a peer's presence). The commit's blob is the encoded receipt, its id the BLAKE3 digest of that blob, its parents the tree's heads when it is made, and its author the commit's verified signer.

A view is the fold of a tree's commits: walked in canonical order (topological, the smallest commit id next among the ready), a receipt is admitted when it is the tree's Open, when its author owns the tree, or when an admitted grant to its author is among its ancestors, except that a claim is admitted from the owner alone, a presence only when its proof holds for its author under the presented endpoint's key, and a member's withdrawal only of its own presence; everything else is refused with its reason — wrong tree, undecodable, duplicate operation, no authority, not owner, second Open, bad proof, foreign endpoint, foreign presence. The tree's Open is the root Open with the smallest commit id among those whose proof holds under the tree id, so a tree id names exactly the tree its key opened. Among the admitted binds of one path, the last in canonical order binds it, among the admitted introductions of one label, the last introduces it, and among an author's admitted presences, the last is its entry in the book unless an admitted withdrawal of it follows; an anchor's path resolves to that binding or to unbound. The view keeps the id of every commit it admitted beside every refusal, so a commit resolves to the fold's verdict on it. Every peer holding the same commits folds them to the same view, whatever order they arrived in. Refused commits stay in the tree and sync like any other.

## Anchors and witnesses

An anchor names its tree in one of three forms, told apart by its authority. The key form, `domhringr://<tree-id>/…`, names the tree by its key and resolves in that tree's view. The DNS form, `domhringr://<domain>/…`, whose authority holds a dot, names the one tree that a witness names for the DNS name and whose own view admits its owner's claim of it: a witness naming no tree is `unwitnessed`, no witnessed tree holding the claim `unclaimed`, and two holding it `ambiguous`. The label form, `domhringr://<label>/…`, whose authority holds no dot and is not spelled as a tree id, names the tree introduced by that label in the tree the label is read in (`Scope::In`): read in no tree it is `unscoped`, and a label that tree never introduced is `unintroduced`. A bare DNS or label anchor resolves to the key-form anchor of the tree it names, bound under the claim's or the introduction's author; a path or a commit under it resolves in that tree's view. A label means what one tree says it means, so the same label read in two trees names two trees or none.

Within its tree an anchor names nothing (the bare anchor, `domhringr://<authority>/`), a path, or a commit, `domhringr://<authority>/.commit/<commit-id>`, the id as 64 lowercase hex digits. A segment beginning with `.` is reserved for forms the scheme names, `.commit` among them, so no path holds one, in an anchor or in a receipt. A commit resolves to the fold's verdict on it, `admitted` or `refused` with the refusal's reason, and to `unknown` when its tree holds no commit by that id, among them a commit held in another tree. An `Anchor` carries the whole id, as a receipt does. A `Reference`, what a reader types, may also abbreviate it, as git does, to a prefix of at least eight hex digits: the prefix names the one commit of the tree whose id begins with it, resolves to `unknown` when none does, and is refused as `ambiguous commit` with every match when several do. A prefix is not stable as the tree grows, so no receipt carries one.

The witness alone resolves nothing. A tree resolves only when its own signed root claims the name, so a forged or stale record can make a name fail but cannot point it at a tree that did not claim it; a witnessed tree the store does not hold claims nothing until it is synced. The `Dns` witness queries the absolute name `_domhringr.<domain>.` for TXT records, each naming one tree as `tree=<tree-id>`; a name with no records, or none at all, names no tree, and other records are ignored. A DNS name is lowercase letters, digits, and hyphens in at least two dot-separated labels of at most 63 characters, at most 242 in all so that the witness name fits DNS's 253; an internationalized name is written in its ASCII form.

## Presence

A member says where it is reached by committing a presence: `Node::present` waits up to five seconds for the endpoint to reach its home relay, then commits the endpoint at the addresses iroh names for it, its direct addresses and its relay. The book (`View::book`) holds, per author, the presence admitted last, and the commit that presented it is its `since`; a superseded or withdrawn presence is absent, never a default. `Peer::route` names the remote a dial for a tree reaches: the peer aimed at — a named peer or the tree's owner — at an endpoint named by hand, or else at its presence in the book; the dialer itself is no one to reach, and a peer the book holds no presence of is unreachable. `Peer::reads` names the trees a resolution reads, so a caller syncs each through its route before resolving.

**A presence proves its endpoint by the endpoint key's signature naming the author.** A peer's endpoint key and its signing key are distinct, so the commit's author does not name the endpoint by itself; the presence carries the endpoint key's signature over a fixed domain and the author's peer key, and the fold refuses one whose signature does not hold for its author as `foreign endpoint`. A member therefore presents only an endpoint whose key it holds.

- the author's signing key as the endpoint key: one key for both roles, which the state directory keeps apart.
- no proof, relying on the handshake: a dial to a stolen presence fails authentication, but a member could still point every dialer at an address it does not hold.

Reversal: a peer whose endpoint and signing keys are one key, when the check becomes key equality.

**A presence carries no time.** Its commit is when it holds since, and it holds until the record supersedes or withdraws it; liveness is the record's, never a clock's.

- a timestamp in the payload: a clock in the record, and liveness judged by elapsed time.

Reversal: a design that names a clock in the record.

**A withdrawal names the peer whose presence it withdraws.** The owner withdraws anyone's presence and a member its own (`foreign presence` otherwise); a withdrawal of a presence the book does not hold is admitted and changes nothing, so a withdrawal and a presence made concurrently settle by canonical order alone.

- a withdrawal naming the presenting commit: it would leave a later presence by the same author standing, and the owner could not clear an author's entry in one receipt.

Reversal: presences of resources other than the author's own endpoint, which need naming by more than the author.

**An endpoint is its id and an ordered set of addresses.** A direct address is an IP address and port, an IPv6 address without its flow label and scope id, both local to the host naming them; a relay is an `http` or `https` URL written as it parses back and holding no `@`, the character the text form `<endpoint-id>@<address>…` separates addresses by. The receipt lists the addresses in that order, each once, so an endpoint has one encoding; an address of another transport iroh names is left out.

- iroh's `EndpointAddr` through serde: a second canonical form beside the value plane's, its order the serializer's.
- an iroh ticket string: base32 of a postcard encoding, opaque to the decoder's refusals.

Reversal: a transport beyond IP and relays that a dialer needs from the book.

**An endpoint named by hand overrides the book.** A dial reads the book only when no endpoint is named. A presence goes stale when its peer moves before presenting again, and a book read first would then leave the peer unreachable even with its current address in hand.

- the book first, the endpoint named by hand only when the book holds no presence: one fewer way to name a remote, at the cost of the stale case.

Reversal: a book that cannot go stale, as when a dial that fails at a presence falls back on its own.

## Tasks

A tree is also a task. A `Dispatch { seat, brief }` names the peer that is to act and the brief it acts on — an anchor, or a content hash; a `Report { dispatch, content, summary }` answers a dispatch with the manifest digest of what the seat produced, kept as evidence, and a one-line summary of at most 256 bytes; a `Handoff { dispatch, to }` moves the dispatch's slot to another peer; a `Retire { dispatch }` gives the slot up. `View::task` holds every admitted seat receipt in canonical order and the current attempt — the admitted dispatch last in canonical order, its slot, held or retired, its answer, awaited or reported, and its progress past the report, as the decisions below state it — and prints as one line per step and one saying where the task stands: `undispatched`; for an attempt checked past its report, `verified <dispatch> <verification>`, `graded <dispatch> <grading> <composed>`, `decided <dispatch> <decision-commit> <decision>` or `landed <dispatch> <landing> <revision>`; otherwise `dispatched <dispatch> <holder>`, `reported <dispatch> <report>` or `stalled <dispatch> <retirement>`.

**Causal authority and protocol conformance are independent conditions.** The owner or a member may dispatch; only the causal holder of the current dispatch may report, hand off, retire or pause. The fold also replays each dispatch's accepted canonical prefix through the [Seat session type](../arena-session/README.md). Report is required before handoff or retirement, and either ending closes the endpoint. A protocol refusal names the move, expected action and endpoint index. It precedes the authority refusal for that candidate; probing an unauthorized move never advances the play.

- the canonical-order latest dispatch instead of the causal one: a report written before a concurrent dispatch arrived would be refused by where the dispatch sorts, not by what its author saw.
- a second receipt automaton embedded in the fold: its protocol could drift from the arena and the kernel-certified widening.

Reversal: a dispatch that names several seats or slots, which needs a slot per seat in the course.

**Silence does not end a play.** The record names no time. A dispatch without a report stays open; retirement before the first report is a named protocol refusal, not an inferred stall. Whether abandonment should be an explicit widening is a protocol decision, not a timeout or a default in the fold.

`Peer::view_at` selects Base or the certified pause extension without changing any stored receipt. Ordinary views use the extension. `Pause { dispatch }` retains the slot and the report phase; it does not suspend a running process. Existing receipt tags are unchanged and pause occupies tag `0x12`.

**A receipt names evidence by its value manifest and carries no bytes.** A report's content, a verdict's transcript and a verification's output are committed into gandr's value plane as chunk DAGs, and the receipt names each by its `ManifestDigest`: the BLAKE3 digest of the manifest, which binds the root, the length and the profile the value was cut under. `domhringr-record-evidence` holds the bytes beside the tree store and reads them back by that digest, from its own store or fetched from the peer that holds them; `Task::evidence` lists every digest a task names with that peer — a report's author, a verdict's judge, a verification's runner — in canonical order. The tree records what was produced; the evidence plane holds it, so an operator on another machine reads what it judges.

- the bytes in the receipt: a tree grows with every artifact, and a sync carries what only a reader of that artifact needs.
- the BLAKE3 hash of the flat bytes: names the bytes but resolves through nothing the record can reach, and a reader can check them only whole.

Reversal: a change to the value plane's manifest identity, which needs a new receipt version naming the new one.

**A judge's verdict is admitted from the judge alone, on the current dispatch, judged in the receipt's causal past.** A `Verdict { dispatch, judge, rubric, transcript, answers }` names the judge, the BLAKE3 hash of the rubric its questions come from, the manifest digest of the transcript it read, kept as evidence, and one ruling per question, each question named by its hash, in the order asked. A ruling is `read <letter> A=<p> B=<p> … outside=<p>` — the answer, each option's probability, summing to one, and the mass the judge put outside the options — or `unread <reason>`: `no letter`, `outside`, `tied`, `endpoint` or `malformed`. A verdict whose author is not the judge it names is refused `not judge`, one on another dispatch `not current`; an admitted verdict is a step of the task, printed `verdict <commit> <dispatch> <judge> <rubric> <transcript>` and one `ruling <commit> <question> <ruling>` line per question, and changes no attempt: a ruling informs the operator, who acts on it with a receipt of their own.

- a judge granted by the tree: the operator chooses the judge by acting on its verdict, so the fold checks only that the judge speaks for itself.
- a verdict as a report: a report answers the dispatch, and the seat alone answers it.
- a ruling that defaults an unread question to a letter: a judge that did not answer would read as one that did.

Reversal: a verdict that settles the task — accepting or reopening the attempt — which needs the judge's authority in the course.

**A runner's verification is admitted from the runner alone, on the current dispatch.** A `Verified { dispatch, runner, playbook, step, output, status }` records that the runner ran a playbook step's verifier on the dispatch: the BLAKE3 hash of the playbook, the step's identifier in it (`StepId`: 1 to 64 lowercase ASCII letters, digits and hyphens, beginning with a letter), the manifest digest of what the process wrote to its output and error streams, kept as evidence, and how the process ended (`Status`): `exit <code>` or `signal <number>`. A verification whose author is not the runner it names is refused `not runner`, one on another dispatch `not current`; an admitted one is a step of the task, printed `verified <commit> <dispatch> <runner> <playbook> <step> <output> <status>`, and advances the attempt to verified: a failing verifier is recorded as it ended, and the operator acts on it.

- the step without its playbook: a step's identifier names it only within its playbook, so two playbooks' `test` steps would read as one check.
- a pass or fail flag: a process ended by a signal would read as one that failed its check, and what a nonzero code means is the verifier's to say.
- the output's bytes in the receipt: the receipt grows with every run, as a report's would.

Reversal: a check that reads the output and error streams apart, which needs a digest per stream.

**A grading is admitted from its verdict's judge alone, of a verdict in its causal past.** A `Graded { verdict, grades, composed }` names the verdict it grades and gives one `Grade` per answer, in the verdict's order — `met`, `unmet`, `undecided`, or `refused` for an unread ruling — and the grades composed across the rubric. The task, the rubric and the questions are the verdict's, so the grading names them through it rather than again. A grading naming no admitted verdict among its ancestors is refused `no verdict`, one whose author is not that verdict's judge `not judge`, one whose grades number other than the answers or are refused other than exactly where the ruling is unread `misgraded`, and one whose verdict's dispatch is no longer current `not current`; an admitted grading is a step of the task, printed `graded <commit> <dispatch> <verdict> <rubric> <composed>` and one `grade <commit> <question> <grade>` line per answer, and advances the attempt to graded. The fold checks that a grade answers its ruling, never where the ruling stands against the band or how the grades compose: the band and the composition are the rubric's, which the record names by hash and does not hold.

- the task and the rubric in the grading: a second statement of what the verdict records, free to disagree with it.
- the grades inside the verdict: the judge's readout and the rubric's band are two acts, and a band revised later grades the same readout again without asking the judge again.
- a grading from any member: two keys could grade one verdict differently, and the grades would not be the asking key's.
- the fold recomputing grades and composition: it needs the rubric's band and rule, which are not in the record.

Reversal: a rubric reachable from the record, when the fold can recompute each grade from the band and the readout and refuse a grading that misstates one.

**A decision is admitted from the operator it names, on the current dispatch.** A `Decide { dispatch, operator, decision }` records what the operator decides of the attempt the dispatch made: `land` its change, `rework <reason>`, the reason one line as a report's summary is, or `abandon` the task. The operator is a role, the one that dispatches — the owner or a member — and the receipt names the key in that role that decided, as a verdict names its judge: one owner per choice. A decision whose author holds no operator role is refused `no authority`, one whose author is not the operator it names `not operator`, one on another dispatch `not current`; an admitted decision is a step of the task, printed `decide <commit> <dispatch> <operator> <decision>`, and advances the attempt to decided. A later decision on the same dispatch replaces an earlier one as the attempt's progress.

The receipt the design sketched was `Decide { task, verdict }`. A tree is the task, so the receipt names the attempt it decides, its dispatch, as a report and a verdict do; and `verdict` already names the judge's receipt, so what the operator decides is a `decision`.

- the signer alone, no operator field: the decision would say who made it only through the commit, unlike every other ruling the fold admits from the key it names.
- the decision as a verdict or a grading: a judge rules and grades, and its key holds no authority over the attempt; deciding on those readings is the operator's act.
- one decision per dispatch, a second refused: an operator who reconsiders — reworks, then lands after a check by hand — would need a fresh dispatch to say so.

Reversal: a decision that binds once made, which needs the fold to refuse a second on the same dispatch.

**A landing is admitted from its decision's operator alone, carrying out a decision to land in its causal past.** A `Landed { decided, merge }` names the decision it carries out by commit and the revision the repository's default branch stood at once the change was in: the merge commit, or the change's own commit when the branch fast-forwarded to it, as git's object id (`Revision`, 20 bytes in a SHA-1 repository, 32 in a SHA-256 one, printed as 40 or 64 lowercase hex digits). A landing naming no admitted decision among its ancestors is refused `no decision`, one whose author is not that decision's operator `not operator`, one whose decision is to rework or abandon `not land`, and one whose decision's dispatch is no longer current `not current`; an admitted landing is a step of the task, printed `landed <commit> <dispatch> <decision> <operator> <revision>`, and advances the attempt to landed. The landing names its operator through the decision, as a grading names its judge through the verdict. The fold never checks that the revision holds the change: the repository is not in the record.

The receipt the design sketched was `Landed { task, merge }`; it names the decision instead, for the first reason below.

- the landing naming the task or the dispatch: two decisions on one dispatch would leave unsaid which one it carries out, and a landing could not be told from one made after a rework.
- a landing from any operator: two operators could land one decision, and the landing would not be the deciding key's.
- the revision as text: a second spelling of a fixed-width id, and a parser in the decoder.
- the repository or the branch in the receipt: where the repository lives is the operator's configuration, never the record's.

Reversal: a repository the record can reach, when the fold checks that the revision holds the reported change.

**An attempt's progress only advances.** A verification, a grading, a decision and a landing on the current dispatch each advance its progress, ranked in that order; within a rank the latest in canonical order holds, and a lower rank never undoes a higher, so a verification after a grading leaves the attempt graded, and a decision after a landing leaves it landed. The standing line prints the furthest. A verdict moves nothing: it is graded before it counts. A new dispatch is a new attempt, unchecked.

- the latest of any kind: a verifier run after a landing would read the task as no longer landed.
- one standing per kind: a reader would rebuild the lifecycle the fold already orders.

Reversal: a lifecycle that goes back — a landing reverted — which needs a receipt that undoes a step and a rank to fall to.

## Networking

A bound peer is reached by endpoint id alone: on the local network through mDNS and direct addresses, across networks through n0's relay and DNS. It binds an ephemeral UDP port, or a fixed one that a firewall rule can name. A sync dials the remote, runs one batch round for one tree, and disconnects; a dialer that knows the remote's addresses — from its presence in the book, or named by hand — names them in the dial, and the dial does not wait on the lookups. Each side reports the network path iroh selected — direct, relayed, or not yet chosen. A caller holds a link open instead with `Node::connect`, pulls trees over it with `Node::pull` — the other side may pull over the same link — and drops it with `Node::disconnect`.

**A node accepts other application protocols beside subduction's, routed by ALPN.** `Peer::bind` takes the `Protocol`s the node accepts; `Node::accept` yields an `Incoming`: a peer admitted to subduction, or a connection under another protocol, handed over unread; `Node::open` dials a remote under one. The node runs subduction's handshake itself on the connections it accepts, one at a time, so a peer that links and then opens another protocol is linked before its second connection is handed over.

- subduction_iroh's `accept_one`: it accepts any connection and runs subduction's handshake on it, so a second protocol on the endpoint fails its handshake.
- one endpoint per protocol: two ports to bind, present and reach for one peer.

Reversal: subduction_iroh routing ALPNs itself, when the node hands it the endpoint's other protocols.

## Codec

**Receipts use the value plane's flat form, `gandr-storage-values` at the pinned sibling revision.** `Receipt` implements `CanonicalValue` using the token grammar in [`src/receipt.rs`](src/receipt.rs). A commit's blob is the flat form written by `encode_flat` and read by `decode_flat`. This is the token stream `cam_commit` cuts, so committing a receipt through the value plane's chunk DAG requires no re-encoding; a receipt fitting one chunk is exactly the body that chunk frames. The decoder admits exactly what the encoder writes, giving each receipt one blob and one commit id.

Two identities name a receipt and neither stands in for the other. The `CommitId` is sedimentree's: the BLAKE3 digest of the blob, the flat bytes alone. A value-plane `ContentPtr` names the framed chunk: BLAKE3 over the chunk image, the plane's domain and frame header included. A commit is found by its `CommitId`; a `ContentPtr` names a receipt committed into the value plane.

- postcard over a serde mirror of the receipt: compact, but requires re-encoding for the value plane and maintains a second canonical form.
- sedimentree's `codec`: the format of its signed payloads (schema header, issuer key, fields, signature) with big-endian integers; it already seals the commit that carries the blob, and as a receipt form it would be a second canonical form in another byte order.
- a hand-rolled fixed layout: one more canonical form to keep in step with the value plane's.

Reversal: an incompatible change to the value plane's token grammar or flat form requires a matching receipt version change; moving receipts into the value plane's store makes the blob a `ContentPtr` and changes what the commit id hashes.

**A bind's target carries its anchor as typed parts, not as anchor text.** The target is a constructor — anchor, endpoint, or datum — and an anchor a constructor for what it names in its tree — nothing, a path, or a commit — around an authority constructor — key, DNS name, or label. Each part is the record the receipt grammar already uses for its kind: a 32-byte key, a DNS name or label as UTF-8 bytes, a path as its text, a commit id as its 32 bytes. Each part has one encoding, the decoder refuses what the parsers refuse (an empty or reserved segment, a short key, a commit id of other than 32 bytes), and an abbreviated commit has none. The receipt grammar is version 3; a receipt of any other version is refused.

- the anchor's text as one UTF-8 record: a second canonical form to keep in step with the parser, its refusals reached only by parsing decoded text.
- a commit id and a tree id as targets of their own beside the anchor: two spellings of what an anchor names.

Reversal: a new form within a tree or a new authority adds a constructor under a new receipt version.

**A presence and a withdrawal are new kinds, not a new version.** A decoder that predates them refuses them as an unknown kind, folded as undecodable, while every receipt it knows keeps its blob and its commit id; a version change would make every new receipt unreadable to it instead.

- a new receipt version: an old decoder refuses notes and binds it could read.

Reversal: a change to an existing kind's payload, which needs a new version.

**The seat receipts are new kinds, not a new version, and a brief a constructor.** `Dispatch`, `Report`, `Handoff` and `Retire` follow the presence and the withdrawal for the same reason; a brief is an anchor, as a bind's target carries it, or a content hash of 32 bytes; a summary is UTF-8 bytes that parse as a summary.

- a new receipt version: an old decoder refuses every receipt it could read.

Reversal: a change to an existing kind's payload.

**A verdict is a new kind, and a ruling a constructor.** `Verdict` follows the seat receipts for the same reason. A read ruling is a word per option, in letter order, then a word for the mass outside the options, each the IEEE 754 binary64 bits of a number from zero to one, never negative zero; its answer letter is not written, since it is the option holding the most. An unread ruling is a constructor naming its reason. The decoder refuses a probability out of `[0, 1]` or negative zero, a readout `Readout::new` refuses — fewer than two options or more than twenty-six, a sum other than one, a tie — and a reason it does not know.

- probabilities as decimal text: a second canonical form of each number, and a parser in the decoder.
- fixed-point integers: a rounding step between the readout and the record, and a sum that no longer reads back exactly.

Reversal: a change to the readout's form — another number of options, a log-probability — which needs a new kind.

**A verification and a grading are new kinds, a status and a grade constructors.** `Verified` and `Graded` follow the verdict for the same reason. A step is ASCII bytes that parse as a `StepId`; a status is a constructor, exited or signalled, holding one word, the 32 bits of the code's or the signal's two's-complement value; a grade is an empty constructor, and a grading writes its count of grades, the grades, then the composed grade. The decoder refuses a step `StepId` refuses, a status or a grade it does not know, and a word beyond 32 bits.

- the code as signed decimal text: a second canonical form of each number, and a parser in the decoder.
- one word carrying a flag bit beside the number: a case named by a bit rather than by a constructor, as the grammar names every other case.

Reversal: a platform whose exit status does not fit 32 bits, which needs a new constructor.

**A decision and a landing are new kinds, with a decision constructor and a revision of either git width.** `Decide` and `Landed` follow the grading for the same reason. A `Decide` writes its dispatch, its operator's 32-byte peer id, then the decision: a constructor, land and abandon empty, rework holding its reason as one bytes record that parses as a `Summary`; a `Landed` writes its decision, then the revision as one bytes record of 20 or 32 bytes. The decoder refuses a decision it does not know, a reason `Summary` refuses, and a revision of any other length.

- a revision padded to 32 bytes: a padded SHA-1 id reads back as a SHA-256 one.
- the reason as a field of every decision, empty for land and abandon: an absence named by an empty value, which a decoder must then refuse elsewhere.

Reversal: a version control system whose ids are neither width, which needs a revision constructor per system.

**Evidence is named by manifest digest under receipt version 3.** A report's content, a verdict's transcript and a verification's output are each the 32 bytes of a `ManifestDigest`, where version 2 held the BLAKE3 hash of the bytes in the same 32 bytes. The layout is unchanged and the meaning is not, so the version moves: a version-2 receipt is refused at its version word as an unexpected constructor, never read as naming a manifest, and a version-2 decoder refuses every version-3 receipt the same way.

- new kinds beside the old, a digest report beside a hash report: two kinds for one step of the task, and a fold that must say which counts.
- a constructor per evidence field, hash or digest: a receipt could still name evidence no reader can dereference.
- the old version read on: a hash read as a digest names a manifest that does not exist, and the refusal arrives at the read instead of at the decode.

Reversal: a change to an existing kind's payload, which needs a new version again.

## Dependencies

**Operation fences use `getrandom` 0.4 with no features.** `getrandom::fill` draws the 16 fence bytes from the operating system's source. iroh already brings the crate into the dependency graph, so it adds no crate to the build; native targets require no feature.

- `rand`: a seeded generator and its traits where one read from the OS source suffices.
- `uuid` with `v4`: a crate and a UUID type for what is 16 opaque bytes.

Reversal: a high-risk advisory against `getrandom`, its departure from the dependency graph, or a fence source the value plane supplies.

**The DNS witness uses iroh's resolver, `iroh::dns::DnsResolver`.** iroh resolves endpoint ids through DNS with it, so reading a name's TXT records adds no crate and no feature to the build. It reads the host's resolver configuration, falls back to public resolvers, bounds a lookup by `iroh::dns::DNS_TIMEOUT`, and reports a name that does not exist apart from a failed lookup.

- `hickory-resolver`: a second resolver, with its own configuration and feature set, beside the one iroh already carries.
- the operating system's resolver through the standard library: it resolves addresses and returns no TXT records.

Reversal: iroh no longer exporting its resolver, or a witness that needs record types or DNSSEC validation the resolver does not expose.

**A content hash is `blake3` 1.8 with no features.** It names a brief, a playbook, a rubric and a question; it is the hash sedimentree names commits by, already in the graph through sedimentree, iroh and subduction, so it adds no crate to the build. Evidence is named by the value plane's manifest digest instead (§ Tasks).

- SHA-256: a second hash function, and a crate the graph does not otherwise need.

Reversal: a brief, a playbook or a rubric reachable from the record, when it is named by a manifest digest as evidence is.

**subduction_iroh is built without its `server` feature.** The node accepts connections itself to route them by ALPN, so the crate's server half is unused.

Reversal: subduction_iroh's own accept loop, when it routes other protocols.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
