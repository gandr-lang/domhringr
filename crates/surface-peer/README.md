# domhringr-surface-peer

The `domhringr-peer` binary manages and synchronizes a record-plane peer over a state directory, dispatches seats to tasks and serves as one, fetches the evidence a task names, judges a task's transcript into a verdict, runs playbooks and grades rubrics on a task, and checks a concepts tree against the checkouts that cite it and hold its pages.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Identifiers and state](#identifiers-and-state)
- [Output](#output)
- [Networking](#networking)
- [Tasks](#tasks)
- [Evidence](#evidence)
- [Judging](#judging)
- [Playbooks and rubrics](#playbooks-and-rubrics)
- [Drift](#drift)
- [License](#license)

## Synopsis

**What.** `domhringr-surface-peer` provides the `domhringr-peer` command-line binary. It opens sedimentrees, delegates write authority, writes notes, binds paths, claims DNS names for a tree, introduces other trees by label, presents the peer's endpoint in a tree and withdraws presences, resolves anchors and commits by key, by DNS name, or by label, reads views, books, and heads, synchronizes a tree with another peer reached through the tree's book or at an endpoint named by hand, dispatches a seat to a task and wakes it, reports, hands off and retires as a seat, replays a task with the evidence it names, fetches a value by its digest, serves as a seat acting through a program, asks a judge lettered questions about a transcript and commits its rulings as a verdict on the task, reads playbooks and rubrics, runs a playbook's verifiers and grades a rubric's questions on the task, and reports where a concepts tree has drifted from a public checkout and a vault.

**Why.** A peer needs a persistent identity and a command-line surface for operating its trees and inspecting their interpretation. Separate state directories let peers retain independent keys and stores while exchanging the same signed commits. Public text that cites private pages by anchor stays in step with them only if something checks each citation against its binding and each binding against its page.

**How.** Commands use `domhringr-record-tree` for identity, storage, receipt construction, folding, routing, resolution, and synchronization, and `domhringr-record-evidence` for the evidence a receipt names: `report`, a seat's act, `judge verdict`, `playbook run` and `rubric grade` keep what they record in the evidence store beside the tree store, `replay` and `evidence` fetch what it lacks over the evidence protocol, and `serve` answers those fetches. `whence` asks DNS for a DNS name's `_domhringr.<domain>` TXT records unless `--witness` names the candidate trees, reads a label in the `--in` tree, and syncs each tree it reads from the peer aimed at before resolving. `serve` accepts connections over iroh; `sync` dials one remote, at its presence in the tree's book or at an endpoint named by hand, exchanges one tree in a batch round, and disconnects. `judge` asks through `domhringr-judge-oracle`, of the endpoint the environment configures or from a table file. `playbook` and `rubric` read their documents, run verifiers and grade rulings through `domhringr-strategy-document`, and ask as `judge` asks. `drift` folds the concepts tree from the local store and reads both checkouts with the `git` binary: `git grep` for the tree's anchor over the public checkout's tracked files, and one `git cat-file --batch-check` for every bound page's blob at the vault's `HEAD` and at its bound commit.

## References

- `domhringr-record-tree`, [crate documentation](../record-tree/README.md): the persistent peer, receipt fold, and synchronization operation.
- `domhringr-seat-slot`, [crate documentation](../seat-slot/README.md): the wake and the serving seat.
- `domhringr-judge-oracle`, [crate documentation](../judge-oracle/README.md): the question, the readout and the judge's backends.
- `domhringr-strategy-document`, [crate documentation](../strategy-document/README.md): the playbook and rubric documents, the verifier, the band and the composition.
- `iroh`, [crate documentation](https://docs.rs/iroh): endpoint discovery and direct or relayed network paths.
- `lexopt`, [crate documentation](https://docs.rs/lexopt): command-line options and operands.

## Provided features

- Identity inspection and persistent state creation.
- Tree opening under a freshly minted tree key, printing the tree's anchor.
- `Grant`, `Note`, `Bind`, `Claim`, `Introduce`, `Present`, `Withdraw`, `Dispatch`, `Report`, `Handoff`, `Retire`, `Verdict`, `Verified` and `Graded` receipt submission; `present` commits the endpoint at the addresses it binds, the seat verbs answer the task's current dispatch, and a verdict, a verification and a grading rule on it.
- Resolution of a tree, a path, or a commit in the key, DNS, and label forms, a commit by its whole id or a unique prefix of it, with DNS witnesses or witnesses supplied by hand; canonical views; and sorted tree heads.
- Serving on an ephemeral or fixed UDP port, as a seat that holds its slots or acts through a program.
- Dispatching a seat and waking it at its presence in the task's book or at an endpoint named by hand, and replaying a task through its seat, each value its receipts name fetched from the seat when the local store lacks it.
- A value of the evidence plane by its digest, read from the local store or fetched from the peer that holds it, written byte for byte or refused by name.
- A tree's book: each present peer, the endpoint it is reached at, and the commit that presented it.
- Single-tree synchronization with the tree's owner or a named peer, at its presence in the book or at an endpoint named by hand, reporting where the endpoint came from and the selected path; `whence` reaches each tree it reads the same way, or resolves from the local store alone.
- A drift check of a concepts tree against a public and a vault checkout: unbound citations, drifted, missing and orphaned bindings, and malformed data and citations, one line each in anchor order, with an exit status a gate can read.
- A judge's question about a transcript, by file or by its digest in the evidence store, answered by an OpenAI-compatible endpoint or a table file, and a verdict of such rulings on a task's current dispatch.
- Playbook and rubric validation, refused by file and field; a playbook's verifiers run in the task's state and its questions graded, or a rubric's, on the task's current dispatch.

## Expected features

- A writable state directory; commands using its store require exclusive access.
- A native target with an operating-system random source for identities and receipts.
- For synchronization and for `whence` without `--local`, a serving remote: the tree's owner, or a peer named by `--peer`, present in the tree's book; at first contact, or when the book holds no presence of it, its endpoint named by `--at`, with its loopback or direct address on one host.
- Network access for iroh discovery and transport; a fixed port must be available for binding.
- For `serve --surface <program>`, an executable as [`domhringr-seat-slot`](../seat-slot/README.md#expected-features) expects it; `dispatch` needs the seat serving, reached at `--at` the first time and through its presence after.
- For a DNS-form anchor, DNS resolvers reaching the name's `_domhringr.<domain>` TXT records, unless `--witness` names its trees; and in the local store, the witnessed tree whose root claims the name.
- For a label-form anchor, the tree that introduced the label, named by `--in` and held in the local store.
- For `drift`, the `git` binary on `PATH`, both checkouts local, each a directory in a git working tree, and the concepts tree in the local store; a `sync` brings it there, since `drift` dials no one.
- For `judge` without `--static`, an OpenAI-compatible endpoint reporting log-probabilities, configured as [`domhringr-judge-oracle`](../judge-oracle/README.md#configuration) reads it from the environment; for `judge verdict`, the task in the local store with a dispatch.
- For `playbook run` and `rubric grade`, the task in the local store with a dispatch, the task's state directory holding each state file its rubrics read, each verifier's command on `PATH` or named by path, and the judge as `judge` expects it.
- For the ignored test `strategy::tests::a_configured_judge_grades_a_fixture_pair_of_the_set`, a judge endpoint configured as `judge` expects it; the test fails naming the missing variable when none is, and CI does not run it.

## Examples

From the workspace root, build the binary and operate a tree in a fresh state directory:

```sh
mise exec -- cargo build -p domhringr-surface-peer
state=$(mktemp -d)
target/debug/domhringr-peer --state "$state" id
tree=$(target/debug/domhringr-peer --state "$state" open)
note=$(target/debug/domhringr-peer --state "$state" note "$tree" hello)
target/debug/domhringr-peer --state "$state" bind "${tree}greeting" anchor "${tree}.commit/$note"
target/debug/domhringr-peer --state "$state" whence "${tree}greeting"
target/debug/domhringr-peer --state "$state" whence "${tree}.commit/$(printf %.12s "$note")"
target/debug/domhringr-peer --state "$state" claim "$tree" example.test
id=${tree#domhringr://}; id=${id%/}
target/debug/domhringr-peer --state "$state" whence domhringr://example.test/greeting --witness "example.test=$id"
other=$(target/debug/domhringr-peer --state "$state" open)
target/debug/domhringr-peer --state "$state" introduce "$tree" other "$other"
target/debug/domhringr-peer --state "$state" whence domhringr://other/ --in "$tree"
target/debug/domhringr-peer --state "$state" present "$tree" --port 4433
target/debug/domhringr-peer --state "$state" book "$tree"
target/debug/domhringr-peer --state "$state" view "$tree"
target/debug/domhringr-peer --state "$state" heads "$tree"
```

`open` prints the new tree's anchor, `domhringr://<tree-id>/`; appending a path to it names that path in the tree, and appending `.commit/<commit-id>` a commit in it. The first `whence` prints the anchor of the note's commit that `greeting` is bound to, and the second resolves that commit by the first 12 digits of its id to `commit <commit-id> admitted`. The two `whence` lines after the claim resolve the same path by the DNS name the tree claimed, witnessed by hand, and the second tree by the label the first introduced it by; every tree they read is this peer's own, so none dials. `present` commits the endpoint at port 4433 as this peer's presence in the tree, which `book` prints and at which a peer that syncs the tree reaches it once `serve --port 4433` runs. The commands print endpoint, signing-peer, and commit ids in hex; the forms are defined in [Identifiers and state](#identifiers-and-state).

With `domhringr-peer` on `PATH`, the complete invocation set is:

```text
domhringr-peer --state <dir> id                                    # endpoint id, then peer id
domhringr-peer --state <dir> serve [--port <port>] [--surface <program>]  # ids, listening, then what the peer and the seat do
domhringr-peer --state <dir> present <tree> [--port <port>]        # the presence's commit id
domhringr-peer --state <dir> withdraw <tree> [<peer-id>]           # the withdrawal's commit id
domhringr-peer --state <dir> book <tree>                           # one line per present peer
domhringr-peer --state <dir> open                                  # the new tree's anchor
domhringr-peer --state <dir> grant <tree> <peer-id>                # the grant's commit id
domhringr-peer --state <dir> note <tree> <text>                    # the note's commit id
domhringr-peer --state <dir> bind <anchor> anchor <name>           # the bind's commit id
domhringr-peer --state <dir> bind <anchor> endpoint <endpoint-id>  # the bind's commit id
domhringr-peer --state <dir> bind <anchor> datum <text>            # the bind's commit id
domhringr-peer --state <dir> claim <tree> <domain>                 # the claim's commit id
domhringr-peer --state <dir> introduce <tree> <label> <tree>       # the introduction's commit id
domhringr-peer --state <dir> whence <name> [--witness <domain>=<tree-id>]... [--in <tree>] [--peer <peer-id>] [--at <endpoint>] [--local]  # where each tree read was reached, then what the name resolves to
domhringr-peer --state <dir> view <tree>                           # the view, one line per fact
domhringr-peer --state <dir> heads <tree>                          # the heads, one sorted hex line each
domhringr-peer --state <dir> sync <tree> [--peer <peer-id>] [--at <endpoint>]  # where the endpoint came from, the heads after sync, then its path
domhringr-peer --state <dir> dispatch <tree> <peer-id> anchor <anchor> [--at <endpoint>]  # the dispatch's commit id, where the seat was reached, woken
domhringr-peer --state <dir> dispatch <tree> <peer-id> content <hash> [--at <endpoint>]   # the same, for a brief named by content hash
domhringr-peer --state <dir> report <tree> <file> <summary>        # the report's commit id
domhringr-peer --state <dir> handoff <tree> <peer-id>              # the handoff's commit id
domhringr-peer --state <dir> retire <tree>                         # the retirement's commit id
domhringr-peer --state <dir> replay <tree> [--peer <peer-id>] [--at <endpoint>] [--local]  # where the task was reached, one line per step and its standing, then one line per value it names
domhringr-peer --state <dir> evidence <tree> <digest> [--peer <peer-id>] [--at <endpoint>] [--local]  # the value's bytes
domhringr-peer --state <dir> drift --public <checkout> --vault <checkout> <tree>  # one line per finding, nothing when consistent
domhringr-peer --state <dir> judge ask --question <text> --option <text>... --transcript <digest> | --transcript-file <file> [--static <file>]  # the transcript's digest, then the ruling
domhringr-peer --state <dir> judge verdict <tree> --rubric <hash> --transcript <digest> | --transcript-file <file> (--question <text> --option <text>...)... [--static <file>]  # the transcript's digest, one ruling per question, then the verdict's commit id
domhringr-peer --state <dir> playbook validate <file>              # the playbook's hash and name, then one line per step
domhringr-peer --state <dir> playbook run <file> <tree> [--task-state <dir>] [--static <file>]  # one line per verification, then each rubric's rulings, verdict, grades and grading
domhringr-peer --state <dir> rubric validate <file>                # the rubric's hash and name, then one line per question
domhringr-peer --state <dir> rubric grade <file> <tree> [--task-state <dir>] [--static <file>]  # the rubric's rulings, verdict, grades and grading
```

Run the crate's tests, including two-process synchronization, reaching a peer through its presence, a seat dispatched, woken and reporting across restarts of both sides, a reader fetching a seat's report and refused a missing chunk, a judge ruling on a task from a table file, a playbook running its verifiers and grading its questions on a task, every rubric of the [rubric set](../../rubrics/README.md#tests) grading its fixture pair, and a drift check over throwaway git repositories:

```sh
mise exec -- cargo nextest run -p domhringr-surface-peer
```

## Identifiers and state

A tree is named by its anchor; every other id is 64 hex digits, and the binary prints each in the form it reads:

| Name | Form | Meaning |
| ---- | ---- | ------- |
| Tree | `domhringr://<tree-id>/` | Selects a sedimentree; the tree id is the tree key's verifying key in 52 z-base-32 characters. |
| Anchor | `domhringr://<tree-id>/<segment>/…/<segment>` | A path in a tree; each segment is non-empty, holds no `/`, and does not begin with `.`, which is reserved for forms the scheme names. |
| Commit | `domhringr://<tree-id>/.commit/<commit-id>` | A commit in a tree by its whole id; `whence` also reads a prefix of at least 8 hex digits that no other commit of the tree begins with. |
| Name, key form | a tree, an anchor, or a commit | What `whence` resolves, and a bind's target anchor, its tree named by key; a bare tree resolves as no bind binds it. |
| Name, DNS form | `domhringr://<domain>/…` | The tree a witness names for the DNS name and whose root claims it; the name holds a dot and is lowercase letters, digits, and hyphens. |
| Name, label form | `domhringr://<label>/…` | The tree introduced by the label in the `--in` tree; the label holds no dot and no `/` and is not spelled as a tree id. |
| Witness | `<domain>=<tree-id>` | A `--witness` value: a candidate tree for the DNS name, in place of its TXT records. Any `--witness` replaces DNS for the command. |
| Commit id | 64 hex digits | BLAKE3 digest of the encoded receipt blob. |
| Endpoint id | 64 hex digits | Public key of the remote's iroh endpoint. |
| Endpoint | `<endpoint-id>@<address>…` | An endpoint id and the addresses it is reached at, each an IP address and port, an IPv6 address in brackets, or a relay URL: `<endpoint-id>@192.0.2.7:4433@https://relay.example.org/`. What `--at` reads and `book` prints. |
| Peer id | 64 hex digits | Public key of the subduction signer that authenticates handshakes and signs commits. |

Only `whence` and a bind's target anchor read the DNS and label forms, and only `whence` reads an abbreviated commit id; every other tree operand and the anchor to bind name the tree by key, and a DNS name or a label there is a usage error. The state directory's two keys and store are created on first use, and `open` keeps each tree's key beside them. Secret keys are never printed. A running command holds the store exclusively, so every command but `id` fails while `serve` runs on the same directory; `id` runs beside it.

## Output

`view` prints `owner <peer-id>`, then `member <peer-id>` for each peer granted write authority, `note <peer-id> <text>` for each admitted note in canonical order, `bind <path> <target>` for each bound path in path order, `claim <domain>` for each claimed DNS name in name order, `introduce <label> <tree>` for each introduced label in label order, `present <peer-id> <endpoint> <commit-id>` for each peer in the book in peer order, and `refused <commit-id> <reason>` for each refused commit. A target reads `anchor <anchor>`, its anchor a tree, a path, or a commit in any of the three forms, `endpoint <endpoint-id>`, or `datum <text>`. Notes, paths, labels, data, and target anchors escape backslashes and control characters; paths and labels escape spaces as `\u{20}` too. Refusal reasons are `wrong tree`, `undecodable`, `duplicate operation`, `no authority`, `not owner` (a claim by anyone but the owner), `second open`, `bad proof`, `foreign endpoint` (a presence of an endpoint whose key did not sign for its author), and `foreign presence` (a member's withdrawal of another peer's presence).

`open` prints the new tree's anchor; `present` and `withdraw` print their commit's id, a presence's id being the commit `book` prints for it. `book` prints `<peer-id> <endpoint> <commit-id>` for each peer in the book in peer order, the commit the one that presented the endpoint, and nothing for a book that is empty. For a path, `whence` prints the target the path is bound to in the local view of the tree its name resolves to, as `view` writes it, or `unbound`; for a bare DNS-form or label-form name, `anchor <tree>` naming by key the tree it names; and for a commit, `commit <commit-id> admitted`, `commit <commit-id> refused <reason>`, or `unknown` when that tree holds no commit by the id, the id printed whole however it was abbreviated. Before it resolves, `whence` syncs each tree the resolution reads — the key's tree, every tree the DNS name's witness names, or the label's `--in` tree and then the tree it introduces — with the peer aimed at, and prints a source line for each tree reached at another peer; a tree whose peer aimed at is this one is read as held, so an owner's `whence` of its own tree dials no one and prints the resolution alone. With `--local` it reads the local store and syncs nothing. It asks DNS only for a DNS-form name with no `--witness`. A name that does not resolve fails the command with one of `unwitnessed <domain>` (the witness names no tree), `unclaimed <domain>` (no witnessed tree in the store claims it), `ambiguous <domain>` (more than one does), `unscoped <label>` (no `--in`), `unintroduced <label>` (the `--in` tree did not introduce it), `cannot read the witness of <domain>` (the DNS lookup failed), `cannot fold the tree <tree-id>` (a tree the resolution reads is not in the store), or `ambiguous commit <prefix>` (more than one commit of the tree begins with the prefix), each followed by its cause where it has one. `serve` prints its endpoint id, peer id, and `listening`, then `accepted <peer-id>` and the selected path for each admitted peer. `sync` prints its source line, then sorted heads, then its selected path.

The exit status is 0 on success, 1 when the command fails, 2 for a command line that cannot be run, and 3 when `drift` reports a finding. Diagnostics go to standard error.

## Networking

`serve --port` binds iroh's IPv4 and IPv6 UDP sockets at that port so a firewall rule can name it; without it the port is ephemeral. A path line reads `path <peer-id> direct <address>`, `path <peer-id> relay <url>`, or `path <peer-id> pending`.

`present <tree> --port <port>` binds the endpoint at that port, waits up to five seconds for it to reach its home relay, and commits a presence of it at the addresses iroh then names for it: the host's direct addresses at that port, and the relay. The book is the record's: a peer is reached where it last said it is, until it presents again or it or the tree's owner withdraws the presence. `withdraw <tree>` withdraws this peer's own presence and `withdraw <tree> <peer-id>` another's, which only the owner may.

`sync` and `whence` dial the tree's owner, or the peer `--peer` names, at the endpoint `--at` names, or else at that peer's presence in the tree's book, and print where the endpoint came from: `source <tree> at <endpoint>` or `source <tree> book <commit-id>`, the commit that presented it. The dial names the endpoint's addresses and does not wait on iroh's lookups. A peer the book holds no presence of, with no `--at`, fails the command as `unreachable <peer-id>: no presence in the book`; a tree not in the store has no owner to aim at and no book, so it fails as `unheld <tree-id>` unless `--peer` and `--at` name the remote; `sync` aimed at this peer fails as `no one to reach`. First contact names the endpoint by hand, and that sync carries the book.

`serve` reports the path selected when it admits a peer. `sync` reports the path once its round ends, giving iroh up to five seconds to move a relayed connection to a direct path. iroh does not promise that move, even between two peers on one host, so a sync can end relayed.

**`present` runs before `serve`, at the port `serve` binds.** A command holds the store exclusively, so no other command commits while `serve` runs; `present` binds at the fixed port first, commits the addresses that port is reached at, and exits, and `serve --port` binds the same port after it. An ephemeral port is presented too, but no later `serve` binds it, so only the relay in such a presence reaches the peer. `serve` commits on its own only as a seat: its presence in a task whose book lacks it, and its reports.

- `serve` presenting itself as it starts: a commit for every start, whether or not the addresses changed.
- a control channel to a running `serve`: a second interface to the store for one verb.

Reversal: a `serve` that can commit while it serves, as one that holds the store for other writers.

**An endpoint `--at` names overrides the book.** A presence goes stale when its peer moves before presenting again; reading the book first would leave the peer unreachable even with its current endpoint in hand.

- the book first, `--at` only when the book holds no presence: one fewer way to name the remote, at the cost of the stale case.

Reversal: a book that cannot go stale, as when a dial that fails at a presence falls back on its own.

**`whence` syncs the trees it reads before resolving.** A name resolves against the record as the peer aimed at holds it, not as the local store last synced it; `--local` keeps the local, offline resolution.

- resolving from the local store unless asked to sync: a stale binding read as current, with nothing in the output saying where it came from.

Reversal: a resolution that needs no remote, as one served from a published snapshot.

## Tasks

An operator dispatches a seat with `dispatch <tree> <peer-id> <brief>`, the brief an anchor or a content hash. The command routes to the seat first, at `--at` or its presence in the task's book, so a seat no endpoint names gets no dispatch. It then commits the dispatch, prints its commit id, wakes the seat, and prints `source <tree> at <endpoint>` or `source <tree> book <commit-id>` and `woken`. A seat that declines fails the command as `the seat declined the wake: <reason>`, and a seat that cannot be reached fails it after the dispatch's id is printed: the dispatch stays committed, to be sent again. A woken operator holds the seat's presence, so the next dispatch, a `replay` or a `sync` reaches the seat through the book.

`serve --surface <program>` serves as a seat. It prints `accepted` and `path` lines for each link, `woken <tree> <dispatch-id>` for a wake it answers, `declined <reason>` for one it declines, `reported <tree> <commit-id>` for a report it commits, `unreported <tree> <dispatch-id>` for an act that committed none, `served <digest>` for a fetch it answers with the value it holds, and `unserved <digest>` for one whose manifest it does not hold, each failure's cause on standard error. Without `--surface` the seat holds the slots it is dispatched to and never reports. `report <tree> <file> <summary>` keeps the file's bytes as evidence and commits a report naming them by digest; it, `handoff <tree> <peer-id>` and `retire <tree>` commit their receipt on the task's current dispatch, and fail as `the task has no dispatch: nothing to report on, hand off, retire from or rule on` when there is none; the fold admits them from the slot's holder alone.

`replay <tree>` reaches the current attempt's seat, the owner when nothing is dispatched, or the peer `--peer` names, syncs the task as `sync` does, and prints the source line and the task. The task is one line per admitted seat receipt in canonical order: `dispatch <commit-id> <peer-id> <brief>`, `report <commit-id> <dispatch-id> <peer-id> <digest> <summary>`, `handoff <commit-id> <dispatch-id> <from> <to>` and `retire <commit-id> <dispatch-id> <peer-id>`; a verdict is `verdict <commit-id> <dispatch-id> <judge> <rubric> <transcript-digest>` and one `ruling <commit-id> <question> <ruling>` line per question; a verification is `verified <commit-id> <dispatch-id> <runner> <playbook> <step> <output-digest> <status>`; a grading is `graded <commit-id> <dispatch-id> <verdict-id> <rubric> <composed>` and one `grade <commit-id> <question> <grade>` line per question; an operator's decision is `decide <commit-id> <dispatch-id> <operator> <decision>`, the decision `land`, `rework <reason>` or `abandon`, and a landing `landed <commit-id> <dispatch-id> <decision-id> <operator> <revision>`. Then one line says where the task stands: `undispatched`; for an attempt checked past its report, its furthest step — `landed <dispatch-id> <landing-id> <revision>`, `decided <dispatch-id> <decision-id> <decision>`, `graded <dispatch-id> <grading-id> <composed>` or `verified <dispatch-id> <verification-id>`; otherwise `dispatched <dispatch-id> <holder>`, `reported <dispatch-id> <report-id>` or `stalled <dispatch-id> <retirement-id>`. Last comes one line per value the task names, as [Evidence](#evidence) states. `--local` prints the local store's task and its evidence and dials no one.

**A dispatch to the seat already holding the current attempt's slot, for the same brief, is sent again, not committed again.** The command prints the same commit id and wakes the seat once more. An operator whose wake failed, or that was killed while it dialed, repeats the command and reaches the same dispatch, and a seat that already reported answers `woken` without acting again.

- a dispatch per invocation: a second dispatch supersedes the first, and a report the seat is writing to the first is then refused as not current.
- a separate `wake` verb for an existing dispatch: a second command for what repeating the first already says.

Reversal: a task that dispatches one seat to one brief twice on purpose, which needs the new commit asked for.

**The seat acts through a program and reports its standard output.** The design and its alternatives are the seat's, in [`domhringr-seat-slot`](../seat-slot/README.md#the-command-surface); the binary adds only the `--surface` option and the event lines.

## Evidence

A report's content, a verdict's transcript and a verification's output are evidence: values in the state directory's evidence store, named in their receipt by manifest digest, as [`domhringr-record-evidence`](../record-evidence/README.md) holds and fetches them. `report`, a seat's act, `judge verdict`, `playbook run` and `rubric grade` keep what they record before committing the receipt that names it, so a name this peer commits resolves in its own store.

**`replay` ends with one line per value the task names, held or not.** After the task it prints `evidence <digest> held` or `evidence <digest> unheld`, once per digest in the order the task first names it, the cause of an unheld value on standard error. A replay that reached a peer first fetches from it each value the local store lacks, every chunk checked before the value is kept; `--local` and a route to this peer read the local store alone. An unheld value is a line, and the command still succeeds: the record replayed is whole, and what this peer can read of its evidence is a fact about its store.

- failing the replay on an unheld value: the record could not be read while the peer that keeps one value is away.
- fetching each value from the peer that holds it, its receipt's author: a dial per author, where a replay reaches one peer.

Reversal: a replay that must prove every value whole, as an audit does, which needs an exit status for an unheld one.

**`evidence <tree> <digest>` writes a value's bytes and nothing else.** A value the local store holds whole is read from it; otherwise the command reaches the peer `--peer` names, or else the author of the first admitted receipt of the local task naming the digest, at `--at` or through the task's book, and fetches the value, keeping it before it writes a byte. A refusal writes nothing to standard output, names its cause — `evidence <digest> is refused: no chunk is stored under <chunk-digest>` for a chunk neither side holds — and exits 1; `--local` reads the local store alone.

- a header line before the bytes: the output would no longer be the value, and a reader comparing it would strip it first.

Reversal: a value too large to hold in memory, which needs the read streamed to standard output as the walk checks each chunk.

## Judging

`judge ask` asks one question about a transcript and prints `transcript <digest>` and `ruling <question-hash> <ruling>`. A question is a `--question <text>` and the `--option <text>`s after it, two to twenty-six, lettered `A`, `B`, … in the order given, and named by the hash [`domhringr-judge-oracle`](../judge-oracle/README.md#questions-and-transcripts) defines. The transcript is the content of `--transcript-file`, or the content `--transcript` names by its digest, read whole from the local evidence store. `judge verdict <tree> --rubric <hash>` first names the task's current dispatch, then asks each question in the order given, prints the same lines, keeps the transcript as evidence, commits this peer's verdict on that dispatch, and prints the verdict's commit id. A ruling reads `read <letter> A=<p> B=<p> … outside=<p>`, the answer letter, each option's probability and the mass outside the options, or `unread <reason>`: `no letter`, `outside`, `tied`, `endpoint` or `malformed`.

Without `--static` the judge asks the endpoint the environment configures ([configuration](../judge-oracle/README.md#configuration)). With `--static <file>` it answers from a table instead, one `<question-hash> <transcript-digest> <ruling>` line per ruling, a later line for the same pair winning; a question the table does not hold is unread as `malformed`. An endpoint is asked the transcript's text, and a transcript it cannot read is unread as `malformed`.

**A refused question is a ruling, and the command succeeds.** An unread ruling is printed and committed as a read one is, with its cause on standard error. The command fails, committing nothing, only when it cannot ask at all: no endpoint configured, a table file that cannot be read, a transcript file that cannot be read, a transcript `--transcript` names that the evidence store does not hold whole, or a task with no dispatch.

- failing the command on any refusal: a verdict with one unread question would not be committed, the rulings that were read would be lost, and a refusal would read as an error rather than an outcome.

Reversal: a gate that must tell an unread ruling from the exit status. It reads the `unread` lines today.

**`judge verdict` takes its questions on the command line, and the rubric by its hash.** The verdict records the rubric's hash and each question's; `judge verdict` reads no rubric document, so it asks questions no document holds. `rubric grade` and `playbook run` read the document and ask its questions ([Playbooks and rubrics](#playbooks-and-rubrics)).

- `judge verdict` reading the rubric document alone: no way to ask a question before a rubric holds it.
- questions named by their hashes alone: a model is asked a question's text.

Reversal: every question asked belonging to a rubric document, when `judge verdict` reduces to `rubric grade`.

## Playbooks and rubrics

A playbook and a rubric are TOML documents whose shapes [`domhringr-strategy-document`](../strategy-document/README.md#playbooks) states. `playbook validate <file>` reads a playbook and each rubric its steps name, from the playbook's directory, and prints `playbook <hash> <name>` and one line per step: `step <id> verifier`, or `step <id> question <rubric-hash> <question> <question-hash>`. `rubric validate <file>` prints `rubric <hash> <name>` and `question <name> <question-hash>` per question in the names' order: the hashes a `--static` table names questions by. A document is named by the BLAKE3 hash of its file's bytes. One that does not read fails the command, naming the file, the field and why: `<file>: steps[0].why: missing field`.

`playbook run <file> <tree>` reads the documents, names the task's current dispatch, and prints the `playbook` line. It runs each verifier step in order in the task's state directory, `--task-state` or the working directory, keeps its output as evidence, commits a verification, this peer the runner, and prints `verified <commit-id> <step> <output-digest> <status>`, the status `exit <code>` or `signal <number>`. Then, for each rubric its steps name, it prints the `rubric` line, reads the rubric's state files into the transcript and prints `transcript <digest>`, asks the questions its steps name as `judge verdict` asks them, printing each `ruling` line, keeps the transcript as evidence, commits the verdict, this peer the judge, and prints `verdict <commit-id>`. It grades each ruling against the rubric's band, printing `grade <question-hash> <grade>`, composes the grades, commits the grading of the verdict, and prints `graded <commit-id> <composed>`. `rubric grade <file> <tree>` does the same for every question of one rubric. Both answer from `--static <file>` or the configured endpoint, as `judge` does.

**A run names the dispatch before it runs anything.** A task with no dispatch fails the command as `the task has no dispatch: nothing to report on, hand off, retire from or rule on`, before a verifier runs or a question is asked: a check run against no attempt has nothing to be committed on.

**A failing verifier and a grade short of met are outcomes, and the command succeeds.** Each is printed and committed like a passing one, with its cause, for an unread ruling, on standard error. The command fails only when it cannot check at all: a document that does not read, a verifier that cannot be started or waited on, a state file that cannot be read, or a judge it cannot ask. Verifications committed before such a failure stay committed.

- failing the command on a failing verifier or an unmet grade: a playbook stopped at its first failure records nothing of the checks after it, and an outcome reads as an error.

Reversal: a gate that must read the outcome from the exit status. It reads the `verified` and `graded` lines today.

**Verifiers run first, in step order, then each rubric is graded once.** A verifier may write the state a rubric reads, and the questions of one rubric are asked of one transcript and recorded as one verdict, so a grading composes all the grades its rubric's steps ask for.

- every step in its own order, a verdict per question step: a transcript read once per question, and a grading of one grade that composes nothing.

Reversal: a playbook whose question must read the state before a later verifier changes it, which needs the run to follow the steps' order and a verdict per stretch of questions.

## Drift

`drift` checks one concepts tree, named by its key, against two git checkouts. The tree binds each concept, a path in it, to the vault page its public derivative was written or last confirmed against; the public checkout cites each concept by its anchor; the vault holds the pages.

A binding's target is a datum `vault:<path>@<commit>`. `<path>` is the page's path from the vault repository's top: one or more `/`-separated segments, none empty, `.` or `..`, holding no control character. `<commit>` is the vault commit the page was confirmed at, 40 lowercase hex digits. The path ends at the datum's last `@`, so a path may hold one. Any other target is malformed.

A citation is an occurrence of the tree's anchor, `domhringr://<tree-id>/`, in a tracked text file of the public checkout, and runs to the first whitespace, control character, or one of `` ` `` `"` `'` `<` `>` `(` `)` `[` `]` `{` `}` `|` `\`, less any `.` `,` `:` `;` `!` `?` that ends it, so a citation stands in backticks, angle brackets, a Markdown link, or at the end of a sentence. A citation naming a path cites that concept; one naming the bare tree or a commit in it cites no concept and is not reported; one that is no anchor is malformed. Binary files are skipped, and files are named from the repository's top.

The report holds one line per finding, `<state> <anchor> <file>:<line>` for a citation and `<state> <anchor> <vault path>@<commit>` for a binding, a binding whose target is no page datum naming the target as `view` writes it:

| State | Finding |
| ----- | ------- |
| `unbound` | A cited concept no binding names, once per line citing it. |
| `drifted` | A binding whose page is at the vault's `HEAD` with a blob other than its blob at the bound commit, or that commit holds no such page. A rebind at the current revision clears it. |
| `missing` | A binding whose page is not at the vault's `HEAD`: renamed, deleted, or not a file. |
| `orphaned` | A binding whose concept nothing in the public checkout cites. |
| `malformed` | A binding whose target is no page datum, or a citation that reads as no anchor. |

A binding can be both orphaned and drifted, missing or malformed, and then has a line for each. Lines are in anchor order, then in the state order of the table, then by place: a citing file by name and its lines by number, before a page, before a target. Anchors escape backslashes, control characters, and spaces as paths do in `view`; file and page paths escape backslashes and control characters. A consistent pair prints nothing and exits 0; any finding exits 3, with nothing written to standard error. A checkout git cannot read fails the command with exit status 1.

Each checkout is read as the repository at its path whatever repository the environment names: `drift` clears the variables git itself clears before running a command in another repository, such as `GIT_DIR` and `GIT_INDEX_FILE`, so it reads the right repositories inside another repository's hook.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
