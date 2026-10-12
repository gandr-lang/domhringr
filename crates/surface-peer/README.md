# domhringr-surface-peer

The `domhringr-peer` binary manages and synchronizes a record-plane peer over a state directory, dispatches seats to tasks and serves as one, fetches the evidence a task names, judges a task's transcript into a verdict, runs playbooks and grades rubrics on a task, and checks a concepts tree against the checkouts that cite it and hold its pages.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** `domhringr-surface-peer` provides the `domhringr-peer` command-line binary. It opens sedimentrees, delegates write authority, writes notes, binds paths, claims DNS names for a tree, introduces other trees by label, presents the peer's endpoint in a tree and withdraws presences, resolves anchors and commits by key, by DNS name, or by label, reads views, books, and heads, synchronizes a tree with another peer reached through the tree's book or at an endpoint named by hand, dispatches a seat to a task and wakes it, reports, hands off and retires as a seat, replays a task with the evidence it names, fetches a value by its digest, serves as a seat acting through a program, asks a judge lettered questions about a transcript and commits its rulings as a verdict on the task, reads playbooks and rubrics, runs a playbook's verifiers and grades a rubric's questions on the task, and reports where a concepts tree has drifted from a public checkout and a vault.

**Why.** A peer needs a persistent identity and a command-line surface for operating its trees and inspecting their interpretation. Separate state directories let peers retain independent keys and stores while exchanging the same signed commits. Public text that cites private pages by anchor stays in step with them only if something checks each citation against its binding and each binding against its page.

**How.** Commands use `domhringr-record-tree` for identity, storage, receipt construction, folding, routing, resolution, and synchronization, and `domhringr-record-evidence` for the evidence a receipt names: `report`, a seat's act, `judge verdict`, `playbook run` and `rubric grade` keep what they record in the evidence store beside the tree store, `replay` and `evidence` fetch what it lacks over the evidence protocol, and `serve` answers those fetches. `whence` asks DNS for a DNS name's `_domhringr.<domain>` TXT records unless `--witness` names the candidate trees, reads a label in the `--in` tree, and syncs each tree it reads from the peer aimed at before resolving. `serve` accepts connections over iroh; `sync` dials one remote, at its presence in the tree's book or at an endpoint named by hand, exchanges one tree in a batch round, and disconnects. `judge` asks through `domhringr-judge-oracle`, of the endpoint the environment configures or from a table file. `playbook` and `rubric` read their documents, run verifiers and grade rulings through `domhringr-strategy-document`, and ask as `judge` asks. `drift` folds the concepts tree from the local store and reads both checkouts with the `git` binary: `git grep` for the tree's anchor over the public checkout's tracked files, and one `git cat-file --batch-check` for every bound page's blob at the vault's `HEAD` and at its bound commit.

## Provided features

- Identity inspection and persistent state creation.
- Tree opening under a freshly minted tree key, printing the tree's anchor.
- `Grant`, `Note`, `Bind`, `Claim`, `Introduce`, `Present`, `Withdraw`, `Dispatch`, `Report`, `Handoff`, `Retire`, `Verdict`, `Verified` and `Graded` receipt submission; `present` commits the endpoint at the addresses it binds, the seat verbs answer the task's current dispatch, and a verdict, a verification and a grading rule on it.
- Resolution of a tree, a path, or a commit in the key, DNS, and label forms, a commit by its whole id or a unique prefix of it, with DNS witnesses or witnesses supplied by hand; canonical views; and sorted tree heads.
- Serving on an ephemeral or fixed UDP port, as a seat that holds its slots or acts through a program.
- Dispatching a seat and waking it at its presence in the task's book or at an endpoint named by hand, and replaying a task through its seat, each value its receipts name fetched from the seat when the local store lacks it.
- A value of the evidence plane by its digest, read from the local store or fetched from the peer that holds it, written byte for byte or refused by name.
- Attested project and dialogue indexes, root-verified task and move questions, historical agreement checks and exact proof-size measurements.
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
- For `judge` without `--static`, an OpenAI-compatible endpoint reporting log-probabilities, configured as [`domhringr-judge-oracle`](../judge-oracle/src/chat.rs) reads it from the environment; for `judge verdict`, the task in the local store with a dispatch.
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

`open` prints the new tree's anchor, `domhringr://<tree-id>/`; appending a path to it names that path in the tree, and appending `.commit/<commit-id>` a commit in it. The first `whence` prints the anchor of the note's commit that `greeting` is bound to, and the second resolves that commit by the first 12 digits of its id to `commit <commit-id> admitted`. The two `whence` lines after the claim resolve the same path by the DNS name the tree claimed, witnessed by hand, and the second tree by the label the first introduced it by; every tree they read is this peer's own, so none dials. `present` commits the endpoint at port 4433 as this peer's presence in the tree, which `book` prints and at which a peer that syncs the tree reaches it once `serve --port 4433` runs. The commands print endpoint, signing-peer, and commit ids in hex; the forms are defined in [`main.rs`](src/main.rs) § Identifiers and state.

Run the crate's tests, including two-process synchronization, reaching a peer through its presence, a seat dispatched, woken and reporting across restarts of both sides, a reader fetching a seat's report and refused a missing chunk, a judge ruling on a task from a table file, a playbook running its verifiers and grading its questions on a task, every rubric of the [rubric set](../../rubrics/README.md#tests) grading its fixture pair, and a drift check over throwaway git repositories:

```sh
mise exec -- cargo nextest run -p domhringr-surface-peer
```

## Where the detail lives

Mechanism, decisions with their alternatives and reversals, and witnesses live in the rustdoc beside the code:

| Topic | Module |
| ----- | ------ |
| Every invocation and what it prints; identifiers and state, output, networking, tasks, evidence, judging, references | [`main`](src/main.rs) |
| Keyed indexes | [`index`](src/index.rs) |
| Playbooks and rubrics | [`strategy`](src/strategy.rs) |
| Drift | [`drift`](src/drift.rs) |

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
