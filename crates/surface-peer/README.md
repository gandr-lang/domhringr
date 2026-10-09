# domhringr-surface-peer

The `domhringr-peer` binary manages and synchronizes a record-plane peer over a state directory, and checks a concepts tree against the checkouts that cite it and hold its pages.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Identifiers and state](#identifiers-and-state)
- [Output](#output)
- [Networking](#networking)
- [Drift](#drift)
- [License](#license)

## Synopsis

**What.** `domhringr-surface-peer` provides the `domhringr-peer` command-line binary. It opens sedimentrees, delegates write authority, writes notes, binds paths, claims DNS names for a tree, introduces other trees by label, presents the peer's endpoint in a tree and withdraws presences, resolves anchors and commits by key, by DNS name, or by label, reads views, books, and heads, synchronizes a tree with another peer reached through the tree's book or at an endpoint named by hand, and reports where a concepts tree has drifted from a public checkout and a vault.

**Why.** A peer needs a persistent identity and a command-line surface for operating its trees and inspecting their interpretation. Separate state directories let peers retain independent keys and stores while exchanging the same signed commits. Public text that cites private pages by anchor stays in step with them only if something checks each citation against its binding and each binding against its page.

**How.** Commands use `domhringr-record-tree` for identity, storage, receipt construction, folding, routing, resolution, and synchronization. `whence` asks DNS for a DNS name's `_domhringr.<domain>` TXT records unless `--witness` names the candidate trees, reads a label in the `--in` tree, and syncs each tree it reads from the peer aimed at before resolving. `serve` accepts connections over iroh; `sync` dials one remote, at its presence in the tree's book or at an endpoint named by hand, exchanges one tree in a batch round, and disconnects. `drift` folds the concepts tree from the local store and reads both checkouts with the `git` binary: `git grep` for the tree's anchor over the public checkout's tracked files, and one `git cat-file --batch-check` for every bound page's blob at the vault's `HEAD` and at its bound commit.

## References

- `domhringr-record-tree`, [crate documentation](../record-tree/README.md): the persistent peer, receipt fold, and synchronization operation.
- `iroh`, [crate documentation](https://docs.rs/iroh): endpoint discovery and direct or relayed network paths.
- `lexopt`, [crate documentation](https://docs.rs/lexopt): command-line options and operands.

## Provided features

- Identity inspection and persistent state creation.
- Tree opening under a freshly minted tree key, printing the tree's anchor.
- `Grant`, `Note`, `Bind`, `Claim`, `Introduce`, `Present`, and `Withdraw` receipt submission; `present` commits the endpoint at the addresses it binds.
- Resolution of a tree, a path, or a commit in the key, DNS, and label forms, a commit by its whole id or a unique prefix of it, with DNS witnesses or witnesses supplied by hand; canonical views; and sorted tree heads.
- Serving on an ephemeral or fixed UDP port.
- A tree's book: each present peer, the endpoint it is reached at, and the commit that presented it.
- Single-tree synchronization with the tree's owner or a named peer, at its presence in the book or at an endpoint named by hand, reporting where the endpoint came from and the selected path; `whence` reaches each tree it reads the same way, or resolves from the local store alone.
- A drift check of a concepts tree against a public and a vault checkout: unbound citations, drifted, missing and orphaned bindings, and malformed data and citations, one line each in anchor order, with an exit status a gate can read.

## Expected features

- A writable state directory; commands using its store require exclusive access.
- A native target with an operating-system random source for identities and receipts.
- For synchronization and for `whence` without `--local`, a serving remote: the tree's owner, or a peer named by `--peer`, present in the tree's book; at first contact, or when the book holds no presence of it, its endpoint named by `--at`, with its loopback or direct address on one host.
- Network access for iroh discovery and transport; a fixed port must be available for binding.
- For a DNS-form anchor, DNS resolvers reaching the name's `_domhringr.<domain>` TXT records, unless `--witness` names its trees; and in the local store, the witnessed tree whose root claims the name.
- For a label-form anchor, the tree that introduced the label, named by `--in` and held in the local store.
- For `drift`, the `git` binary on `PATH`, both checkouts local, each a directory in a git working tree, and the concepts tree in the local store; a `sync` brings it there, since `drift` dials no one.

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
domhringr-peer --state <dir> serve [--port <port>]                 # ids, listening, accepted peers and paths
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
domhringr-peer --state <dir> drift --public <checkout> --vault <checkout> <tree>  # one line per finding, nothing when consistent
```

Run the crate's tests, including two-process synchronization, reaching a peer through its presence, and a drift check over throwaway git repositories:

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

**`present` runs before `serve`, at the port `serve` binds.** A command holds the store exclusively, so a running `serve` cannot commit; `present` binds at the fixed port first, commits the addresses that port is reached at, and exits, and `serve --port` binds the same port after it. An ephemeral port is presented too, but no later `serve` binds it, so only the relay in such a presence reaches the peer.

- `serve` presenting itself as it starts: a commit for every start, whether or not the addresses changed.
- a control channel to a running `serve`: a second interface to the store for one verb.

Reversal: a `serve` that can commit while it serves, as one that holds the store for other writers.

**An endpoint `--at` names overrides the book.** A presence goes stale when its peer moves before presenting again; reading the book first would leave the peer unreachable even with its current endpoint in hand.

- the book first, `--at` only when the book holds no presence: one fewer way to name the remote, at the cost of the stale case.

Reversal: a book that cannot go stale, as when a dial that fails at a presence falls back on its own.

**`whence` syncs the trees it reads before resolving.** A name resolves against the record as the peer aimed at holds it, not as the local store last synced it; `--local` keeps the local, offline resolution.

- resolving from the local store unless asked to sync: a stale binding read as current, with nothing in the output saying where it came from.

Reversal: a resolution that needs no remote, as one served from a published snapshot.

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
