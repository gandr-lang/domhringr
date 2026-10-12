# domhringr

The `domhringr` binary is the operator's: it lists a project's seats and tasks, dispatches a seat to a task, reads the report the seat keeps as evidence, verifies and decides the change the report names, and lands it in a git repository, all from the record.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** `domhringr` runs the task loop for one operator: `open` lists the project, `dispatch` puts a seat to work on a task, `verify` runs a playbook's verifiers on the change the seat reports, `decide` grades it by rubrics and decides to land or rework it, and `land` merges it. Every step is a receipt in the task's tree. Acting commands read the fold; `open` reads its derived index. The report, each verifier's output and each transcript are evidence, read from and kept in the operator's evidence store.

**Why.** The loop — dispatch, report, verify, judge, decide, land — has to run from the record alone, with no server holding its state: any synced member can pick it up where the journal says it stands, and each choice is the receipt of the key that made it.

**How.** The driver composes the libraries: `domhringr-record-tree` for the store, the fold and sync, `domhringr-record-evidence` for the evidence store and the fetch, `domhringr-seat-slot` for the wake, `domhringr-strategy-document` for playbooks, rubrics and verifiers, and `domhringr-judge-oracle` for the judge. It runs `git` as a program for checkouts, diffs and merges. It binds an endpoint only to wake a seat, to sync a task from one or to fetch a report from one, and closes it before it returns.

## Provided features

- `open`: the project's seats with their presences, and its tasks with where each stands, synced from each seat a report is awaited from.
- `dispatch`: a task minted and bound in the project on first use, a seat dispatched to it and woken, a current dispatch re-sent rather than repeated.
- `verify`, `decide`, `land`: the report read whole from the evidence store, fetched from the seat that reported it when the store lacks it, and named as `report <digest>`.
- `verify`: the reported commit checked out into a temporary worktree, each verifier run there and its output kept as evidence, a `Verified` receipt per step.
- `decide`: the change written as rubric state, each rubric graded into a `Verdict`, its transcript kept as evidence, and a `Graded` receipt, the grades composed with the latest verifications, and a `Decide` receipt to land or rework.
- `land`: the change merged into the branch the repository has checked out, fast forward or by a merge commit, and a `Landed` receipt naming the revision; a refused merge leaves the repository as it was.

## Expected features

- A writable state directory: `DOMHRINGR_STATE`, else `domhringr` under `XDG_STATE_HOME`, else `$HOME/.local/state/domhringr`. It holds the operator's keys, store and evidence store, created on first use; a command holds the store exclusively while it runs.
- A project the store holds: a tree whose owner is this peer or granted it, named by `--project` or `DOMHRINGR_PROJECT` as its bare anchor, `domhringr://<tree-id>/`, with each seat present in its book.
- Seats serving with a surface, as [`domhringr-seat-slot`](../seat-slot/README.md#expected-features) expects, reachable at their presence and answering fetches of the reports they keep until the operator holds each; network access for iroh.
- The `git` binary on `PATH`, and a repository at `--repo` holding the reported commit, its working tree clean for `land`.
- For `decide` without `--static`, a judge endpoint configured as [`domhringr-judge-oracle`](../judge-oracle/src/chat.rs) reads it.
- For `verify`, each verifier's command on `PATH`; it runs in a fresh checkout of the change, with nothing untracked beside it.

## Examples

The operator's run of one task on this repository, from its root, with the project in `DOMHRINGR_PROJECT` and a seat present in it:

1. `domhringr open`
2. `domhringr dispatch <task> --seat <peer-id> --brief <anchor|content-hash>`
3. `domhringr verify <task> --playbook examples/playbook.toml --repo .`
4. `domhringr decide <task> --rubric rubrics/code.toml --rubric rubrics/stable-refs.toml --repo .`
5. `domhringr land <task> --repo .`

`open` between the steps shows the task reported, verified, graded, decided and landed. The process tests run the same loop on a throwaway repository, two seats serving in-process through a script that commits and reports a change:

```sh
mise exec -- cargo nextest run -p domhringr
```

## Where the detail lives

Mechanism, decisions with their alternatives and reversals, and witnesses live in the rustdoc beside the code:

| Topic | Module |
| ----- | ------ |
| Commands, decisions with their alternatives and reversals, what is not yet built, references | [`main`](src/main.rs) |
| The lifecycle | [`project`](src/project.rs) |
| The change | [`change`](src/change.rs) |

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
