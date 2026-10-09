# domhringr

The `domhringr` binary is the operator's: it lists a project's seats and tasks, dispatches a seat to a task, verifies and decides the change the seat reports, and lands it in a git repository, all from the record.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Commands](#commands)
- [The lifecycle](#the-lifecycle)
- [The change](#the-change)
- [Decisions](#decisions)
- [Not yet](#not-yet)
- [License](#license)

## Synopsis

**What.** `domhringr` runs the task loop for one operator: `open` lists the project, `dispatch` puts a seat to work on a task, `verify` runs a playbook's verifiers on the change the seat reports, `decide` grades it by rubrics and decides to land or rework it, and `land` merges it. Every step is a receipt in the task's tree, and every command reads the task as the fold derives it.

**Why.** The loop — dispatch, report, verify, judge, decide, land — has to run from the record alone, with no server holding its state: any synced member can pick it up where the journal says it stands, and each choice is the receipt of the key that made it.

**How.** The driver composes the libraries: `domhringr-record-tree` for the store, the fold and sync, `domhringr-seat-slot` for the wake, `domhringr-strategy-document` for playbooks, rubrics and verifiers, and `domhringr-judge-oracle` for the judge. It runs `git` as a program for checkouts, diffs and merges. It binds an endpoint only to wake a seat or to sync a task from one, and closes it before it returns.

## References

- `domhringr-record-tree`, [crate documentation](../record-tree/README.md): the store, the task view and its lifecycle, the `Decide` and `Landed` receipts.
- `domhringr-seat-slot`, [crate documentation](../seat-slot/README.md): the wake and the seat that reports.
- `domhringr-strategy-document`, [crate documentation](../strategy-document/README.md): playbooks, rubrics, verifiers, grades and their composition.
- `domhringr-judge-oracle`, [crate documentation](../judge-oracle/README.md): the judge's backends and their configuration.
- The [rubric set](../../rubrics/README.md): the rubrics `decide` grades a change of this repository by.
- `git`, [`git-worktree`](https://git-scm.com/docs/git-worktree), [`git-diff`](https://git-scm.com/docs/git-diff) and [`git-merge`](https://git-scm.com/docs/git-merge) documentation: the checkout, the state and the landing.
- `lexopt`, [crate documentation](https://docs.rs/lexopt): command-line options and operands.
- `tempfile`, [crate documentation](https://docs.rs/tempfile): the checkout's and the state's temporary directories.

## Provided features

- `open`: the project's seats with their presences, and its tasks with where each stands, synced from each seat a report is awaited from.
- `dispatch`: a task minted and bound in the project on first use, a seat dispatched to it and woken, a current dispatch re-sent rather than repeated.
- `verify`: the reported commit checked out into a temporary worktree, each verifier run there, a `Verified` receipt per step.
- `decide`: the change written as rubric state, each rubric graded into a `Verdict` and a `Graded` receipt, the grades composed with the latest verifications, and a `Decide` receipt to land or rework.
- `land`: the change merged into the branch the repository has checked out, fast forward or by a merge commit, and a `Landed` receipt naming the revision; a refused merge leaves the repository as it was.

## Expected features

- A writable state directory: `DOMHRINGR_STATE`, else `domhringr` under `XDG_STATE_HOME`, else `$HOME/.local/state/domhringr`. It holds the operator's keys and store, created on first use; a command holds the store exclusively while it runs.
- A project the store holds: a tree whose owner is this peer or granted it, named by `--project` or `DOMHRINGR_PROJECT` as its bare anchor, `domhringr://<tree-id>/`, with each seat present in its book.
- Seats serving with a surface, as [`domhringr-seat-slot`](../seat-slot/README.md#expected-features) expects, reachable at their presence; network access for iroh.
- The `git` binary on `PATH`, and a repository at `--repo` holding the reported commit, its working tree clean for `land`.
- For `decide` without `--static`, a judge endpoint configured as [`domhringr-judge-oracle`](../judge-oracle/README.md#configuration) reads it.
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

## Commands

```text
domhringr open [--project <tree>]
domhringr dispatch <task> --seat <peer-id> --brief <anchor|content-hash> [--at <endpoint>] [--project <tree>]
domhringr verify <task> --playbook <file> [--repo <dir>] [--project <tree>]
domhringr decide <task> --rubric <file>... [--repo <dir>] [--static <file>] [--project <tree>]
domhringr land <task> --repo <dir> [--project <tree>]
```

A `<task>` is its name in the project — ASCII letters, digits, `-`, `_` and `.`, not beginning with `.` — or the anchor of its path there, `domhringr://<project-id>/tasks/<name>`. `--repo` defaults to the working directory for `verify` and `decide`.

| Command | Prints | Commits |
| ------- | ------ | ------- |
| `open` | `project <anchor>`; `seat <peer-id> <endpoint> <commit-id>` per presence but the operator's; `task <anchor> <standing>` per task, or `unheld` for a task tree the store lacks | nothing |
| `dispatch` | `dispatch <commit-anchor>`, then `woken` | `Open` and `Bind` for a new task, then `Dispatch` |
| `verify` | `change <branch> <commit>`, `playbook <hash> <name>`, `verified <commit-id> <step> <output-hash> <status>` per verifier | `Verified` per verifier |
| `decide` | `change`; `step <id> <status>` per verified step; per rubric `rubric`, `transcript`, `ruling`, `verdict`, `grade` and `graded` lines; `composed <grade>`; `decide <commit-id> <decision>` | `Verdict` and `Graded` per rubric, then `Decide` unless undecided |
| `land` | `change <branch> <commit>`, `landed <commit-id> <revision>` | `Landed` |

The exit status is 0 on success, 1 when a command fails, 2 for a command line that cannot be run, and 3 when `decide` decides nothing. Diagnostics go to standard error.

## The lifecycle

A task's tree folds to its current attempt — the latest dispatch — and how far the attempt has gone. The standing is the last line of the peer's `replay` and the end of each `task` line `open` prints.

| Standing | Reached by | Command |
| -------- | ---------- | ------- |
| `undispatched` | the task's `Open` | `dispatch`, minting the task |
| `dispatched <dispatch> <holder>` | `Dispatch` | `dispatch` |
| `reported <dispatch> <report>` | the holder's `Report` | the seat |
| `stalled <dispatch> <retirement>` | the holder's `Retire`, with no report | the seat |
| `verified <dispatch> <verification>` | `Verified` | `verify` |
| `graded <dispatch> <grading> <composed>` | `Graded` | `decide` |
| `decided <dispatch> <decision-commit> <decision>` | `Decide` | `decide` |
| `landed <dispatch> <landing> <revision>` | `Landed` | `land` |

Past the report, the attempt only advances: a verification after a grading leaves it graded. A rework is a decision; the next attempt is a new dispatch, back to `dispatched`.

## The change

A seat reports its change as its summary, the first line of its report: `<branch> <commit>[ <text>]`. The branch is one or more ASCII letters, digits, `-`, `_`, `.` and `/`, not beginning with `-`; the commit is 40 or 64 lowercase hex digits, git's object id in a SHA-1 or SHA-256 repository; the text after a third space is the seat's own. `verify`, `decide` and `land` act on the commit, which the repository at `--repo` must hold — the seat pushes the branch there, or the operator fetches it — and the branch names the merge commit, `Merge branch '<branch>'`. A report that names no change is refused by every command that reads it.

## Decisions

**A task is a tree of its own, bound in the project.** `dispatch` mints a tree for a new task, opens it as this peer, and binds `tasks/<name>` in the project to its anchor; `open` reads the project's bindings under `tasks/` to find the tasks, and each task's own fold for its standing. A task is the tree its seat receipts live in, as the record already shapes it, and the project is the one place that names them.

- one tree for the project and every task: one slot per tree, so one task at a time.
- tasks named by their tree anchors alone, kept by the operator: a second operator syncing the project would not find them.

Reversal: tasks that move between projects, which needs a binding per project and a task tree that names none.

**A seat is reached through the task's book, then the project's.** The first dispatch to a new task finds no presence in it, so the seat is reached at its presence in the project; once woken, the seat presents itself in the task, and later syncs reach it there.

- the project's book alone: a seat that moved would be reached where it was when it joined the project.
- `--at` on every command: the endpoint the record already holds, typed again.

Reversal: seats with no presence in any project, reached through a discovery service, which needs a route that reads it.

**git is run as a program.** Checkouts, diffs, logs and merges go through the `git` on `PATH`, with the variables that name another repository cleared, as `domhringr-peer`'s drift check does. The repository's own configuration applies — hooks, signing, merge drivers — as it does to the operator by hand.

- `gix`: its documented status leaves merge orchestration, checkout and worktree removal unimplemented, and it signs no commits; the landing needs all four.
- `git2`: it builds libgit2 from C, and it neither runs hooks nor signs merges as the repository configures.

Reversal: `gix` gaining merge, checkout and signing, or a target without a `git` binary.

**`verify` runs in a temporary worktree of the reported commit.** `git worktree add --detach` checks the commit out beside the repository, the verifiers run there, and the worktree is removed whatever they did; the repository's own working tree is never touched.

- the repository's working tree, switched to the commit: the operator's checkout would move under them, and a failure would leave it there.
- a fresh clone: every object copied for a check that reads one commit.

Reversal: verifiers that need state the checkout lacks, such as untracked files, which needs a setup step in the playbook.

**`decide` writes the change as the rubric set's state.** `change.diff` is `git diff HEAD...<commit>`, the change from where it branched, and `commits.txt` each commit `HEAD` lacks, oldest first, with its message: the two files the set's `code`, `stable-refs` and `public-private-stance` rubrics read. A rubric reading anything else is refused naming the file.

- the checkout as the state: the rubrics would read the whole tree, not the change.
- every artifact the set reads, the issue and the review among them: the record does not hold them yet.

Reversal: tasks whose record holds their issue and review, when `decide` writes those too.

**`decide` composes the rubrics with the verifications.** The recorded design decides from the rubrics' composed grade. `decide` composes that with the latest verification of each step on the dispatch — met when it exited 0, unmet otherwise — because a change whose gates fail would otherwise land on a reading of its diff. Unmet reworks with the first failure, a step before a question.

- the rubrics alone: a failing verifier is recorded and ignored.
- every verification on the dispatch: a step fixed by a second run would still count as failing.

Reversal: verifications that are advisory, which needs a playbook field saying so.

**Undecided and refused decide nothing.** A grade between the band's bounds, or a question the judge did not read, is no ground to land or to rework: `decide` commits its gradings, prints `composed undecided` or `composed refused`, and exits 3, so the operator can ask again or decide by hand.

- reworking on undecided: a seat would be sent back over an answer nobody gave.

Reversal: a policy that resolves undecided grades, which needs it named in the rubric.

**`land` merges into the branch `HEAD` names, and commits only once the merge stands.** It refuses a detached `HEAD`, uncommitted changes to tracked files and a commit the repository lacks before running git; then `git merge --ff` fast-forwards, or makes `Merge branch '<branch>'`; a merge that stops is aborted. `Landed` names the revision `HEAD` then stands at, and only the operator that decided can land: the fold admits the landing from that key alone. A rerun after the merge but before the receipt finds the commit already merged and records where the branch stands.

- `--ff-only`: every change whose base moved would be refused.
- rebase or squash: the landed commit would not be the one verified and graded.
- pushing to a remote: where the repository lives is the operator's configuration, never the record's.

Reversal: a review host that merges, when `land` records the host's merge instead of making one.

**Stalled is a retirement, not a clock.** The design sketched stalled as a dispatch without a report past a horizon the surface names. The fold reads receipts only, and a horizon would make a task's standing depend on when it is read; a seat that gives up retires, and the attempt stands stalled from that receipt. An operator who judges a quiet seat stalled dispatches again.

- a horizon in `open`: two operators listing the same journal would disagree.

Reversal: a receipt that records the operator's judgement that a seat is quiet.

## Not yet

- Component installation: fetching, verifying and installing the toolchain's components from signed release artifacts by `(component, version, target)`, the driver's other job.
- Publication: the package depends on the workspace's crates by path, and is published once they are.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
