# rubrics

The rubric set: seven rubrics that grade a change to a repository of this workspace's shape, each with a fixture pair that one state meets and the other does not.

- [The set](#the-set)
- [State files](#state-files)
- [Questions](#questions)
- [The band](#the-band)
- [Fixture pairs](#fixture-pairs)
- [Tests](#tests)
- [Deferred](#deferred)

## The set

A rubric is an Opponent strategy: the state files it reads into a transcript, a band, and named questions a judge answers about the transcript. Each answer is graded against the band, and the grades compose as the conjunction of the rubric's criteria; [`domhringr-strategy-document`](../crates/strategy-document/README.md#rubrics) states the document's shape and the grading. The `domhringr-peer` binary grades a rubric on a task and commits the verdict and the grading: `rubric grade <file> <tree> --task-state <dir>` ([`domhringr-surface-peer`](../crates/surface-peer/README.md#playbooks-and-rubrics)).

| Rubric | The question it answers | Reads | Questions |
| ------ | ----------------------- | ----- | --------- |
| `stable-refs` | Does every reference the change adds resolve for a reader who holds only the text and the public sources it names? | `change.diff`, `commits.txt` | 4 |
| `public-private-stance` | Does the change carry only what any clone needs, with no secret, no fact about one machine or installation, no private source and no contributor's own concerns? | `change.diff`, `commits.txt` | 5 |
| `issues` | Does the issue ask one question, with evidence a reader can reproduce and a test that closes it? | `issue.md` | 4 |
| `pull-requests` | Does the review hold the change to the record's own words, line by line, and decide by its findings? | `change.diff`, `review.md` | 5 |
| `ci-shape` | Does CI run every gate over the whole workspace from pinned actions, and does the committed workflow run on a workstation? | `ci.yml`, `tasks.toml` | 7 |
| `docs` | Does the README state what its package is, why and how, its decisions and its needs, as present fact? | `README.md` | 6 |
| `code` | Does the code carry its specifications, keep every diagnostic, say why a value is absent, convert numbers totally, name its tests for what they witness, and declare its dependencies once? | `change.diff` | 6 |

## State files

A rubric reads its state files from the task's state directory, by these names. The grader writes there what the task's record supplies.

| File | Holds |
| ---- | ----- |
| `change.diff` | the change, as a unified diff against its base |
| `commits.txt` | the change's commits, oldest first, each as a `commit <hash>` line and its message |
| `issue.md` | an issue: its title as a heading, then its body |
| `review.md` | a review of the change: its findings, then its verdict |
| `ci.yml` | the CI workflow |
| `tasks.toml` | the task definitions the repository's gates run |
| `README.md` | a README as the change leaves it |

**A state file is named for what it holds, not for where a repository keeps it.** A task's record supplies a diff, commit messages, an issue or a review body, a workflow and a README; a checkout holds only some of them, and each repository lays them out in its own way. Naming the content lets one rubric grade any task that supplies it.

- the repository's own paths, such as `.github/workflows/ci.yml`: a rubric that reads only a checkout of one layout, and never a diff, an issue or a review, which no checkout holds.

Reversal: a rubric that grades a whole checkout rather than a task's artifacts, whose state directory is then the checkout itself.

## Questions

Each question is one criterion. Its `instructions` say what to read and what counts; its `criteria.true` and `criteria.false` are one line each, offered to the judge as `A` and `B`.

**A state with nothing to judge meets the criterion.** A change that cites no paper meets `citations`, and a review with no findings meets `cites-line`; each such question says so in its instructions and its true criterion, so a judge never fails a small change on a question the change gives no occasion for.

- a question that fails on absence: a rubric whose grade measures the size of a change rather than its conformance.

Reversal: a criterion whose subject must be present, such as a README section every package carries, which states the presence as its own question.

**Each criterion is written as public judgement, in the words of this workspace's own documents.** A rubric names no tool, host, person or private source, and cites nothing: the criterion is the text, and the fixtures are its witnesses.

## The band

Every rubric in the set grades against `low = 0.2` and `high = 0.8`, the band of [`examples/rubric.toml`](../examples/rubric.toml). A ruling whose probability on the criterion holding is 0.8 or more is met, one of 0.2 or less unmet, and one between undecided.

**The set shares one band until calibration measures a judge per rubric.**

- a band per rubric, set by hand: numbers no measurement backs.
- a wider undecided range, such as 0.15 to 0.85: fewer rulings met or unmet, with no measurement saying the extra undecided ones belong there.

Reversal: calibration that measures, per rubric, where a judge's rulings on met and unmet states fall.

## Fixture pairs

`fixtures/<rubric>/` holds the rubric's pair: `met/` and `unmet/`, each a task's state directory holding every state file the rubric reads, and `isolates`, the name of one of the rubric's questions. The `unmet` member is the `met` member changed in one place, so that it fails the question `isolates` names and meets every other: the pair isolates that question.

A pair is authored in four steps:

1. Write `met/`: the smallest state that meets every question of the rubric, public and written for the pair.
2. Copy it to `unmet/` and change one place so that exactly one question fails.
3. Write that question's name in `isolates`.
4. Run the tests below.

**A pair isolates one question.** A pair whose `unmet` member failed several questions would show the rubric grading `unmet` without showing which criterion tells the members apart.

- a pair per question: thirty-seven pairs, most of whose members differ by a line, as evidence that no test reads before calibration.

Reversal: calibration, which needs a pair, or more, for every question.

## Tests

The peer binary's process test `strategy::tests::every_rubric_in_the_set_grades_its_fixture_pair`, in [`crates/surface-peer/tests/strategy.rs`](../crates/surface-peer/tests/strategy.rs), walks this directory. Every `<name>.toml` validates through `rubric validate` and is named `<name>`; its pair's `met` and `unmet` states read and differ, and `isolates` names one of its questions. From a table reading every question at 0.9 on the criterion holding over `met`, and the isolated question at 0.1 over `unmet`, `rubric grade` grades the rubric `met` over `met` and `unmet` over `unmet`, the isolated question alone unmet, and the replay holds each grading naming the rubric and every question. A rubric added here, with its pair, is tested with no change to the test:

```sh
mise exec -- cargo nextest run -p domhringr-surface-peer -E 'test(every_rubric_in_the_set_grades_its_fixture_pair)'
```

**The set is tested through the peer binary.** The grade is `domhringr-strategy-document`'s, and the verdict and the grading that record it are committed by `domhringr-peer`'s `rubric grade`, which grades a fixture's state directory as it stands, so the test reads the receipts a real grading leaves. The operator's `domhringr decide` grades by the same rubrics, but over the state it writes from a reported change — a diff and its commit messages — so a fixture pair, which is a state directory and not a change, is graded through the peer.

- a test in `domhringr-strategy-document`: it would build the verdict and the grading itself and test its own construction, and the layering keeps the strategy crate below the binary, so it cannot run it.
- a test crate of its own: a member with no library, which still cannot run another package's binary.
- a test through `domhringr decide`: each pair would first be turned into a change in a repository, and a rubric reading an issue or a workflow would find none of it in the diff `decide` writes.

Reversal: `decide` writing every artifact the set reads — the issue, the review, the workflow — from the record of the task, when its tests then walk the set.

**A table grades what it is told.** The test shows that each rubric reads, that each pair's states read and differ, and that the band grades a judge 90 percent sure as met or unmet; it does not show that a model tells a pair apart. An ignored test asks that of a real judge, grading the `stable-refs` pair through the endpoint the environment configures, as [`domhringr-judge-oracle`](../crates/judge-oracle/README.md#configuration) states:

```sh
DOMHRINGR_JUDGE_ENDPOINT=http://127.0.0.1:8000/v1 DOMHRINGR_JUDGE_MODEL=<model> \
  mise exec -- cargo nextest run -p domhringr-surface-peer --run-ignored only \
  -E 'test(a_configured_judge_grades_a_fixture_pair_of_the_set)'
```

## Deferred

- Calibration: measuring where a judge's rulings fall on each rubric's met and unmet states, which sets each band and says which questions a model answers reliably.
- Dialogue reuse: a ruling recorded for one question about one transcript, answered again from the record when the same pair is asked.
- The loader as a type checker: a rubric whose state files, questions and band are checked against the task it grades before any question is asked.
