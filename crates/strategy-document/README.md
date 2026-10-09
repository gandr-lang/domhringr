# domhringr-strategy-document

Playbooks and rubrics: TOML documents read with every refusal named by its field, a playbook's verifiers run as processes, and a rubric's questions graded against its band and composed.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Playbooks](#playbooks)
- [Rubrics](#rubrics)
- [Refusals](#refusals)
- [Verifiers](#verifiers)
- [Grades and their composition](#grades-and-their-composition)
- [The rubric set](#the-rubric-set)
- [Dependencies](#dependencies)
- [License](#license)

## Synopsis

**What.** `domhringr-strategy-document` reads the two strategy documents a task is checked by. A `Playbook` is a Player strategy written down: steps in order, each with the reason it holds, each bound to a `Verifier` (a program run on the task's state) or to a question of a `Rubric`. A rubric is an Opponent strategy: the state files it reads into a transcript, a `Band` that grades a judge's ruling, and named questions. A document read from its file is named by the BLAKE3 hash of its bytes (`Loaded`); a playbook is read with every rubric it names (`Plan`).

**Why.** A check that lives in prose is skipped, and one that lives in code is changed without review. Written as data, a playbook says what is checked and why, and its hash names exactly the checks a receipt answers to. A verifier decides what a program can compute; a rubric question takes what can only be judged to the judge oracle and grades the answer, so both leave a receipt on the task. A document that does not read is refused at the field at fault, so its author fixes the field rather than reading a parser trace.

**How.** The documents are TOML, parsed into the `toml` crate's document tree and read from it by hand, each table against the fields it admits. A verifier runs through `std::process` in the task's state directory, its standard output and standard error in one pipe; its output is named by hash and its exit status kept. A rubric question is a `domhringr-judge-oracle` `Question` whose options are the criterion holding (`A`) and failing (`B`); its ruling is graded by the probability on `A` against the band, and the grades compose as a conjunction. The receipts that record a run, `Verified` and `Graded`, are `domhringr-record-tree`'s; this crate reads, runs and grades, and its caller commits.

## References

| Artifact | Use |
| -------- | --- |
| T. Preston-Werner, P. Gedam et al., _TOML v1.0.0_, [toml.io/en/v1.0.0](https://toml.io/en/v1.0.0) | The document language. |
| S. C. Kleene, _Introduction to Metamathematics_, North-Holland, 1952, ISBN 978-0-7204-2103-3, § 64 | The strong three-valued conjunction the grades compose by, with refusal placed between failure and indecision. |
| `toml`, [crate documentation](https://docs.rs/toml) | `de::DeTable::parse`: the document tree with each key's and value's span. |
| `domhringr-judge-oracle`, [crate documentation](../judge-oracle/README.md) | The question a rubric asks and the judge that answers it. |
| `domhringr-record-tree`, [crate documentation](../record-tree/README.md#tasks) | The `Verified` and `Graded` receipts, `StepId`, `Status`, `Grade` and the `Ruling` a grade reads. |

## Provided features

- `Playbook` and `Rubric`, read from TOML text with `FromStr`, refused with a `Refusal`: the `Field` at fault and the `Reason`.
- `Loaded<D>`: a document read from its file and named by the hash of its bytes; `LoadError` names the file.
- `Plan`: a playbook and each rubric its steps name, read beside it, every question it names checked to exist; `Plan::gradings` groups the questions by rubric.
- `Verifier::run`: a program run in a directory to its end, its merged output by hash and its `Status`.
- `Rubric::transcript`: the state files read into one transcript.
- `Band::grade`: a ruling graded `met`, `unmet`, `undecided` or `refused`; `compose`: a rubric's grades composed into one.

## Expected features

- A file system holding the documents, a playbook's rubrics at the relative paths its steps name.
- For `Verifier::run`, a platform `std::process` spawns on; on Unix a signal is recorded as the status, elsewhere only an exit code is.
- For a grade, a ruling from a judge: `domhringr-judge-oracle`'s `Backend`, asked each question about the rubric's transcript.

## Examples

`examples/playbook.toml` checks a change to this repository: its gates as a verifier, and two questions of `examples/rubric.toml` about its READMEs. The `domhringr-peer` binary [validates and runs them](../surface-peer/README.md#playbooks-and-rubrics):

```sh
cargo build -p domhringr-surface-peer
state=$(mktemp -d)
target/debug/domhringr-peer --state "$state" playbook validate examples/playbook.toml
target/debug/domhringr-peer --state "$state" rubric validate examples/rubric.toml
```

With this crate and `domhringr-record-tree` as dependencies, this program grades two rulings against the example rubric's band and composes them:

```rust
use std::path::Path;

use domhringr_record_tree::{Grade, Ruling};
use domhringr_strategy_document::{Loaded, Rubric, compose};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rubric = Loaded::<Rubric>::read(Path::new("examples/rubric.toml"))?;
    let band = rubric.document().band();
    let grades = ["read A A=0.9 B=0.1 outside=0", "read A A=0.6 B=0.4 outside=0"]
        .into_iter()
        .map(|text| text.parse::<Ruling>().map(|ruling| band.grade(&ruling)))
        .collect::<Result<Vec<Grade>, _>>()?;
    println!("{}", compose(&grades)); // undecided: met beside undecided
    Ok(())
}
```

Run the crate's tests from the workspace root; one reads both examples:

```sh
mise exec -- cargo nextest run -p domhringr-strategy-document
```

## Playbooks

```toml
name = "change-review"

[[steps]]
id = "gates"
why = "Every gate the repository defines passes on the change."
verifier = { command = "mise", args = ["run", "check"] }

[[steps]]
id = "synopsis"
why = "The README's synopsis states what the project is, why it exists, and how it works."
question = { rubric = "rubric.toml", question = "synopsis" }
```

A playbook holds `name` and `steps`, nothing else. `name` and each step's `id` are identifiers: one to 64 bytes, a lowercase ASCII letter, then lowercase letters, digits and hyphens. `steps` is a non-empty array of tables, each holding `id`, unique in the playbook, `why`, a non-empty text, and exactly one of `verifier` and `question`. A verifier is `command`, a non-empty text, and `args`, an array of texts, none when absent. A question is `rubric`, a non-empty relative path read from the playbook's directory, and `question`, the name of a question that rubric holds.

**Every step says why it holds and is backed by a check.** A step without a verifier or a question is refused: a reason with nothing behind it is a step nobody runs.

- steps of prose alone, run by whoever reads them: a playbook that records intent and checks nothing.

Reversal: a step that a human performs and attests to, which needs a third binding and a receipt for the attestation.

## Rubrics

```toml
name = "change-review"
state = ["README.md", "Cargo.toml", "crates/README.md"]

[band]
low = 0.2
high = 0.8

[questions.synopsis]
instructions = "Read the README's synopsis. Does it state what, why and how, in the present tense?"
criteria.true = "The synopsis states what, why and how, in the present tense."
criteria.false = "The synopsis misses what, why or how, or narrates history."
```

A rubric holds `name`, `state`, `band` and `questions`, nothing else. `state` is a non-empty array of paths relative to the task's state directory: `/`-separated segments of ASCII letters, digits, `.`, `_` and `-`, none empty, `.` or `..`. `band` holds `low` and `high`, floats from zero to one with `low` strictly below `high`; an integer such as `1` is refused, as TOML keeps the two types apart, so a bound is written `1.0`. `questions` is a non-empty table of questions by name, each holding `instructions`, `criteria.true` and `criteria.false`, three non-empty texts, the criteria each one line.

The transcript is each state file in order as `<state name="<path>">`, the file's bytes, a newline when they lack one, and `</state>`. Each question is asked as the judge's question with its instructions as the text and two options, `A` the true criterion and `B` the false one. A rubric's questions are kept in the order of their names; a playbook asks those its steps name, rubric by rubric in the order each rubric is first named, and within a rubric in step order, a question named twice asked once.

**A question is a choice between its criterion holding and failing.** The judge reads a probability on each letter, and the band reads the probability on `A`.

- a question kind field (`type`) beside the boolean kind: a field with one value, read by nothing.
- a free-form scale of options per question: a band would then need a reading per option.

Reversal: a question that has more than two answers worth telling apart, which adds a `type` and a grade for its options.

## Refusals

A refusal names the field at fault and why: `steps[1].verifier.args[0]: expected a string`, `band: the band's low bound is not below its high bound`, `questions.synopsis.criteria.false: missing field`. A field is the path of keys and array positions from the document's root; a text that is not TOML is refused at the root with the line and column where the parser stopped. Each table refuses an unknown field first, the smallest key in order, then reads its fields in the order the shapes above list them, so the first refusal in that order is the one reported.

**The documents are read by hand from the TOML document tree.** Each refusal is a value with a field path and a reason a test compares exactly, and every rule — a unique step id, a bound strictly below the other, a question the rubric holds — is checked where the field is read.

- `serde` derives with `deny_unknown_fields`: the type checks for free, and a refusal is a message with a byte span, not a field, while the cross-field rules still need code of their own.
- a JSON Schema validator over the document read as JSON: a second language for the shape, whose errors name a JSON pointer and know nothing of a rubric file's questions.
- `toml_edit` or `toml-span`: a format-preserving editor or a second spanned parser for documents this crate only reads.

Reversal: a consumer that needs the shape as a machine-readable schema, such as an editor completing a playbook's fields. A schema is then generated from these readers' field lists, and the readers stay the authority.

## Verifiers

**A verifier runs in the task's state directory, and its output is recorded by hash.** It runs with its standard input closed and its standard output and standard error in one pipe, so the hash names everything it wrote in the order written. The receipt holds the hash and the status, `exit <code>` or `signal <number>`; a failing status is recorded, never hidden behind an error. The bytes are not kept: as a report does, a verification records what was produced, not where it lives.

- two hashes, one per stream: interleaving lost, and a diagnostic read apart from the output it explains.
- the output's bytes in the receipt: every receipt sized by its noisiest verifier.
- Tokio's `process`: an async child for one blocking wait per verifier, at the cost of a feature and its signal handling; the caller runs `run` on a blocking thread.

Reversal: a verifier whose output must be read again later, which needs the bytes stored under their hash beside the record.

## Grades and their composition

**A ruling is graded by the probability on its true criterion against the band.** At or above `high` it is `met`, at or below `low` `unmet`, strictly between `undecided`; an unread ruling is `refused`.

**A rubric's grades compose as the conjunction of its criteria.** Any `unmet` makes the composition `unmet`; otherwise any `refused` makes it `refused`; otherwise any `undecided` makes it `undecided`; otherwise it is `met`, as is an empty composition. This is the strong three-valued conjunction with refusal placed between failure and indecision: a criterion decided as failing settles the conjunction whatever the others say, and a refusal is never read as met, nor as merely close.

- refusal absorbing everything: an unread question would hide a criterion that was decided as failing.
- `undecided` before `refused`: a judge that did not answer would read as one that weighed the evidence and stayed between.
- a number per rubric (the least or the product of the probabilities) and a threshold over it: a second band per rubric, and a refusal with no number to stand for it.

Reversal: rubrics whose questions are not a conjunction, such as alternatives of which one must hold. A composition rule per rubric is then a field of the rubric.

## The rubric set

The example rubric grades two questions about a checkout of this repository. The rubric set that grades a repository's conformance adds seven rubrics: `stable-refs`, `public-private-stance`, `issues`, `pull-requests`, `ci-shape`, `docs` and `code`. Each is graded on a fixture pair, one tree that meets it and one that does not, so a rubric that cannot tell the two apart is caught before it grades real work.

## Dependencies

**`toml` 1.1 with the `parse` feature alone.** It reads a document into its tree, and a text that is not TOML into an error with the span a refusal's line and column come from; `serde`, `display` and the standard library features stay off. It adds two crates to the lock, `toml` and `serde_spanned`; its parser, `toml_parser` with `winnow`, and `toml_datetime` are already in the graph. The five crates build in about half a second from clean.

- `toml_edit`: a format-preserving document model for files this crate never writes.
- `toml-span`: a second, smaller parser beside the `toml_parser` the graph already carries.

Reversal: a document read on a hot path, where a parser without the span bookkeeping wins.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
