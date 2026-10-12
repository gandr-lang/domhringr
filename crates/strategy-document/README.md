# domhringr-strategy-document

Playbooks and rubrics: TOML documents read with every refusal named by its field, a playbook's verifiers run as processes, and a rubric's questions graded against its band and composed.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** `domhringr-strategy-document` reads the two strategy documents a task is checked by. A `Playbook` is a Player strategy written down: steps in order, each with the reason it holds, each bound to a `Verifier` (a program run on the task's state) or to a question of a `Rubric`. A rubric is an Opponent strategy: the state files it reads into a transcript, a `Band` that grades a judge's ruling, and named questions. A document read from its file is named by the BLAKE3 hash of its bytes (`Loaded`); a playbook is read with every rubric it names (`Plan`).

**Why.** A check that lives in prose is skipped, and one that lives in code is changed without review. Written as data, a playbook says what is checked and why, and its hash names exactly the checks a receipt answers to. A verifier decides what a program can compute; a rubric question takes what can only be judged to the judge oracle and grades the answer, so both leave a receipt on the task. A document that does not read is refused at the field at fault, so its author fixes the field rather than reading a parser trace.

**How.** The documents are TOML, parsed into the `toml` crate's document tree and read from it by hand, each table against the fields it admits. A verifier runs through `std::process` in the task's state directory, its standard output and standard error in one pipe; its output is handed to the caller, who commits it as evidence, and its exit status kept. A rubric question is a `domhringr-judge-oracle` `Question` whose options are the criterion holding (`A`) and failing (`B`); its ruling is graded by the probability on `A` against the band, and the grades compose as a conjunction. The receipts that record a run, `Verified` and `Graded`, are `domhringr-record-tree`'s; this crate reads, runs and grades, and its caller commits.

## Provided features

- `Playbook` and `Rubric`, read from TOML text with `FromStr`, refused with a `Refusal`: the `Field` at fault and the `Reason`.
- `Loaded<D>`: a document read from its file and named by the hash of its bytes; `LoadError` names the file.
- `Plan`: a playbook and each rubric its steps name, read beside it, every question it names checked to exist; `Plan::gradings` groups the questions by rubric.
- `Verifier::run`: a program run in a directory to its end, its merged output and its `Status`.
- `Rubric::transcript`: the state files read into one transcript, staged as evidence and named by its value manifest; `TranscriptError` names the state file that cannot be read.
- `Band::grade`: a ruling graded `met`, `unmet`, `undecided` or `refused`; callers compose grades with `domhringr_record_tree::compose`.

## Expected features

- A file system holding the documents, a playbook's rubrics at the relative paths its steps name.
- For `Verifier::run`, a platform `std::process` spawns on; on Unix a signal is recorded as the status, elsewhere only an exit code is.
- For a grade, a ruling from a judge: `domhringr-judge-oracle`'s `Backend`, asked each question about the rubric's transcript.

## Examples

`examples/playbook.toml` checks a change to this repository: its gates as a verifier, and two questions of `examples/rubric.toml` about its READMEs. The `domhringr-peer` binary [validates and runs them](../surface-peer/src/strategy.rs):

```sh
cargo build -p domhringr-surface-peer
state=$(mktemp -d)
target/debug/domhringr-peer --state "$state" playbook validate examples/playbook.toml
target/debug/domhringr-peer --state "$state" rubric validate examples/rubric.toml
```

With this crate and `domhringr-record-tree` as dependencies, this program grades two rulings against the example rubric's band and composes them:

```rust
use std::path::Path;

use domhringr_record_tree::{Grade, Ruling, compose};
use domhringr_strategy_document::{Loaded, Rubric};

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

## Where the detail lives

Mechanism, decisions with their alternatives and reversals, and witnesses live in the rustdoc beside the code:

| Topic | Module |
| ----- | ------ |
| Playbooks | [`playbook`](src/playbook.rs) |
| Rubrics, grades and their composition | [`rubric`](src/rubric.rs) |
| Refusals | [`document`](src/document.rs) |
| Verifiers | [`verify`](src/verify.rs) |
| The rubric set, dependencies, references | [`src/lib.rs`](src/lib.rs) |

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
