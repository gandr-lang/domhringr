# domhringr-judge-oracle

The judge asks a model one lettered question about a transcript and reads the answer letter and a probability per option from the model's next-token distribution, or records why it read none.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** `domhringr-judge-oracle` is the Opponent's oracle. It holds a `Question` (a text and two to twenty-six options, lettered `A`, `B`, … in order, named by the hash of its canonical form), a `Transcript` (the content asked about, staged as evidence and named by its value manifest), and a `Backend` trait that answers a question about a transcript with a `Readout` or a `Refusal`. `ChatCompletions` asks an OpenAI-compatible endpoint. `Static` answers from a table of recorded rulings, for tests and for replay.

**Why.** Some criteria can only be judged, not computed, and a judge that answers in prose cannot be graded, compared or replayed. A lettered answer read from the model's next-token distribution gives a probability per option along with the letter. A refusal recorded by its reason keeps a judge that did not answer apart from one that did. The verdict that carries the rulings is a receipt of the task's tree (see [`domhringr-record-tree`](../record-tree/src/task.rs)): this crate reads the rulings, and its caller commits them.

**How.** `ChatCompletions` posts one chat request: a system message stating the judge's task, and a user message holding the transcript, the question and its lettered options. It asks for one token at temperature zero, with the twenty most probable tokens at that position and their log-probabilities. Each option holds the mass of the reported tokens that are its letter. The masses are renormalised over the option letters, the rest is recorded as the outside mass, and the option holding the most is the answer.

## Provided features

- `Question`: its text and lettered options, named by the BLAKE3 hash of its canonical form, with its named refusals (`QuestionError`).
- `Transcript`: content staged as evidence ([`domhringr-record-evidence`](../record-evidence/README.md)), named by its manifest digest, its text read when it is UTF-8; `staged` hands the value to the caller to keep beside the verdict.
- `Backend`: a question about a transcript, answered with a `Readout` or a `Refusal` whose `reason` is the `Unread` a verdict records.
- `ChatCompletions` over an OpenAI-compatible endpoint, configured by `Config` from the environment, with `Ceiling`, an optional bound on the outside mass.
- `Static`: a table from a question's hash and a transcript's manifest digest to a ruling, collected from triples or parsed from lines of `<question-hash> <transcript-digest> <ruling>`.

## Expected features

- An async runtime to drive `Backend::ask`; `ChatCompletions` needs Tokio's, as `reqwest` does.
- For `ChatCompletions`: an endpoint serving `POST <base>/chat/completions` with `logprobs` and `top_logprobs` for chat requests, and the configuration the [`chat`](src/chat.rs) module states. A transcript asked about must be UTF-8.

## Examples

With `domhringr-judge-oracle`, `domhringr-record-tree` and Tokio's `rt` feature as dependencies, this program asks a question about a transcript from a table recording one ruling, and prints the ruling as a verdict records it:

```rust
use domhringr_judge_oracle::{Backend, Question, Static, Transcript};
use domhringr_record_tree::{Content, Ruling};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let question = Question::new("Did every check pass?".into(), vec!["yes".into(), "no".into()])?;
    let transcript = Transcript::held(Content::from(b"Every check passed.".to_vec()))?;
    let recorded = "read A A=0.9 B=0.1 outside=0".parse::<Ruling>()?;
    let table: Static = [(question.hash(), transcript.digest(), recorded)].into_iter().collect();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let ruling = match runtime.block_on(table.ask(&question, &transcript)) {
        Ok(readout) => Ruling::Read(readout),
        Err(refusal) => Ruling::Unread(refusal.reason()),
    };
    println!("ruling {} {ruling}", question.hash());
    Ok(())
}
```

The [`domhringr-peer` binary](../surface-peer/src/main.rs) puts the judge on the command line: `judge ask` and `judge verdict`. Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-judge-oracle
```

One test is ignored: it asks a real endpoint a question whose transcript states the answer. Run it by hand against a server you started, naming the endpoint and model:

```sh
DOMHRINGR_JUDGE_ENDPOINT=http://127.0.0.1:8000/v1 DOMHRINGR_JUDGE_MODEL=<model> \
  mise exec -- cargo nextest run -p domhringr-judge-oracle --run-ignored only
```

## Where the detail lives

Mechanism, decisions with their alternatives and reversals, and witnesses live in the rustdoc beside the code:

| Topic | Module |
| ----- | ------ |
| The laws, references | [`src/lib.rs`](src/lib.rs) |
| Questions and transcripts | [`question`](src/question.rs) |
| The readout | [`readout`](src/readout.rs) |
| The endpoint, its configuration and the HTTP client | [`chat`](src/chat.rs) |

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
