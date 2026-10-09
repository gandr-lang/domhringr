# domhringr-judge-oracle

The judge asks a model one lettered question about a transcript and reads the answer letter and a probability per option from the model's next-token distribution, or records why it read none.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [The laws](#the-laws)
- [Questions and transcripts](#questions-and-transcripts)
- [The readout](#the-readout)
- [The endpoint](#the-endpoint)
- [Configuration](#configuration)
- [Dependencies](#dependencies)
- [License](#license)

## Synopsis

**What.** `domhringr-judge-oracle` is the Opponent's oracle. It holds a `Question` (a text and two to twenty-six options, lettered `A`, `B`, … in order, named by the hash of its canonical form), a `Transcript` (the content asked about, held, or named by its hash), and a `Backend` trait that answers a question about a transcript with a `Readout` or a `Refusal`. `ChatCompletions` asks an OpenAI-compatible endpoint. `Static` answers from a table of recorded rulings, for tests and for replay.

**Why.** Some criteria can only be judged, not computed, and a judge that answers in prose cannot be graded, compared or replayed. A lettered answer read from the model's next-token distribution gives a probability per option along with the letter. A refusal recorded by its reason keeps a judge that did not answer apart from one that did. The verdict that carries the rulings is a receipt of the task's tree (see [`domhringr-record-tree`](../record-tree/README.md#tasks)): this crate reads the rulings, and its caller commits them.

**How.** `ChatCompletions` posts one chat request: a system message stating the judge's task, and a user message holding the transcript, the question and its lettered options. It asks for one token at temperature zero, with the twenty most probable tokens at that position and their log-probabilities. Each option holds the mass of the reported tokens that are its letter. The masses are renormalised over the option letters, the rest is recorded as the outside mass, and the option holding the most is the answer.

## References

| Artifact | Use |
| -------- | --- |
| D. Ahman, A. Bauer, _Sheaves as oracle computations_, arXiv, February 2026, [arXiv:2602.22135](https://arxiv.org/abs/2602.22135) | The oracle reading: a judge answers a query and classifies evidence, and never contributes a witness. |
| OpenAI, _Chat Completions API reference_, [`POST /v1/chat/completions`](https://platform.openai.com/docs/api-reference/chat/create) | The request and its `logprobs` and `top_logprobs` fields: the next-token distribution at the answer's position. |
| vLLM, _OpenAI-Compatible Server_, [documentation](https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html) | A local server of that API, reporting log-probabilities for chat requests. |
| `reqwest`, [crate documentation](https://docs.rs/reqwest) | The HTTP client. |
| `serde_json`, [crate documentation](https://docs.rs/serde_json) | The request and response bodies. |

## Provided features

- `Question`: its text and lettered options, named by the BLAKE3 hash of its canonical form, with its named refusals (`QuestionError`).
- `Transcript`: content held, its text read when it is UTF-8, or a hash alone.
- `Backend`: a question about a transcript, answered with a `Readout` or a `Refusal` whose `reason` is the `Unread` a verdict records.
- `ChatCompletions` over an OpenAI-compatible endpoint, configured by `Config` from the environment, with `Ceiling`, an optional bound on the outside mass.
- `Static`: a table from a question's hash and a transcript's hash to a ruling, collected from triples or parsed from lines of `<question-hash> <transcript-hash> <ruling>`.

## Expected features

- An async runtime to drive `Backend::ask`; `ChatCompletions` needs Tokio's, as `reqwest` does.
- For `ChatCompletions`: an endpoint serving `POST <base>/chat/completions` with `logprobs` and `top_logprobs` for chat requests, and the configuration in [Configuration](#configuration). A transcript asked about must be held and UTF-8.

## Examples

With `domhringr-judge-oracle`, `domhringr-record-tree` and Tokio's `rt` feature as dependencies, this program asks a question about a transcript from a table recording one ruling, and prints the ruling as a verdict records it:

```rust
use domhringr_judge_oracle::{Backend, Question, Static, Transcript};
use domhringr_record_tree::{Content, Ruling};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let question = Question::new("Did every check pass?".into(), vec!["yes".into(), "no".into()])?;
    let transcript = Transcript::held(Content::from(b"Every check passed.".to_vec()));
    let recorded = "read A A=0.9 B=0.1 outside=0".parse::<Ruling>()?;
    let table: Static = [(question.hash(), transcript.hash(), recorded)].into_iter().collect();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let ruling = match runtime.block_on(table.ask(&question, &transcript)) {
        Ok(readout) => Ruling::Read(readout),
        Err(refusal) => Ruling::Unread(refusal.reason()),
    };
    println!("ruling {} {ruling}", question.hash());
    Ok(())
}
```

The [`domhringr-peer` binary](../surface-peer/README.md#judging) puts the judge on the command line: `judge ask` and `judge verdict`. Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-judge-oracle
```

One test is ignored: it asks a real endpoint a question whose transcript states the answer. Run it by hand against a server you started, naming the endpoint and model:

```sh
DOMHRINGR_JUDGE_ENDPOINT=http://127.0.0.1:8000/v1 DOMHRINGR_JUDGE_MODEL=<model> \
  mise exec -- cargo nextest run -p domhringr-judge-oracle --run-ignored only
```

## The laws

A judge classifies evidence and never adds to it. Refusal is outside the laws: an endpoint that fails, a question the endpoint refuses, or an answer that names no option is an operational outcome, recorded as an unread ruling with its reason, never as a letter. Three laws bind what the judge records, each witnessed by a test:

- **Unit.** A verdict changes no attempt: the task stands where its seat receipts put it, with or without rulings. Witnesses: `fold::tests::a_judge_rules_on_the_current_dispatch` in `domhringr-record-tree`, and `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict` in `domhringr-surface-peer`, where the task replays `dispatched` after the verdict.
- **Composition.** A verdict over several questions holds, in the order asked, the ruling each question gets when asked alone: a ruling depends on its question and its transcript alone. Witnesses: `backend::tests::a_table_answers_what_it_records`, and the peer's process test, where the verdict's first ruling is the one `judge ask` printed.
- **Property grade.** A verdict is a function of what it records. Replay reads the same rulings from the record on any day and against no endpoint, and `Static` answers a recorded ruling again. The verdict names the rubric and the transcript by hash and holds only the rulings, so it adds no evidence. Witnesses: `receipt::tests::every_kind_round_trips` and `ruling::tests::a_ruling_reads_back_from_its_text` in `domhringr-record-tree`, and `backend::tests::each_refusal_records_its_reason` for refusals.

## Questions and transcripts

**A question is named by the BLAKE3 hash of its canonical form in the value plane's token records.** The form is `open 0x01 · word 1 · bytes text · word count · bytes option{count} · close`, the leading word its version. Two judges asking the same question name it alike, and a verdict names each question by that hash. The text and every option are non-empty and UTF-8, and each option is one line with no control character. A transcript is named by the hash of its bytes, as a report names its content.

- the question's text alone as its name: two questions with the same text and different options would share it.
- a JSON form: a second canonical form beside the value plane's, with its own key-order and number rules.

Reversal: a question that depends on an earlier answer, which needs that dependency in the form under a new version.

## The readout

**The readout renormalises the option letters' mass, records the outside mass, and refuses only what names no answer.** Each option's probability is the summed mass of the reported tokens that are its letter, a token trimmed of whitespace being exactly the uppercase letter, divided by the mass on all the option letters. A letter reported twice, as `B` and `B`, holds both masses; a letter not reported holds none. The outside mass is one less the option letters' mass, never below zero: what the model put on prose, a lowercase letter, or a letter past the last option. The readout refuses, in this order, a reported log-probability that is NaN or above zero (`endpoint`), a distribution with no option letter in it (`no letter`), an outside mass above the configured ceiling (`outside`), and two options sharing the most (`tied`). It never chooses a default letter.

The recorded design constrained decoding to the option letters: it tokenized each letter through the server, allowed only those token ids in a one-token completion, and normalised their log-probabilities. This crate reads the unconstrained distribution instead, for two reasons. Constraining is a server extension (`allowed_token_ids`, `/tokenize`) that the OpenAI-compatible API does not define, and it needs a tokenization per model. It also erases the outside mass, which measures how far the model was answering the question at all and is what a ceiling bounds.

- constrained decoding to the letters' token ids: an exact distribution over the letters on the servers that offer it, without the outside mass, and with a judge tied to one server's extensions.
- refusing whenever the outside mass passes a fixed bound: a threshold fixed in the tree before any calibration says what a good one is. The ceiling is the same refusal, configured, and unbounded by default.
- the argmax token alone: a letter with no probability to grade or compare.

Reversal: calibration showing a judge's top twenty tokens miss an option letter that a constrained decoding would find. Constrained decoding is then the better read where the server offers it, behind the same `Backend`.

## The endpoint

**The judge asks the chat API, and the server applies the model's chat template.** The request is `POST <base>/chat/completions` with `max_tokens` 1, `temperature` 0, `logprobs` and `top_logprobs` 20, the most the API admits. Its system message states the judge's task and the answer's form, a letter alone. The user message holds the transcript between `<transcript>` tags, the question, and one `<letter>. <option>` line per option. A `400`, `413` or `422` answer means the endpoint refused the request as put, and the question is unread as `malformed`. Every other failure is unread as `endpoint`: no connection, another status, a body that is not the API's, or an answer without log-probabilities. A request may take five minutes.

- the completions API with the prompt rendered here: a model-specific template kept in the crate for every model a judge might use.
- the reasoning or tool-call forms of the chat API: an answer that is no longer the first token.

Reversal: a model whose chat template puts text before the answer, such as a thinking preamble. Its first token is then never a letter, and the judge needs the completions API with the template rendered and the preamble closed.

## Configuration

**The endpoint is configured by the environment, never by the tree.** `DOMHRINGR_JUDGE_ENDPOINT` is the base URL the API's paths follow (`…/v1`), `http` or `https`. `DOMHRINGR_JUDGE_MODEL` is the model asked. `DOMHRINGR_JUDGE_KEY`, when set, is sent as a bearer key, and its `Debug` form never shows it. `DOMHRINGR_JUDGE_CEILING`, when set, is the most outside mass a readout may hold, a number from zero to one. An unset endpoint or model, a value that is not Unicode, an endpoint that is no `http` or `https` URL, an empty model, and a ceiling that is no probability are each refused by name (`ConfigError`).

- a file under the XDG configuration directory: a path and a format for four values that the environment of the process already carries.
- command-line options: a key on a command line is visible to every process on the host.

Reversal: a peer that runs several judges against different endpoints, or a key that must not sit in the environment. A file under `$XDG_CONFIG_HOME/domhringr/` then names each judge.

## Dependencies

**The HTTP client is `reqwest` 0.13 with `rustls-no-provider`, configured with iroh's TLS.** iroh already brings `reqwest` with that feature into the graph, so the client adds no crate to the build. The TLS configuration is iroh's `CaTlsConfig::embedded()` with the ring provider, the roots and provider the endpoint already uses, handed over through `tls_backend_preconfigured`.

- `ureq`: a blocking client, so a thread per request in an async caller, and a second TLS setup and crate set beside iroh's.
- `hyper` and `hyper-util` directly: the connection pool, timeout and TLS connector `reqwest` already compiles, written again.

Reversal: iroh dropping `reqwest` from its graph. The client would then cost a build of its own, and `hyper-util` over iroh's rustls is the smaller one.

**The request and response bodies are `serde` derives and `serde_json` with `alloc` alone.** `serde` with `derive` is already in the graph; `serde_json` adds itself and its float formatter. The wire structs are the only `serde` types, and no `serde` type leaves the crate.

- `miniserde` or `nanoserde`: a second derive framework beside the one the graph already carries.
- writing and reading the JSON by hand: a parser for the response's nested arrays and the API's escaping, kept in step with the API.

Reversal: a response large enough that parsing its whole tree costs more than the request, which needs a streaming reader.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
