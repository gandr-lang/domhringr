//! The chat-completions backend: an OpenAI-compatible endpoint asked for one
//! token, with the log-probabilities of its most probable tokens.
//!
//! The request is `POST <endpoint>/chat/completions` with a system message
//! stating the judge's task and a user message holding the transcript, the
//! question and its lettered options; it asks for one token at temperature
//! zero with `logprobs` and the twenty most probable tokens
//! (`top_logprobs`), the most the API admits. The readout is read from
//! those tokens at the first position ([`crate::readout`]). A `400`, `413`
//! or `422` answer is the endpoint refusing the request as put, so the
//! question is malformed; every other failure, and an answer without
//! log-probabilities, is the endpoint's.
//!
//! The endpoint is configured outside the tree, by the environment:
//! `DOMHRINGR_JUDGE_ENDPOINT` the base URL the API's paths follow (`…/v1`),
//! `DOMHRINGR_JUDGE_MODEL` the model asked, and optionally
//! `DOMHRINGR_JUDGE_KEY` a bearer key and `DOMHRINGR_JUDGE_CEILING` the most
//! mass the judge admits outside the option letters. TLS is iroh's: the
//! embedded Mozilla roots and the ring provider.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;
use std::ffi::OsString;

use domhringr_record_tree::Letter;
use domhringr_record_tree::ParseProbabilityError;
use domhringr_record_tree::Probability;
use domhringr_record_tree::Readout;
use reqwest::Client;
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use serde::Serialize;

use crate::backend::Backend;
use crate::backend::EndpointError;
use crate::backend::MalformedError;
use crate::backend::Refusal;
use crate::question::Question;
use crate::question::TextError;
use crate::question::Transcript;
use crate::readout::Candidate;
use crate::readout::Ceiling;
use crate::readout::read;

/// The variable naming the endpoint's base URL.
const ENDPOINT: &str = "DOMHRINGR_JUDGE_ENDPOINT";

/// The variable naming the model asked.
const MODEL: &str = "DOMHRINGR_JUDGE_MODEL";

/// The variable holding the bearer key, when the endpoint takes one.
const KEY: &str = "DOMHRINGR_JUDGE_KEY";

/// The variable holding the ceiling on the outside mass, when one is set.
const CEILING: &str = "DOMHRINGR_JUDGE_CEILING";

/// How long a request may take, connection to last byte: a large model
/// reading a long transcript on a busy endpoint, with room to spare.
const DEADLINE: Duration = Duration::from_secs(300);

/// How many of the most probable tokens the request asks reported: the most
/// the chat completions API admits.
const REPORTED: u8 = 20;

/// The system message: the judge's task and the answer's form.
const TASK: &str = "You are a judge. Read the transcript, then answer the question about it by \
                    choosing exactly one of the lettered options. Reply with the option's letter \
                    alone.";

/// An environment variable the judge reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variable
{
    /// `DOMHRINGR_JUDGE_ENDPOINT`: the endpoint's base URL.
    Endpoint,
    /// `DOMHRINGR_JUDGE_MODEL`: the model asked.
    Model,
    /// `DOMHRINGR_JUDGE_KEY`: the bearer key.
    Key,
    /// `DOMHRINGR_JUDGE_CEILING`: the ceiling on the outside mass.
    Ceiling,
}

impl fmt::Display for Variable
{
    /// Write the variable's name.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Endpoint => ENDPOINT,
            | Self::Model => MODEL,
            | Self::Key => KEY,
            | Self::Ceiling => CEILING,
        })
    }
}

/// What a request carries to be authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Authorization
{
    /// Nothing: the endpoint is open.
    Anonymous,
    /// This bearer key.
    Bearer(Key),
}

/// A bearer key, kept out of debug output.
#[derive(Clone, PartialEq, Eq)]
#[repr(transparent)]
struct Key(String);

impl fmt::Debug for Key
{
    /// Write `Key(..)`, never the key.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str("Key(..)")
    }
}

/// Where and how a judge asks an OpenAI-compatible endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config
{
    /// The chat completions URL: the base URL with `chat/completions` after
    /// it.
    url: Url,
    /// The model asked.
    model: String,
    /// What a request carries to be authorized.
    authorization: Authorization,
    /// The most mass the judge admits outside the option letters.
    ceiling: Ceiling,
}

impl Config
{
    /// The configuration `variables` name, read as the environment is.
    ///
    /// # Specification
    /// - ensures: the URL is `DOMHRINGR_JUDGE_ENDPOINT` with `chat/completions`
    ///   after its path, a trailing `/` or none; the model is
    ///   `DOMHRINGR_JUDGE_MODEL`; requests carry `DOMHRINGR_JUDGE_KEY` as a
    ///   bearer key when it is set and nothing otherwise; the ceiling is
    ///   `DOMHRINGR_JUDGE_CEILING` when set and unbounded otherwise. Other
    ///   variables are ignored, and a later variable of one name replaces an
    ///   earlier one.
    /// - fails: [`ConfigError::Unset`] for an endpoint or a model not set,
    ///   [`ConfigError::Unicode`] for a value that is not Unicode,
    ///   [`ConfigError::Endpoint`] for an endpoint that is no `http` or `https`
    ///   URL, [`ConfigError::Model`] for an empty model, and
    ///   [`ConfigError::Ceiling`] for a ceiling that is no probability.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ConfigError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a full configuration, one with a trailing `/` and one
    ///   with only the two required variables are read and compared; each
    ///   refusal is met by a configuration one variable away from a good one.
    /// - witness: `chat::tests::the_configuration_is_read_from_the_environment`
    #[inline]
    pub fn from_variables<Variables>(variables: Variables) -> Result<Self, ConfigError>
    where
        Variables: IntoIterator<Item = (OsString, OsString)>,
    {
        let (mut endpoint, mut model, mut key, mut ceiling) = (None, None, None, None);
        for (name, value) in variables {
            let slot = match name.to_str() {
                | Some(ENDPOINT) => &mut endpoint,
                | Some(MODEL) => &mut model,
                | Some(KEY) => &mut key,
                | Some(CEILING) => &mut ceiling,
                | Some(_) | None => continue,
            };
            *slot = Some(value);
        }
        let text = |variable: Variable, value: OsString| {
            value
                .into_string()
                .map_err(|_not_unicode| ConfigError::Unicode(variable))
        };
        let endpoint = endpoint.ok_or(ConfigError::Unset(Variable::Endpoint))?;
        let endpoint = text(Variable::Endpoint, endpoint)?;
        let mut url = Url::parse(&endpoint).map_err(|_not_a_url| ConfigError::Endpoint)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::Endpoint);
        }
        url.path_segments_mut()
            .map_err(|()| ConfigError::Endpoint)?
            .pop_if_empty()
            .extend(["chat", "completions"]);
        let model = model.ok_or(ConfigError::Unset(Variable::Model))?;
        let model = text(Variable::Model, model)?;
        if model.is_empty() {
            return Err(ConfigError::Model);
        }
        let authorization = match key {
            | Some(key) => Authorization::Bearer(Key(text(Variable::Key, key)?)),
            | None => Authorization::Anonymous,
        };
        let ceiling = match ceiling {
            | Some(ceiling) => {
                let ceiling = text(Variable::Ceiling, ceiling)?;
                let ceiling = ceiling
                    .parse::<Probability>()
                    .map_err(ConfigError::Ceiling)?;
                Ceiling::At(ceiling)
            },
            | None => Ceiling::Unbounded,
        };
        Ok(Self {
            url,
            model,
            authorization,
            ceiling,
        })
    }

    /// The configuration the process's environment names.
    ///
    /// # Specification
    /// - ensures: [`Config::from_variables`] over the process's environment.
    /// - fails: as [`Config::from_variables`].
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ConfigError`]: as [`Config::from_variables`].
    #[inline]
    pub fn from_environment() -> Result<Self, ConfigError>
    {
        Self::from_variables(std::env::vars_os())
    }
}

/// Why the environment configures no endpoint.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError
{
    /// A required variable is not set.
    #[error("{0} is not set")]
    Unset(Variable),
    /// A variable's value is not Unicode.
    #[error("{0} is not Unicode")]
    Unicode(Variable),
    /// The endpoint is not an `http` or `https` URL.
    #[error("{ENDPOINT} is not an http or https URL")]
    Endpoint,
    /// The model is empty.
    #[error("{MODEL} is empty")]
    Model,
    /// The ceiling is not a probability.
    #[error("{CEILING} is not a number from 0 to 1")]
    Ceiling(#[source] ParseProbabilityError),
}

/// A judge asking an OpenAI-compatible endpoint's chat completions.
#[derive(Clone, Debug)]
pub struct ChatCompletions
{
    /// The HTTP client, its TLS iroh's.
    client: Client,
    /// Where and how to ask.
    config: Config,
}

impl ChatCompletions
{
    /// A judge asking as `config` says.
    ///
    /// # Specification
    /// - ensures: requests trust the embedded Mozilla roots through the ring
    ///   provider, and are abandoned after five minutes.
    /// - fails: [`EndpointError::Tls`] when the TLS configuration cannot be
    ///   built, [`EndpointError::Client`] when the client cannot.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EndpointError`]: as listed above.
    #[inline]
    pub fn new(config: Config) -> Result<Self, EndpointError>
    {
        let tls = iroh::tls::CaTlsConfig::embedded()
            .client_config(iroh::tls::default_provider())
            .map_err(EndpointError::Tls)?;
        let client = Client::builder()
            .tls_backend_preconfigured(tls)
            .timeout(DEADLINE)
            .build()
            .map_err(EndpointError::Client)?;
        Ok(Self { client, config })
    }
}

impl Backend for ChatCompletions
{
    /// Ask the endpoint `question` about `transcript`, and read the answer.
    ///
    /// # Specification
    /// - ensures: one request as the module states, whose user message holds
    ///   the transcript between `<transcript>` lines, the question, and each
    ///   option on its own line after its letter and `. `; the readout of the
    ///   tokens reported at the first position, under the configured ceiling.
    /// - fails: [`MalformedError::Text`] for a transcript whose text is not
    ///   held, before any request; [`MalformedError::Refused`] for a `400`,
    ///   `413` or `422` answer; [`EndpointError`] for a request not answered,
    ///   another failure status, a body that does not read or is no chat
    ///   completion, and a completion without log-probabilities; and as the
    ///   readout refuses.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a loopback server captures the request and answers a
    ///   distribution, and the request's line, bearer key and body and the
    ///   readout are compared; a refused connection, a `503`, a `400`, a body
    ///   that is no JSON, a completion without log-probabilities and a
    ///   transcript named alone each meet their own refusal.
    /// - witness: `chat::tests::the_endpoint_is_asked_for_one_letter_and_read`
    /// - witness: `chat::tests::what_the_endpoint_cannot_answer_is_refused_by_cause`
    #[inline]
    async fn ask(
        &self,
        question: &Question,
        transcript: &Transcript,
    ) -> Result<Readout, Refusal>
    {
        let user = prompt(question, transcript)
            .map_err(|text| Refusal::Malformed(MalformedError::Text(text)))?;
        let request = Request {
            model: &self.config.model,
            messages: [
                Message {
                    role: Role::System,
                    content: TASK,
                },
                Message {
                    role: Role::User,
                    content: &user,
                },
            ],
            max_tokens: 1,
            temperature: 0.0_f64,
            logprobs: true,
            top_logprobs: REPORTED,
        };
        let body = serde_json::to_vec(&request)
            .map_err(|encode| Refusal::Endpoint(EndpointError::Encode(encode)))?;
        let mut post = self
            .client
            .post(self.config.url.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        if let Authorization::Bearer(ref key) = self.config.authorization {
            post = post.bearer_auth(&key.0);
        }
        let response = post
            .send()
            .await
            .map_err(|unanswered| Refusal::Endpoint(EndpointError::Request(unanswered)))?;
        let status = response.status();
        if matches!(
            status,
            StatusCode::BAD_REQUEST
                | StatusCode::PAYLOAD_TOO_LARGE
                | StatusCode::UNPROCESSABLE_ENTITY
        ) {
            return Err(Refusal::Malformed(MalformedError::Refused(status)));
        }
        if !status.is_success() {
            return Err(Refusal::Endpoint(EndpointError::Status(status)));
        }
        let body = response
            .bytes()
            .await
            .map_err(|unread| Refusal::Endpoint(EndpointError::Body(unread)))?;
        let completion = serde_json::from_slice::<Completion>(&body)
            .map_err(|shape| Refusal::Endpoint(EndpointError::Response(shape)))?;
        let first = completion
            .choices
            .into_iter()
            .next()
            .and_then(|choice| choice.logprobs)
            .and_then(|logprobs| logprobs.content)
            .and_then(|positions| positions.into_iter().next())
            .ok_or(Refusal::Endpoint(EndpointError::NoDistribution))?;
        read(question, &first.top_logprobs, self.config.ceiling)
    }
}

/// The user message asking `question` about `transcript`.
///
/// # Specification
/// - ensures: the transcript's text between a `<transcript>` and a
///   `</transcript>` line, then `Question: ` and the question's text, then each
///   option on its own line after its letter and `. `, then the request for one
///   letter.
/// - fails: as [`Transcript::text`].
/// - panics: none.
///
/// # Errors
/// - [`TextError`]: the transcript is not UTF-8 text.
///
/// # Adequacy
/// - hypothesis: L3 — through the client, the user message a loopback server
///   captures is compared whole.
/// - witness: `chat::tests::the_endpoint_is_asked_for_one_letter_and_read`
fn prompt(
    question: &Question,
    transcript: &Transcript,
) -> Result<String, TextError>
{
    let text = transcript.text()?;
    let mut prompt = String::from("<transcript>\n");
    prompt.push_str(text);
    prompt.push_str("\n</transcript>\n\nQuestion: ");
    prompt.push_str(question.text());
    prompt.push_str("\n\n");
    for (letter, option) in Letter::sequence().zip(question.options()) {
        prompt.push(char::from(letter));
        prompt.push_str(". ");
        prompt.push_str(option);
        prompt.push('\n');
    }
    prompt.push_str("\nAnswer with the letter of one option.");
    Ok(prompt)
}

/// A chat completion request.
#[derive(Serialize)]
struct Request<'request>
{
    /// The model asked.
    model: &'request str,
    /// The system message, then the user message.
    messages: [Message<'request>; 2],
    /// One token: the answer's letter.
    max_tokens: u8,
    /// Greedy decoding; the readout is the reported distribution.
    temperature: f64,
    /// Report log-probabilities.
    logprobs: bool,
    /// Report this many of the most probable tokens at each position.
    top_logprobs: u8,
}

/// One message of a chat.
#[derive(Serialize)]
struct Message<'request>
{
    /// Who speaks.
    role: Role,
    /// What is said.
    content: &'request str,
}

/// Who speaks a message.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Role
{
    /// The instructions.
    System,
    /// The asker.
    User,
}

/// A chat completion, as far as the readout reads it.
#[derive(Deserialize)]
#[repr(transparent)]
struct Completion
{
    /// The completions: one is asked for.
    choices: Vec<Choice>,
}

/// One completion.
#[derive(Deserialize)]
#[repr(transparent)]
struct Choice
{
    /// Its log-probabilities, when the endpoint reports them.
    logprobs: Option<Logprobs>,
}

/// A completion's log-probabilities.
#[derive(Deserialize)]
#[repr(transparent)]
struct Logprobs
{
    /// One entry per generated token, when the endpoint reports them.
    content: Option<Vec<Position>>,
}

/// The log-probabilities at one generated position.
#[derive(Deserialize)]
#[repr(transparent)]
struct Position
{
    /// The most probable tokens there.
    top_logprobs: Vec<Candidate>,
}

#[cfg(test)]
mod tests
{
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::net::Ipv4Addr;
    use std::ffi::OsString;
    use std::io::BufRead as _;
    use std::io::BufReader;
    use std::io::Read as _;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::thread::JoinHandle;

    use domhringr_record_tree::Content;
    use domhringr_record_tree::ParseProbabilityError;
    use domhringr_record_tree::Probability;
    use reqwest::StatusCode;
    use serde_json::Value;
    use serde_json::json;

    use super::Authorization;
    use super::CEILING;
    use super::ChatCompletions;
    use super::Config;
    use super::ConfigError;
    use super::ENDPOINT;
    use super::KEY;
    use super::Key;
    use super::MODEL;
    use super::TASK;
    use super::Variable;
    use crate::backend::Backend as _;
    use crate::backend::EndpointError;
    use crate::backend::MalformedError;
    use crate::backend::Refusal;
    use crate::question::Question;
    use crate::question::Transcript;
    use crate::readout::Ceiling;

    /// What a loopback endpoint answers.
    struct Reply
    {
        /// The status line's code and reason.
        status: StatusCode,
        /// The body.
        body: Vec<u8>,
    }

    /// What a loopback endpoint read.
    struct Captured
    {
        /// The request line and headers, each line ending in CRLF.
        head: String,
        /// The body.
        body: Vec<u8>,
    }

    /// The configuration of an endpoint at `endpoint` asking `judge-model`
    /// with the bearer key `secret`.
    ///
    /// # Specification
    /// trivial.
    fn configured(endpoint: String) -> Config
    {
        Config::from_variables([
            (OsString::from(ENDPOINT), OsString::from(endpoint)),
            (OsString::from(MODEL), OsString::from("judge-model")),
            (OsString::from(KEY), OsString::from("secret")),
        ])
        .unwrap()
    }

    /// A loopback endpoint that reads one request, answers it with `reply`
    /// and hands back what it read, and the configuration naming it.
    ///
    /// # Specification
    /// trivial.
    fn endpoint(reply: Reply) -> (Config, JoinHandle<Captured>)
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let served = std::thread::spawn(move || {
            let (stream, _peer) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (mut head, mut length) = (String::new(), 0_usize);
            loop {
                let mut line = String::new();
                let _read = reader.read_line(&mut line).unwrap();
                assert!(!line.is_empty(), "the request ends inside its head");
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
                head.push_str(&line);
            }
            let mut body = vec![0_u8; length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                reply.status,
                reply.body.len()
            )
            .unwrap();
            stream.write_all(&reply.body).unwrap();
            Captured { head, body }
        });
        (configured(format!("http://{address}/v1")), served)
    }

    /// A runtime for one client's requests.
    ///
    /// # Specification
    /// trivial.
    fn runtime() -> tokio::runtime::Runtime
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// The question the tests ask.
    ///
    /// # Specification
    /// trivial.
    fn question() -> Question
    {
        Question::new(String::from("What colour is the sky?"), vec![
            String::from("green"),
            String::from("blue"),
            String::from("red"),
        ])
        .unwrap()
    }

    /// The transcript the tests ask about, held.
    ///
    /// # Specification
    /// trivial.
    fn transcript() -> Transcript
    {
        Transcript::held(Content::from(b"The sky was blue all day.".to_vec())).unwrap()
    }

    #[test]
    fn the_endpoint_is_asked_for_one_letter_and_read()
    {
        let top = json!([
            { "token": "B", "logprob": 0.75_f64.ln() },
            { "token": "A", "logprob": 0.2_f64.ln() },
            { "token": "The", "logprob": 0.05_f64.ln() },
        ]);
        let completion = json!({
            "choices": [{
                "index": 0_u8,
                "message": { "role": "assistant", "content": "B" },
                "logprobs": {
                    "content": [{ "token": "B", "logprob": 0.75_f64.ln(), "top_logprobs": top }],
                },
                "finish_reason": "length",
            }],
        });
        let (config, served) = endpoint(Reply {
            status: StatusCode::OK,
            body: serde_json::to_vec(&completion).unwrap(),
        });
        let chat = ChatCompletions::new(config).unwrap();
        let readout = runtime()
            .block_on(chat.ask(&question(), &transcript()))
            .unwrap();
        assert_eq!(readout.letter().to_string(), "B", "B holds the most");
        let read = readout
            .probabilities()
            .map(|(_letter, probability)| f64::from(probability))
            .chain([f64::from(readout.outside())]);
        for (read, expected) in
            read.zip([0.2_f64 / 0.95_f64, 0.75_f64 / 0.95_f64, 0.0_f64, 0.05_f64])
        {
            assert!(
                (read - expected).abs() < 1.0e-12_f64,
                "each option renormalised over the letters, the word outside: {readout}"
            );
        }
        let captured = served.join().unwrap();
        let head = captured.head.to_ascii_lowercase();
        assert!(
            head.starts_with("post /v1/chat/completions http/1.1\r\n"),
            "the chat completions path under the base URL: {head}"
        );
        assert!(
            head.contains("\r\nauthorization: bearer secret\r\n"),
            "the bearer key: {head}"
        );
        assert!(
            head.contains("\r\ncontent-type: application/json\r\n"),
            "a JSON body: {head}"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&captured.body).unwrap(),
            json!({
                "model": "judge-model",
                "messages": [
                    { "role": "system", "content": TASK },
                    {
                        "role": "user",
                        "content": "<transcript>\nThe sky was blue all day.\n</transcript>\n\n\
                                    Question: What colour is the sky?\n\nA. green\nB. blue\n\
                                    C. red\n\nAnswer with the letter of one option.",
                    },
                ],
                "max_tokens": 1_u8,
                "temperature": 0.0_f64,
                "logprobs": true,
                "top_logprobs": 20_u8,
            }),
            "one greedy token, with the twenty most probable reported"
        );
    }

    #[test]
    fn what_the_endpoint_cannot_answer_is_refused_by_cause()
    {
        let runtime = runtime();
        let refused = |reply: Reply| {
            let (config, served) = endpoint(reply);
            let chat = ChatCompletions::new(config).unwrap();
            let refusal = runtime
                .block_on(chat.ask(&question(), &transcript()))
                .unwrap_err();
            let _captured = served.join().unwrap();
            refusal
        };
        let reply = |status: StatusCode, body: Value| Reply {
            status,
            body: serde_json::to_vec(&body).unwrap(),
        };
        assert!(
            matches!(
                refused(reply(StatusCode::SERVICE_UNAVAILABLE, json!({}))),
                Refusal::Endpoint(EndpointError::Status(StatusCode::SERVICE_UNAVAILABLE))
            ),
            "a failure status is the endpoint's"
        );
        assert!(
            matches!(
                refused(reply(StatusCode::BAD_REQUEST, json!({}))),
                Refusal::Malformed(MalformedError::Refused(StatusCode::BAD_REQUEST))
            ),
            "a request the endpoint refuses as put is malformed"
        );
        assert!(
            matches!(
                refused(Reply {
                    status: StatusCode::OK,
                    body: b"<html>".to_vec(),
                }),
                Refusal::Endpoint(EndpointError::Response(_))
            ),
            "a body that is no JSON is no chat completion"
        );
        let unreported = json!({
            "choices": [{ "message": { "role": "assistant", "content": "B" } }],
        });
        assert!(
            matches!(
                refused(reply(StatusCode::OK, unreported)),
                Refusal::Endpoint(EndpointError::NoDistribution)
            ),
            "a completion without log-probabilities carries no distribution"
        );
        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap();
        let chat = ChatCompletions::new(configured(format!("http://{closed}/v1"))).unwrap();
        assert!(
            matches!(
                runtime.block_on(chat.ask(&question(), &transcript())),
                Err(Refusal::Endpoint(EndpointError::Request(_)))
            ),
            "a refused connection leaves the request unanswered"
        );
        let binary = Transcript::held(Content::from(vec![0x68, 0xff])).unwrap();
        assert!(
            matches!(
                runtime.block_on(chat.ask(&question(), &binary)),
                Err(Refusal::Malformed(MalformedError::Text(_)))
            ),
            "a transcript that is no text cannot be put to a model"
        );
    }

    #[test]
    fn the_configuration_is_read_from_the_environment()
    {
        let variables = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|&(name, value)| (OsString::from(name), OsString::from(value)))
                .collect::<Vec<_>>()
        };
        let full = Config::from_variables(variables(&[
            ("PATH", "/bin"),
            (ENDPOINT, "https://judge.example/v1"),
            (MODEL, "judge-model"),
            (KEY, "secret"),
            (CEILING, "0.25"),
        ]))
        .unwrap();
        assert_eq!(
            full,
            Config {
                url: "https://judge.example/v1/chat/completions".parse().unwrap(),
                model: String::from("judge-model"),
                authorization: Authorization::Bearer(Key(String::from("secret"))),
                ceiling: Ceiling::At(Probability::try_from(0.25_f64).unwrap()),
            },
            "every variable read, the others ignored"
        );
        for endpoint in ["http://127.0.0.1:8000/v1/", "http://127.0.0.1:8000/v1"] {
            let bare =
                Config::from_variables(variables(&[(ENDPOINT, endpoint), (MODEL, "m")])).unwrap();
            assert_eq!(
                (bare.url.as_str(), bare.authorization, bare.ceiling),
                (
                    "http://127.0.0.1:8000/v1/chat/completions",
                    Authorization::Anonymous,
                    Ceiling::Unbounded
                ),
                "{endpoint}: anonymous and unbounded unless set"
            );
        }
        for (pairs, refusal) in [
            (&[(MODEL, "m")][..], ConfigError::Unset(Variable::Endpoint)),
            (
                &[(ENDPOINT, "http://h/v1")][..],
                ConfigError::Unset(Variable::Model),
            ),
            (
                &[(ENDPOINT, "ftp://h/v1"), (MODEL, "m")][..],
                ConfigError::Endpoint,
            ),
            (
                &[(ENDPOINT, "judge.example/v1"), (MODEL, "m")][..],
                ConfigError::Endpoint,
            ),
            (
                &[(ENDPOINT, "http://h/v1"), (MODEL, "")][..],
                ConfigError::Model,
            ),
            (
                &[(ENDPOINT, "http://h/v1"), (MODEL, "m"), (CEILING, "1.5")][..],
                ConfigError::Ceiling(ParseProbabilityError::Range(
                    domhringr_record_tree::NotProbability,
                )),
            ),
        ] {
            assert_eq!(
                Config::from_variables(variables(pairs)),
                Err(refusal),
                "{pairs:?}"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            let mut pairs = variables(&[(ENDPOINT, "http://h/v1"), (MODEL, "m")]);
            pairs.push((OsString::from(KEY), OsString::from_vec(vec![0xff])));
            assert_eq!(
                Config::from_variables(pairs),
                Err(ConfigError::Unicode(Variable::Key)),
                "a key that is not Unicode"
            );
        }
    }

    #[test]
    #[ignore = "asks the endpoint the environment configures: run with --ignored where \
                DOMHRINGR_JUDGE_ENDPOINT and DOMHRINGR_JUDGE_MODEL name one"]
    fn a_configured_endpoint_reads_the_answer_a_transcript_states()
    {
        let chat = ChatCompletions::new(Config::from_environment().unwrap()).unwrap();
        let readout = runtime()
            .block_on(chat.ask(&question(), &transcript()))
            .unwrap();
        assert_eq!(
            readout.letter().to_string(),
            "B",
            "the transcript states the sky was blue: {readout}"
        );
    }
}
