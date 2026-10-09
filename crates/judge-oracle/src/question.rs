//! Questions and transcripts: what a judge is asked, and what about.
//!
//! A question is its text and two to twenty-six options, each one line,
//! lettered `A`, `B`, … in order. Its name is the BLAKE3 hash of its
//! canonical form in the value plane's token records:
//!
//! ```text
//! question := open 0x01 · word 1 · bytes text (UTF-8) · word count
//!             · bytes option (UTF-8){count} · close
//! ```
//!
//! so two judges asking the same question name it alike, and a verdict names
//! each question it rules on by that hash. A transcript is named by the
//! identity of the value manifest its bytes stage to in the evidence plane
//! ([`Staged`]): a judge asking a model needs its text, a judge answering
//! from a table its name, and a verdict names it so any reader can fetch it.

use alloc::string::String;
use alloc::vec::Vec;
use core::str::Utf8Error;

use domhringr_record_evidence::EvidenceError;
use domhringr_record_evidence::Staged;
use domhringr_record_tree::Content;
use domhringr_record_tree::ContentHash;
use gandr_storage_values::CanonicalValue;
use gandr_storage_values::CanonicalWord;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::ManifestDigest;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;
use gandr_storage_values::ValueQuantity;
use gandr_storage_values::encode_flat;

/// The question's constructor tag.
const QUESTION: u8 = 0x01;

/// The question form this crate writes, and the only one it reads.
const VERSION: u64 = 1;

/// The fewest options a question lists: one option is no choice.
const FEWEST: usize = 2;

/// The most options a question lists: one per letter.
const MOST: usize = 26;

/// A question a judge asks: its text and its options in letter order, named
/// by the hash of its canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question
{
    /// What is asked and answered.
    form: Form,
    /// The hash of the form's flat bytes.
    hash: ContentHash,
}

impl Question
{
    /// The question asking `text`, offering `options` lettered in order.
    ///
    /// # Specification
    /// - ensures: the question holds `text` and `options` as given, and its
    ///   hash is the BLAKE3 hash of its form's flat bytes, as the module
    ///   grammar writes them.
    /// - fails: [`QuestionError::Few`] for fewer than two options,
    ///   [`QuestionError::Many`] for more than twenty-six, then
    ///   [`QuestionError::Blank`] for an empty text or option, then
    ///   [`QuestionError::Broken`] for an option holding a line break or
    ///   another control character, then [`QuestionError::Encoding`] when the
    ///   value plane refuses the form.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`QuestionError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a question's hash is compared with the BLAKE3 of flat
    ///   bytes written record by record, two questions differing in one option
    ///   hash apart, its form decodes back to itself, and one and twenty-seven
    ///   options, an empty text, an empty option and an option of two lines
    ///   each meet their own refusal.
    /// - witness: `question::tests::a_question_is_named_by_the_hash_of_its_form`
    /// - witness: `question::tests::a_question_offers_two_to_twenty_six_one_line_options`
    #[inline]
    pub fn new(
        text: String,
        options: Vec<String>,
    ) -> Result<Self, QuestionError>
    {
        if options.len() < FEWEST {
            return Err(QuestionError::Few);
        }
        if options.len() > MOST {
            return Err(QuestionError::Many);
        }
        if text.is_empty() || options.iter().any(String::is_empty) {
            return Err(QuestionError::Blank);
        }
        if options
            .iter()
            .any(|option| option.chars().any(char::is_control))
        {
            return Err(QuestionError::Broken);
        }
        let form = Form { text, options };
        let flat = encode_flat(&form).map_err(QuestionError::Encoding)?;
        let hash = ContentHash::of(&Content::from(flat.as_ref().to_vec()));
        Ok(Self { form, hash })
    }

    /// The question's text.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn text(&self) -> &String
    {
        &self.form.text
    }

    /// The question's options, in letter order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn options(&self) -> &[String]
    {
        &self.form.options
    }

    /// The question's name: the hash of its form's flat bytes.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn hash(&self) -> ContentHash
    {
        self.hash
    }
}

/// Why a question cannot be asked.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum QuestionError
{
    /// Fewer than two options.
    #[error("a question offers at least {FEWEST} options")]
    Few,
    /// More than twenty-six options.
    #[error("a question offers at most {MOST} options, one per letter")]
    Many,
    /// The text or an option is empty.
    #[error("the question and each option hold text")]
    Blank,
    /// An option holds a line break or another control character.
    #[error("an option is one line")]
    Broken,
    /// The value plane refused the question's form.
    #[error("cannot encode the question")]
    Encoding(#[source] ValueError),
}

/// A question's text and options: the part its hash names.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Form
{
    /// What is asked.
    text: String,
    /// The options, in letter order.
    options: Vec<String>,
}

impl CanonicalValue for Form
{
    /// Walk the form into `sink` in the module grammar's order.
    ///
    /// # Specification
    /// - ensures: on success `sink` received exactly one balanced value: the
    ///   question's constructor holding the version word, the text's bytes, the
    ///   count of the options and each option's bytes in order.
    /// - fails: propagates the sink's refusal unchanged, and the value plane's
    ///   overflow refusal for more options than a word counts.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a record.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a question's flat bytes are compared byte for byte
    ///   with records written independently.
    /// - witness: `question::tests::a_question_is_named_by_the_hash_of_its_form`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        sink.open(ConstructorTag::from(QUESTION))?;
        sink.word(CanonicalWord::from(VERSION))?;
        sink.bytes(TokenBytes::from(self.text.as_bytes()))?;
        let count = u64::try_from(self.options.len()).map_err(|_too_many| {
            ValueError::ArithmeticOverflow {
                quantity: ValueQuantity::TokenCount,
            }
        })?;
        sink.word(CanonicalWord::from(count))?;
        for option in &self.options {
            sink.bytes(TokenBytes::from(option.as_bytes()))?;
        }
        sink.close()
    }

    /// Read one form from `reader`.
    ///
    /// # Specification
    /// - ensures: on success the form whose emission the records are, and the
    ///   reader stands after its close.
    /// - fails: [`ValueError::UnexpectedConstructor`] at the question's open
    ///   record for another tag, another version, or text that is not UTF-8;
    ///   and the reader's own refusals for fewer options than the count, more,
    ///   or any other record.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a question's form decodes back to itself.
    /// - witness: `question::tests::a_question_is_named_by_the_hash_of_its_form`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let position = reader.position();
        let tag = reader.read_tag()?;
        let refused = ValueError::UnexpectedConstructor {
            found: tag,
            position,
        };
        if u8::from(tag) != QUESTION || u64::from(reader.read_word()?) != VERSION {
            return Err(refused);
        }
        let text = <&[u8]>::from(reader.read_bytes()?);
        let text = core::str::from_utf8(text).map_err(|_not_utf8| refused)?;
        let count = u64::from(reader.read_word()?);
        let mut options = Vec::new();
        for _place in 0 .. count {
            let option = <&[u8]>::from(reader.read_bytes()?);
            let option = core::str::from_utf8(option).map_err(|_not_utf8| refused)?;
            options.push(String::from(option));
        }
        reader.read_close()?;
        Ok(Self {
            text: String::from(text),
            options,
        })
    }
}

/// The content a judge is asked about, staged as evidence: its text, and the
/// value that names it.
#[derive(Clone, Debug)]
pub struct Transcript
{
    /// The transcript staged in the value plane; its manifest names it.
    staged: Staged,
    /// Its text, or why it is none.
    held: Held,
}

impl Transcript
{
    /// The transcript `content`, staged as evidence.
    ///
    /// # Specification
    /// - ensures: the transcript is named by the identity of the manifest its
    ///   content stages to ([`Staged::new`]), and [`Transcript::text`] reads
    ///   the content as UTF-8.
    /// - fails: [`EvidenceError::Commit`] when the value plane refuses the
    ///   content as a value.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`EvidenceError::Commit`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a held transcript is named by the manifest its bytes
    ///   stage to, its text reads back, and content holding an invalid byte is
    ///   no text.
    /// - witness: `question::tests::a_transcript_is_named_by_its_manifest`
    #[inline]
    pub fn held(content: Content) -> Result<Self, EvidenceError>
    {
        let staged = Staged::new(&content)?;
        let held = match String::from_utf8(Vec::from(content)) {
            | Ok(text) => Held::Text(text),
            | Err(binary) => Held::Binary(binary.utf8_error()),
        };
        Ok(Self { staged, held })
    }

    /// The transcript's name: the identity of its value manifest.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn digest(&self) -> ManifestDigest
    {
        self.staged.digest()
    }

    /// The transcript staged as evidence, to keep beside the verdict that
    /// names it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn staged(&self) -> &Staged
    {
        &self.staged
    }

    /// The transcript's text, to put to a model.
    ///
    /// # Specification
    /// - ensures: the content read as UTF-8.
    /// - fails: [`TextError`] for content that is not UTF-8.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`TextError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — held text reads back, and content holding an invalid
    ///   byte meets the refusal.
    /// - witness: `question::tests::a_transcript_is_named_by_its_manifest`
    #[inline]
    pub fn text(&self) -> Result<&String, TextError>
    {
        match self.held {
            | Held::Text(ref text) => Ok(text),
            | Held::Binary(error) => Err(TextError(error)),
        }
    }
}

/// What a transcript's bytes read as.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Held
{
    /// UTF-8 text.
    Text(String),
    /// No text, as this error says; its manifest names the bytes.
    Binary(Utf8Error),
}

/// Why a transcript's text cannot be put to a model: its content is not
/// UTF-8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the transcript is not UTF-8 text")]
#[repr(transparent)]
pub struct TextError(#[source] Utf8Error);

#[cfg(test)]
mod tests
{
    use alloc::string::String;
    use alloc::vec::Vec;

    use domhringr_record_evidence::Staged;
    use domhringr_record_tree::Content;
    use domhringr_record_tree::ContentHash;
    use gandr_storage_values::TokenBody;
    use gandr_storage_values::decode_flat;
    use gandr_storage_values::encode_flat;

    use super::Form;
    use super::Question;
    use super::QuestionError;
    use super::Transcript;

    #[test]
    fn a_question_is_named_by_the_hash_of_its_form()
    {
        let bytes = |payload: &[u8]| {
            let length = u64::try_from(payload.len()).unwrap().to_le_bytes();
            [&[0x03_u8][..], &length, payload].concat()
        };
        let word = |value: u64| [&[0x02_u8][..], &value.to_le_bytes()].concat();
        let ask = |last: &str| {
            Question::new(String::from("Is the sky blue?"), vec![
                String::from("no"),
                String::from(last),
            ])
            .unwrap()
        };
        let question = ask("yes");
        let flat = [
            vec![0x01_u8, 0x01],
            word(1),
            bytes(b"Is the sky blue?"),
            word(2),
            bytes(b"no"),
            bytes(b"yes"),
            vec![0x05],
        ]
        .concat();
        assert_eq!(
            encode_flat(&question.form).unwrap().as_ref(),
            flat,
            "open question, version word, text, option count, each option, close"
        );
        assert_eq!(
            question.hash(),
            ContentHash::of(&Content::from(flat.clone())),
            "the question is named by the hash of its flat bytes"
        );
        assert_eq!(
            decode_flat::<Form>(TokenBody::from(flat.as_slice())).unwrap(),
            question.form,
            "the form decodes back to itself"
        );
        assert_ne!(
            ask("yes, always").hash(),
            question.hash(),
            "two questions differing in one option are named apart"
        );
    }

    #[test]
    fn a_question_offers_two_to_twenty_six_one_line_options()
    {
        let options = |count: usize| {
            core::iter::repeat_n(String::from("an option"), count).collect::<Vec<_>>()
        };
        let text = || String::from("Which?");
        for count in [2, 26] {
            assert!(
                Question::new(text(), options(count)).is_ok(),
                "{count} options are offered"
            );
        }
        for (text, options, refusal, case) in [
            (text(), options(1), QuestionError::Few, "one option"),
            (text(), options(27), QuestionError::Many, "27 options"),
            (
                String::new(),
                options(2),
                QuestionError::Blank,
                "an empty question",
            ),
            (
                text(),
                vec![String::from("an option"), String::new()],
                QuestionError::Blank,
                "an empty option",
            ),
            (
                text(),
                vec![String::from("two\nlines"), String::from("one")],
                QuestionError::Broken,
                "an option of two lines",
            ),
        ] {
            assert_eq!(Question::new(text, options), Err(refusal), "{case}");
        }
    }

    #[test]
    fn a_transcript_is_named_by_its_manifest()
    {
        let content = Content::from(b"the sky is blue".to_vec());
        let held = Transcript::held(content.clone()).unwrap();
        assert_eq!(
            held.digest(),
            Staged::new(&content).unwrap().digest(),
            "a held transcript is named by the manifest its bytes stage to"
        );
        assert_eq!(
            held.text().map(String::as_str),
            Ok("the sky is blue"),
            "its text reads back"
        );
        assert!(
            Transcript::held(Content::from(vec![0x68, 0xff]))
                .unwrap()
                .text()
                .is_err(),
            "content with an invalid byte is no text"
        );
    }
}
