//! The evidence codec: content as lines, every prefix of whole lines a value.
//!
//! ```text
//! lines := Start | Line(lines, bytes)
//! ```
//!
//! A line runs to and including the first newline within the next
//! [`LINE_BYTES`] bytes, or is exactly [`LINE_BYTES`] bytes when no newline
//! falls there; the last line ends where the content does, newline or not.
//! The value nests to the left: the content's last line is the root's payload
//! and its first sits innermost beside `Start`. A prefix of whole lines is
//! then a subtree of every content extending it, so two contents sharing a
//! prefix share the chunks it was cut into wherever the scanner's pending
//! count agrees, and an appended line is a path edit at the root.
//!
//! Emission walks the lines twice, opening one `Line` per line and then
//! closing each after its payload; decoding reads the opens, then the payloads
//! in content order. Neither recurses. The decoder admits only the split
//! [`Split`] produces, so one content has one value and one manifest.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use domhringr_record_tree::Content;
use gandr_storage_values::CanonicalValue;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenOffset;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;

/// The tag of the empty prefix.
const START: u8 = 0x01_u8;

/// The tag of a prefix extended by one line.
const LINE: u8 = 0x02_u8;

/// The most bytes one line holds. A chunk holds lines whole, so this bounds a
/// chunk's payload at half the token cap times it; the README's measurement
/// states the choice.
pub const LINE_BYTES: usize = 512_usize;

/// Content as the codec reads it: borrowed when committed, owned when read.
#[derive(Debug)]
#[repr(transparent)]
pub struct Lines<'content>(Cow<'content, [u8]>);

impl<'content> Lines<'content>
{
    /// The lines of `content`, borrowed.
    ///
    /// # Specification
    /// trivial.
    pub fn of(content: &'content Content) -> Self
    {
        Self(Cow::Borrowed(content.as_ref()))
    }
}

impl From<Lines<'_>> for Content
{
    /// The content the lines spell, in order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(lines: Lines<'_>) -> Self
    {
        Self::from(lines.0.into_owned())
    }
}

/// Where a line stands in its content: before the last, or the last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place
{
    /// A line another follows: it ends in its newline or holds
    /// [`LINE_BYTES`] bytes.
    Inner,
    /// The content's last line: it ends where the content does.
    Last,
}

/// The lines of a content, in order, as the codec splits them.
#[derive(Clone, Debug)]
#[repr(transparent)]
struct Split<'content>(&'content [u8]);

impl<'content> Iterator for Split<'content>
{
    type Item = TokenBytes<'content>;

    /// The next line: through the first newline within [`LINE_BYTES`] bytes,
    /// or those bytes when none falls there.
    ///
    /// # Specification
    /// - ensures: a non-empty line no longer than [`LINE_BYTES`] holding no
    ///   newline but as its last byte, which ends in a newline or holds
    ///   [`LINE_BYTES`] bytes unless it ends the content; the lines concatenate
    ///   to the content; `None` once the content is spent.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — contents of no line, of a line without a newline, of
    ///   lines at, below and past [`LINE_BYTES`] round-trip, and a decoder fed
    ///   any other split refuses it.
    /// - witness: `lines::tests::contents_round_trip_through_their_lines`
    /// - witness: `lines::tests::a_line_split_otherwise_is_refused`
    fn next(&mut self) -> Option<Self::Item>
    {
        let window = self.0.get(.. LINE_BYTES).unwrap_or(self.0);
        let line = window.split_inclusive(|byte| *byte == b'\n').next()?;
        self.0 = self.0.get(line.len() ..).unwrap_or_default();
        Some(TokenBytes::from(line))
    }
}

/// Refuse a line the split would not produce at `place`.
///
/// # Specification
/// - ensures: `Ok` exactly when the line is non-empty, at most [`LINE_BYTES`]
///   long, holds a newline only as its last byte, and — at [`Place::Inner`] —
///   ends in a newline or holds [`LINE_BYTES`] bytes.
/// - fails: [`ValueError::UnexpectedConstructor`] naming the `Line` tag at
///   `position`, the line's open record, otherwise.
/// - panics: none.
///
/// # Errors
/// - [`ValueError::UnexpectedConstructor`]: as listed above.
fn admit(
    line: TokenBytes<'_>,
    place: Place,
    position: TokenOffset,
) -> Result<(), ValueError>
{
    let bytes: &[u8] = line.into();
    let refused = ValueError::UnexpectedConstructor {
        found: ConstructorTag::from(LINE),
        position,
    };
    let Some((last, before)) = bytes.split_last()
    else {
        return Err(refused);
    };
    let whole = *last == b'\n' || bytes.len() == LINE_BYTES;
    if bytes.len() > LINE_BYTES || before.contains(&b'\n') || (place == Place::Inner && !whole) {
        return Err(refused);
    }
    Ok(())
}

impl CanonicalValue for Lines<'_>
{
    /// Emit the content's lines, nested to the left.
    ///
    /// # Specification
    /// - ensures: one `Line` open per line, then `Start` opened and closed,
    ///   then per line in content order its bytes and a close: one balanced
    ///   value, with no recursion.
    /// - fails: the sink's refusals.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refuses.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — contents of no line, of one line, and of lines at,
    ///   below and past [`LINE_BYTES`] commit and read back equal.
    /// - witness: `lines::tests::contents_round_trip_through_their_lines`
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        let lines = Split(&self.0);
        for _line in lines.clone() {
            sink.open(ConstructorTag::from(LINE))?;
        }
        sink.open(ConstructorTag::from(START))?;
        sink.close()?;
        for line in lines {
            sink.bytes(line)?;
            sink.close()?;
        }
        Ok(())
    }

    /// Read the lines back into the content they spell.
    ///
    /// # Specification
    /// - requires: `reader` stands at the value's root.
    /// - ensures: the content whose lines the value holds, read without
    ///   recursion.
    /// - fails: [`ValueError::UnexpectedConstructor`] for a tag other than
    ///   `Line` before `Start`, or for a line the split would not produce,
    ///   naming its open record; the reader's refusals.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — committed contents read back equal; an empty line, a
    ///   line holding an inner newline, an inner line cut short and a line past
    ///   [`LINE_BYTES`] are each refused at their open record, and a foreign
    ///   tag at its own.
    /// - witness: `lines::tests::contents_round_trip_through_their_lines`
    /// - witness: `lines::tests::a_line_split_otherwise_is_refused`
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let mut opened = Vec::new();
        loop {
            let position = reader.position();
            let tag = reader.read_tag()?;
            match u8::from(tag) {
                | LINE => opened.push(position),
                | START => break,
                | _ => {
                    return Err(ValueError::UnexpectedConstructor {
                        found: tag,
                        position,
                    });
                },
            }
        }
        reader.read_close()?;
        let mut content = Vec::new();
        let mut lines = opened.into_iter().rev().peekable();
        while let Some(position) = lines.next() {
            let line = reader.read_bytes()?;
            let place = match lines.peek() {
                | Some(_) => Place::Inner,
                | None => Place::Last,
            };
            admit(line, place, position)?;
            content.extend_from_slice(line.as_ref());
            reader.read_close()?;
        }
        Ok(Self(Cow::Owned(content)))
    }
}

#[cfg(test)]
mod tests
{
    use alloc::vec::Vec;

    use domhringr_record_tree::Content;
    use gandr_storage_values::CanonicalValue;
    use gandr_storage_values::ConstructorTag;
    use gandr_storage_values::InMemoryChunkStore;
    use gandr_storage_values::TokenBytes;
    use gandr_storage_values::TokenSink;
    use gandr_storage_values::ValueError;
    use gandr_storage_values::cam_commit;

    use super::LINE;
    use super::LINE_BYTES;
    use super::Lines;
    use super::START;
    use crate::profile::profile;

    /// Commit `content` under the evidence profile and read it back.
    ///
    /// # Specification
    /// trivial.
    fn round_trip(content: &Content) -> Result<Content, ValueError>
    {
        let mut store = InMemoryChunkStore::new();
        let manifest = cam_commit(&mut store, &profile(), &Lines::of(content))?;
        manifest
            .read_under::<Lines<'_>>(&store, &profile())
            .map(Content::from)
    }

    /// Lines written by hand, nested as the codec nests them: the value the
    /// decoder reads, whatever split it holds.
    #[repr(transparent)]
    struct Written(Vec<Vec<u8>>);

    impl CanonicalValue for Written
    {
        /// Emit the lines as given.
        ///
        /// # Specification
        /// trivial.
        fn emit_tokens<Sink>(
            &self,
            sink: &mut Sink,
        ) -> Result<(), ValueError>
        where
            Sink: TokenSink + ?Sized,
        {
            for _line in &self.0 {
                sink.open(ConstructorTag::from(LINE))?;
            }
            sink.open(ConstructorTag::from(START))?;
            sink.close()?;
            for line in &self.0 {
                sink.bytes(TokenBytes::from(line.as_slice()))?;
                sink.close()?;
            }
            Ok(())
        }

        /// Never read: the tests read [`Lines`].
        ///
        /// # Specification
        /// trivial.
        fn decode_tokens(
            reader: &mut gandr_storage_values::TokenReader<'_>
        ) -> Result<Self, ValueError>
        {
            Err(ValueError::UnexpectedConstructor {
                found: ConstructorTag::from(0_u8),
                position: reader.position(),
            })
        }
    }

    #[test]
    fn contents_round_trip_through_their_lines()
    {
        let mut long = [vec![b'x'; LINE_BYTES], vec![b'x'; LINE_BYTES]].concat();
        long.extend_from_slice(b"xyz");
        let mut exact = vec![b'y'; LINE_BYTES];
        if let Some(last) = exact.last_mut() {
            *last = b'\n';
        }
        exact.extend_from_slice(b"tail");
        let contents: [&[u8]; 7] = [
            b"",
            b"one line without a newline",
            b"one line\n",
            b"two\nlines\n",
            b"\n\n\n",
            &long,
            &exact,
        ];
        for bytes in contents {
            let content = Content::from(bytes.to_vec());
            assert_eq!(
                round_trip(&content),
                Ok(content.clone()),
                "{} bytes",
                bytes.len()
            );
        }
    }

    #[test]
    fn a_line_split_otherwise_is_refused()
    {
        let read = |lines: &[&[u8]]| {
            let written = Written(lines.iter().map(|line| line.to_vec()).collect());
            let mut store = InMemoryChunkStore::new();
            let manifest = cam_commit(&mut store, &profile(), &written).unwrap();
            manifest
                .read_under::<Lines<'_>>(&store, &profile())
                .map(Content::from)
        };
        let refused_at = |record: u32| {
            Err(ValueError::UnexpectedConstructor {
                found: ConstructorTag::from(LINE),
                position: gandr_storage_values::TokenOffset::from(record),
            })
        };
        let mut too_long = vec![b'z'; LINE_BYTES];
        too_long.push(b'z');
        let mut short = vec![b'z'; LINE_BYTES];
        let _dropped = short.pop();

        // The first line's open record is the innermost: the one before
        // `Start`, at the position one less than the line count.
        assert_eq!(read(&[b"", b"b\n"]), refused_at(1));
        assert_eq!(read(&[b"a\nb\n"]), refused_at(0));
        assert_eq!(read(&[b"a", b"b\n"]), refused_at(1));
        assert_eq!(read(&[&short, b"b"]), refused_at(1));
        assert_eq!(read(&[b"a\n", &too_long]), refused_at(0));
        assert_eq!(read(&[b"a\n", b"b"]), Ok(Content::from(b"a\nb".to_vec())));
    }
}
