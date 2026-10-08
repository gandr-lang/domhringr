//! One-line fields: the escaping that keeps every fact a view or a resolution
//! prints on its own line, however its text reads.

use core::fmt;

/// Where a field stands on its line, which decides what its escape covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field
{
    /// The line's last field: a space is part of it.
    Last,
    /// A field another follows: a space would end it, so it is escaped too.
    Inner,
}

/// A writer that passes text through to a formatter, escaping what would
/// break the field out of its line.
pub struct OneLine<'formatter, 'output>
{
    /// The formatter written to.
    output: &'formatter mut fmt::Formatter<'output>,
    /// Where the field stands.
    field: Field,
}

impl<'formatter, 'output> OneLine<'formatter, 'output>
{
    /// Write a field standing at `field` to `output`.
    ///
    /// # Specification
    /// trivial.
    pub const fn new(
        output: &'formatter mut fmt::Formatter<'output>,
        field: Field,
    ) -> Self
    {
        Self { output, field }
    }
}

impl fmt::Write for OneLine<'_, '_>
{
    /// Write `s`, escaping a backslash as `\\`, a control character as its
    /// Rust escape (`\n`, `\u{7}`), and in an inner field a space as `\u{20}`.
    ///
    /// # Specification
    /// - ensures: the output holds no control character, and in an inner field
    ///   no space; distinct texts write distinct outputs, since every escape
    ///   begins with the backslash a literal backslash is escaped to.
    /// - fails: the formatter's own error.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`fmt::Error`]: the formatter refused a write.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a note carrying a newline, a backslash and a bell,
    ///   and a bound path carrying a space, are printed in a view and compared
    ///   with their escaped lines.
    /// - witness: `fold::tests::a_view_prints_one_line_per_fact`
    fn write_str(
        &mut self,
        s: &str,
    ) -> fmt::Result
    {
        for character in s.chars() {
            if character == '\\' || character.is_control() {
                write!(self.output, "{}", character.escape_default())?;
            }
            else if character == ' ' && self.field == Field::Inner {
                write!(self.output, "{}", character.escape_unicode())?;
            }
            else {
                self.output.write_char(character)?;
            }
        }
        Ok(())
    }
}
