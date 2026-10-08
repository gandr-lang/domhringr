//! The names a tree goes by beside its key: a DNS name, which a witness and
//! the tree's own claim resolve to the key together, and a label, which an
//! introduction resolves inside the one tree that made it.
//!
//! A DNS name is lowercase ASCII labels joined by dots, at least two of them,
//! read as written with no IDNA mapping. A label is one anchor segment holding
//! no dot, never spelled as a tree id, so the three forms an anchor's authority
//! takes never read alike.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use crate::id::ParseIdError;
use crate::id::TreeId;

/// The longest DNS name a claim names: 242 characters, so that its witness
/// name `_domhringr.<domain>` stays within DNS's 253.
const DOMAIN_CHARACTERS: usize = 242;

/// The longest label of a DNS name, as DNS bounds it.
const DNS_LABEL_CHARACTERS: usize = 63;

/// A DNS name: two or more labels joined by dots, each 1 to 63 lowercase ASCII
/// letters, digits and hyphens that neither begins nor ends with a hyphen, 242
/// characters in all at most.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Domain(String);

impl FromStr for Domain
{
    type Err = ParseDomainError;

    /// Read a DNS name from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the DNS names this type admits, keeping the
    ///   text as written, so [`Display`] writes it back; no case folding or
    ///   IDNA mapping is applied, so a name has one text.
    /// - fails: the first refusal that holds, in this order:
    ///   [`ParseDomainError::Long`] for more than 242 characters,
    ///   [`ParseDomainError::Undotted`] for text with no dot; then, label by
    ///   label from the left, [`ParseDomainError::EmptyLabel`],
    ///   [`ParseDomainError::LongLabel`], [`ParseDomainError::Uppercase`] or
    ///   [`ParseDomainError::Character`] at the first character the label does
    ///   not admit, and [`ParseDomainError::Hyphen`] for a label beginning or
    ///   ending with a hyphen.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseDomainError::Long`]: the text is longer than 242 characters.
    /// - [`ParseDomainError::Undotted`]: the text holds no dot.
    /// - [`ParseDomainError::EmptyLabel`]: a label is empty.
    /// - [`ParseDomainError::LongLabel`]: a label is longer than 63 characters.
    /// - [`ParseDomainError::Uppercase`]: a letter is uppercase.
    /// - [`ParseDomainError::Character`]: a character is not an ASCII letter,
    ///   digit or hyphen.
    /// - [`ParseDomainError::Hyphen`]: a label begins or ends with a hyphen.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two-, three- and many-label names with digits and
    ///   inner hyphens round-trip, a 242-character name and a 63-character
    ///   label are admitted while 243 and 64 are refused, and each refusal is
    ///   met by a text that differs from an admitted one in the one place it
    ///   names: a single label, a leading, trailing and doubled dot, an
    ///   uppercase letter, an underscore, a space and a non-ASCII letter, and a
    ///   label with a leading or trailing hyphen.
    /// - witness: `name::tests::a_domain_round_trips_through_its_text`
    /// - witness: `name::tests::a_malformed_domain_is_refused_by_name`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.len() > DOMAIN_CHARACTERS {
            return Err(ParseDomainError::Long);
        }
        if !text.contains('.') {
            return Err(ParseDomainError::Undotted);
        }
        for label in text.split('.') {
            if label.is_empty() {
                return Err(ParseDomainError::EmptyLabel);
            }
            if label.len() > DNS_LABEL_CHARACTERS {
                return Err(ParseDomainError::LongLabel);
            }
            for byte in label.bytes() {
                match byte {
                    | b'a' ..= b'z' | b'0' ..= b'9' | b'-' => {},
                    | b'A' ..= b'Z' => return Err(ParseDomainError::Uppercase),
                    | _other => return Err(ParseDomainError::Character),
                }
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(ParseDomainError::Hyphen);
            }
        }
        Ok(Self(text.into()))
    }
}

impl fmt::Display for Domain
{
    /// Write the name as read.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Domain
{
    /// The name's text, as read.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &str
    {
        &self.0
    }
}

/// Why a text is not a DNS name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseDomainError
{
    /// The text is longer than a claimed name may be.
    #[error("a DNS name is {DOMAIN_CHARACTERS} characters at most")]
    Long,
    /// The text holds no dot: one label alone is a label, not a DNS name.
    #[error("a DNS name holds a dot")]
    Undotted,
    /// A label is empty: the name begins or ends with a dot, or holds two in
    /// a row.
    #[error("a DNS name's labels are not empty")]
    EmptyLabel,
    /// A label is longer than DNS admits.
    #[error("a DNS name's labels are {DNS_LABEL_CHARACTERS} characters at most")]
    LongLabel,
    /// A letter is uppercase.
    #[error("a DNS name is written in lowercase")]
    Uppercase,
    /// A character is not an ASCII letter, digit or hyphen.
    #[error("a DNS name is written in ASCII letters, digits and hyphens")]
    Character,
    /// A label begins or ends with a hyphen.
    #[error("a DNS name's labels neither begin nor end with a hyphen")]
    Hyphen,
}

/// A petname for a tree: one non-empty anchor segment holding no dot, never
/// the 52 z-base-32 characters of a tree id.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Label(String);

impl FromStr for Label
{
    type Err = ParseLabelError;

    /// Read a label from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the non-empty texts with no `/` and no `.`
    ///   that are not 52 z-base-32 characters, keeping the text as written, so
    ///   [`Display`] writes it back; an anchor's authority therefore reads as a
    ///   label exactly when it reads as neither a DNS name nor a tree id.
    /// - fails: the first refusal that holds, in this order:
    ///   [`ParseLabelError::Empty`], [`ParseLabelError::Slash`],
    ///   [`ParseLabelError::Dot`], and [`ParseLabelError::TreeId`] for text
    ///   spelled as a tree id, whether or not it spells a key.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseLabelError::Empty`]: the text is empty.
    /// - [`ParseLabelError::Slash`]: the text holds a `/`.
    /// - [`ParseLabelError::Dot`]: the text holds a `.`.
    /// - [`ParseLabelError::TreeId`]: the text is 52 z-base-32 characters.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — one-letter, spaced, uppercase and non-ASCII labels
    ///   and the 51-, 53-character and uppercase spellings beside a tree id
    ///   round-trip, and the empty text, a slash, a dot, a tree id's text and a
    ///   52-character z-base-32 text that spells no key are each refused by
    ///   their own reason.
    /// - witness: `name::tests::a_label_round_trips_through_its_text`
    /// - witness: `name::tests::a_malformed_label_is_refused_by_name`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.is_empty() {
            return Err(ParseLabelError::Empty);
        }
        if text.contains('/') {
            return Err(ParseLabelError::Slash);
        }
        if text.contains('.') {
            return Err(ParseLabelError::Dot);
        }
        match text.parse::<TreeId>() {
            | Err(ParseIdError::TreeLength | ParseIdError::TreeAlphabet) => Ok(Self(text.into())),
            | Ok(_) | Err(_) => Err(ParseLabelError::TreeId),
        }
    }
}

impl fmt::Display for Label
{
    /// Write the label as read.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Label
{
    /// The label's text, as read.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &str
    {
        &self.0
    }
}

/// Why a text is not a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseLabelError
{
    /// The text is empty.
    #[error("a label is not empty")]
    Empty,
    /// The text holds a `/`: a label is one segment.
    #[error("a label is one segment, holding no /")]
    Slash,
    /// The text holds a dot: the form of a DNS name.
    #[error("a label holds no dot; a dotted name is a DNS name")]
    Dot,
    /// The text is spelled as a tree id.
    #[error("a label is not spelled as a tree id")]
    TreeId,
}

#[cfg(test)]
mod tests
{
    use super::Domain;
    use super::Label;
    use super::ParseDomainError;
    use super::ParseLabelError;

    /// The z-base-32 spelling of the all-zero key.
    const ZERO: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    #[test]
    fn a_domain_round_trips_through_its_text()
    {
        let label = "a".repeat(63);
        let long = [
            label.as_str(),
            label.as_str(),
            label.as_str(),
            &"b".repeat(50),
        ]
        .join(".");
        assert_eq!(long.len(), 242, "the longest admitted name");
        for text in [
            "example.test",
            "gandr-lang.example.org",
            "a.b.c.d.e.f",
            "xn--bcher-kva.example",
            "0.9z",
            long.as_str(),
        ] {
            let domain = text.parse::<Domain>().unwrap();
            assert_eq!(domain.to_string(), text, "{text} displays back");
            assert_eq!(
                AsRef::<str>::as_ref(&domain),
                text,
                "{text} is kept as written"
            );
        }
    }

    #[test]
    fn a_malformed_domain_is_refused_by_name()
    {
        let refused = |text: &str| text.parse::<Domain>().unwrap_err();
        let label = "a".repeat(63);
        let too_long = [
            label.as_str(),
            label.as_str(),
            label.as_str(),
            &"b".repeat(51),
        ]
        .join(".");
        assert_eq!(too_long.len(), 243, "one past the longest admitted name");
        assert_eq!(refused(&too_long), ParseDomainError::Long);
        for undotted in ["localhost", "", "example-test"] {
            assert_eq!(
                refused(undotted),
                ParseDomainError::Undotted,
                "{undotted:?} holds no dot"
            );
        }
        for empty in [".example.test", "example.test.", "example..test", "."] {
            assert_eq!(
                refused(empty),
                ParseDomainError::EmptyLabel,
                "{empty:?} has an empty label"
            );
        }
        assert_eq!(
            refused(&format!("{}.test", "a".repeat(64))),
            ParseDomainError::LongLabel,
            "a 64-character label"
        );
        for uppercase in ["Example.test", "example.TEST", "exAmple.test"] {
            assert_eq!(
                refused(uppercase),
                ParseDomainError::Uppercase,
                "{uppercase:?} has an uppercase letter"
            );
        }
        for foreign in [
            "exa_mple.test",
            "exa mple.test",
            "bücher.example",
            "example.test/x",
        ] {
            assert_eq!(
                refused(foreign),
                ParseDomainError::Character,
                "{foreign:?} has a character outside letters, digits and hyphens"
            );
        }
        for hyphen in ["-example.test", "example-.test", "example.-"] {
            assert_eq!(
                refused(hyphen),
                ParseDomainError::Hyphen,
                "{hyphen:?} has a label at a hyphen"
            );
        }
    }

    #[test]
    fn a_label_round_trips_through_its_text()
    {
        let (short, _last) = ZERO.split_at(51);
        let long = format!("{ZERO}y");
        let upper = ZERO.to_uppercase();
        for text in [
            "b",
            "my friend",
            "Größe",
            short,
            long.as_str(),
            upper.as_str(),
        ] {
            let label = text.parse::<Label>().unwrap();
            assert_eq!(label.to_string(), text, "{text} displays back");
            assert_eq!(
                AsRef::<str>::as_ref(&label),
                text,
                "{text} is kept as written"
            );
        }
    }

    #[test]
    fn a_malformed_label_is_refused_by_name()
    {
        let refused = |text: &str| text.parse::<Label>().unwrap_err();
        let (short, _last) = ZERO.split_at(51);
        assert_eq!(refused(""), ParseLabelError::Empty);
        assert_eq!(refused("a/b"), ParseLabelError::Slash);
        assert_eq!(refused("example.test"), ParseLabelError::Dot);
        assert_eq!(refused("b."), ParseLabelError::Dot);
        assert_eq!(
            refused(ZERO),
            ParseLabelError::TreeId,
            "a tree id's text is the key form"
        );
        assert_eq!(
            refused(&format!("{short}b")),
            ParseLabelError::TreeId,
            "52 z-base-32 characters spelling no key are still the key form"
        );
    }
}
