//! Checked byte framing shared by manifests and proof streams.

use anodized::spec;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

/// An owned, untrusted wire image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct WireImage(pub Vec<u8>);

impl AsRef<[u8]> for WireImage
{
    /// Borrow the image without changing its trust status.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &[u8]
    {
        &self.0
    }
}

/// A byte extent within a wire image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Length(pub usize);

/// A fixed-width field read from the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Fixed<const N: usize>(pub [u8; N]);

/// A borrowed field body, before interpretation by its owner.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Body<'image>(pub &'image [u8]);

/// A cursor over a bounded image; failed reads leave it unchanged.
#[derive(Debug)]
#[repr(transparent)]
pub struct Cursor<'image>(&'image [u8]);

/// A wire image violates its framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError
{
    /// A declared field extends beyond the image.
    #[error("truncated index image")]
    Truncated,
    /// Bytes follow the final field.
    #[error("trailing index bytes")]
    Trailing,
    /// A length cannot be represented by the framing or address space.
    #[error("index frame length overflow")]
    Length,
    /// A discriminator has no defined meaning.
    #[error("unknown index frame tag")]
    Tag,
}

impl<'image> Cursor<'image>
{
    /// Read fields from the supplied image.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn new(body: Body<'image>) -> Self
    {
        Self(body.0)
    }

    /// Read one fixed-width field.
    ///
    /// # Specification
    /// - ensures: consumes exactly N bytes on success, none on failure.
    /// - fails: an incomplete field is refused before it is consumed.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WireError::Truncated`]: fewer than N bytes remain.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — foreign and truncated manifests distinguish bounded
    ///   reads.
    /// - witness: `manifest::tests::a_foreign_kind_layout_or_commitment_is_refused_before_any_node`
    #[spec(captures: before = self.0.len(), ensures: |ret| match ret {
        Ok(_) => arith::checked_add(Int::from(self.0.len()), Int::from(N)).map(usize::from) == Ok(before),
        Err(_) => self.0.len() == before,
    })]
    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<Fixed<N>, WireError>
    {
        let (bytes, remaining) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(WireError::Truncated)?;
        self.0 = remaining;
        Ok(Fixed(*bytes))
    }

    /// Read a field whose extent was checked by its framing.
    ///
    /// # Specification
    /// - ensures: consumes exactly the named extent on success.
    /// - fails: an incomplete field leaves the cursor unchanged.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WireError::Truncated`]: fewer than the named bytes remain.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — truncated commitment bodies cannot become valid
    ///   manifests.
    /// - witness: `manifest::tests::a_foreign_kind_layout_or_commitment_is_refused_before_any_node`
    #[spec(captures: before = self.0.len(), ensures: |ret| match ret {
        Ok(body) => body.0.len() == length.0 && arith::checked_add(Int::from(self.0.len()), Int::from(length.0)).map(usize::from) == Ok(before),
        Err(_) => self.0.len() == before,
    })]
    pub(crate) fn take(
        &mut self,
        length: Length,
    ) -> Result<Body<'image>, WireError>
    {
        let (bytes, remaining) = self
            .0
            .split_at_checked(length.0)
            .ok_or(WireError::Truncated)?;
        self.0 = remaining;
        Ok(Body(bytes))
    }

    /// Read a length-prefixed byte field without allocating its body.
    ///
    /// # Specification
    /// - ensures: success consumes the four-byte length and exactly its body.
    /// - fails: a short header or body is refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WireError`]: incomplete framing or an unrepresentable length.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — bounded answer parsing rejects an over-cap image.
    /// - witness: `stream::tests::an_answer_at_the_cap_is_read_and_one_byte_past_is_refused`
    pub(crate) fn framed(&mut self) -> Result<Body<'image>, WireError>
    {
        let Fixed(bytes) = self.fixed::<4>()?;
        let length =
            usize::try_from(u32::from_le_bytes(bytes)).map_err(|_width| WireError::Length)?;
        self.take(Length(length))
    }

    /// Require the final field to end the image.
    ///
    /// # Specification
    /// - ensures: succeeds exactly when no unread bytes remain.
    /// - fails: trailing bytes are refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WireError::Trailing`]: unread bytes remain.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — appending one byte invalidates a manifest.
    /// - witness: `manifest::tests::a_foreign_kind_layout_or_commitment_is_refused_before_any_node`
    #[spec(ensures: |ret| ret.is_ok() == self.0.is_empty())]
    pub(crate) fn finish(self) -> Result<(), WireError>
    {
        if self.0.is_empty() {
            Ok(())
        }
        else {
            Err(WireError::Trailing)
        }
    }
}
