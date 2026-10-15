//! Canonical standings carried by derived project entries.
//!
//! Constructors: current = 1 undispatched | 2 attempt; slot = 1 held | 2
//! retired; answer = 1 awaited | 2 reported; progress = 1 unchecked | 2
//! verified | 3 graded | 4 decided | 5 landed. Attempt fields follow their
//! declaration order. Identity fields are bytes; edition is a word.

use gandr_storage_values::CanonicalValue;
use gandr_storage_values::CanonicalWord;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;

use super::Answer;
use super::Attempt;
use super::Brief;
use super::Current;
use super::Progress;
use super::Slot;
use crate::Decision;
use crate::Edition;
use crate::Grade;
use crate::receipt::Opened;

impl CanonicalValue for Current
{
    /// Encode the complete standing, including the slot behind its display.
    ///
    /// # Specification
    /// - ensures: one balanced constructor preserves every current field.
    /// - fails: propagates a sink refusal.
    /// - panics: none.
    /// - executable: none — the generic token sink is write-only; complete
    ///   standing round-trips observe every encoded field.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a token.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — combinations of slot, answer and progress round-trip.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            Self::Undispatched => sink.open(ConstructorTag::from(1))?,
            Self::Attempt(ref attempt) => {
                sink.open(ConstructorTag::from(2))?;
                sink.bytes(TokenBytes::from(attempt.dispatch.as_bytes().as_slice()))?;
                sink.word(CanonicalWord::from(u64::from(attempt.edition)))?;
                attempt.brief.emit_tokens(sink)?;
                attempt.slot.emit_tokens(sink)?;
                attempt.answer.emit_tokens(sink)?;
                attempt.progress.emit_tokens(sink)?;
            },
        }
        sink.close()
    }

    /// Decode the complete standing, without interpreting the claim.
    ///
    /// # Specification
    /// - ensures: reads precisely the fields emitted by this codec.
    /// - fails: refuses unknown constructors and malformed fields.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the complete
    ///   standing round-trip and unknown-constructor fixture are the oracle.
    ///
    /// # Errors
    /// - [`ValueError`]: invalid constructor, payload or framing.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — field combinations and unknown constructors are
    ///   covered.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let current = match u8::from(opened.tag) {
            1 => Self::Undispatched,
            2 => {
                let dispatch = opened.commit(reader)?;
                let edition = reader.read_word()?;
                let edition = Edition::from(u64::from(edition));
                let brief = Brief::decode_tokens(reader)?;
                let slot = Slot::decode_tokens(reader)?;
                let answer = Answer::decode_tokens(reader)?;
                let progress = Progress::decode_tokens(reader)?;
                Self::Attempt(Attempt {
                    dispatch,
                    edition,
                    brief,
                    slot,
                    answer,
                    progress,
                })
            },
            _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(current)
    }
}

impl CanonicalValue for Slot
{
    /// Encode the holder and, when retired, the retirement's identity.
    ///
    /// # Specification
    /// - ensures: preserves holder, retirement and constructor.
    /// - fails: propagates the sink refusal.
    /// - panics: none.
    /// - executable: none — the generic token sink is write-only; complete
    ///   standing round-trips observe every encoded field.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a token.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — both slots survive a complete standing round-trip.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            Self::Held(holder) => {
                sink.open(ConstructorTag::from(1))?;
                sink.bytes(TokenBytes::from(holder.peer_id().as_bytes().as_slice()))?;
            },
            Self::Retired { by, at } => {
                sink.open(ConstructorTag::from(2))?;
                sink.bytes(TokenBytes::from(by.peer_id().as_bytes().as_slice()))?;
                sink.bytes(TokenBytes::from(at.as_bytes().as_slice()))?;
            },
        }
        sink.close()
    }

    /// Read the slot without assigning authority to its holder.
    ///
    /// # Specification
    /// - ensures: reads the emitted slot exactly.
    /// - fails: unknown tags and malformed identity fields are refused.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the complete
    ///   standing round-trip and unknown-constructor fixture are the oracle.
    ///
    /// # Errors
    /// - [`ValueError`]: invalid constructor, payload or framing.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — both variants retain their identities.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let slot = match u8::from(opened.tag) {
            1 => {
                let peer = opened.peer(reader)?;
                Self::Held(peer)
            },
            2 => {
                let by = opened.peer(reader)?;
                let at = opened.commit(reader)?;
                Self::Retired { by, at }
            },
            _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(slot)
    }
}

impl CanonicalValue for Answer
{
    /// Encode the optional report identity.
    ///
    /// # Specification
    /// - ensures: distinguishes awaited from every reported identity.
    /// - fails: propagates the sink refusal.
    /// - panics: none.
    /// - executable: none — the generic token sink is write-only; complete
    ///   standing round-trips observe every encoded field.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a token.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — each answer survives a standing round-trip.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            Self::Awaited => sink.open(ConstructorTag::from(1))?,
            Self::Reported(report) => {
                sink.open(ConstructorTag::from(2))?;
                sink.bytes(TokenBytes::from(report.as_bytes().as_slice()))?;
            },
        }
        sink.close()
    }

    /// Read the answer's constructor and report identity.
    ///
    /// # Specification
    /// - ensures: reads the emitted answer exactly.
    /// - fails: unknown tags and malformed identity fields are refused.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the complete
    ///   standing round-trip and unknown-constructor fixture are the oracle.
    ///
    /// # Errors
    /// - [`ValueError`]: invalid constructor, payload or framing.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — each answer retains its identity.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let answer = match u8::from(opened.tag) {
            1 => Self::Awaited,
            2 => {
                let commit = opened.commit(reader)?;
                Self::Reported(commit)
            },
            _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(answer)
    }
}

impl CanonicalValue for Progress
{
    /// Encode the exact milestone, including its decision or grade.
    ///
    /// # Specification
    /// - ensures: preserves every progress field under a distinct constructor.
    /// - fails: propagates the sink refusal.
    /// - panics: none.
    /// - executable: none — the generic token sink is write-only; complete
    ///   standing round-trips observe every encoded field.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a token.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every milestone and payload round-trips.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            Self::Unchecked => sink.open(ConstructorTag::from(1))?,
            Self::Verified(commit) => {
                sink.open(ConstructorTag::from(2))?;
                sink.bytes(TokenBytes::from(commit.as_bytes().as_slice()))?;
            },
            Self::Graded { grading, composed } => {
                sink.open(ConstructorTag::from(3))?;
                sink.bytes(TokenBytes::from(grading.as_bytes().as_slice()))?;
                composed.emit_tokens(sink)?;
            },
            Self::Decided {
                decide,
                ref decision,
            } => {
                sink.open(ConstructorTag::from(4))?;
                sink.bytes(TokenBytes::from(decide.as_bytes().as_slice()))?;
                decision.emit_tokens(sink)?;
            },
            Self::Landed { landed, merge } => {
                sink.open(ConstructorTag::from(5))?;
                sink.bytes(TokenBytes::from(landed.as_bytes().as_slice()))?;
                sink.bytes(TokenBytes::from(merge.as_ref()))?;
            },
        }
        sink.close()
    }

    /// Decode a milestone as a claim, leaving validation to re-derivation.
    ///
    /// # Specification
    /// - ensures: reads the emitted progress exactly.
    /// - fails: unknown tags and malformed fields are refused.
    /// - panics: none.
    /// - executable: none — the function is its own specification; the complete
    ///   standing round-trip and unknown-constructor fixture are the oracle.
    ///
    /// # Errors
    /// - [`ValueError`]: invalid constructor, payload or framing.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every milestone retains its fields.
    /// - witness: `task::codec::tests::every_standing_preserves_its_fields`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let opened = Opened::read(reader)?;
        let progress = match u8::from(opened.tag) {
            1 => Self::Unchecked,
            2 => {
                let commit = opened.commit(reader)?;
                Self::Verified(commit)
            },
            3 => {
                let grading = opened.commit(reader)?;
                let composed = Grade::decode_tokens(reader)?;
                Self::Graded { grading, composed }
            },
            4 => {
                let decide = opened.commit(reader)?;
                let decision = Decision::decode_tokens(reader)?;
                Self::Decided { decide, decision }
            },
            5 => {
                let landed = opened.commit(reader)?;
                let merge = opened.revision(reader)?;
                Self::Landed { landed, merge }
            },
            _unknown => return Err(opened.refused()),
        };
        reader.read_close()?;
        Ok(progress)
    }
}

#[cfg(test)]
mod tests
{
    use gandr_storage_values::TokenBody;
    use gandr_storage_values::decode_flat;
    use gandr_storage_values::encode_flat;

    use super::Answer;
    use super::Attempt;
    use super::Brief;
    use super::Current;
    use super::Decision;
    use super::Edition;
    use super::Grade;
    use super::Progress;
    use super::Slot;
    use super::ValueError;
    use crate::CommitId;
    use crate::ContentHash;
    use crate::Revision;
    use crate::testing::owner;

    #[test]
    fn every_standing_preserves_its_fields()
    {
        let commit = CommitId::new([5; 32]);
        let held = crate::testing::key(&owner());
        let flat = encode_flat(&Current::Undispatched).unwrap();
        assert_eq!(
            decode_flat::<Current>(flat.as_body()).unwrap(),
            Current::Undispatched
        );
        for slot in [Slot::Held(held), Slot::Retired {
            by: held,
            at: commit,
        }] {
            for answer in [Answer::Awaited, Answer::Reported(commit)] {
                for progress in [
                    Progress::Unchecked,
                    Progress::Verified(commit),
                    Progress::Graded {
                        grading: commit,
                        composed: Grade::Met,
                    },
                    Progress::Decided {
                        decide: commit,
                        decision: Decision::Land,
                    },
                    Progress::Decided {
                        decide: commit,
                        decision: Decision::Rework {
                            reason: "revise".parse().unwrap(),
                        },
                    },
                    Progress::Decided {
                        decide: commit,
                        decision: Decision::Abandon,
                    },
                    Progress::Landed {
                        landed: commit,
                        merge: Revision::Sha1([6; 20]),
                    },
                    Progress::Landed {
                        landed: commit,
                        merge: Revision::Sha256([7; 32]),
                    },
                ] {
                    let current = Current::Attempt(Attempt {
                        dispatch: commit,
                        edition: Edition::TWO,
                        brief: Brief::Content(ContentHash::from(blake3::hash(b"brief"))),
                        slot,
                        answer,
                        progress,
                    });
                    let flat = encode_flat(&current).unwrap();
                    assert_eq!(decode_flat::<Current>(flat.as_body()).unwrap(), current);
                    let mut malformed = flat.as_ref().to_vec();
                    malformed[1] = 99;
                    assert!(matches!(
                        decode_flat::<Current>(TokenBody::from(malformed.as_slice())),
                        Err(ValueError::UnexpectedConstructor { .. })
                    ));
                }
            }
        }
    }
}
