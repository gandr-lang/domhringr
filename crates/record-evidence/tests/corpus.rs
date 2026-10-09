//! The evidence profile's measurement, pinned: the chunker commitment, and the
//! cuts of the checked-in corpus under it — each value's chunk count and the
//! size of every distinct chunk. The corpus is the reports, verifier outputs
//! and transcripts the tree's tests and the operator loop produce, frozen
//! under `tests/corpus`; the README states the measurement this pins.

extern crate alloc;

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeMap;
    use alloc::collections::BTreeSet;
    use std::path::Path;

    use domhringr_record_evidence::Staged;
    use domhringr_record_evidence::profile;
    use domhringr_record_tree::Content;
    use gandr_storage_values::CodecId;
    use gandr_storage_values::CodecIdentity;
    use gandr_storage_values::CodecVersion;

    #[test]
    fn the_commitment_is_pinned()
    {
        // The chunker commitment is the parameter domain, the typed profile's
        // discriminator 2, then kappa 64 (0x40) and the cap 512 (0x0200), each
        // a little-endian u64.
        let mut expected = b"gandr:storage-chunker:params:v1".to_vec();
        expected.extend_from_slice(&[0x02, 0x00]);
        expected.extend_from_slice(&[0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        expected.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(profile().chunker_commitment().as_ref(), expected.as_slice());
        assert_eq!(
            profile().codec(),
            CodecIdentity::new(CodecId::from(1_u16), CodecVersion::from(1_u16))
        );
    }

    #[test]
    fn the_cuts_of_the_corpus_are_pinned()
    {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("corpus");
        let mut names = std::fs::read_dir(&corpus)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        let mut bytes = 0_usize;
        let mut counts = Vec::new();
        let mut sizes = BTreeMap::new();
        let mut closures = BTreeMap::new();
        for name in &names {
            let content = std::fs::read(corpus.join(name)).unwrap();
            bytes = bytes.checked_add(content.len()).unwrap();
            let staged = Staged::new(&Content::from(content)).unwrap();
            let closure = staged
                .chunks()
                .map(|(digest, image)| {
                    let _size = sizes.insert(digest, image.as_ref().len());
                    digest
                })
                .collect::<BTreeSet<_>>();
            counts.push((name.as_str(), closure.len()));
            let _closure = closures.insert(name.as_str(), closure);
        }

        assert_eq!((names.len(), bytes), (21, 203_337), "the corpus is frozen");
        // Where values are cut is protocol: these counts are what every
        // manifest committed under the profile is made of.
        assert_eq!(counts, [
            ("output-empty", 1),
            ("output-failing", 1),
            ("output-nextest", 3),
            ("report-branch", 1),
            ("report-echo", 1),
            ("transcript-ci-shape-met", 2),
            ("transcript-ci-shape-unmet", 1),
            ("transcript-code-change", 27),
            ("transcript-code-met", 2),
            ("transcript-code-unmet", 1),
            ("transcript-docs-met", 2),
            ("transcript-docs-unmet", 2),
            ("transcript-issues-met", 1),
            ("transcript-issues-unmet", 1),
            ("transcript-public-private-stance-met", 1),
            ("transcript-public-private-stance-unmet", 1),
            ("transcript-pull-requests-met", 1),
            ("transcript-pull-requests-unmet", 1),
            ("transcript-stable-refs-change", 27),
            ("transcript-stable-refs-met", 1),
            ("transcript-stable-refs-unmet", 1),
        ]);
        let mut distinct = sizes.into_values().collect::<Vec<_>>();
        distinct.sort_unstable();
        assert_eq!(distinct, [
            50, 70, 121, 135, 229, 279, 410, 422, 496, 506, 646, 964, 1067, 1104, 1114, 1241, 1295,
            1321, 1392, 1403, 1535, 1536, 1559, 1567, 1592, 1597, 1637, 1680, 1738, 1987, 2027,
            2374, 2380, 2463, 2596, 3108, 3212, 3330, 3577, 3815, 3894, 4061, 5773, 7137, 7696,
            8137, 8516, 9257, 9926, 13372, 17974
        ]);
        let shared = closures["transcript-code-change"]
            .intersection(&closures["transcript-stable-refs-change"])
            .count();
        assert_eq!(
            shared, 26,
            "two transcripts of one change share every chunk of its diff but the root"
        );
    }
}
