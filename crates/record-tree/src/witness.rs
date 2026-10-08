//! Witnesses: what names the candidate keys of a DNS name.
//!
//! A DNS name resolves to a tree only when two sides agree: a witness names
//! the tree's key for the name, and the tree's fold admits its owner's claim of
//! the name ([`Kind::Claim`]). The witness is never an authority on its own: a
//! compromised one can make a name fail, never point it at a tree that did not
//! claim it. The DNS witness reads the `_domhringr.<domain>` TXT records, one
//! tree per record of the form `tree=<tree id>`; a witness supplied by hand is
//! a map.
//!
//! [`Kind::Claim`]: crate::receipt::Kind::Claim

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use core::fmt;

use crate::id::TREE_CHARACTERS;
use crate::id::TreeId;
use crate::name::Domain;

/// The label a domain's witness records sit beneath.
const WITNESS_LABEL: &str = "_domhringr";

/// The text a witness record begins with, the tree id following it.
const TREE_PREFIX: &[u8] = b"tree=";

/// What names the candidate trees of a DNS name.
pub trait Witness
{
    /// The trees the witness names for `domain`.
    ///
    /// # Specification
    /// - ensures: the set of trees the witness names for `domain`, empty when
    ///   it names none; naming a tree is no claim by it, so the set is
    ///   candidates only.
    /// - fails: [`WitnessError`] when the witness cannot be read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WitnessError`]: the witness cannot be read.
    fn lookup(
        &self,
        domain: &Domain,
    ) -> impl Future<Output = Result<BTreeSet<TreeId>, WitnessError>> + Send;
}

/// A witness supplied by hand: the trees each domain names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Static(BTreeMap<Domain, BTreeSet<TreeId>>);

impl FromIterator<(Domain, TreeId)> for Static
{
    /// A witness naming each pair's tree for its domain.
    ///
    /// # Specification
    /// - ensures: a domain names every tree a pair names for it, and no other;
    ///   a domain no pair names names none.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a domain named twice with two trees and once more
    ///   with a repeat names both, and a domain no pair names names none.
    /// - witness: `witness::tests::a_static_witness_names_what_it_was_given`
    #[inline]
    fn from_iter<Pairs>(iter: Pairs) -> Self
    where
        Pairs: IntoIterator<Item = (Domain, TreeId)>,
    {
        let mut trees: BTreeMap<Domain, BTreeSet<TreeId>> = BTreeMap::new();
        for (domain, tree) in iter {
            let _named_before = trees.entry(domain).or_default().insert(tree);
        }
        Self(trees)
    }
}

impl Witness for Static
{
    /// The trees the map holds for `domain`.
    ///
    /// # Specification
    /// - ensures: the trees the pairs named for `domain`, or none; a map is
    ///   read without failure, so the lookup is never an error.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the trees given for one domain are returned for it
    ///   and none for another.
    /// - witness: `witness::tests::a_static_witness_names_what_it_was_given`
    #[inline]
    fn lookup(
        &self,
        domain: &Domain,
    ) -> impl Future<Output = Result<BTreeSet<TreeId>, WitnessError>> + Send
    {
        core::future::ready(Ok(self.0.get(domain).cloned().unwrap_or_default()))
    }
}

/// The DNS witness: the `_domhringr.<domain>` TXT records, read through
/// iroh's resolver.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Dns(iroh::dns::DnsResolver);

impl Dns
{
    /// A witness over the host's DNS configuration, with public resolvers
    /// behind it as iroh configures them.
    ///
    /// # Specification
    /// - ensures: no query is made until a lookup.
    /// - panics: none.
    #[inline]
    #[must_use]
    pub fn system() -> Self
    {
        Self(iroh::dns::DnsResolver::new())
    }
}

impl Witness for Dns
{
    /// The trees the `_domhringr.<domain>` TXT records name.
    ///
    /// # Specification
    /// - ensures: queries the absolute name `_domhringr.<domain>.`, so no
    ///   search domain is appended, within iroh's DNS timeout, and returns one
    ///   tree per record whose text is `tree=` followed by a tree id
    ///   ([`named`]); a name with no records and a name that does not exist
    ///   both name none.
    /// - fails: [`WitnessError::Dns`] when the resolver fails otherwise: a
    ///   timeout, no response, a server failure.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`WitnessError::Dns`]: the lookup failed for a reason other than the
    ///   name's absence.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the text-to-tree parsing is witnessed without the
    ///   network; the lookup itself only against a real record, a test CI does
    ///   not run.
    /// - witness: `witness::tests::txt_records_name_the_trees_they_spell`
    /// - witness: `witness::tests::the_dns_witness_reads_a_real_record`
    #[inline]
    fn lookup(
        &self,
        domain: &Domain,
    ) -> impl Future<Output = Result<BTreeSet<TreeId>, WitnessError>> + Send
    {
        let name = WitnessName(domain);
        async move {
            match self.0.lookup_txt(name, iroh::dns::DNS_TIMEOUT).await {
                | Ok(records) => Ok(named(records)),
                | Err(iroh::dns::DnsError::NxDomain { .. }) => Ok(BTreeSet::new()),
                | Err(failure) => Err(WitnessError::Dns(failure)),
            }
        }
    }
}

/// The absolute name a domain's witness records sit at.
#[repr(transparent)]
struct WitnessName<'domain>(&'domain Domain);

impl fmt::Display for WitnessName<'_>
{
    /// Write `_domhringr.<domain>.`, the trailing dot making it absolute.
    ///
    /// # Specification
    /// trivial.
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        write!(f, "{WITNESS_LABEL}.{}.", self.0)
    }
}

/// What one TXT record says.
enum Record
{
    /// The record names this tree.
    Tree(TreeId),
    /// The record is not a tree record.
    Other,
}

/// The trees `records` name: one for each record whose text is `tree=`
/// followed by a tree id.
///
/// # Specification
/// - ensures: a record's text is its character strings joined; a record names a
///   tree exactly when that text is `tree=` followed by the 52 z-base-32
///   characters of a tree id, with nothing before or after, and every other
///   record is ignored; several records name several trees, and a tree named
///   twice is one.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — a record in one string and one split across strings name
///   their trees, a repeat collapses, and a record differing from a tree record
///   in one place — uppercase prefix, a space before or after, a short or long
///   id, an id spelling no key, another key-value pair — is ignored.
/// - witness: `witness::tests::txt_records_name_the_trees_they_spell`
fn named<Records>(records: Records) -> BTreeSet<TreeId>
where
    Records: IntoIterator<Item = iroh::dns::TxtRecordData>,
{
    records
        .into_iter()
        .filter_map(|record| match read(&record) {
            | Record::Tree(tree) => Some(tree),
            | Record::Other => None,
        })
        .collect()
}

/// Read one TXT record as a tree record or another.
///
/// # Specification
/// - ensures: [`Record::Tree`] exactly when the record's character strings,
///   joined, are `tree=` followed by a tree id's text; [`Record::Other`]
///   otherwise. No allocation: the joined text is compared and copied into a
///   fixed buffer as it is read.
/// - panics: none.
fn read(record: &iroh::dns::TxtRecordData) -> Record
{
    let mut bytes = record.iter().flatten().copied();
    if !TREE_PREFIX
        .iter()
        .all(|expected| bytes.next() == Some(*expected))
    {
        return Record::Other;
    }
    let mut id = [0_u8; TREE_CHARACTERS];
    for slot in &mut id {
        let Some(byte) = bytes.next()
        else {
            return Record::Other;
        };
        *slot = byte;
    }
    if bytes.next().is_some() {
        return Record::Other;
    }
    let tree = core::str::from_utf8(&id).map(str::parse::<TreeId>);
    match tree {
        | Ok(Ok(tree)) => Record::Tree(tree),
        | Ok(Err(_)) | Err(_) => Record::Other,
    }
}

/// Why a witness cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError
{
    /// The DNS lookup failed for a reason other than the name's absence.
    #[error("the DNS lookup failed")]
    Dns(#[source] iroh::dns::DnsError),
}

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeSet;
    use alloc::string::String;

    use super::Dns;
    use super::Static;
    use super::Witness as _;
    use super::named;
    use crate::id::TreeId;
    use crate::name::Domain;
    use crate::testing::elsewhere_key;
    use crate::testing::runtime;
    use crate::testing::tree_key;

    /// The variable naming the real record the DNS witness is tested
    /// against, as `<domain>=<tree id>`.
    const REAL_RECORD: &str = "DOMHRINGR_WITNESS";

    #[test]
    fn txt_records_name_the_trees_they_spell()
    {
        let record = |strings: &[&str]| {
            let strings = strings.iter().map(|&text| String::from(text));
            iroh::dns::TxtRecordData::from(strings.collect::<Vec<_>>())
        };
        let (a, b) = (tree_key().tree(), elsewhere_key().tree());
        let (a_text, b_text) = (a.to_string(), b.to_string());
        let whole = format!("tree={a_text}");
        let (head, tail) = b_text.split_at(20);
        let named_trees = named([
            record(&[whole.as_str()]),
            record(&["tree=", head, tail]),
            record(&[whole.as_str()]),
        ]);
        assert_eq!(
            named_trees,
            BTreeSet::from([a, b]),
            "a whole and a split record each name a tree, and a repeat is one"
        );
        let (short, _last) = a_text.split_at(51);
        let ignored = [
            format!("TREE={a_text}"),
            format!(" tree={a_text}"),
            format!("tree={a_text} "),
            format!("tree= {a_text}"),
            format!("tree={short}"),
            format!("tree={a_text}y"),
            format!("tree={short}b"),
            format!("v=spf1 tree={a_text}"),
            String::from("tree="),
            String::new(),
        ];
        for text in ignored {
            assert_eq!(
                named([record(&[text.as_str()])]),
                BTreeSet::new(),
                "{text:?} is not a tree record"
            );
        }
        assert_eq!(
            named([record(&[whole.as_str()]), record(&["other=1"])]),
            BTreeSet::from([a]),
            "a record that is not a tree record is ignored beside one that is"
        );
    }

    #[test]
    fn a_static_witness_names_what_it_was_given()
    {
        let (a, b) = (tree_key().tree(), elsewhere_key().tree());
        let domain = |text: &str| text.parse::<Domain>().unwrap();
        let witness = [
            (domain("example.test"), a),
            (domain("example.test"), b),
            (domain("example.test"), a),
            (domain("other.test"), b),
        ]
        .into_iter()
        .collect::<Static>();
        runtime().block_on(async {
            assert_eq!(
                witness.lookup(&domain("example.test")).await.unwrap(),
                BTreeSet::from([a, b]),
                "both trees given for the domain"
            );
            assert_eq!(
                witness.lookup(&domain("other.test")).await.unwrap(),
                BTreeSet::from([b]),
                "the one tree given for the other"
            );
            assert_eq!(
                witness.lookup(&domain("unnamed.test")).await.unwrap(),
                BTreeSet::new(),
                "a domain no pair names names none"
            );
        });
    }

    #[test]
    #[ignore = "reads a real `_domhringr` TXT record named by DOMHRINGR_WITNESS"]
    fn the_dns_witness_reads_a_real_record()
    {
        let real = std::env::var(REAL_RECORD).unwrap_or_else(|_unset| {
            panic!("{REAL_RECORD} is unset: set it to <domain>=<tree id> of a published record")
        });
        let (domain, tree) = real
            .split_once('=')
            .unwrap_or_else(|| panic!("{REAL_RECORD} is <domain>=<tree id>: {real:?}"));
        let domain = domain.parse::<Domain>().unwrap();
        let tree = tree.parse::<TreeId>().unwrap();
        let named_trees = runtime().block_on(Dns::system().lookup(&domain)).unwrap();
        assert!(
            named_trees.contains(&tree),
            "_domhringr.{domain} names {tree}: {named_trees:?}"
        );
    }
}
