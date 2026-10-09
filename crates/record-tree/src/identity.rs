//! A peer's state directory, the two ed25519 identities kept in it, and the
//! keys of the trees the peer opened.
//!
//! The iroh endpoint key names the peer on the network; the subduction signer
//! authenticates its handshakes and signs its commits. The two are distinct
//! keys, created together on first use, stored as raw 32-byte seeds readable
//! by the owner alone, and never printed: only their public halves leave this
//! module.
//!
//! A tree key is minted when the peer opens a tree, one file per tree in the
//! same shape, named by the tree id: its verifying key is the tree id, and it
//! signs the proof the tree's Open carries ([`TreeKey::prove`]).

use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use subduction_core::peer::id::PeerId;
use subduction_crypto::signer::memory::MemorySigner;

use crate::id::EndpointKey;
use crate::id::PeerKey;
use crate::id::TreeId;
use crate::receipt::OpenProof;

/// Directory, beneath the state directory, holding the key files.
const IDENTITY_DIR: &str = "identity";

/// Directory, beneath the state directory, holding one key file per tree the
/// peer opened.
const TREE_KEY_DIR: &str = "tree-keys";

/// The extension of a tree's key file, whose stem is the tree id.
const TREE_KEY_EXTENSION: &str = "key";

/// Directory, beneath the state directory, holding the tree store.
const STORE_DIR: &str = "store";

/// Directory, beneath the state directory, holding the evidence store.
const EVIDENCE_DIR: &str = "evidence";

/// Key file holding the iroh endpoint seed.
const ENDPOINT_KEY_FILE: &str = "endpoint.key";

/// Key file holding the subduction signer seed.
const SIGNER_KEY_FILE: &str = "signer.key";

/// A peer's state directory: its identity, its tree keys, its tree store and
/// its evidence store live beneath it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct StateDir(PathBuf);

impl From<PathBuf> for StateDir
{
    /// Take a path as a state directory.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(path: PathBuf) -> Self
    {
        Self(path)
    }
}

impl StateDir
{
    /// The directory holding the key files.
    ///
    /// # Specification
    /// trivial.
    fn identity_dir(&self) -> PathBuf
    {
        self.0.join(IDENTITY_DIR)
    }

    /// The directory holding the tree keys.
    ///
    /// # Specification
    /// trivial.
    fn tree_key_dir(&self) -> PathBuf
    {
        self.0.join(TREE_KEY_DIR)
    }

    /// The directory holding the tree store.
    ///
    /// # Specification
    /// trivial.
    pub(crate) fn store_dir(&self) -> PathBuf
    {
        self.0.join(STORE_DIR)
    }

    /// The directory holding the evidence store: the value plane's chunks and
    /// manifests for the content receipts name.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn evidence_dir(&self) -> PathBuf
    {
        self.0.join(EVIDENCE_DIR)
    }
}

/// The two ed25519 keys a peer is known by.
#[derive(Clone)]
pub struct Identity
{
    /// The iroh endpoint's secret key.
    endpoint: iroh::SecretKey,
    /// The subduction handshake and commit signer.
    signer: MemorySigner,
}

impl Identity
{
    /// Read the peer's identity from its state directory, creating each key
    /// that is absent.
    ///
    /// # Specification
    /// - ensures: on success both key files exist beneath `state`, each holding
    ///   exactly one 32-byte seed; a key file present before the call is read
    ///   and never rewritten, so a peer keeps its ids across runs.
    /// - ensures: a created key file is fresh randomness from the operating
    ///   system, opened exclusively (an existing file is never clobbered),
    ///   synced to disk before the call returns, and on Unix readable and
    ///   writable by its owner alone.
    /// - fails: [`IdentityError::Malformed`] when a key file holds anything but
    ///   32 bytes, including a file a concurrent first run has created but not
    ///   yet written; the identity is never regenerated over it.
    /// - fails: [`IdentityError::Directory`], [`IdentityError::Read`] and
    ///   [`IdentityError::Write`] carry the path and the I/O error.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`IdentityError::Directory`]: the identity directory cannot be
    ///   created.
    /// - [`IdentityError::Read`]: a key file exists but cannot be read.
    /// - [`IdentityError::Write`]: a missing key file cannot be created or
    ///   written.
    /// - [`IdentityError::Malformed`]: a key file is not a 32-byte seed.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a first call against an empty directory, a second
    ///   call against the files it left, and a call against a truncated key
    ///   file separate creation, persistence and refusal; the ids before and
    ///   after are compared exactly, and the created files' mode is read back.
    /// - witness: `identity::tests::an_identity_is_created_once_and_read_back`
    /// - witness: `identity::tests::a_truncated_key_file_is_refused`
    #[inline]
    pub fn load_or_create(state: &StateDir) -> Result<Self, IdentityError>
    {
        let directory = state.identity_dir();
        std::fs::create_dir_all(&directory).map_err(|source| IdentityError::Directory {
            path: directory.clone(),
            source,
        })?;
        let endpoint = Seed::load_or_create(&directory.join(ENDPOINT_KEY_FILE))?;
        let signer = Seed::load_or_create(&directory.join(SIGNER_KEY_FILE))?;
        Ok(Self {
            endpoint: iroh::SecretKey::from_bytes(&endpoint.0),
            signer: MemorySigner::from_bytes(&signer.0),
        })
    }

    /// The iroh endpoint id the peer is dialed by.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn endpoint_key(&self) -> EndpointKey
    {
        EndpointKey::new(self.endpoint.public())
    }

    /// The subduction peer id the peer authenticates as.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn peer_key(&self) -> PeerKey
    {
        PeerKey::new(PeerId::from(self.signer.verifying_key()))
    }

    /// The iroh endpoint's secret key.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn endpoint_secret(&self) -> &iroh::SecretKey
    {
        &self.endpoint
    }

    /// The subduction signer.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn signer(&self) -> &MemorySigner
    {
        &self.signer
    }
}

/// The signing key of a tree this peer opened: the tree id is its verifying
/// key, so only its holder can make the proof the tree's Open carries.
#[repr(transparent)]
pub struct TreeKey(iroh::SecretKey);

impl TreeKey
{
    /// Mint a fresh tree key and keep it in the state directory.
    ///
    /// # Specification
    /// - ensures: on success the key is fresh randomness, and a new file
    ///   beneath `state`, named by the key's tree id, holds its 32-byte seed:
    ///   created exclusively (an existing file is never clobbered), synced to
    ///   disk before the call returns, and on Unix readable and writable by its
    ///   owner alone, as an identity's key files are.
    /// - fails: [`IdentityError::Directory`] when the key directory cannot be
    ///   created and [`IdentityError::Write`] when the key file cannot be
    ///   created or written, each carrying the path and the I/O error.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`IdentityError::Directory`]: the key directory cannot be created.
    /// - [`IdentityError::Write`]: the key file cannot be created or written.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two keys minted in one directory differ, and each
    ///   file is read back by its tree id's name: its length, its mode, and the
    ///   verifying key of the seed it holds, compared with the tree id.
    /// - witness: `identity::tests::a_minted_tree_key_is_kept_under_its_tree_id`
    #[inline]
    pub fn mint(state: &StateDir) -> Result<Self, IdentityError>
    {
        let directory = state.tree_key_dir();
        std::fs::create_dir_all(&directory).map_err(|source| IdentityError::Directory {
            path: directory.clone(),
            source,
        })?;
        let seed = Seed::fresh();
        let key = iroh::SecretKey::from_bytes(&seed.0);
        let tree = TreeId::new(key.public());
        seed.store(&directory.join(format!("{tree}.{TREE_KEY_EXTENSION}")))?;
        Ok(Self(key))
    }

    /// Take an ed25519 secret key as a tree key, kept nowhere.
    ///
    /// # Specification
    /// trivial.
    #[cfg(test)]
    pub(crate) const fn new(key: iroh::SecretKey) -> Self
    {
        Self(key)
    }

    /// The tree this key names: its verifying key.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn tree(&self) -> TreeId
    {
        TreeId::new(self.0.public())
    }

    /// The proof that this key names `owner` the tree's owner.
    ///
    /// # Specification
    /// - ensures: the proof verifies under [`TreeKey::tree`] for `owner`, and
    ///   for no other peer key and under no other tree id
    ///   ([`OpenProof::verify`]).
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the fold admits an Open whose proof this key made for
    ///   the Open's author, and refuses one this key made for another author
    ///   and one another key made.
    /// - witness: `fold::tests::an_open_proved_by_another_key_is_refused`
    #[inline]
    #[must_use]
    pub fn prove(
        &self,
        owner: PeerKey,
    ) -> OpenProof
    {
        OpenProof::sign(&self.0, owner)
    }
}

/// Why a peer's identity cannot be read or created, or a tree key minted.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError
{
    /// A key directory cannot be created.
    #[error("cannot create the key directory {}", path.display())]
    Directory
    {
        /// The directory.
        path: PathBuf,
        /// The I/O failure.
        source: io::Error,
    },
    /// A key file exists but cannot be read.
    #[error("cannot read the key file {}", path.display())]
    Read
    {
        /// The key file.
        path: PathBuf,
        /// The I/O failure.
        source: io::Error,
    },
    /// A missing key file cannot be created or written.
    #[error("cannot create the key file {}", path.display())]
    Write
    {
        /// The key file.
        path: PathBuf,
        /// The I/O failure.
        source: io::Error,
    },
    /// A key file is not a 32-byte seed.
    #[error("the key file {} is not a 32-byte ed25519 seed", path.display())]
    Malformed
    {
        /// The key file.
        path: PathBuf,
    },
}

/// An ed25519 secret seed.
#[repr(transparent)]
struct Seed([u8; 32]);

impl Seed
{
    /// Read the seed in `path`, or create the file with a fresh one.
    ///
    /// # Specification
    /// - ensures: an existing file is read and never rewritten; a missing one
    ///   is created exclusively, written, and synced before the seed is
    ///   returned.
    /// - fails: as [`Identity::load_or_create`], per file.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`IdentityError::Read`], [`IdentityError::Write`],
    ///   [`IdentityError::Malformed`], each carrying `path`.
    fn load_or_create(path: &Path) -> Result<Self, IdentityError>
    {
        match std::fs::read(path) {
            | Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                | Ok(seed) => Ok(Self(seed)),
                | Err(_wrong_length) => Err(IdentityError::Malformed {
                    path: path.to_path_buf(),
                }),
            },
            | Err(error) if error.kind() == io::ErrorKind::NotFound => Self::create(path),
            | Err(source) => Err(IdentityError::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Create `path` exclusively and write a fresh seed into it.
    ///
    /// # Specification
    /// - ensures: the file did not exist, now holds the returned seed, and is
    ///   synced; on Unix its mode is `0600`.
    /// - fails: [`IdentityError::Write`] carrying `path` when the file exists
    ///   already or cannot be written.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`IdentityError::Write`]: the exclusive create, the write or the sync
    ///   fails.
    fn create(path: &Path) -> Result<Self, IdentityError>
    {
        let seed = Self::fresh();
        seed.store(path)?;
        Ok(seed)
    }

    /// A fresh seed from the operating system's random source.
    ///
    /// # Specification
    /// trivial.
    fn fresh() -> Self
    {
        Self(iroh::SecretKey::generate().to_bytes())
    }

    /// Create `path` exclusively and write this seed into it.
    ///
    /// # Specification
    /// - ensures: the file did not exist, now holds the seed, and is synced; on
    ///   Unix its mode is `0600`.
    /// - fails: [`IdentityError::Write`] carrying `path` when the file exists
    ///   already or cannot be written.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`IdentityError::Write`]: the exclusive create, the write or the sync
    ///   fails.
    fn store(
        &self,
        path: &Path,
    ) -> Result<(), IdentityError>
    {
        Self::write_new(path, self).map_err(|source| IdentityError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Write `seed` into a file that must not exist yet, and sync it.
    ///
    /// # Specification
    /// - ensures: the file is created exclusively, holds `seed`, and is synced
    ///   to disk; on Unix its mode is `0600`.
    /// - fails: the underlying I/O error, including `AlreadyExists`.
    /// - panics: none.
    ///
    /// # Errors
    /// - any I/O error from the exclusive create, the write or the sync.
    fn write_new(
        path: &Path,
        seed: &Self,
    ) -> io::Result<()>
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(path)?;
        file.write_all(&seed.0)?;
        file.sync_all()
    }
}

#[cfg(test)]
mod tests
{
    use super::ENDPOINT_KEY_FILE;
    use super::IDENTITY_DIR;
    use super::Identity;
    use super::IdentityError;
    use super::SIGNER_KEY_FILE;
    use super::StateDir;
    use super::TREE_KEY_DIR;
    use super::TreeKey;
    use crate::id::TreeId;

    #[test]
    fn an_identity_is_created_once_and_read_back()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let first = Identity::load_or_create(&state).unwrap();
        let second = Identity::load_or_create(&state).unwrap();
        assert_eq!(
            first.endpoint_key(),
            second.endpoint_key(),
            "the endpoint id persists"
        );
        assert_eq!(first.peer_key(), second.peer_key(), "the peer id persists");
        assert_ne!(
            first.endpoint_key().endpoint_id().as_bytes(),
            first.peer_key().peer_id().as_bytes(),
            "the endpoint key and the signer are distinct keys"
        );
        let directory = root.path().join(IDENTITY_DIR);
        for name in [ENDPOINT_KEY_FILE, SIGNER_KEY_FILE] {
            let metadata = std::fs::metadata(directory.join(name)).unwrap();
            assert_eq!(metadata.len(), 32, "{name} holds one seed");
            #[cfg(unix)]
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o777,
                0o600,
                "{name} is private to its owner"
            );
        }
    }

    #[test]
    fn a_truncated_key_file_is_refused()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let directory = root.path().join(IDENTITY_DIR);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(ENDPOINT_KEY_FILE), [1_u8; 31]).unwrap();
        let refused = Identity::load_or_create(&state);
        assert!(
            matches!(refused, Err(IdentityError::Malformed { ref path }) if path.ends_with(ENDPOINT_KEY_FILE)),
            "a 31-byte key file is refused, naming the file"
        );
        assert_eq!(
            std::fs::read(directory.join(ENDPOINT_KEY_FILE)).unwrap(),
            [1_u8; 31],
            "the refused file is left as it was"
        );
    }

    #[test]
    fn a_minted_tree_key_is_kept_under_its_tree_id()
    {
        let root = tempfile::tempdir().unwrap();
        let state = StateDir::from(root.path().to_path_buf());
        let first = TreeKey::mint(&state).unwrap();
        let second = TreeKey::mint(&state).unwrap();
        assert_ne!(first.tree(), second.tree(), "each mint is a fresh key");
        for key in [first, second] {
            let path = root
                .path()
                .join(TREE_KEY_DIR)
                .join(format!("{}.key", key.tree()));
            let seed = <[u8; 32]>::try_from(std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                TreeId::new(iroh::SecretKey::from_bytes(&seed).public()),
                key.tree(),
                "the file named by the tree id holds the seed whose verifying key it is"
            );
            #[cfg(unix)]
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(
                    &std::fs::metadata(&path).unwrap().permissions()
                ) & 0o777,
                0o600,
                "a tree key is private to its owner"
            );
        }
    }
}
