//! Structural key derivation for L2 read scoping — the Cryptree-style lower
//! tier of the retention key tree (whitepaper §4.3 + §5.1).
//!
//! A channel is a node in the key tree. Its data key is **derived** from the
//! space's current epoch data key (itself derived from the group key, §4.2) and
//! the channel identifier — realizing §5.1's *"data encryption key, derived from
//! the group key and the column's structural path."* Derivation is one-way:
//!
//! ```text
//!   group key ──(§4.2 temporal chain)──▶ epoch data key
//!                                            └──(structural, per channel)──▶ channel data key
//! ```
//!
//! A **full** member holds the group key, so it derives the epoch data key and
//! thus any channel's key for free. A **scoped** member is *delivered* only the
//! channel keys it may read and cannot invert the HKDF to recover the epoch key
//! or a sibling channel's key — *"granting access to a directory grants its whole
//! subtree"* while siblings stay unreachable (§4.3). This is the read plane only;
//! writes are governed by the L1 authorization plane (ACL predicates).

use encrypted_spaces_crypto::key_derivation::{
    DerivationKoalaBearPoseidon2_16, DerivationTag, KeyDerivation,
};
use encrypted_spaces_crypto::KeyMaterial;
use serde::{Deserialize, Serialize};

/// Domain-separation prefix for the structural (per-channel) subtree derivation.
const CHANNEL_ROOT_TAG_PREFIX: &str = "es:l2:channel-root:";
/// Domain-separation prefix for the per-channel AES data-key HKDF.
const CHANNEL_DATA_HKDF_PREFIX: &str = "es:l2:channel-data:";

/// Reserved channel value for the space's **root** line — the plane covering
/// channel-less/global tables, encrypted under the group's epoch key directly.
/// Real channels use their app `channel_id` (>= 0).
pub const ROOT_CHANNEL: i64 = i64::MIN;

/// Identifies a data key: which channel (or [`ROOT_CHANNEL`]) and which epoch
/// sequence. Embedded in each row's ciphertext header so the reader knows
/// whether to use the root line or derive a channel key, and at which epoch.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TreeKeyId {
    pub channel: i64,
    pub seq: u64,
}

impl TreeKeyId {
    pub fn new(channel: i64, seq: u64) -> Self {
        Self { channel, seq }
    }

    /// A key id on the root (global) line.
    pub fn root(seq: u64) -> Self {
        Self {
            channel: ROOT_CHANNEL,
            seq,
        }
    }

    pub fn is_root(&self) -> bool {
        self.channel == ROOT_CHANNEL
    }
}

impl std::fmt::Display for TreeKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_root() {
            write!(f, "root:{}", self.seq)
        } else {
            write!(f, "ch{}:{}", self.channel, self.seq)
        }
    }
}

impl encrypted_spaces_key_manager::KeyId for TreeKeyId {}

/// Derive a channel's **subtree key** from the group key and the channel id
/// (§4.3 "each directory key is derived from its parent's key"). Poseidon
/// derivation → a valid [`KeyMaterial`], so it can be mVE-delivered to a scoped
/// member. One-way: a holder cannot recover the group key or a sibling channel's
/// subtree key. A full member derives this from the group key; a scoped member
/// is delivered it.
pub fn channel_root(group_key: &KeyMaterial, channel: i64) -> KeyMaterial {
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let tag =
        DerivationTag::from_bytes(format!("{CHANNEL_ROOT_TAG_PREFIX}{channel}").as_bytes());
    derivation.derive(group_key, tag)
}

/// Derive a channel's **AES data key** at epoch sequence `seq` from its subtree
/// key (HKDF-SHA256 → arbitrary 32 bytes, fine for AES). Forward-derivable:
/// holding the subtree key yields every `seq` for that channel, so a scoped
/// member ratchets its channel without re-delivery each step.
pub fn channel_data_key(channel_root: &KeyMaterial, seq: u64) -> [u8; 32] {
    let info = format!("{CHANNEL_DATA_HKDF_PREFIX}{seq}");
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, channel_root.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut okm)
        .expect("HKDF expand to 32 bytes is infallible");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_roots_are_distinct_and_one_way() {
        let gk = KeyMaterial::random();
        let a1 = channel_root(&gk, 1);
        let a2 = channel_root(&gk, 1);
        let b = channel_root(&gk, 2);
        assert_eq!(a1.as_bytes(), a2.as_bytes(), "deterministic per channel");
        assert_ne!(a1.as_bytes(), b.as_bytes(), "distinct channels differ");
        assert_ne!(a1.as_bytes(), gk.as_bytes(), "differs from the group key");
    }

    #[test]
    fn channel_data_keys_derive_forward() {
        let root = channel_root(&KeyMaterial::random(), 1);
        assert_eq!(channel_data_key(&root, 0), channel_data_key(&root, 0));
        assert_ne!(channel_data_key(&root, 0), channel_data_key(&root, 1));
    }

    #[test]
    fn root_sentinel_never_collides_with_a_channel() {
        assert!(TreeKeyId::root(0).is_root());
        assert!(!TreeKeyId::new(0, 0).is_root());
        assert!(!TreeKeyId::new(5, 0).is_root());
    }
}
