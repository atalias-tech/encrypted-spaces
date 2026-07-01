//! `TreeSpaceKey` — L2 read scoping via Cryptree-style key **derivation**
//! (whitepaper §4.3 + §5.1), the read-plane counterpart to L1's write ACLs.
//!
//! A channel is a node in the retention key tree rooted at the current group
//! key. A row in channel `K` is encrypted under
//! `channel_data_key(epoch_data_key, K)` — derived from the space's epoch data
//! key (§4.2 temporal tier) and the channel (§4.3/§5.1 structural derivation).
//!
//! - A **full** member holds the group key (via [`SimpleLine2SpaceKey`]), so it
//!   resolves the epoch data key and derives **any** channel's key for free.
//! - A **scoped** member (e.g. an agent) holds **no** group key — only the
//!   channel keys delivered to it — so it reads exactly its granted channels and
//!   nothing else; derivation is one-way, so it cannot reach siblings or the root.
//!
//! Basic read scoping needs no on-chain per-channel state and no new op: it is
//! pure client-side derivation plus mVE delivery of subtree keys to scoped
//! members. Per-channel *deletion* (§4.3 "delete a directory") would later add
//! `KeyTreeTransition` proofs; it is intentionally out of scope here.

use std::collections::HashMap;

use async_trait::async_trait;
use encrypted_spaces_changelog_core::changelog::OpType;
use encrypted_spaces_crypto::{KeyCommitment, KeyMaterial};
use encrypted_spaces_key_manager::error::KeyManagerError;
use encrypted_spaces_key_manager::{
    GroupKeySync, OperationBuilder, OperationReader, SimpleKeyId, SpaceKey,
};
use serde::{Deserialize, Serialize};

use crate::simple_line2::{DefaultProver, SimpleLine2RuntimeProver, SimpleLine2SpaceKey};
use crate::tree_keys::{channel_data_key, channel_root, TreeKeyId};

/// The tree read plane. Either a full member (holds the group key) or a scoped
/// member (holds only delivered channel keys).
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")] // P lives only in skipped PhantomData inside the group line
pub struct TreeSpaceKey<P: SimpleLine2RuntimeProver = DefaultProver> {
    /// Group-key tier (§4.2): group key + temporal chain + rekey. `Some` for a
    /// full member (which derives every channel); `None` for a scoped member.
    group: Option<SimpleLine2SpaceKey<P>>,
    /// Delivered channel subtree keys (§4.3) — the channels a scoped member may
    /// read. Empty for a full member (it derives channels from `group`).
    #[serde(default)]
    channel_keys: HashMap<i64, KeyMaterial>,
}

impl<P: SimpleLine2RuntimeProver + Send + Sync> TreeSpaceKey<P> {
    /// Create a fresh full-member tree (initializes the group line).
    pub async fn new(builder: &mut dyn OperationBuilder) -> Result<Self, KeyManagerError> {
        Ok(Self {
            group: Some(SimpleLine2SpaceKey::new(builder).await?),
            channel_keys: HashMap::new(),
        })
    }

    /// Construct a **scoped** member holding only the given channel keys (no
    /// group key). Reads are cryptographically limited to these channels.
    pub fn scoped(channel_keys: impl IntoIterator<Item = (i64, KeyMaterial)>) -> Self {
        Self {
            group: None,
            channel_keys: channel_keys.into_iter().collect(),
        }
    }

    /// Whether this member holds the group key (full read access).
    pub fn is_full(&self) -> bool {
        self.group.is_some()
    }

    /// The explicit channel set a scoped member holds (empty for a full member).
    pub fn scoped_channels(&self) -> Vec<i64> {
        self.channel_keys.keys().copied().collect()
    }

    /// Derive a channel's subtree key from the current group key, for delivery
    /// to a scoped member (§4.3). Full members only (`None` for a scoped member,
    /// which holds no group key).
    ///
    /// Derived from the *current* group key (epoch). Reading a channel's data
    /// written under a previous group key (before a rekey) requires recovering
    /// that epoch's group key via the §4.2 encryption-edge chain — a tracked
    /// follow-up; not needed within an epoch.
    pub fn channel_subtree_key(&self, channel: i64) -> Option<KeyMaterial> {
        self.group
            .as_ref()
            .map(|g| channel_root(&g.current_group_key(), channel))
    }

    /// Install a delivered channel subtree key (scoped grant).
    pub fn install_channel_key(&mut self, channel: i64, key: KeyMaterial) {
        self.channel_keys.insert(channel, key);
    }

    /// Drop a channel subtree key — read revocation for this member.
    pub fn drop_channel_key(&mut self, channel: i64) {
        self.channel_keys.remove(&channel);
    }

    fn group_ref(&self) -> Result<&SimpleLine2SpaceKey<P>, KeyManagerError> {
        self.group.as_ref().ok_or(KeyManagerError)
    }

    fn group_mut(&mut self) -> Result<&mut SimpleLine2SpaceKey<P>, KeyManagerError> {
        self.group.as_mut().ok_or(KeyManagerError)
    }
}

#[async_trait]
impl<P: SimpleLine2RuntimeProver + Send + Sync> SpaceKey for TreeSpaceKey<P> {
    type KeyId = TreeKeyId;

    fn from_group_key(group_key: KeyMaterial) -> Self {
        Self {
            group: Some(SimpleLine2SpaceKey::from_group_key(group_key)),
            channel_keys: HashMap::new(),
        }
    }

    async fn current_key_id(
        &self,
        reader: &dyn OperationReader,
    ) -> Result<Self::KeyId, KeyManagerError> {
        // Channel-less "current" id is the root line's (full members only).
        let SimpleKeyId(seq) = self.group_ref()?.current_key_id(reader).await?;
        Ok(TreeKeyId::root(seq))
    }

    async fn data_key_for_key_id(
        &self,
        key_id: &Self::KeyId,
        reader: &dyn OperationReader,
    ) -> Result<[u8; 32], KeyManagerError> {
        if key_id.is_root() {
            // Channel-less/global tables: the root line's data key (full only).
            return self
                .group_ref()?
                .data_key_for_key_id(&SimpleKeyId(key_id.seq), reader)
                .await;
        }
        // Channel row: derive the AES data key from the channel's subtree key —
        // which a full member derives from the group key, and a scoped member
        // holds directly (delivered). Out of scope ⇒ error (→ MissingKey).
        let subtree = if let Some(g) = &self.group {
            let _ = reader; // group-key derivation needs no reader
            channel_root(&g.current_group_key(), key_id.channel)
        } else if let Some(k) = self.channel_keys.get(&key_id.channel) {
            k.clone()
        } else {
            return Err(KeyManagerError);
        };
        Ok(channel_data_key(&subtree, key_id.seq))
    }

    async fn produce_group_key(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        self.group_mut()?.produce_group_key(builder).await
    }

    async fn generate_group_key(
        &self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        self.group_ref()?.generate_group_key(builder).await
    }

    async fn apply_new_group_key(
        &mut self,
        new_group_key: KeyMaterial,
        commitment: KeyCommitment,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        self.group_mut()?
            .apply_new_group_key(new_group_key, commitment, reader)
            .await
    }

    async fn extend(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<Self::KeyId, KeyManagerError> {
        let SimpleKeyId(seq) = self.group_mut()?.extend(builder).await?;
        Ok(TreeKeyId::root(seq))
    }

    async fn reduce(
        &mut self,
        before: &Self::KeyId,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(), KeyManagerError> {
        self.group_mut()?
            .reduce(&SimpleKeyId(before.seq), builder)
            .await
    }

    async fn sync_group_key(
        &mut self,
        reader: &dyn OperationReader,
    ) -> Result<GroupKeySync, KeyManagerError> {
        // Scoped members hold no group key and never sync one.
        match self.group.as_mut() {
            Some(g) => g.sync_group_key(reader).await,
            None => Ok(GroupKeySync::AlreadyCurrent),
        }
    }

    async fn recover_group_key_from_candidate(
        &mut self,
        candidate: KeyMaterial,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        self.group_mut()?
            .recover_group_key_from_candidate(candidate, reader)
            .await
    }

    fn op_may_need_delivery(op_type: OpType) -> bool {
        SimpleLine2SpaceKey::<P>::op_may_need_delivery(op_type)
    }

    async fn verify_retention_proofs(
        op_type: OpType,
        proofs: &[Vec<u8>],
        pre_state: &dyn OperationReader,
        pending_writes: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        // The retention/group-key tier is the group line's; channel keys are
        // pure derivation (no on-chain state, no proofs).
        SimpleLine2SpaceKey::<P>::verify_retention_proofs(
            op_type,
            proofs,
            pre_state,
            pending_writes,
        )
        .await
    }

    async fn canonical_group_key_commitment(
        reader: &dyn OperationReader,
    ) -> Result<KeyCommitment, KeyManagerError> {
        SimpleLine2SpaceKey::<P>::canonical_group_key_commitment(reader).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple_line2::NoProver;
    use encrypted_spaces_key_manager::MemoryOperationBuilder;

    type Tree = TreeSpaceKey<NoProver>;

    #[tokio::test]
    async fn full_member_derives_and_reads_every_channel() {
        let mut mem = MemoryOperationBuilder::new();
        let tree: Tree = TreeSpaceKey::new(&mut mem).await.unwrap();

        // Root (global) and any channel resolve; distinct channels differ.
        let root = tree.data_key_for_key_id(&TreeKeyId::root(0), &mem).await.unwrap();
        let c1 = tree.data_key_for_key_id(&TreeKeyId::new(1, 0), &mem).await.unwrap();
        let c2 = tree.data_key_for_key_id(&TreeKeyId::new(2, 0), &mem).await.unwrap();
        assert_ne!(c1, c2);
        assert_ne!(c1, root);
    }

    #[tokio::test]
    async fn scoped_member_reads_only_delivered_channels() {
        let mut mem = MemoryOperationBuilder::new();
        let full: Tree = TreeSpaceKey::new(&mut mem).await.unwrap();

        // Full member derives channel 1's subtree key and "delivers" it.
        let ch1_key = full.channel_subtree_key(1).unwrap();
        let scoped: Tree = TreeSpaceKey::scoped([(1, ch1_key)]);

        // Scoped reads channel 1 with the SAME key the full member derives...
        let full_c1 = full.data_key_for_key_id(&TreeKeyId::new(1, 0), &mem).await.unwrap();
        let scoped_c1 = scoped.data_key_for_key_id(&TreeKeyId::new(1, 0), &mem).await.unwrap();
        assert_eq!(full_c1, scoped_c1);

        // ...but channel 2 and the root/global line are out of scope.
        assert!(scoped.data_key_for_key_id(&TreeKeyId::new(2, 0), &mem).await.is_err());
        assert!(scoped.data_key_for_key_id(&TreeKeyId::root(0), &mem).await.is_err());
    }

    #[tokio::test]
    async fn channel_key_delivery_grants_scoped_read() {
        use encrypted_spaces_crypto::key_derivation::{
            DerivationKoalaBearPoseidon2_16, KeyDerivation,
        };
        use encrypted_spaces_crypto::pke::{DefaultMkem, KemKeyPair};
        use encrypted_spaces_key_manager::{prove_channel_delivery, verify_channel_delivery};
        use encrypted_spaces_zkp::mve::PoseidonMve;

        let mut rng = rand::rng();
        let b_kp = KemKeyPair::<DefaultMkem>::new(&mut rng); // scoped recipient

        let mut mem = MemoryOperationBuilder::new();
        let full: Tree = TreeSpaceKey::new(&mut mem).await.unwrap();

        // Full member derives channel 1's subtree key and mVE-wraps it to B.
        let subtree = full.channel_subtree_key(1).unwrap();
        let commitment = DerivationKoalaBearPoseidon2_16::default().commit(&subtree);
        let req = prove_channel_delivery(1, commitment, &subtree, &[b_kp.public().clone()]);
        let cts = verify_channel_delivery(&[b_kp.public().clone()], &req).unwrap();
        let b_ct = cts.get(0).unwrap();
        let delivered =
            PoseidonMve::<DefaultMkem>::decrypt(b_kp.secret(), &b_ct, req.commitment).unwrap();

        // B is a scoped member holding only the delivered channel-1 key.
        let scoped: Tree = TreeSpaceKey::scoped([(1, delivered)]);

        // B derives the SAME channel-1 data key the full member derives...
        let full_c1 = full.data_key_for_key_id(&TreeKeyId::new(1, 0), &mem).await.unwrap();
        let scoped_c1 = scoped.data_key_for_key_id(&TreeKeyId::new(1, 0), &mem).await.unwrap();
        assert_eq!(full_c1, scoped_c1, "delivered subtree key reproduces the data key");
        // ...but channel 2 stays out of scope.
        assert!(scoped.data_key_for_key_id(&TreeKeyId::new(2, 0), &mem).await.is_err());
    }

    #[tokio::test]
    async fn dropping_a_channel_key_revokes_read() {
        let mut mem = MemoryOperationBuilder::new();
        let full: Tree = TreeSpaceKey::new(&mut mem).await.unwrap();
        let ch1_key = full.channel_subtree_key(1).unwrap();
        let mut scoped: Tree = TreeSpaceKey::scoped([(1, ch1_key)]);

        assert!(scoped.data_key_for_key_id(&TreeKeyId::new(1, 0), &mem).await.is_ok());
        scoped.drop_channel_key(1);
        assert!(scoped.data_key_for_key_id(&TreeKeyId::new(1, 0), &mem).await.is_err());
    }
}
