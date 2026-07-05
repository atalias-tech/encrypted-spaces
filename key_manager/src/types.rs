use encrypted_spaces_crypto::pke::DefaultMkem;
use encrypted_spaces_crypto::{KeyCommitment, KeyMaterial};
use encrypted_spaces_zkp::mve::{MveCiphertext, MveRecipientCiphertext, PoseidonMveProof};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Rekey (remove user)
// ---------------------------------------------------------------------------

/// Client -> Server: request to rekey after removing member(s).
#[derive(Clone, Serialize, Deserialize)]
pub struct RekeyRequest {
    pub new_root_commitment: KeyCommitment,
    pub proof: PoseidonMveProof<DefaultMkem>,
}

/// Server -> remaining members: verified rekey result.
/// Returned by `verify_rekey`.
#[derive(Clone, Serialize, Deserialize)]
pub struct RekeyResult {
    pub ciphertexts: MveCiphertext<DefaultMkem, KeyMaterial>,
}

// ---------------------------------------------------------------------------
// Invite (add user)
// ---------------------------------------------------------------------------

/// Client -> Server: request to invite a new member.
#[derive(Clone, Serialize, Deserialize)]
pub struct InviteRequest {
    pub root_commitment: KeyCommitment,
    pub proof: PoseidonMveProof<DefaultMkem>,
}

/// Server verification result after handling an invite.
/// Returned by `verify_invite`.
#[derive(Clone, Serialize, Deserialize)]
pub struct InviteResult {
    pub ciphertexts: MveCiphertext<DefaultMkem, KeyMaterial>,
    pub root_commitment: KeyCommitment,
}

// ---------------------------------------------------------------------------
// Channel-key delivery (L2 read scoping)
// ---------------------------------------------------------------------------

/// Client -> Server: deliver one channel's key line to its readers. Same mVE
/// shape as a rekey/invite, but carries a specific channel's HGK so a member is
/// granted read access to exactly that channel (the L2 read boundary).
#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelDeliveryRequest {
    pub channel: i64,
    pub commitment: KeyCommitment,
    pub proof: PoseidonMveProof<DefaultMkem>,
}

/// Client -> Server: invite a member with **scoped** read access — it receives
/// only these channels' subtree keys, never the group key. Each entry is an mVE
/// delivery of one channel's derived subtree key to the new member's update key.
///
/// `grant_proofs` runs parallel to `channels` (one per channel, same order): a
/// §4.3 channel-grant derivation proof binding that channel's committed key to
/// the group key. The server verifies each against the canonical group-key
/// commitment before letting the InviteUser op's grant `_retention` rows land,
/// so a client cannot persist a channel-grant record for a key it did not
/// actually derive from the group key.
#[derive(Clone, Serialize, Deserialize)]
pub struct ScopedInviteRequest {
    pub channels: Vec<ChannelDeliveryRequest>,
    #[serde(default)]
    pub grant_proofs: Vec<Vec<u8>>,
}

/// One channel's subtree key mVE-wrapped to a scoped member (server-side, after
/// verifying the delivery proof).
#[derive(Clone, Serialize, Deserialize)]
pub struct ScopedChannelDelivery {
    pub channel: i64,
    pub binding_commitment: KeyCommitment,
    pub ciphertext: MveRecipientCiphertext<DefaultMkem, KeyMaterial>,
}

/// A scoped member's delivery slot: channel subtree keys only, **no group key**.
/// The read-scoping counterpart to [`GkDeliveryEnvelope`]. Its fields are
/// disjoint from `GkDeliveryEnvelope`, so `join` distinguishes the two by
/// attempting the full envelope first and falling back to this.
#[derive(Clone, Serialize, Deserialize)]
pub struct ScopedDeliveryEnvelope {
    pub channels: Vec<ScopedChannelDelivery>,
}

// ---------------------------------------------------------------------------
// GK delivery slot
// ---------------------------------------------------------------------------

/// Per-recipient envelope that bundles an mVE ciphertext with the binding
/// commitment a recipient needs to decapsulate it. Stored in the server's
/// GK delivery slots and fetched via `fetch_my_key_delivery`.
#[derive(Clone, Serialize, Deserialize)]
pub struct GkDeliveryEnvelope {
    pub binding_commitment: KeyCommitment,
    pub ciphertext: MveRecipientCiphertext<DefaultMkem, KeyMaterial>,
}
