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
    /// Surviving scoped members' refreshed channel grants (L2 Part B rekey
    /// re-delivery). A rekey rotates the group key, so each channel's subtree
    /// key changes; without this, scoped members go dark on their channels.
    /// Empty when no scoped members exist. `#[serde(default)]` keeps the wire
    /// format backward-compatible with pre-Part-B rekeys.
    #[serde(default)]
    pub scoped_regrants: Vec<ScopedRegrant>,
}

/// One channel's refreshed grant during a rekey re-delivery (L2 Part B): the
/// mVE delivery of the channel's NEW-epoch subtree key to a scoped member,
/// paired with the §4.3 derivation proof binding that key to the NEW group key.
/// The server verifies both before re-depositing the member's delivery slot.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelRegrant {
    pub delivery: ChannelDeliveryRequest,
    /// §4.3 channel-grant derivation proof (opaque STARK bytes), the rekey
    /// counterpart to [`ScopedInviteRequest::grant_proofs`].
    pub grant_proof: Vec<u8>,
}

/// A surviving scoped member's refreshed channel grants for a rekey (L2 Part
/// B). The server re-derives nothing: it verifies each [`ChannelRegrant`]
/// against the AUTHORITATIVE new group-key commitment (never client-supplied)
/// and the grant `_retention` rows the signed op persists, that each channel
/// was ALREADY granted (no scope expansion), and that the delivery is wrapped
/// to `uid`'s current update key — then re-deposits a fresh
/// [`ScopedDeliveryEnvelope`] in `uid`'s slot so the member keeps reading its
/// channels across the rekey.
#[derive(Clone, Serialize, Deserialize)]
pub struct ScopedRegrant {
    pub uid: i64,
    pub channels: Vec<ChannelRegrant>,
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
    /// The epoch (FGK ordinal) `channel_root(group_key_at(epoch), channel)`
    /// was derived under — so the recipient installs the delivered key at
    /// the epoch it ACTUALLY belongs to (`TreeSpaceKey::install_channel_key`),
    /// rather than inferring "current" from its own possibly-stale local
    /// state (the epoch-indexed channel-keys design's closed race).
    ///
    /// Pure delivery **metadata**, like `channel` above: the mVE proof below
    /// binds `commitment`/`recipients` only (see `prove_channel_delivery`),
    /// not `epoch`, so this field carries no cryptographic weight of its own
    /// — a wrong value can only misfile the delivered key locally (denying
    /// that epoch's read), never leak or corrupt anything, exactly like a
    /// wrong `channel` value already could (see `ScopedChannelDelivery`'s
    /// doc). The value is trusted from the same source `channel` already is:
    /// the full member driving the grant (invite/rekey), which is bound by
    /// the §4.3 channel-grant derivation proof for its COMMITMENT+CHANNEL,
    /// but not (and does not need to be) for this epoch tag.
    pub epoch: u64,
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
    /// The epoch this delivered key was derived under — relayed verbatim
    /// from the verified [`ChannelDeliveryRequest::epoch`] the server
    /// checked before depositing this envelope. See that field's doc for why
    /// this rides as payload metadata rather than proof-bound state.
    pub epoch: u64,
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
