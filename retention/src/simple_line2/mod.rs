//! SimpleLine2: storage-native key retention with lazy client key resolution.
//!
//! This module implements the SimpleLine2 retention algorithm over key-value
//! `Storage`. Public retention state is stored canonically in storage; only
//! secret local state (the current HGK) is held on `SimpleLine2SpaceKey`.

mod proof;
mod space_key;
mod stark_proofs;
mod store;

#[cfg(test)]
mod tests;

pub use proof::{
    ChannelGrantProofInput, ChannelGrantVerifyInput, DefaultDerivation, DeleteKeysProofInput,
    DeleteKeysSurvivor, DeleteKeysVerifyInput, ExtendProofInput, ExtendVerifyInput, NoProver,
    RekeyProofInput, RekeyVerifyInput, SimpleLine2Proofs, SimpleLine2RuntimeProver, VecProofs,
};
pub use space_key::SimpleLine2SpaceKey;
// Crate-visible only: the live-chain reconstruction primitive, re-exported so
// `tree_space_key` (a sibling module of `simple_line2`, not a descendant) can
// reach it for `TreeSpaceKey::live_chain_current_epoch` — the epoch-indexed
// channel-key write path's storage-only "what epoch is it right now" query,
// usable by scoped members too (no group key needed; see that fn's doc).
pub(crate) use space_key::reconstruct_live_chain;
pub use stark_proofs::StarkProver;

/// Default prover type selected at compile time.
///
/// `real-proofs` feature on (default) → [`StarkProver`] (real STARK proof bytes).
/// `real-proofs` feature off → [`NoProver`] (fast, empty proof bytes).
#[cfg(feature = "real-proofs")]
pub type DefaultProver = StarkProver;

#[cfg(not(feature = "real-proofs"))]
pub type DefaultProver = NoProver;
