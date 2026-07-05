use encrypted_spaces_crypto::KeyCommitment;
use base64::{engine::general_purpose::STANDARD, Engine};

/// Prefix for channel-grant records in the retention layer.
pub const GRANT_KEY_PREFIX: &str = "sl2/channel_grant/";

/// Construct a grant row key from user and channel IDs.
pub fn grant_row_key(uid: i64, channel: i64) -> String {
    format!("{}{}/{}", GRANT_KEY_PREFIX, uid, channel)
}

/// Parse a grant row key back to (uid, channel) IDs.
pub fn parse_grant_row_key(key: &str) -> Option<(i64, i64)> {
    if !key.starts_with(GRANT_KEY_PREFIX) {
        return None;
    }

    let remainder = &key[GRANT_KEY_PREFIX.len()..];
    let parts: Vec<&str> = remainder.split('/').collect();

    if parts.len() != 2 {
        return None;
    }

    let uid = parts[0].parse::<i64>().ok()?;
    let channel = parts[1].parse::<i64>().ok()?;

    Some((uid, channel))
}

/// Encode a KeyCommitment to its base64-encoded string representation.
pub fn encode_grant_value(commitment: &KeyCommitment) -> String {
    STANDARD.encode(commitment.as_bytes())
}

/// Decode a base64-encoded string back to a KeyCommitment.
pub fn decode_grant_value(encoded: &str) -> Option<KeyCommitment> {
    let bytes = STANDARD.decode(encoded).ok()?;
    KeyCommitment::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_crypto::{KeyMaterial, KeyDerivation};
    use encrypted_spaces_crypto::key_derivation::DerivationKoalaBearPoseidon2_16;

    #[test]
    fn grant_row_key_and_value_roundtrip() {
        assert_eq!(grant_row_key(5, 3), "sl2/channel_grant/5/3");
        assert_eq!(parse_grant_row_key("sl2/channel_grant/5/3"), Some((5, 3)));
        assert_eq!(parse_grant_row_key("sl2/fgk/row/0"), None); // not a grant row
        let key_material = KeyMaterial::digest(b"test");
        let c = DerivationKoalaBearPoseidon2_16::default().commit(&key_material);
        assert_eq!(decode_grant_value(&encode_grant_value(&c)), Some(c));
    }
}
