const DOMAIN: &[u8] = b"halyard-auth-challenge-v1";

pub fn auth_challenge_message(space_id: crate::SpaceId, uid: i64, nonce: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 16 + 8 + nonce.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(space_id.as_bytes());
    m.extend_from_slice(&uid.to_le_bytes());
    m.extend_from_slice(nonce);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_message_is_domain_separated_and_stable() {
        let sid = crate::SpaceId::from([7u8; 16]);
        let m = auth_challenge_message(sid, 42, &[1, 2, 3]);
        assert!(m.starts_with(b"halyard-auth-challenge-v1"));
        // deterministic for same inputs
        assert_eq!(m, auth_challenge_message(sid, 42, &[1, 2, 3]));
        // changes with uid / nonce / space
        assert_ne!(m, auth_challenge_message(sid, 43, &[1, 2, 3]));
        assert_ne!(m, auth_challenge_message(sid, 42, &[1, 2, 4]));
        // changes with different space_id
        let sid2 = crate::SpaceId::from([8u8; 16]);
        assert_ne!(m, auth_challenge_message(sid2, 42, &[1, 2, 3]));
    }
}
