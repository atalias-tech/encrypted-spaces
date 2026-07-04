use super::{
    append_multi_row_insert_index_puts, bump_next_id_after_chain, column_names_from_keys,
    derive_column_keys_for_chain, derive_column_keys_with_row_id, extract_i64_column_from_entry,
    is_grant_key_column_entry, is_provisional_status, next_id_after, next_id_put,
    partition_composite_entry, read_next_id, read_schema_columns, require_full_member_signer,
    validate_invite_grant_bindings, validate_user_access, OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{BatchOp, TraceStep};
/// InviteUser operation verifier.
///
/// # User-ID allocation
///
/// New-user UIDs are allocated the same way as any other insert — read
/// from the `_users` table's `schema_next_id_key` counter and bumped
/// with a counter `Put`.  UIDs are therefore sequential and
/// monotonically increasing, not randomized.
pub struct InviteUserOp;

impl OpVerifier for InviteUserOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &super::OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let parts = partition_composite_entry(entry, "invite_user")?;
        if !parts.key_history.is_empty() {
            return Err(ChangelogError::Generic(
                "invite_user: unexpected _key_history entries".to_string(),
            ));
        }
        let user_entries = parts.users;
        let retention_entries = parts.retention;
        if user_entries.is_empty() {
            return Err(ChangelogError::Generic(
                "invite_user: _users entries must not be empty".to_string(),
            ));
        }

        let signer_status = validate_user_access(entry, OpType::InviteUser, "invite_user", reader)?;

        // §4.2: channel-grant rows may only be issued by a FULL member. The
        // detector is prefix-based so a non-canonical spelling cannot dodge
        // this gate (it is additionally rejected as non-canonical below).
        // Blocks the sockpuppet path: a Scoped signer inviting a puppet and
        // handing it grant rows.
        let has_grant_rows = retention_entries.iter().any(is_grant_key_column_entry);
        if has_grant_rows {
            require_full_member_signer(signer_status, entry.uid, "invite_user")?;
        }

        let expected_user_cols =
            read_schema_columns(crate::USERS_TABLE, "invite_user", reader, ctx)?;
        let user_entry_keys: Vec<Vec<u8>> = user_entries.iter().map(|kv| kv.key.clone()).collect();
        let actual_user_cols = column_names_from_keys(&user_entry_keys);
        if actual_user_cols != expected_user_cols {
            let missing: Vec<_> = expected_user_cols.difference(&actual_user_cols).collect();
            return Err(ChangelogError::Generic(format!(
                "invite_user: _users insert missing columns {missing:?}"
            )));
        }

        // --- Validate that the status of the new user row is set to provisional ---
        // (0 = Provisional for a full invite, 3 = ScopedProvisional for a scoped invite).
        let inserted_status =
            extract_i64_column_from_entry(entry, crate::USERS_TABLE, "status", "invite_user")?;
        if !is_provisional_status(inserted_status) {
            return Err(ChangelogError::Generic(format!(
                "invite_user: inserted _users.status must be provisional (0 or 3), got {inserted_status}"
            )));
        }

        // Grant rows are only meaningful on a SCOPED invite (status 3): they
        // hand the invitee its channel subtree keys in lieu of the group key.
        // A FULL invite (status 0) receives the group key — grant rows there
        // are a smuggling vector and are rejected.
        if has_grant_rows && inserted_status != 3 {
            return Err(ChangelogError::Generic(format!(
                "invite_user: channel_grant rows are only allowed on a scoped invite \
                 (inserted _users.status 3), got status {inserted_status}"
            )));
        }

        let user_row_id = read_next_id(crate::USERS_TABLE, "invite_user", reader)?;
        let user_column_keys =
            derive_column_keys_with_row_id(&user_entries, user_row_id, "invite_user")?;

        let mut batch_ops: Vec<BatchOp> =
            Vec::with_capacity(user_column_keys.len() + retention_entries.len());
        for (col_key, kv) in user_column_keys.iter().zip(user_entries.iter()) {
            batch_ops.push(kv.to_batch_op(col_key));
        }

        // Counter was already read to derive `user_row_id`; emit the bump Put.
        let next_user_id = next_id_after(user_row_id, crate::USERS_TABLE, "invite_user")?;
        batch_ops.push(next_id_put(crate::USERS_TABLE, next_user_id));

        if !retention_entries.is_empty() {
            // Any channel-grant row in a scoped invite hands the invitee its
            // initial channel subtree key; each grant's {uid} MUST equal the
            // invitee's freshly-allocated row id (user_row_id). This forbids an
            // inviter from smuggling a grant for a different (e.g. their own) uid.
            validate_invite_grant_bindings(&retention_entries, user_row_id, "invite_user")?;

            let expected_retention_cols =
                read_schema_columns(crate::RETENTION_TABLE, "invite_user", reader, ctx)?;
            let retention_entry_keys: Vec<Vec<u8>> =
                retention_entries.iter().map(|kv| kv.key.clone()).collect();
            let actual_retention_cols = column_names_from_keys(&retention_entry_keys);
            if actual_retention_cols != expected_retention_cols {
                let missing: Vec<_> = expected_retention_cols
                    .difference(&actual_retention_cols)
                    .collect();
                return Err(ChangelogError::Generic(format!(
                    "invite_user: _retention insert missing columns {missing:?}"
                )));
            }
            let retention_col_count = expected_retention_cols.len();
            if retention_col_count == 0 {
                return Err(ChangelogError::Generic(
                    "invite_user: _retention has no schema columns".to_string(),
                ));
            }
            if retention_entries.len() % retention_col_count != 0 {
                return Err(ChangelogError::Generic(format!(
                    "invite_user: _retention entry count {} is not a \
                     multiple of col_count={retention_col_count}",
                    retention_entries.len()
                )));
            }

            let retention_counter = read_next_id(crate::RETENTION_TABLE, "invite_user", reader)?;
            let retention_column_keys = derive_column_keys_for_chain(
                &retention_entries,
                retention_counter,
                retention_col_count,
                "invite_user",
            )?;
            for (col_key, kv) in retention_column_keys.iter().zip(retention_entries.iter()) {
                batch_ops.push(kv.to_batch_op(col_key));
            }

            append_multi_row_insert_index_puts(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                &retention_column_keys,
                &retention_entries,
                "invite_user",
                reader,
                ctx,
            )?;

            let num_rows = (retention_entries.len() / retention_col_count) as i64;
            bump_next_id_after_chain(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                retention_counter,
                num_rows,
                "invite_user",
            )?;
        }

        batch_ops.sort_by(|a, b| a.key().cmp(b.key()));

        Ok(OpVerifyResult {
            write_steps: vec![TraceStep::Write(batch_ops)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
    use encrypted_spaces_storage_encoding::{
        encode_column_names,
        keys::{column_key, schema_columns_key, schema_indexes_key, schema_next_id_key},
    };
    use std::collections::BTreeSet;

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    fn stored_i64(v: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(v)).unwrap()
    }

    fn stored_str(s: &str) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(s)).unwrap()
    }

    /// Build an InviteUser entry from explicit (key, value) pairs so tests can
    /// control the invitee's status and the `_retention` grant "key" payload.
    fn make_invite_entry_kv(uid: u32, kvs: Vec<(Vec<u8>, Vec<u8>)>) -> ChangelogEntry {
        let entries: Vec<KvData> = kvs
            .into_iter()
            .map(|(key, value)| KvData { key, value })
            .collect();
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::InviteUser,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    /// Common reads for a scoped invite carrying one `_retention` grant row.
    /// `next_user_id` becomes the invitee's row id (its uid). Order matches the
    /// verifier: inviter status → schema _users → next_id _users → schema
    /// _retention → next_id _retention → schema_indexes _retention.
    fn invite_grant_reads(inviter: u32, next_user_id: i64) -> Vec<ProvenRead> {
        let user_cols: BTreeSet<String> = ["auth_key", "status", "update_key"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(inviter);
        vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_users")),
                results: vec![(
                    schema_columns_key("_users"),
                    encode_column_names(&user_cols),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key("_users")),
                results: vec![(
                    schema_next_id_key("_users"),
                    next_user_id.to_be_bytes().to_vec(),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_retention")),
                results: vec![(
                    schema_columns_key("_retention"),
                    encode_column_names(&retention_cols),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key("_retention")),
                results: vec![(
                    schema_next_id_key("_retention"),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key("_retention")),
                results: vec![(schema_indexes_key("_retention"), b"key".to_vec())],
            },
        ]
    }

    /// A scoped invite whose grant row binds to the invitee's own uid
    /// (== the allocated `_users` row id) is accepted.
    #[test]
    fn test_channel_grant_bound_to_invitee_accepted() {
        let inviter = 7u32;
        let invitee_uid = 1i64; // next_id(_users) == 1
        let entry = make_invite_entry_kv(
            inviter,
            vec![
                (column_key("_users", 0, "auth_key"), vec![0xAA; 32]),
                (column_key("_users", 0, "status"), stored_i64(3)),
                (column_key("_users", 0, "update_key"), vec![0xAA; 32]),
                (
                    column_key("_retention", 0, "key"),
                    stored_str(&format!("sl2/channel_grant/{invitee_uid}/5")),
                ),
                (column_key("_retention", 0, "value"), vec![0xBB; 32]),
            ],
        );
        let reads = invite_grant_reads(inviter, invitee_uid);
        let mut reader = VerifierReader::new(&reads);
        let result = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    /// An invite whose grant row binds to a DIFFERENT uid than the invitee
    /// (e.g. the inviter smuggling a grant for themselves) is rejected.
    #[test]
    fn test_channel_grant_wrong_uid_rejected_for_invite() {
        let inviter = 7u32;
        let invitee_uid = 1i64;
        let entry = make_invite_entry_kv(
            inviter,
            vec![
                (column_key("_users", 0, "auth_key"), vec![0xAA; 32]),
                (column_key("_users", 0, "status"), stored_i64(3)),
                (column_key("_users", 0, "update_key"), vec![0xAA; 32]),
                // Grant bound to uid=2, but the invitee will be uid=1.
                (
                    column_key("_retention", 0, "key"),
                    stored_str("sl2/channel_grant/2/5"),
                ),
                (column_key("_retention", 0, "value"), vec![0xBB; 32]),
            ],
        );
        let reads = invite_grant_reads(inviter, invitee_uid);
        let mut reader = VerifierReader::new(&reads);
        let result = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(result.is_err(), "grant for a non-invitee uid must be rejected");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("must bind to the invited user") && msg.contains("uid=2"),
            "expected an invitee-binding rejection, got: {msg}"
        );
    }

    /// A `+`-signed (non-canonical) grant key must be rejected even when its
    /// loose-parsed uid equals the invitee's — canonical form is required so a
    /// forged spelling cannot masquerade as a legitimate grant.
    #[test]
    fn test_channel_grant_noncanonical_rejected_for_invite() {
        let inviter = 7u32;
        let invitee_uid = 1i64;
        let entry = make_invite_entry_kv(
            inviter,
            vec![
                (column_key("_users", 0, "auth_key"), vec![0xAA; 32]),
                (column_key("_users", 0, "status"), stored_i64(3)),
                (column_key("_users", 0, "update_key"), vec![0xAA; 32]),
                // "+1" parses to 1 (== invitee) but is NOT canonical.
                (
                    column_key("_retention", 0, "key"),
                    stored_str("sl2/channel_grant/+1/5"),
                ),
                (column_key("_retention", 0, "value"), vec![0xBB; 32]),
            ],
        );
        let reads = invite_grant_reads(inviter, invitee_uid);
        let mut reader = VerifierReader::new(&reads);
        let result = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(
            result.is_err(),
            "a non-canonical (+signed) grant key must be rejected"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("non-canonical channel_grant key"),
            "expected a non-canonical rejection, got: {msg}"
        );
    }

    /// CRITICAL (review follow-up): a Scoped(2) member must not be able to
    /// issue channel grants via InviteUser (sockpuppet invite: a scoped
    /// signer invites a puppet and hands it grant rows). Grant-carrying
    /// invites require a FULL member signer.
    ///
    /// RED before fix: `extract_and_validate` returns `Ok`. GREEN after: `Err`
    /// naming the full-member signer requirement.
    #[test]
    fn test_scoped_signer_invite_with_grant_rejected() {
        let inviter = 7u32;
        let invitee_uid = 1i64;
        // Same shape as the accepted case (scoped invite, grant bound to the
        // invitee) — only the signer's status differs.
        let entry = make_invite_entry_kv(
            inviter,
            vec![
                (column_key("_users", 0, "auth_key"), vec![0xAA; 32]),
                (column_key("_users", 0, "status"), stored_i64(3)),
                (column_key("_users", 0, "update_key"), vec![0xAA; 32]),
                (
                    column_key("_retention", 0, "key"),
                    stored_str(&format!("sl2/channel_grant/{invitee_uid}/5")),
                ),
                (column_key("_retention", 0, "value"), vec![0xBB; 32]),
            ],
        );
        let mut reads = invite_grant_reads(inviter, invitee_uid);
        // Signer is Scoped(2), not Full — pre-fix this passes the provisional
        // gate and the invite runs to completion.
        reads[0].results = vec![(user_status_key(inviter), stored_i64(2))];
        let mut reader = VerifierReader::new(&reads);
        let result = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(
            result.is_err(),
            "a Scoped signer's grant-carrying invite must be rejected, got Ok"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("full member"),
            "expected the full-member signer rejection, got: {msg}"
        );
    }

    /// IMPORTANT (review follow-up): grant rows are only meaningful on a
    /// SCOPED invite (inserted status 3) — they hand the invitee its channel
    /// subtree keys in lieu of the group key. A FULL invite (inserted status
    /// 0) receives the group key; grant rows there are a smuggling vector and
    /// must be rejected even when bound to the invitee's uid.
    ///
    /// RED before fix: `extract_and_validate` returns `Ok`. GREEN after: `Err`
    /// naming the scoped-invite requirement.
    #[test]
    fn test_full_invite_with_grant_rejected() {
        let inviter = 7u32;
        let invitee_uid = 1i64;
        let entry = make_invite_entry_kv(
            inviter,
            vec![
                (column_key("_users", 0, "auth_key"), vec![0xAA; 32]),
                // FULL invite: inserted status = Provisional(0), not 3.
                (column_key("_users", 0, "status"), stored_i64(0)),
                (column_key("_users", 0, "update_key"), vec![0xAA; 32]),
                (
                    column_key("_retention", 0, "key"),
                    stored_str(&format!("sl2/channel_grant/{invitee_uid}/5")),
                ),
                (column_key("_retention", 0, "value"), vec![0xBB; 32]),
            ],
        );
        let reads = invite_grant_reads(inviter, invitee_uid);
        let mut reader = VerifierReader::new(&reads);
        let result = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(
            result.is_err(),
            "grant rows on a full (non-scoped) invite must be rejected, got Ok"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("scoped invite"),
            "expected the scoped-invite-only rejection, got: {msg}"
        );
    }

    fn make_invite_entry(
        uid: u32,
        user_keys: &[Vec<u8>],
        retention_keys: &[Vec<u8>],
    ) -> ChangelogEntry {
        let entries: Vec<KvData> = user_keys
            .iter()
            .chain(retention_keys.iter())
            .map(|key| KvData {
                key: key.clone(),
                value: vec![0xAA; 32],
            })
            .collect();
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::InviteUser,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn make_invite_entry_with_status(
        uid: u32,
        user_keys: &[Vec<u8>],
        retention_keys: &[Vec<u8>],
        status: i64,
    ) -> ChangelogEntry {
        let status_bytes = value_to_bytes(&serde_json::json!(status)).unwrap();
        let status_key = &user_keys[1];
        let entries: Vec<KvData> = user_keys
            .iter()
            .chain(retention_keys.iter())
            .map(|key| KvData {
                key: key.clone(),
                value: if key == status_key {
                    status_bytes.clone()
                } else {
                    vec![0xAA; 32]
                },
            })
            .collect();
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::InviteUser,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn test_provisional_user_rejected_for_invite_user() {
        let uid = 1u32;
        let user_row_id = 5i64;
        let user_keys = vec![
            column_key("_users", user_row_id, "auth_key"),
            column_key("_users", user_row_id, "status"),
            column_key("_users", user_row_id, "update_key"),
        ];
        let retention_keys = vec![
            column_key("_retention", 0, "key"),
            column_key("_retention", 0, "value"),
        ];
        let entry = make_invite_entry(uid, &user_keys, &retention_keys);

        let user_cols: BTreeSet<String> = ["auth_key", "status", "update_key"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(0)).unwrap())],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_users")),
                results: vec![(
                    schema_columns_key("_users"),
                    encode_column_names(&user_cols),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_retention")),
                results: vec![(
                    schema_columns_key("_retention"),
                    encode_column_names(&retention_cols),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("provisional user"), "unexpected error: {msg}");
    }

    #[test]
    fn test_invited_user_must_be_provisional() {
        let uid = 1u32;
        let user_row_id = 5i64;
        let user_keys = vec![
            column_key("_users", user_row_id, "auth_key"),
            column_key("_users", user_row_id, "status"),
            column_key("_users", user_row_id, "update_key"),
        ];
        let retention_keys = vec![
            column_key("_retention", 0, "key"),
            column_key("_retention", 0, "value"),
        ];
        let entry = make_invite_entry_with_status(uid, &user_keys, &retention_keys, 1);

        let user_cols: BTreeSet<String> = ["auth_key", "status", "update_key"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(1)).unwrap())],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_users")),
                results: vec![(
                    schema_columns_key("_users"),
                    encode_column_names(&user_cols),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_retention")),
                results: vec![(
                    schema_columns_key("_retention"),
                    encode_column_names(&retention_cols),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("inserted _users.status must be provisional"),
            "unexpected error: {msg}"
        );
    }

    /// Positive case: an invite that stamps `ScopedProvisional` (status=3) — the
    /// L2 scoped-invite marker — is accepted. Full invites stamp 0, scoped
    /// invites stamp 3; both are provisional. This locks in that 3 is allowed
    /// (previously only covered indirectly via the SDK integration flow).
    #[test]
    fn test_invited_scoped_provisional_status_accepted() {
        let uid = 1u32;
        // Placeholder row_id=0 so the verifier can derive the assigned row_id.
        let user_keys = vec![
            column_key("_users", 0, "auth_key"),
            column_key("_users", 0, "status"),
            column_key("_users", 0, "update_key"),
        ];
        // Scoped invites carry no _retention rows; status = 3 (ScopedProvisional).
        let entry = make_invite_entry_with_status(uid, &user_keys, &[], 3);

        let user_cols: BTreeSet<String> = ["auth_key", "status", "update_key"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let sk = user_status_key(uid);
        let reads = vec![
            // Inviter is a full member (non-provisional) → allowed to invite.
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(1)).unwrap())],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_users")),
                results: vec![(
                    schema_columns_key("_users"),
                    encode_column_names(&user_cols),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key("_users")),
                results: vec![(
                    schema_next_id_key("_users"),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let result = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }
}
