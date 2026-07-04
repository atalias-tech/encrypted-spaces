use super::{
    append_multi_row_insert_index_puts, bump_next_id_after_chain, column_names_from_keys,
    derive_column_keys_for_chain, read_next_id, read_schema_columns, require_full_member_signer,
    table_from_column_keys, validate_scoped_grant_bindings, validate_user_access, OpReader,
    OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{BatchOp, TraceStep};
/// Standalone rekey operation verifier.
pub struct RekeyOp;

impl OpVerifier for RekeyOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &super::OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        if entry.message.entries.is_empty() {
            return Err(ChangelogError::Generic(
                "rekey: no retention columns".to_string(),
            ));
        }

        let entry_keys: Vec<Vec<u8>> = entry
            .message
            .entries
            .iter()
            .map(|kv| kv.key.clone())
            .collect();
        let retention_table = table_from_column_keys(&entry_keys, "rekey")?;
        if retention_table != crate::RETENTION_TABLE {
            return Err(ChangelogError::Generic(format!(
                "rekey: retention columns target table \
                 '{retention_table}', expected '{}'",
                crate::RETENTION_TABLE
            )));
        }

        let signer_status = validate_user_access(entry, OpType::Rekey, "rekey", reader)?;

        // §4.2: a rekey rotates the group key, which scoped members never hold
        // (the SDK excludes them from group-key delivery) — the signer must be
        // a FULL member, unconditionally. This also closes the forged
        // self-grant path: without it, a Scoped signer's own status (2) would
        // satisfy the scoped-uid grant binding below.
        require_full_member_signer(signer_status, entry.uid, "rekey")?;

        // Standalone retention rekey is one of the two authorized grant paths:
        // it may (re)issue channel grants, but each grant row must bind to an
        // existing Scoped/ScopedProvisional _users row (read per grant's own
        // uid — decoy-proof). Non-grant retention rows pass untouched.
        validate_scoped_grant_bindings(&entry.message.entries, "rekey", reader, None)?;

        let expected_retention_cols =
            read_schema_columns(crate::RETENTION_TABLE, "rekey", reader, ctx)?;
        let actual_retention_cols = column_names_from_keys(&entry_keys);
        if actual_retention_cols != expected_retention_cols {
            let missing: Vec<_> = expected_retention_cols
                .difference(&actual_retention_cols)
                .collect();
            return Err(ChangelogError::Generic(format!(
                "rekey: _retention insert missing columns {missing:?}"
            )));
        }
        let retention_col_count = expected_retention_cols.len();
        if retention_col_count == 0 {
            return Err(ChangelogError::Generic(
                "rekey: _retention has no schema columns".to_string(),
            ));
        }
        if !entry
            .message
            .entries
            .len()
            .is_multiple_of(retention_col_count)
        {
            return Err(ChangelogError::Generic(format!(
                "rekey: entry count {} is not a multiple of \
                 _retention col_count={retention_col_count}",
                entry.message.entries.len()
            )));
        }

        let counter = read_next_id(crate::RETENTION_TABLE, "rekey", reader)?;
        let retention_column_keys = derive_column_keys_for_chain(
            &entry.message.entries,
            counter,
            retention_col_count,
            "rekey",
        )?;

        let mut batch_ops: Vec<BatchOp> = retention_column_keys
            .iter()
            .zip(entry.message.entries.iter())
            .map(|(col_key, kv)| kv.to_batch_op(col_key))
            .collect();

        append_multi_row_insert_index_puts(
            &mut batch_ops,
            crate::RETENTION_TABLE,
            &retention_column_keys,
            &entry.message.entries,
            "rekey",
            reader,
            ctx,
        )?;

        let num_rows = (entry.message.entries.len() / retention_col_count) as i64;
        bump_next_id_after_chain(
            &mut batch_ops,
            crate::RETENTION_TABLE,
            counter,
            num_rows,
            "rekey",
        )?;

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

    fn make_rekey_entry_kv(uid: u32, kvs: Vec<(Vec<u8>, Vec<u8>)>) -> ChangelogEntry {
        let entries: Vec<KvData> = kvs
            .into_iter()
            .map(|(key, value)| KvData { key, value })
            .collect();
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Rekey,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    /// One `_retention` grant row keyed to `grant_uid`/`channel`.
    fn grant_row_kvs(grant_uid: i64, channel: i64) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                column_key("_retention", 0, "key"),
                stored_str(&format!("sl2/channel_grant/{grant_uid}/{channel}")),
            ),
            (column_key("_retention", 0, "value"), vec![0xBB; 32]),
        ]
    }

    /// Tail reads for a rekey that reaches the retention-write phase (i.e. all
    /// grant bindings passed): schema _retention → next_id → schema_indexes.
    fn rekey_retention_tail_reads() -> Vec<ProvenRead> {
        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        vec![
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

    /// A standalone rekey may (re)issue a grant to a Scoped(2) member; accepted.
    #[test]
    fn test_channel_grant_scoped_uid_accepted_for_rekey() {
        let signer = 1u32;
        let grant_uid = 5i64;
        let entry = make_rekey_entry_kv(signer, grant_row_kvs(grant_uid, 7));

        let sk = user_status_key(signer);
        let guk = user_status_key(grant_uid as u32);
        let mut reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(guk.clone()),
                results: vec![(guk, stored_i64(2))], // Scoped
            },
        ];
        reads.extend(rekey_retention_tail_reads());
        let mut reader = VerifierReader::new(&reads);
        let result =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    /// A grant to a ScopedProvisional(3) member is also accepted.
    #[test]
    fn test_channel_grant_scoped_provisional_uid_accepted_for_rekey() {
        let signer = 1u32;
        let grant_uid = 5i64;
        let entry = make_rekey_entry_kv(signer, grant_row_kvs(grant_uid, 7));

        let sk = user_status_key(signer);
        let guk = user_status_key(grant_uid as u32);
        let mut reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(guk.clone()),
                results: vec![(guk, stored_i64(3))], // ScopedProvisional
            },
        ];
        reads.extend(rekey_retention_tail_reads());
        let mut reader = VerifierReader::new(&reads);
        let result =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    /// A rekey grant bound to a Full(1) member is rejected — a full member
    /// holds the group key and must never be handed a scoped channel grant
    /// (and, inversely, a full member cannot forge itself one via rekey).
    #[test]
    fn test_channel_grant_full_uid_rejected_for_rekey() {
        let signer = 1u32;
        let grant_uid = 5i64;
        let entry = make_rekey_entry_kv(signer, grant_row_kvs(grant_uid, 7));

        let sk = user_status_key(signer);
        let guk = user_status_key(grant_uid as u32);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(guk.clone()),
                results: vec![(guk, stored_i64(1))], // Full
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(result.is_err(), "grant to a Full member must be rejected");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("must bind to an existing") && msg.contains("uid=5"),
            "expected a scoped-binding rejection, got: {msg}"
        );
    }

    /// A multi-row rekey where a legitimate scoped grant is followed by a
    /// forged grant for a Full member must be rejected — every grant row is
    /// checked against its own uid's status, so one legit row can't smuggle
    /// another through.
    #[test]
    fn test_channel_grant_decoy_multi_row_rejected_for_rekey() {
        let signer = 1u32;
        let scoped_uid = 5i64;
        let full_uid = 6i64;
        // Two chained grant rows: row0 → scoped uid 5 (legit), row1 → full uid 6.
        let key_col = column_key("_retention", 0, "key");
        let value_col = column_key("_retention", 0, "value");
        let entry = make_rekey_entry_kv(
            signer,
            vec![
                (
                    key_col.clone(),
                    stored_str(&format!("sl2/channel_grant/{scoped_uid}/7")),
                ),
                (value_col.clone(), vec![0xBB; 32]),
                (
                    key_col,
                    stored_str(&format!("sl2/channel_grant/{full_uid}/7")),
                ),
                (value_col, vec![0xCC; 32]),
            ],
        );

        let sk = user_status_key(signer);
        let s5 = user_status_key(scoped_uid as u32);
        let s6 = user_status_key(full_uid as u32);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(s5.clone()),
                results: vec![(s5, stored_i64(2))], // scoped → passes
            },
            ProvenRead {
                op: ReadOp::Key(s6.clone()),
                results: vec![(s6, stored_i64(1))], // full → rejects
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(
            result.is_err(),
            "a forged grant smuggled behind a legit scoped grant must be rejected"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("must bind to an existing") && msg.contains("uid=6"),
            "expected rejection naming the smuggled uid, got: {msg}"
        );
    }

    /// CRITICAL (review follow-up): a Scoped(2) member must not be able to
    /// sign a Rekey at all — only full members hold the group key a rekey
    /// rotates. Pre-fix, a scoped signer S colluding with the server could
    /// submit a Rekey carrying `sl2/channel_grant/{S}/{C}` for a channel S was
    /// never granted: the scoped-uid binding read S's OWN status (2, Scoped)
    /// and passed, committing a forged grant via the authorized path and
    /// bypassing the Extend/Reduce rejections.
    ///
    /// RED before fix: `extract_and_validate` returns `Ok`. GREEN after: `Err`
    /// naming the full-member signer requirement.
    #[test]
    fn test_scoped_signer_rekey_self_grant_rejected() {
        let signer = 5u32;
        // Self-grant: uid == signer, arbitrary channel the signer never held.
        let entry = make_rekey_entry_kv(signer, grant_row_kvs(signer as i64, 9));

        // Full pre-fix read stream so the vulnerable path runs to completion:
        // signer status (2 — passes the provisional gate), grant-uid status
        // (same row, 2 — scoped binding passes), then the retention tail.
        let sk = user_status_key(signer);
        let mut reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk.clone(), stored_i64(2))],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(2))],
            },
        ];
        reads.extend(rekey_retention_tail_reads());
        let mut reader = VerifierReader::new(&reads);
        let result =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(
            result.is_err(),
            "a Scoped signer's Rekey (self-grant forgery) must be rejected, \
             got Ok (forged grant committed)"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("full member"),
            "expected the full-member signer rejection, got: {msg}"
        );
    }

    /// A non-canonical (negative-uid) grant key is rejected before any status
    /// read — canonical decimal form is mandatory.
    #[test]
    fn test_channel_grant_noncanonical_rejected_for_rekey() {
        let signer = 1u32;
        let entry = make_rekey_entry_kv(
            signer,
            vec![
                (
                    column_key("_retention", 0, "key"),
                    stored_str("sl2/channel_grant/-5/7"),
                ),
                (column_key("_retention", 0, "value"), vec![0xBB; 32]),
            ],
        );
        let sk = user_status_key(signer);
        let reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let result =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(
            result.is_err(),
            "a non-canonical (negative-uid) grant key must be rejected"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("non-canonical channel_grant key"),
            "expected a non-canonical rejection, got: {msg}"
        );
    }

    fn make_rekey_entry(uid: u32, retention_keys: &[Vec<u8>]) -> ChangelogEntry {
        let entries: Vec<KvData> = retention_keys
            .iter()
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
                op_type: OpType::Rekey,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn test_provisional_user_rejected_for_rekey() {
        let uid = 1u32;
        let retention_keys = vec![
            column_key("_retention", 0, "key"),
            column_key("_retention", 0, "value"),
        ];
        let entry = make_rekey_entry(uid, &retention_keys);

        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(0)).unwrap())],
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

        let err =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("provisional user"), "unexpected error: {msg}");
    }

    #[test]
    fn test_wrong_table_rejected_for_rekey() {
        let uid = 1u32;
        let wrong_keys = vec![
            column_key("_users", 0, "key"),
            column_key("_users", 0, "value"),
        ];
        let entry = make_rekey_entry(uid, &wrong_keys);

        let reads = vec![];
        let mut reader = VerifierReader::new(&reads);

        let err =
            RekeyOp::extract_and_validate(&entry, &mut reader, &super::super::OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("retention columns target table"),
            "unexpected error: {msg}"
        );
    }
}
