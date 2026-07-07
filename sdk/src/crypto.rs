use crate::Space;
use encrypted_spaces_backend::{
    error::{Result, SdkError},
    query::{Query, QueryOperation, QueryParam},
    schema::{ColumnType, Schema},
};
use encrypted_spaces_crypto::encryption::{
    decrypt_row, encrypt_row, EncryptedColumn, EncryptionKey, FieldType,
};
use encrypted_spaces_crypto::error::EncryptionError;
use crate::TreeKeyId;
use encrypted_spaces_key_manager::SpaceKey;
use std::collections::HashMap;

/// Convert a schema to a list of encrypted columns (those with `plaintext == false`).
fn encrypted_columns_from_schema(schema: &Schema) -> Vec<EncryptedColumn> {
    schema
        .columns
        .iter()
        .filter(|c| !c.plaintext)
        .map(|c| EncryptedColumn {
            name: c.name.clone(),
            field_type: match c.column_type {
                ColumnType::Integer => FieldType::Integer,
                ColumnType::Real => FieldType::Real,
                ColumnType::String | ColumnType::Text => FieldType::Text,
                ColumnType::Blob => FieldType::Blob,
                ColumnType::FileRef => FieldType::FileRef,
                ColumnType::List => FieldType::List,
            },
        })
        .collect()
}

/// Derive the encryption key for the current key id from the space's key manager.
pub(crate) async fn current_encryption_key(space: &Space) -> Result<EncryptionKey> {
    let builder = space.retention_builder();
    let km = space.key_manager.lock().await;
    let key_id = km
        .current_key_id(&builder)
        .await
        .map_err(|_| SdkError::DecryptionError("current key id failed".into()))?;
    km.data_key_for_key_id(&key_id, &builder)
        .await
        .map(|bytes| EncryptionKey::new(bytes, &key_id))
        .map_err(|_| SdkError::DecryptionError("missing key for current key_id".into()))
}

/// Derive the encryption key for a row in `channel` (L2 read scoping, whitepaper
/// §4.3/§5.1): the channel's data key is derived from the group key **at the
/// current epoch** and the channel — `TreeKeyId{channel, seq}` in the
/// ciphertext header, with `seq` stamped to the current epoch (the FGK
/// ordinal) so the row stays readable-by-epoch across later rekeys (the
/// root line's `resolve_d_key`/`group_key_at` edge-walk is the template).
/// A full member derives it from the epoch's group key; a member scoped away
/// from `channel` cannot, so it can't read the row.
///
/// Getting the current epoch does NOT require the root line's
/// `current_key_id` — `TreeSpaceKey::current_channel_epoch` resolves it from
/// storage directly for a full member, and from the newest delivered grant
/// for a scoped member — so a **scoped** member (no group key) can still
/// post to its own channels, not only read them.
pub(crate) async fn channel_encryption_key(
    space: &Space,
    channel: i64,
) -> Result<EncryptionKey> {
    let builder = space.retention_builder();
    // Snapshot the space key under a brief lock, then RELEASE `key_manager`
    // before the storage reads below. `current_channel_epoch` and
    // `data_key_for_key_id` resolve the live chain / group-key edges through
    // the retention reader, which lazily fast-forwards the changelog when this
    // replica is behind (e.g. writing a channel row before syncing another
    // member's join) -- and the fast-forward path itself re-locks
    // `key_manager`. Holding the (async, single-threaded) lock across those
    // reads re-enters it and deadlocks forever; deriving on a clone lets the
    // fast-forward re-lock `key_manager` freely. No crypto is duplicated. The
    // snapshot is fail-closed and self-healing under a concurrent rekey by
    // another member: deriving from the pre-clone key material against a chain
    // the reader just fast-forwarded fails the commitment check -> a transient
    // "channel key derivation failed" that heals on retry, never a wrong-epoch
    // key. (A member's own key material changes only on its own rekey.)
    let space_key = space.key_manager.lock().await.space_key().clone();
    let current_epoch = space_key
        .current_channel_epoch(channel, &builder)
        .await
        .map_err(|_| SdkError::DecryptionError("current channel epoch failed".into()))?;
    let key_id = TreeKeyId::new(channel, current_epoch);
    space_key
        .data_key_for_key_id(&key_id, &builder)
        .await
        .map(|bytes| EncryptionKey::new(bytes, &key_id))
        .map_err(|_| SdkError::DecryptionError("channel key derivation failed".into()))
}

/// Extract the row's `channel_id` value from an Insert/Update query, if the
/// table has a plaintext `channel_id` column — the routing key for L2 read
/// scoping. `None` ⇒ channel-less/global table ⇒ root line.
fn query_channel_id(operation: &QueryOperation, schema: &Schema) -> Option<i64> {
    if !schema.columns.iter().any(|c| c.name == "channel_id") {
        return None;
    }
    let fields = match operation {
        QueryOperation::Insert(f) | QueryOperation::Update(f) => f,
        _ => return None,
    };
    fields.iter().find_map(|(name, param)| {
        if name == "channel_id" {
            match param {
                QueryParam::Integer(v) => Some(*v),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Encrypt fields in a query's Insert or Update operation, using the current
/// key from `space`. No-op for Select/Delete or tables without encrypted columns.
pub(crate) async fn encrypt_query_fields(query: &mut Query, space: &Space) -> Result<()> {
    let schema = match space.get_table_schema(&query.table) {
        Some(s) => s,
        None => return Ok(()),
    };

    let columns = encrypted_columns_from_schema(&schema);
    if columns.is_empty() {
        return Ok(());
    }

    // Route to the row's channel line (L2 read scoping) when the table carries a
    // channel_id; otherwise the root line.
    let key = match query_channel_id(&query.operation, &schema) {
        Some(channel) => channel_encryption_key(space, channel).await?,
        None => current_encryption_key(space).await?,
    };

    let is_insert = matches!(query.operation, QueryOperation::Insert(_));

    let fields = match &mut query.operation {
        QueryOperation::Insert(fields) => fields,
        QueryOperation::Update(fields) => fields,
        QueryOperation::Select(_) | QueryOperation::Delete => return Ok(()),
    };

    // Validate: all query fields must exist in schema
    for (name, _) in fields.iter() {
        if !schema.columns.iter().any(|c| &c.name == name) {
            return Err(SdkError::InvalidQuery(format!(
                "Query field '{}' not found in schema for table '{}'",
                name, schema.name
            )));
        }
    }

    // Validate: all encrypted columns must be present in insert operations
    if is_insert {
        for col in &columns {
            if !fields.iter().any(|(name, _)| name == &col.name) {
                return Err(SdkError::InvalidQuery(format!(
                    "Encrypted column '{}' missing from query for table '{}'",
                    col.name, schema.name
                )));
            }
        }
    }

    // Build a JSON row map from fields, encrypt, then write back
    let mut row = serde_json::Map::new();
    for (name, param) in fields.iter() {
        row.insert(name.clone(), query_param_to_value(param));
    }

    encrypt_row(&mut row, &columns, &key);

    // Write encrypted values back to fields
    for (name, param) in fields.iter_mut() {
        if let Some(serde_json::Value::String(s)) = row.get(name) {
            if columns.iter().any(|c| &c.name == name) {
                *param = QueryParam::Text(s.clone());
            }
        }
    }

    Ok(())
}

/// Decrypt rows in-place for a specific table. The epoch embedded in each
/// ciphertext header is used to resolve the correct key from `space`.
///
/// Returns an error if key resolution or decryption fails.
pub(crate) async fn decrypt_table_rows(
    rows: &mut Vec<serde_json::Value>,
    table_name: &str,
    schemas: &HashMap<String, Schema>,
    space: &Space,
) -> Result<()> {
    let table_key = table_name.split(" as ").next().unwrap_or(table_name);
    let schema = match schemas.get(table_key) {
        Some(s) => s,
        None => return Ok(()),
    };
    let columns = encrypted_columns_from_schema(schema);
    if columns.is_empty() {
        return Ok(());
    }
    // Snapshot the space key, then RELEASE `key_manager` before decrypting.
    // A channel row resolves its data key via a group-key edge-walk through
    // the retention reader, which lazily fast-forwards the changelog when this
    // replica is behind -- and the fast-forward path re-locks `key_manager`.
    // Holding it across the per-row resolver would re-enter the (async,
    // single-threaded) lock and deadlock; deriving on a clone avoids it (same
    // reasoning as `channel_encryption_key`). Fail-closed under a concurrent
    // rekey: a stale snapshot fails the commitment check → a transient
    // MissingKey (row dropped this pass, reappears on the next read), never a
    // wrong key.
    let space_key = space.key_manager.lock().await.space_key().clone();
    let builder = space.retention_builder();
    let resolver = |key_id: TreeKeyId| {
        let space_key = &space_key;
        let builder = &builder;
        async move {
            space_key
                .data_key_for_key_id(&key_id, builder)
                .await
                .map(|bytes| EncryptionKey::new(bytes, &key_id))
                .map_err(|_| EncryptionError::MissingKey(format!("{key_id:?}").into_bytes()))
        }
    };
    // Decrypt each row in-place. Rows whose keys have been pruned (e.g.
    // after a reduce) are removed. Because decrypt_row is async we can't
    // use retain_mut, so we drain into a new vec in a single pass.
    let mut decrypted = Vec::with_capacity(rows.len());
    for mut row in rows.drain(..) {
        if let serde_json::Value::Object(ref mut obj) = row {
            if let Err(e) = decrypt_row(obj, &columns, &resolver).await {
                log::warn!("Failed to decrypt row, removing from result set: {e}");
                continue;
            }
        }
        decrypted.push(row);
    }
    *rows = decrypted;
    Ok(())
}

#[cfg(all(test, feature = "local-transport"))]
mod tests {
    use super::{decrypt_table_rows, encrypt_query_fields};
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use crate::Space;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
    use encrypted_spaces_backend::schema::Schema;
    use encrypted_spaces_crypto::encryption::ciphertext_key_id;
    use crate::TreeKeyId;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct SecretNote {
        id: Option<i64>,
        title: String,
        body: String,
    }

    fn schema() -> ApplicationSchema {
        ApplicationSchema::for_testing(vec![], crate::testing::initial_internal_data_commitment())
    }

    async fn create_space() -> Result<(LocalTransport, Space)> {
        let transport = LocalTransport::in_memory().await?;
        let space = Space::create(transport.clone(), schema()).await?;
        Ok((transport, space))
    }

    fn notes_schema() -> Result<Schema> {
        SchemaBuilder::new("notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("title", ColumnType::String)?
            .column("body", ColumnType::String)?
            .build()
    }

    async fn create_notes_table(space: &Space) -> Result<crate::Table<SecretNote>> {
        let table = space.table::<SecretNote>("notes");
        space.create_table(&notes_schema()?).await?;
        Ok(table)
    }

    /// A channel-scoped table: plaintext `channel_id` (the L2 routing key) + an
    /// encrypted `body`.
    fn msgs_schema() -> Result<Schema> {
        SchemaBuilder::new("msgs")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("channel_id", ColumnType::Integer)?
            .plaintext()
            .column("body", ColumnType::String)?
            .build()
    }

    fn insert_body_ciphertext_key_id(query: &Query) -> Option<TreeKeyId> {
        let fields = match &query.operation {
            QueryOperation::Insert(f) => f,
            _ => return None,
        };
        let body = fields.iter().find(|(n, _)| n == "body")?;
        let b64 = match &body.1 {
            QueryParam::Text(s) => s,
            _ => return None,
        };
        let raw = STANDARD.decode(b64).ok()?;
        ciphertext_key_id::<TreeKeyId>(&raw)
    }

    #[tokio::test]
    async fn channel_rows_encrypt_under_derived_channel_keys() -> Result<()> {
        let (_, space) = create_space().await?;
        space.create_table(&msgs_schema()?).await?;

        // No channel setup needed — channel keys are pure derivation (§4.3/§5.1).
        // A row for channel 1 encrypts under channel 1's derived key...
        let mut q1 = Query::new(
            "msgs".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(1)),
                ("channel_id".to_string(), QueryParam::Integer(1)),
                ("body".to_string(), QueryParam::Text("secret in ch1".into())),
            ]),
        );
        encrypt_query_fields(&mut q1, &space).await?;
        assert_eq!(
            insert_body_ciphertext_key_id(&q1),
            Some(TreeKeyId::new(1, 0)),
            "channel-1 row must be tagged with channel 1's key id"
        );

        // ...and a channel-2 row under channel 2's line.
        let mut q2 = Query::new(
            "msgs".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(2)),
                ("channel_id".to_string(), QueryParam::Integer(2)),
                ("body".to_string(), QueryParam::Text("secret in ch2".into())),
            ]),
        );
        encrypt_query_fields(&mut q2, &space).await?;
        assert_eq!(
            insert_body_ciphertext_key_id(&q2),
            Some(TreeKeyId::new(2, 0)),
            "channel-2 row must be tagged with channel 2's key id"
        );

        // The full member (holds all channel lines) round-trips the channel-1 row.
        let fields = match &q1.operation {
            QueryOperation::Insert(f) => f,
            _ => panic!("expected Insert"),
        };
        let mut row = serde_json::Map::new();
        for (name, param) in fields {
            let value = match param {
                QueryParam::Integer(i) => serde_json::Value::Number((*i).into()),
                QueryParam::Text(s) => serde_json::Value::String(s.clone()),
                QueryParam::Null => serde_json::Value::Null,
                _ => panic!("unexpected param type"),
            };
            row.insert(name.clone(), value);
        }
        let mut rows = vec![serde_json::Value::Object(row)];
        let schemas = space.with_state(|s| s.table_schemas.clone());
        decrypt_table_rows(&mut rows, "msgs", &schemas, &space).await?;
        assert_eq!(
            rows[0].as_object().unwrap().get("body"),
            Some(&serde_json::Value::String("secret in ch1".into()))
        );

        Ok(())
    }

    #[tokio::test]
    async fn scoped_agent_reads_only_its_channels() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;
        let msgs = alice.table::<Msg>("msgs");
        msgs.insert(&Msg { id: None, channel_id: 1, body: "secret in ch1".into() })
            .execute()
            .await?;
        msgs.insert(&Msg { id: None, channel_id: 2, body: "secret in ch2".into() })
            .execute()
            .await?;

        // Invite an agent SCOPED to channel 1 only; it joins with no group key,
        // holding only channel 1's subtree key.
        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;
        // The agent has the app schema (in the real app it joins with it); register
        // the msgs table locally so it decrypts (and thus scopes) reads.
        agent.register_table_schema(msgs_schema()?);

        // The agent reads only channel 1's row — channel 2 is cryptographically
        // out of scope (its key is underivable), so that row is dropped.
        let rows: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert_eq!(rows.len(), 1, "scoped agent must see only its channel");
        assert_eq!(rows[0].channel_id, 1);
        assert_eq!(rows[0].body, "secret in ch1");
        Ok(())
    }

    /// L2 Part B (Task 4): a scoped invite must commit a `_retention`
    /// channel-grant record per granted channel. Each record commits the SAME
    /// `KeyCommitment` the mVE delivery binds — so the persisted grant ≡ the
    /// delivered channel key — and the server only lets the rows land after
    /// verifying each grant's derivation proof, so their presence is proof the
    /// server accepted them.
    #[tokio::test]
    async fn scoped_invite_writes_grant_records() -> Result<()> {
        use encrypted_spaces_crypto::KeyCommitment;
        use encrypted_spaces_key_manager::channel_grant::grant_row_key;
        use encrypted_spaces_key_manager::ScopedDeliveryEnvelope;

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // Founder scopes an agent to channels [1, 3].
        let invite = alice.invite_user_scoped(&[1, 3]).await?;
        let uid = invite.id().expect("scoped invite carries a provisional uid");

        // The delivered channel keys (mVE binding commitments) recorded in the
        // invitee's server-side delivery slot.
        let server = transport.server_state();
        let slot = server
            .lock()
            .await
            .get_delivery_slot(uid)
            .expect("scoped invitee has a delivery slot");
        let env: ScopedDeliveryEnvelope =
            serde_json::from_slice(&slot).expect("scoped delivery envelope");

        for ch in [1i64, 3i64] {
            let delivered = env
                .channels
                .iter()
                .find(|c| c.channel == ch)
                .unwrap_or_else(|| panic!("channel {ch} must be delivered"))
                .binding_commitment;

            // The scoped invite must have committed a channel-grant `_retention`
            // row keyed by the invitee's uid, committing the delivered key.
            let rec: Option<crate::retention::RetentionRecord> = alice
                .retention_table()
                .select()
                .where_eq("key", grant_row_key(uid, ch).as_str())
                .last()
                .await?;
            let rec = rec.unwrap_or_else(|| panic!("grant row for channel {ch} must exist"));
            let committed = KeyCommitment::from_bytes(&rec.value)
                .expect("grant row value decodes to a KeyCommitment");
            assert_eq!(
                committed, delivered,
                "channel {ch} grant commitment must equal the delivered binding commitment"
            );
        }
        Ok(())
    }

    /// A scoped member (no group key) must be able to WRITE into its channel,
    /// and both it AND a full member must decrypt that write. This is the
    /// agent-posts-a-reply path: the scoped writer derives the channel key from
    /// its delivered subtree key (never `current_key_id`, which needs the group
    /// key), and the full member derives the same key from the group key.
    #[tokio::test]
    async fn scoped_member_writes_and_full_member_reads() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // Scope an agent to channel 2 only; it joins with no group key.
        let invite = alice.invite_user_scoped(&[2]).await?;
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;
        agent.register_table_schema(msgs_schema()?);

        // The SCOPED agent posts into its channel (the previously-broken path).
        agent
            .table::<Msg>("msgs")
            .insert(&Msg { id: None, channel_id: 2, body: "reply from scoped agent".into() })
            .execute()
            .await?;

        // The scoped agent reads back its own post.
        let seen_by_agent: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert_eq!(seen_by_agent.len(), 1, "scoped writer must read its own post");
        assert_eq!(seen_by_agent[0].body, "reply from scoped agent");

        // The FULL member (alice, uid 1) decrypts the scoped agent's post —
        // deriving channel 2's key from the group key must match the agent's
        // delivered subtree key.
        let seen_by_alice: Vec<Msg> = alice.table::<Msg>("msgs").select().all().await?;
        assert_eq!(seen_by_alice.len(), 1, "full member must read scoped member's post");
        assert_eq!(seen_by_alice[0].channel_id, 2);
        assert_eq!(seen_by_alice[0].body, "reply from scoped agent");
        Ok(())
    }

    // -----------------------------------------------------------------
    // `Space::voice_root` — the voice media plane's channel subtree key.
    // Same underlying derivation `invite_user_scoped` delivers (§4.3);
    // exercised here (rather than in `users.rs`) because this module
    // already carries the full-member/scoped-member `Space` harness.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn full_member_voice_root_matches_derived_channel_key() -> Result<()> {
        let (_, space) = create_space().await?;

        // Ground truth: the exact lock/space_key/channel_subtree_key sequence
        // `invite_user_scoped` uses to derive a channel's subtree key for
        // delivery. `voice_root` must expose precisely this value.
        let expected_ch1 = {
            let km = space.key_manager.lock().await;
            km.space_key()
                .channel_subtree_key(1)
                .expect("a full member derives every channel's subtree key")
        };

        let root1 = space.voice_root(1).await;
        assert_eq!(
            root1,
            Some(expected_ch1),
            "voice_root(1) must equal the channel's derived subtree key"
        );

        // A different channel must derive a different root (the channel id is
        // mixed into the derivation, not ignored).
        let root2 = space.voice_root(2).await;
        assert_ne!(
            root1, root2,
            "different channels must derive different voice roots"
        );

        Ok(())
    }

    #[tokio::test]
    async fn scoped_member_voice_root_is_none_even_for_a_delivered_channel() -> Result<()> {
        let (transport, alice) = create_space().await?;

        // Agent scoped to channel 1 only — it joins holding a *delivered*
        // channel-1 subtree key, never the group key.
        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;

        // `voice_root` derives from the group key (mirrors
        // `channel_subtree_key`'s full-member-only contract) — a scoped
        // member holds no group key, so it gets `None` for every channel,
        // even the one it was granted delivered read access to.
        assert_eq!(
            agent.voice_root(1).await,
            None,
            "a scoped member cannot derive — only a full member can"
        );
        assert_eq!(agent.voice_root(2).await, None);

        Ok(())
    }

    #[tokio::test]
    async fn any_channel_derives_without_setup() -> Result<()> {
        let (_, space) = create_space().await?;
        space.create_table(&msgs_schema()?).await?;
        // Channel 5 needs no setup — its key is derived on the fly (pure
        // derivation), tagged with its own channel id (not the root line).
        let mut q = Query::new(
            "msgs".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(1)),
                ("channel_id".to_string(), QueryParam::Integer(5)),
                ("body".to_string(), QueryParam::Text("secret in ch5".into())),
            ]),
        );
        encrypt_query_fields(&mut q, &space).await?;
        assert_eq!(insert_body_ciphertext_key_id(&q), Some(TreeKeyId::new(5, 0)));
        Ok(())
    }

    // ── Unit tests for encrypt_query_fields / decrypt_table_rows ────────

    #[tokio::test]
    async fn encrypt_query_fields_encrypts_non_plaintext_columns() -> Result<()> {
        let (_, space) = create_space().await?;
        // Register the notes schema so encrypt_query_fields can find it.
        let _notes = create_notes_table(&space).await?;

        let mut query = Query::new(
            "notes".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Null),
                ("title".to_string(), QueryParam::Text("secret title".into())),
                ("body".to_string(), QueryParam::Text("secret body".into())),
            ]),
        );

        encrypt_query_fields(&mut query, &space).await?;

        let fields = match &query.operation {
            QueryOperation::Insert(f) => f,
            _ => panic!("expected Insert"),
        };

        // `id` is plaintext — should remain Null.
        let id_param = fields.iter().find(|(n, _)| n == "id").unwrap();
        assert!(matches!(id_param.1, QueryParam::Null));

        // `title` and `body` should now be encrypted (base64 ciphertext).
        for col_name in &["title", "body"] {
            let (_, param) = fields.iter().find(|(n, _)| n == col_name).unwrap();
            let ciphertext_b64 = match param {
                QueryParam::Text(s) => s,
                other => panic!("expected Text for {col_name}, got {other:?}"),
            };
            // Should be valid base64 that decodes to a ciphertext with key_id 0.
            let raw = STANDARD
                .decode(ciphertext_b64)
                .expect("encrypted field should be valid base64");
            assert_eq!(
                ciphertext_key_id::<TreeKeyId>(&raw),
                Some(TreeKeyId::root(0)),
                "{col_name} ciphertext should be tagged with key_id 0"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn encrypt_query_fields_is_noop_for_select() -> Result<()> {
        let (_, space) = create_space().await?;
        let _notes = create_notes_table(&space).await?;

        let mut query = Query::new(
            "notes".to_string(),
            QueryOperation::Select(vec!["*".to_string()]),
        );

        encrypt_query_fields(&mut query, &space).await?;

        // Should still be a Select — unchanged.
        assert!(matches!(query.operation, QueryOperation::Select(_)));

        Ok(())
    }

    #[tokio::test]
    async fn decrypt_table_rows_roundtrips_with_encrypt() -> Result<()> {
        let (_, space) = create_space().await?;
        let _notes = create_notes_table(&space).await?;

        // Encrypt a query's fields.
        let mut query = Query::new(
            "notes".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(1)),
                ("title".to_string(), QueryParam::Text("roundtrip".into())),
                ("body".to_string(), QueryParam::Text("test body".into())),
            ]),
        );
        encrypt_query_fields(&mut query, &space).await?;

        // Build a JSON row from the encrypted fields (simulating what the DB stores).
        let fields = match &query.operation {
            QueryOperation::Insert(f) => f,
            _ => panic!("expected Insert"),
        };
        let mut row = serde_json::Map::new();
        for (name, param) in fields {
            let value = match param {
                QueryParam::Integer(i) => serde_json::Value::Number((*i).into()),
                QueryParam::Text(s) => serde_json::Value::String(s.clone()),
                QueryParam::Null => serde_json::Value::Null,
                _ => panic!("unexpected param type"),
            };
            row.insert(name.clone(), value);
        }

        let mut rows = vec![serde_json::Value::Object(row)];

        // Decrypt using the space's schemas.
        let schemas = space.with_state(|s| s.table_schemas.clone());
        decrypt_table_rows(&mut rows, "notes", &schemas, &space).await?;

        let obj = rows[0].as_object().unwrap();
        assert_eq!(obj.get("id"), Some(&serde_json::Value::Number(1.into())));
        assert_eq!(
            obj.get("title"),
            Some(&serde_json::Value::String("roundtrip".into()))
        );
        assert_eq!(
            obj.get("body"),
            Some(&serde_json::Value::String("test body".into()))
        );

        Ok(())
    }

    #[tokio::test]
    async fn decrypt_table_rows_skips_table_without_schema() -> Result<()> {
        let (_, space) = create_space().await?;

        let mut rows = vec![serde_json::json!({"x": "hello"})];
        let empty_schemas: HashMap<String, Schema> = HashMap::new();

        // Should be a no-op — no error, rows unchanged.
        decrypt_table_rows(&mut rows, "nonexistent", &empty_schemas, &space).await?;
        assert_eq!(
            rows[0].as_object().unwrap().get("x"),
            Some(&serde_json::Value::String("hello".into()))
        );

        Ok(())
    }

    // ── Integration tests via Table ─────────────────────────────────────

    #[tokio::test]
    async fn encrypt_decrypt_at_epoch_zero() -> Result<()> {
        let (_, space) = create_space().await?;
        let notes = create_notes_table(&space).await?;

        // Write encrypted data at epoch 0.
        notes
            .insert(&SecretNote {
                id: None,
                title: "hello".into(),
                body: "world".into(),
            })
            .execute()
            .await?;

        // Read raw rows from the transport (bypassing SDK decryption) to
        // verify stored ciphertext is tagged with epoch 0.
        {
            let raw_query = Query::new(
                "notes".to_string(),
                QueryOperation::Select(vec!["*".to_string()]),
            );
            let commitment = space.current_data_commitment();
            let schemas = HashMap::from([(
                "notes".to_string(),
                space.get_table_schema("notes").expect("notes schema"),
            )]);
            let verified = space
                .transport
                .select(raw_query, &commitment, &schemas)
                .await?;
            let raw_row = verified.main_rows[0].as_object().unwrap();

            for col_name in &["title", "body"] {
                let raw_val = raw_row.get(*col_name).expect("column should exist");
                let b64 = raw_val
                    .as_str()
                    .expect("encrypted column should be a string");
                // Should NOT be the plaintext value.
                assert_ne!(b64, "hello");
                assert_ne!(b64, "world");
                let raw = STANDARD.decode(b64).expect("should be valid base64");
                assert_eq!(
                    ciphertext_key_id::<TreeKeyId>(&raw),
                    Some(TreeKeyId::root(0)),
                    "{col_name} ciphertext should be tagged with key_id 0"
                );
            }
        }

        // Read it back — fields should round-trip through encryption.
        let rows = notes.select().all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "hello");
        assert_eq!(rows[0].body, "world");

        Ok(())
    }

    #[tokio::test]
    async fn both_users_read_after_add_user() -> Result<()> {
        let (transport, alice_space) = create_space().await?;
        let alice_notes = create_notes_table(&alice_space).await?;

        let builder = alice_space.retention_builder();
        let km = alice_space.key_manager.lock().await;
        let key_id_before = km.current_key_id(&builder).await.unwrap();
        drop(km);

        // Alice writes a note at key_id 0.
        alice_notes
            .insert(&SecretNote {
                id: None,
                title: "before invite".into(),
                body: "initial data".into(),
            })
            .execute()
            .await?;

        // Alice invites Bob — key_id does NOT advance.
        let invite = alice_space.invite_user().await?;
        let bob_space = Space::join(
            transport,
            invite,
            ApplicationSchema::for_testing(
                vec![notes_schema()?],
                crate::testing::initial_internal_data_commitment(),
            ),
        )
        .await?;

        let builder_after = alice_space.retention_builder();
        let km = alice_space.key_manager.lock().await;
        let key_id_after = km.current_key_id(&builder_after).await.unwrap();
        drop(km);
        assert_eq!(
            key_id_after, key_id_before,
            "key_id should NOT advance after invite"
        );

        // Alice writes another note (same key_id since invite doesn't advance).
        alice_notes
            .insert(&SecretNote {
                id: None,
                title: "after invite".into(),
                body: "same key data".into(),
            })
            .execute()
            .await?;

        // Read raw rows from the transport to verify key_id tagging.
        {
            let raw_query = Query::new(
                "notes".to_string(),
                QueryOperation::Select(vec!["*".to_string()]),
            );
            let commitment = alice_space.current_data_commitment();
            let schemas = HashMap::from([(
                "notes".to_string(),
                alice_space.get_table_schema("notes").expect("notes schema"),
            )]);
            let verified = alice_space
                .transport
                .select(raw_query, &commitment, &schemas)
                .await?;
            // Both rows written with the same key_id (invite doesn't advance).
            for raw_row in &verified.main_rows {
                let obj = raw_row.as_object().unwrap();
                let id = obj.get("id").and_then(|v| v.as_i64()).unwrap();
                let b64 = obj.get("title").and_then(|v| v.as_str()).unwrap();
                let raw = STANDARD.decode(b64).expect("should be valid base64");
                assert_eq!(
                    ciphertext_key_id::<TreeKeyId>(&raw),
                    Some(key_id_before.clone()),
                    "row id={id} should be encrypted with initial key_id"
                );
            }
        }

        // Alice can read both old and new data.
        let alice_rows = alice_notes.select().ascending().all().await?;
        assert_eq!(alice_rows.len(), 2);
        assert_eq!(alice_rows[0].title, "before invite");
        assert_eq!(alice_rows[1].title, "after invite");

        // Bob can also read both rows.
        let bob_notes = create_notes_table(&bob_space).await?;
        let bob_rows = bob_notes.select().ascending().all().await?;
        assert_eq!(bob_rows.len(), 2);
        assert_eq!(bob_rows[0].title, "before invite");
        assert_eq!(bob_rows[1].title, "after invite");

        Ok(())
    }

    /// SECURITY (§8): after a group rekey, a scoped member's delivery slot must
    /// NOT contain a group-key envelope. If it does, a malicious scoped member
    /// can fetch and decrypt the group key, defeating L2 read scoping.
    #[tokio::test]
    async fn scoped_member_slot_has_no_group_key_after_rekey() -> Result<()> {
        use encrypted_spaces_key_manager::{GkDeliveryEnvelope, ScopedDeliveryEnvelope};

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // Scope an agent to channel 1 only; it joins holding no group key.
        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent_uid = invite.id().expect("scoped invite carries a provisional uid");
        let _agent = crate::Space::join(transport.clone(), invite, schema()).await?;

        // `join` rotates the agent's provisional keypair to a permanent one
        // (an update to _users made by the *agent's* connection). Alice's
        // local _users cache only reflects that rotation once her broadcast
        // listener has processed it, which is not guaranteed by the time
        // control returns here. Without this, `rekey()` below would build a
        // group-key ciphertext against the agent's stale (pre-rotation) pk,
        // and the server's independent re-fetch of _users would fail MVE
        // verification against the *current* pk -- a race unrelated to the
        // §8 leak this test targets. Force alice's view to converge first.
        alice.recover_via_fast_forward().await?;

        // A full member forces a real group rekey (new group key epoch).
        alice.rekey().await?;

        // Inspect the scoped member's server-side delivery slot directly.
        let server = transport.server_state();
        let bytes = server
            .lock()
            .await
            .get_delivery_slot(agent_uid)
            .expect("scoped member has a delivery slot from its invite");

        assert!(
            serde_json::from_slice::<GkDeliveryEnvelope>(&bytes).is_err(),
            "SECURITY LEAK: scoped member's slot contains a GroupKey envelope after rekey"
        );
        assert!(
            serde_json::from_slice::<ScopedDeliveryEnvelope>(&bytes).is_ok(),
            "scoped member's slot should still hold its ScopedDeliveryEnvelope"
        );
        Ok(())
    }

    /// SECURITY (§8, remove-path): the leak test above only drives the
    /// standalone-rekey trigger (`handle_retention`). A member removal is the
    /// *other* path that forces a group rekey (`handle_remove_member`) — a
    /// scoped survivor of that rekey must be just as excluded from group-key
    /// delivery as a survivor of a standalone rekey.
    #[tokio::test]
    async fn scoped_member_slot_has_no_group_key_after_member_removal() -> Result<()> {
        use encrypted_spaces_key_manager::{GkDeliveryEnvelope, ScopedDeliveryEnvelope};

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // Scope an agent to channel 1 only; it joins holding no group key.
        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent_uid = invite.id().expect("scoped invite carries a provisional uid");
        let _agent = crate::Space::join(transport.clone(), invite, schema()).await?;

        // A throwaway FULL member, whose later removal is what triggers the
        // rekey under test (not the scoped agent itself).
        let full_invite = alice.invite_user().await?;
        let throwaway_uid = full_invite.user.id.expect("full invite carries a uid");
        let _throwaway = crate::Space::join(transport.clone(), full_invite, schema()).await?;

        // Converge alice's `_users` cache on both members' post-join key
        // rotations before she builds the removal's rekey (same reasoning as
        // the standalone-rekey leak test above).
        alice.recover_via_fast_forward().await?;

        // Remove the throwaway full member — this forces `handle_remove_member`
        // to rekey the group, which must still exclude the scoped survivor.
        alice.remove_user(throwaway_uid).await?;

        // Inspect the scoped member's server-side delivery slot directly.
        let server = transport.server_state();
        let bytes = server
            .lock()
            .await
            .get_delivery_slot(agent_uid)
            .expect("scoped member has a delivery slot from its invite");

        assert!(
            serde_json::from_slice::<GkDeliveryEnvelope>(&bytes).is_err(),
            "SECURITY LEAK: scoped member's slot contains a GroupKey envelope after a member-removal rekey"
        );
        assert!(
            serde_json::from_slice::<ScopedDeliveryEnvelope>(&bytes).is_ok(),
            "scoped member's slot should still hold its ScopedDeliveryEnvelope"
        );
        Ok(())
    }

    /// A rekey that lands between a scoped invite and the invitee's join must
    /// not escalate them: they must still bootstrap as SCOPED (no group key).
    /// This is Failure Mode 1 from the §8 design review — if the fix only
    /// guarded the delivery-slot *contents* written at rekey time but the
    /// invitee's slot had already been overwritten with a group-key envelope
    /// (e.g. by a naive "rekey writes GK to every _users row" implementation),
    /// this test would catch it: `join` would successfully parse a
    /// `GkDeliveryEnvelope` and the agent would incorrectly hold the group key.
    #[tokio::test]
    async fn scoped_invite_rekeyed_before_join_still_bootstraps_scoped() -> Result<()> {
        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;
        let invite = alice.invite_user_scoped(&[1]).await?;
        // Rekey BEFORE the scoped invitee joins.
        alice.rekey().await?;
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;
        assert!(
            !agent.holds_group_key().await,
            "scoped invitee rekeyed-before-join must not become a full member"
        );
        Ok(())
    }

    /// No-harm check: excluding scoped members from group-key rekey delivery
    /// (the §8 fix) must not disturb normal delivery to FULL members. A full
    /// member must still receive the group key across a rekey and decrypt
    /// data written after it, alongside a scoped member that must not.
    #[tokio::test]
    async fn full_member_still_receives_group_key_across_rekey() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // A second FULL member.
        let bob_invite = alice.invite_user().await?;
        let bob = crate::Space::join(transport.clone(), bob_invite, schema()).await?;
        bob.register_table_schema(msgs_schema()?);

        // A scoped member (must NOT receive the group key across the rekey).
        let agent_invite = alice.invite_user_scoped(&[1]).await?;
        let _agent = crate::Space::join(transport.clone(), agent_invite, schema()).await?;

        // Converge alice's `_users` cache on both members' post-join key
        // rotations before rekeying (same reasoning as the leak test above).
        alice.recover_via_fast_forward().await?;

        alice.rekey().await?;

        // Alice writes AFTER the rekey, under the new group-key epoch.
        alice
            .table::<Msg>("msgs")
            .insert(&Msg { id: None, channel_id: 1, body: "post-rekey secret".into() })
            .execute()
            .await?;

        // Bob (full member) must still be able to decrypt it — proving normal
        // rekey delivery to full members is intact.
        bob.sync().await?;
        let seen_by_bob: Vec<Msg> = bob.table::<Msg>("msgs").select().all().await?;
        assert_eq!(
            seen_by_bob.len(),
            1,
            "full member must still receive the group key across a rekey"
        );
        assert_eq!(seen_by_bob[0].body, "post-rekey secret");

        Ok(())
    }

    /// THE regression gate for epoch-indexed channel keys: the core defect
    /// this branch fixes. A full member writes a channel row under epoch E1;
    /// a rekey rotates the space to E2; the SAME still-present full member
    /// does a FRESH read (a brand-new `select().all()`, not a cached
    /// plaintext) and must still decrypt the E1 row.
    ///
    /// Pre-fix, channel keys ignored `TreeKeyId.seq` entirely — always
    /// derived from `current_group_key()` — so the moment the rekey landed,
    /// this row's key became unrecoverable and `data_key_for_key_id` errored,
    /// silently dropping the row (`decrypt_table_rows`'s per-row `Result`
    /// handling in `channel_encryption_key`'s module). That is the "0
    /// pre-rekey channel rows, 1 pre-rekey root-line row" defect from the
    /// design investigation (root-line rows always survived via
    /// `resolve_d_key`'s edge-walk; channel rows never did) — asserted here
    /// permanently so it can't regress.
    #[tokio::test]
    async fn full_member_reads_pre_rekey_channel_row_after_rekey() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (_transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // Write a channel row under epoch E1 (the space's genesis epoch).
        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "pre-rekey secret".into(),
            })
            .execute()
            .await?;

        // Rotate the group key: E1 -> E2. Alice remains present throughout.
        alice.rekey().await?;

        // A fresh read of the E1 row after the rekey: `select().all()` always
        // re-fetches and re-decrypts from ciphertext (see `Table::all` ->
        // `fetch_and_decrypt`), so this genuinely exercises cross-epoch
        // `data_key_for_key_id` resolution, not a locally-cached plaintext.
        let rows: Vec<Msg> = alice.table::<Msg>("msgs").select().all().await?;
        assert!(
            rows.iter().any(|m| m.body == "pre-rekey secret"),
            "a still-present full member must read a channel row written BEFORE \
             a rekey, after the rekey — the row's key derives from the epoch it \
             was written under (E1), not whatever the current epoch (E2) is"
        );
        Ok(())
    }

    /// Multi-rekey depth variant of the regression gate above: a channel row
    /// written under E1 must still be recoverable after TWO rekeys
    /// (E1 -> E2 -> E3), exercising `group_key_at`'s edge-walk at depth > 1
    /// (not just one hop back from the current epoch).
    #[tokio::test]
    async fn full_member_reads_pre_rekey_channel_row_after_two_rekeys() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (_transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "e1 secret".into(),
            })
            .execute()
            .await?;

        alice.rekey().await?; // E1 -> E2
        alice.rekey().await?; // E2 -> E3

        let rows: Vec<Msg> = alice.table::<Msg>("msgs").select().all().await?;
        assert!(
            rows.iter().any(|m| m.body == "e1 secret"),
            "a channel row written at E1 must survive TWO rekeys (E1->E2->E3), \
             exercising the edge-walk at depth > 1"
        );
        Ok(())
    }

    /// L2 Part B CROWN JEWEL: a scoped member keeps reading NEW messages in its
    /// channel across a rekey. A rekey rotates the group key, so every channel's
    /// subtree key (`channel_root(group_key, channel)`) changes; without
    /// re-delivery the scoped member's installed key goes stale and it can no
    /// longer decrypt post-rekey rows. The rekey path (here a member removal)
    /// must re-derive + re-deliver each surviving scoped member's channel key
    /// against the NEW epoch, and `refresh_scoped_keys` re-installs it.
    #[tokio::test]
    async fn scoped_member_reads_new_message_after_rekey() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // A scoped agent joins channel 1 (holds no group key).
        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;
        agent.register_table_schema(msgs_schema()?);

        // Force a REAL rekey (new group-key epoch): add + remove a throwaway
        // full member. Capture its uid before `join` consumes the invite.
        let throwaway = alice.invite_user().await?;
        let throwaway_uid = throwaway.id().expect("full invite carries a uid");
        let _tj = crate::Space::join(transport.clone(), throwaway, schema()).await?;
        // Converge alice's `_users` cache on both members' post-join rotations
        // before building the removal's rekey (same reasoning as the leak tests).
        alice.recover_via_fast_forward().await?;
        alice.remove_user(throwaway_uid).await?; // triggers the group rekey

        // Alice posts a NEW ch1 message under the new epoch.
        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "post-rekey ch1".into(),
            })
            .execute()
            .await?;

        // The scoped agent re-fetches its refreshed channel key and reads it.
        agent.refresh_scoped_keys().await?; // Task 6 auto-invokes; here explicit.
        let rows: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert!(
            rows.iter().any(|m| m.body == "post-rekey ch1"),
            "scoped agent must read a NEW ch1 message after a rekey"
        );
        Ok(())
    }

    /// L2 Part B, standalone-rekey path: the crown-jewel test above drives the
    /// member-removal rekey (`handle_remove_member`); a STANDALONE rekey
    /// (`Space::rekey` → `handle_retention`) is the other path that rotates the
    /// group key, and a scoped member must keep reading its channel across it
    /// too. Confirms the re-delivery works on both paths.
    #[tokio::test]
    async fn scoped_member_reads_new_message_after_standalone_rekey() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;
        agent.register_table_schema(msgs_schema()?);

        // Converge alice's `_users` cache on the agent's post-join rotation, then
        // do a STANDALONE rekey (no removal) — a fresh group-key epoch.
        alice.recover_via_fast_forward().await?;
        alice.rekey().await?;

        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "post-standalone-rekey ch1".into(),
            })
            .execute()
            .await?;

        agent.refresh_scoped_keys().await?;
        let rows: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert!(
            rows.iter().any(|m| m.body == "post-standalone-rekey ch1"),
            "scoped agent must read a NEW ch1 message after a standalone rekey"
        );
        Ok(())
    }

    /// Task 4 regression gate (epoch-indexed channel-key DELIVERY): the crown
    /// jewels above only assert a scoped member reads NEW messages after a
    /// rekey. This asserts the missing half — a scoped member must RETAIN
    /// read access to a channel row written BEFORE a rekey, via the retained
    /// per-`(channel, epoch)` key Part B re-delivery accumulates (Task 2's
    /// `install_channel_key` retains prior epochs; this task tags each
    /// install with the epoch the key was ACTUALLY delivered at, carried on
    /// `ScopedChannelDelivery::epoch`, rather than inferring one locally).
    ///
    /// Mirrors the full-member version
    /// (`full_member_reads_pre_rekey_channel_row_after_rekey`), for scoped
    /// members. A member never granted the channel still gets nothing for
    /// it (`MissingKey`, silently dropped from the result set) — Part A's
    /// read-scoping boundary must not be disturbed by retaining history.
    #[tokio::test]
    async fn scoped_member_retains_pre_rekey_channel_row_after_rekey() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // Alice writes a channel-1 ("general") row under E1 (genesis epoch),
        // BEFORE Charlie is even invited.
        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "e1-general-secret".into(),
            })
            .execute()
            .await?;

        // Charlie: scoped to channel 1 only. Dave: scoped to channel 2 only —
        // never granted channel 1, the Part A exclusion this test also checks.
        let charlie_invite = alice.invite_user_scoped(&[1]).await?;
        let charlie = crate::Space::join(transport.clone(), charlie_invite, schema()).await?;
        charlie.register_table_schema(msgs_schema()?);
        let dave_invite = alice.invite_user_scoped(&[2]).await?;
        let dave = crate::Space::join(transport.clone(), dave_invite, schema()).await?;
        dave.register_table_schema(msgs_schema()?);

        // Sanity, pre-rekey: Charlie reads the E1 row; Dave does not.
        let charlie_before: Vec<Msg> = charlie.table::<Msg>("msgs").select().all().await?;
        assert!(
            charlie_before.iter().any(|m| m.body == "e1-general-secret"),
            "Charlie must read the E1 channel-1 row before any rekey"
        );
        let dave_before: Vec<Msg> = dave.table::<Msg>("msgs").select().all().await?;
        assert!(
            dave_before.is_empty(),
            "Dave (scoped to channel 2 only) must never see channel 1"
        );

        // Founder rekeys (E1 -> E2): Part B re-derives + re-delivers every
        // surviving scoped member's channel keys against the NEW epoch.
        alice.recover_via_fast_forward().await?;
        alice.rekey().await?;

        // Both scoped members refresh: Charlie's install RETAINS the E1 key
        // (Task 2) tagged at the epoch it was ACTUALLY delivered at (this
        // task) alongside the freshly delivered E2 key.
        charlie.refresh_scoped_keys().await?;
        dave.refresh_scoped_keys().await?;

        // THE regression: Charlie still reads the E1 row AFTER the rekey —
        // this fails (row silently dropped, `MissingKey`) on the pre-Task-4
        // channel-key model, where a rekey clobbers (or, under the Task 3
        // interim, may mis-tag) the retained key instead of accumulating a
        // correctly-tagged one per epoch.
        let charlie_after: Vec<Msg> = charlie.table::<Msg>("msgs").select().all().await?;
        assert!(
            charlie_after.iter().any(|m| m.body == "e1-general-secret"),
            "scoped member must retain read access to a PRE-rekey channel row \
             after a rekey, via its retained per-epoch channel key"
        );

        // Dave (never granted channel 1) still gets nothing for it, even
        // after a rekey re-delivery round — retaining history must not
        // re-open the Part A read-scoping boundary.
        let dave_after: Vec<Msg> = dave.table::<Msg>("msgs").select().all().await?;
        assert!(
            dave_after.is_empty(),
            "a member never granted channel 1 must still get MissingKey for \
             its rows after a rekey"
        );

        Ok(())
    }

    /// Task 4 regression gate, multi-rekey depth + "skipped refresh" variant:
    /// Charlie does NOT refresh between TWO rekeys (E1 -> E2 -> E3) — only
    /// once, after both have landed — and must still retain the E1 row AND
    /// read the NEW E3 row. This is the scenario the Task 3 interim's
    /// docstring names as its "multi-rekey-skip race" (a recipient that
    /// installs after skipping several rekeys' worth of refreshes must get
    /// its epoch tag from the delivery envelope, not from local state that
    /// may have moved on): every install below is tagged from
    /// `ScopedChannelDelivery::epoch`, so correctness does not depend on how
    /// many rekeys were skipped between refreshes, nor on the recipient's
    /// local sync state at install time.
    #[tokio::test]
    async fn scoped_member_retains_pre_rekey_channel_row_after_skipped_multi_rekey() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "e1-general-secret".into(),
            })
            .execute()
            .await?;

        let invite = alice.invite_user_scoped(&[1]).await?;
        let charlie = crate::Space::join(transport.clone(), invite, schema()).await?;
        charlie.register_table_schema(msgs_schema()?);

        // TWO rekeys land (E1 -> E2 -> E3) with NO refresh in between —
        // Charlie's slot is re-derived + re-deposited by both (Part B), but
        // Charlie never processes the intermediate (E2) envelope.
        alice.recover_via_fast_forward().await?;
        alice.rekey().await?; // E1 -> E2
        alice.recover_via_fast_forward().await?;
        alice.rekey().await?; // E2 -> E3

        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "e3-general-secret".into(),
            })
            .execute()
            .await?;

        // ONE catch-up refresh after skipping both intermediate rekeys.
        charlie.refresh_scoped_keys().await?;

        let rows: Vec<Msg> = charlie.table::<Msg>("msgs").select().all().await?;
        assert!(
            rows.iter().any(|m| m.body == "e1-general-secret"),
            "Charlie must retain the E1 row across TWO skipped rekeys"
        );
        assert!(
            rows.iter().any(|m| m.body == "e3-general-secret"),
            "Charlie must read the NEW E3 row after the single catch-up refresh"
        );
        Ok(())
    }

    /// L2 Part B defect fix: a scoped `refresh_scoped_keys` must SKIP a delivery
    /// envelope it has already consumed, not re-process it.
    ///
    /// The server never clears a delivery slot, so the runtime's periodic
    /// refresh re-fetches the SAME (join) envelope on every rescan. That
    /// envelope was wrapped to the invitee's PROVISIONAL update key and
    /// installed at join — but `join` then rotates the update keypair, so
    /// re-running the mVE unwrap on it can never succeed again and only logs
    /// "failed to decrypt against anchored commitment; skipping" every tick.
    /// A redundant refresh with NO new delivery must be a clean no-op: it must
    /// NOT re-invoke the install path, and it must leave the channel key
    /// installed (the agent keeps reading).
    #[tokio::test]
    async fn refresh_skips_already_consumed_delivery() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;
        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "legit ch1".into(),
            })
            .execute()
            .await?;

        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;
        agent.register_table_schema(msgs_schema()?);

        // Join installs the scoped channel key exactly once.
        assert_eq!(
            agent.scoped_install_call_count(),
            1,
            "join installs the scoped channel key once"
        );

        // Sanity: the agent reads its channel with the anchored key.
        let before: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert!(before.iter().any(|m| m.body == "legit ch1"));

        // No rekey has occurred, so the slot still holds the SAME join envelope.
        // A redundant refresh must be deduped — NOT re-processed (which would
        // re-run the now-doomed mVE unwrap and WARN-spam).
        agent.refresh_scoped_keys().await?;
        assert_eq!(
            agent.scoped_install_call_count(),
            1,
            "redundant refresh of an unchanged delivery must be deduped, not re-processed"
        );

        // The channel key remains installed — the agent can still read.
        let after: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert!(
            after.iter().any(|m| m.body == "legit ch1"),
            "channel key must remain installed after the redundant refresh"
        );
        Ok(())
    }

    /// L2 Part B security: `refresh_scoped_keys` must verify each delivered
    /// channel key against its ANCHORED on-chain grant commitment, not the
    /// server-supplied envelope commitment. A malicious server that deposits a
    /// wrong-but-self-consistent `(ciphertext, binding_commitment)` pair (the
    /// old `decrypt_delivered_key`-only check would install it, since
    /// `commit(key) == binding_commitment` holds) must be REJECTED: the agent
    /// keeps its correct, anchored key and can still read its channel.
    #[tokio::test]
    async fn refresh_rejects_server_substituted_channel_key() -> Result<()> {
        use encrypted_spaces_crypto::key_derivation::{
            DerivationKoalaBearPoseidon2_16, KeyDerivation,
        };
        use encrypted_spaces_crypto::KeyMaterial;
        use encrypted_spaces_key_manager::{
            prove_channel_delivery, verify_channel_delivery, ScopedChannelDelivery,
            ScopedDeliveryEnvelope,
        };

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;
        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "legit ch1".into(),
            })
            .execute()
            .await?;

        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent_uid = invite.id().expect("scoped invite carries a uid");
        let agent = crate::Space::join(transport.clone(), invite, schema()).await?;
        agent.register_table_schema(msgs_schema()?);

        // Sanity: the agent reads its channel with the correct, anchored key.
        let before: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert!(before.iter().any(|m| m.body == "legit ch1"));

        // The agent's CURRENT update key (post-join rotation), from alice's view.
        alice.recover_via_fast_forward().await?;
        let agent_pk = alice
            .users()
            .select()
            .all()
            .await?
            .into_iter()
            .find(|u: &crate::users::UserRecord| u.id == Some(agent_uid))
            .expect("agent is a member")
            .update_key;

        // Malicious server: deposit a self-consistent envelope for a WRONG key
        // (commit(wrong) == its own binding_commitment, so the naive check would
        // accept it), wrapped to the agent's real update key.
        let wrong_key = KeyMaterial::digest(b"attacker-substituted-channel-key");
        let wrong_commitment = DerivationKoalaBearPoseidon2_16::default().commit(&wrong_key);
        let req = prove_channel_delivery(
            1,
            0,
            wrong_commitment,
            &wrong_key,
            std::slice::from_ref(&agent_pk),
        );
        let cts = verify_channel_delivery(std::slice::from_ref(&agent_pk), &req)
            .expect("bogus delivery is a well-formed mVE");
        let bogus = ScopedDeliveryEnvelope {
            channels: vec![ScopedChannelDelivery {
                channel: 1,
                epoch: 0,
                binding_commitment: wrong_commitment,
                ciphertext: cts.get(0).unwrap().clone(),
            }],
        };
        transport
            .server_state()
            .lock()
            .await
            .key_delivery_slots
            .put(agent_uid, serde_json::to_vec(&bogus).unwrap());

        // The agent refreshes. The bogus delivery's commitment != the anchored
        // grant commitment, so it must be SKIPPED (not installed). The agent
        // keeps its correct key and still reads its channel. Under the old
        // envelope-commitment check, the wrong key would be installed and this
        // read would return zero rows.
        agent.refresh_scoped_keys().await?;
        let after: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert!(
            after.iter().any(|m| m.body == "legit ch1"),
            "server-substituted channel key must be rejected; agent keeps its anchored key"
        );
        Ok(())
    }

    /// L2 Part B security (Task 7, Step 1 + the carry-forward server-REJECTION
    /// gap from the Task 4/5 reviews): a scoped member cannot have an un-granted
    /// channel delivered to it across a rekey — the server's PRE-EXISTENCE /
    /// no-scope-expansion guard rejects any re-grant for a channel the member
    /// was not ALREADY granted.
    ///
    /// The GUEST-level forgery — a `Scoped` member cannot even SIGN a
    /// channel-grant `_retention` row — is already locked in by Task 3 in
    /// `ffproof/changelog_core`:
    /// `rekey_op::test_scoped_signer_rekey_self_grant_rejected`,
    /// `invite_user_op::test_scoped_signer_invite_with_grant_rejected`,
    /// `remove_user_op::test_scoped_signer_remove_user_with_grant_rejected`,
    /// plus the canonical-form and multi-row-decoy rejections. This test adds
    /// the SDK-level defense-in-depth over the real submission path: even a
    /// FULL-member-signed rekey (the only signer the guest accepts for grant
    /// rows) that bundles a re-grant for a channel the scoped member never held
    /// is rejected by the server BEFORE any delivery slot is written — so a
    /// scoped member's scope can be REFRESHED across a rekey but never EXPANDED.
    ///
    /// TEETH: the forged channel's derivation, grant/delivery binding, and mVE
    /// are all well-formed (they are built with the same primitives an honest
    /// re-grant uses), and the same construction MINUS the forged channel is a
    /// valid rekey that SUCCEEDS (see `scoped_member_reads_new_message_after_
    /// standalone_rekey`). The ONLY defect is that channel 2 has no pre-existing
    /// grant row for this member, and the error is asserted to name the
    /// "expands scope" guard — so the rejection is that guard, not an incidental
    /// failure. Delete the pre-existence check and this rekey would be accepted.
    #[tokio::test]
    async fn scoped_member_cannot_forge_grant() -> Result<()> {
        use crate::users::UserRecord;
        use encrypted_spaces_crypto::key_derivation::{
            DerivationKoalaBearPoseidon2_16, KeyDerivation,
        };
        use encrypted_spaces_key_manager::channel_grant::grant_row_key;
        use encrypted_spaces_key_manager::{prove_channel_delivery, ChannelRegrant};

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // A scoped agent granted channel 1 ONLY.
        let invite = alice.invite_user_scoped(&[1]).await?;
        let agent_uid = invite.id().expect("scoped invite carries a uid");
        let _agent = crate::Space::join(transport.clone(), invite, schema()).await?;

        // Converge alice's `_users` view on the agent's post-join key rotation so
        // the honest channel-1 re-grant delivery is wrapped to the agent's
        // CURRENT update key (otherwise the rekey would fail on channel 1's mVE
        // check, not the scope-expansion guard this test targets).
        alice.recover_via_fast_forward().await?;

        // Build a standalone rekey exactly like `Space::rekey`, keeping the
        // freshly generated group key so we can forge an extra channel re-grant.
        let all_users: Vec<UserRecord> = alice.users().select().all().await?;
        let remaining_pks: Vec<crate::key_manager::SpacePublicKey> = all_users
            .iter()
            .filter(|u| !u.status.is_scoped())
            .map(|u| u.update_key.clone())
            .collect();

        let mut rekey_builder = alice.retention_builder();
        let (mut rekey_request, new_group_key) = alice
            .key_manager()
            .rekey_with_group_key(&remaining_pks, &mut rekey_builder)
            .await?;
        let new_epoch = encrypted_spaces_retention::tree_space_key::TreeSpaceKey::<
            encrypted_spaces_retention::simple_line2::DefaultProver,
        >::live_chain_current_epoch(&rekey_builder)
        .await
        .expect("resolve new rekey epoch");
        let rekey_output = rekey_builder.finalize();
        let mut retention_writes = rekey_output.writes;
        let retention_proofs = rekey_output.proofs;

        // Honest re-grants: refresh the agent's channel 1 against the new epoch.
        let (mut scoped_regrants, mut grant_writes) = alice
            .build_scoped_regrants(&new_group_key, new_epoch, None)
            .await?;

        // ATTACK: forge an extra re-grant for channel 2 — a channel the agent
        // was NEVER granted — plus a matching channel-grant `_retention` row,
        // exactly as an honest re-grant would look. Everything (derivation,
        // binding, delivery mVE) is well-formed; the ONLY thing wrong is that
        // channel 2 has no pre-existing grant row for this member.
        const UNGRANTED_CH: i64 = 2;
        let agent_pk = all_users
            .iter()
            .find(|u| u.id == Some(agent_uid))
            .expect("agent is a member")
            .update_key
            .clone();
        let derivation = DerivationKoalaBearPoseidon2_16::default();
        let (subtree, grant_proof) = {
            let km = alice.key_manager.lock().await;
            km.space_key()
                .channel_grant_for_group_key(&new_group_key, UNGRANTED_CH)
                .expect("derive forged channel subtree key")
        };
        let commitment = derivation.commit(&subtree);
        let delivery = prove_channel_delivery(
            UNGRANTED_CH,
            new_epoch,
            commitment,
            &subtree,
            std::slice::from_ref(&agent_pk),
        );
        let victim = scoped_regrants
            .iter_mut()
            .find(|r| r.uid == agent_uid)
            .expect("agent has an honest re-grant to piggyback on");
        victim.channels.push(ChannelRegrant {
            delivery,
            grant_proof,
        });
        grant_writes.push((
            grant_row_key(agent_uid, UNGRANTED_CH),
            commitment.as_bytes().to_vec(),
        ));

        rekey_request.scoped_regrants = scoped_regrants;
        retention_writes.extend(grant_writes);

        let change =
            crate::changelog::ChangeBuilder::retention_only(std::sync::Arc::new(alice.clone()))
                .build_rekey(&retention_writes)
                .await?;

        let result = alice
            .transport
            .submit_retention(&change, retention_proofs, Some(rekey_request))
            .await;

        // The server must REJECT the whole rekey on the scope-expansion guard.
        let err = result.expect_err(
            "server must reject a rekey that expands a scoped member's scope to an \
             un-granted channel",
        );
        assert!(
            err.to_string().contains("expands scope"),
            "rejection must come from the no-scope-expansion guard, got: {err}"
        );
        Ok(())
    }

    /// L2 Part B (Task 7, Step 2): multi-channel + multi-member retention and
    /// isolation across a rekey. Agent A is scoped to {1, 3} and must keep
    /// reading BOTH channels' NEW messages after a rekey; Agent B is scoped to
    /// {2} and must read ONLY channel 2. Neither may read the other's channel —
    /// the rekey re-delivers each surviving scoped member exactly its own
    /// subtree keys, no more.
    ///
    /// TEETH: the "reads a NEW message" asserts fail if re-delivery breaks (a
    /// stale channel key can't decrypt post-rekey rows); the cross-member
    /// isolation asserts (`all channel ∈ scope`, `!contains the other's body`)
    /// fail if scoping breaks (e.g. a member wrongly held the group key).
    #[tokio::test]
    async fn multi_channel_and_multi_member() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // Agent A → channels {1, 3}; Agent B → channel {2}.
        let invite_a = alice.invite_user_scoped(&[1, 3]).await?;
        let agent_a = crate::Space::join(transport.clone(), invite_a, schema()).await?;
        agent_a.register_table_schema(msgs_schema()?);
        let invite_b = alice.invite_user_scoped(&[2]).await?;
        let agent_b = crate::Space::join(transport.clone(), invite_b, schema()).await?;
        agent_b.register_table_schema(msgs_schema()?);

        // Baseline BEFORE the rekey: each agent sees exactly its own channels.
        for (ch, body) in [(1i64, "a-pre-1"), (2, "b-pre-2"), (3, "a-pre-3")] {
            alice
                .table::<Msg>("msgs")
                .insert(&Msg {
                    id: None,
                    channel_id: ch,
                    body: body.into(),
                })
                .execute()
                .await?;
        }
        let a_before: Vec<Msg> = agent_a.table::<Msg>("msgs").select().all().await?;
        assert!(
            a_before.iter().all(|m| m.channel_id == 1 || m.channel_id == 3),
            "agent A (scope {{1,3}}) must never see channel 2 before rekey"
        );
        assert!(
            a_before.iter().any(|m| m.channel_id == 1)
                && a_before.iter().any(|m| m.channel_id == 3),
            "agent A must see both its channels before rekey"
        );
        let b_before: Vec<Msg> = agent_b.table::<Msg>("msgs").select().all().await?;
        assert!(
            b_before.iter().all(|m| m.channel_id == 2),
            "agent B (scope {{2}}) must see only channel 2 before rekey"
        );
        assert!(
            b_before.iter().any(|m| m.body == "b-pre-2"),
            "agent B must see its channel-2 message before rekey"
        );

        // Force a real group rekey (standalone). Both scoped members survive and
        // must be re-delivered their (and only their) channel keys.
        alice.recover_via_fast_forward().await?;
        alice.rekey().await?;

        // NEW messages under the new epoch, one per channel.
        for (ch, body) in [(1i64, "a-post-1"), (2, "b-post-2"), (3, "a-post-3")] {
            alice
                .table::<Msg>("msgs")
                .insert(&Msg {
                    id: None,
                    channel_id: ch,
                    body: body.into(),
                })
                .execute()
                .await?;
        }

        // Agent A refreshes and must read the NEW ch1 AND ch3 messages, never ch2.
        agent_a.refresh_scoped_keys().await?;
        let a_after: Vec<Msg> = agent_a.table::<Msg>("msgs").select().all().await?;
        assert!(
            a_after.iter().any(|m| m.body == "a-post-1"),
            "agent A must read the NEW channel-1 message after the rekey"
        );
        assert!(
            a_after.iter().any(|m| m.body == "a-post-3"),
            "agent A must read the NEW channel-3 message after the rekey"
        );
        assert!(
            a_after.iter().all(|m| m.channel_id == 1 || m.channel_id == 3),
            "agent A must NEVER read channel 2 (agent B's channel)"
        );
        assert!(
            !a_after.iter().any(|m| m.body == "b-post-2"),
            "agent A must not decrypt agent B's channel-2 message"
        );

        // Agent B refreshes and must read ONLY the NEW ch2 message.
        agent_b.refresh_scoped_keys().await?;
        let b_after: Vec<Msg> = agent_b.table::<Msg>("msgs").select().all().await?;
        assert!(
            b_after.iter().any(|m| m.body == "b-post-2"),
            "agent B must read the NEW channel-2 message after the rekey"
        );
        assert!(
            b_after.iter().all(|m| m.channel_id == 2),
            "agent B must NEVER read channel 1 or 3 (agent A's channels)"
        );
        Ok(())
    }

    /// L2 Part B (Task 7, Step 3): no-harm regression. With a scoped member
    /// present (so the Part B re-grant machinery runs), a FULL member's
    /// invite/join/rekey/read lifecycle is unchanged — Bob reads channel data
    /// under the current epoch before the rekey, and reads NEW channel data
    /// under the fresh epoch after it (i.e. Part B did not disturb full-member
    /// group-key delivery). And the Part A read boundary still holds: the scoped
    /// member cannot read a channel it was never granted.
    ///
    /// NOTE on epochs: channel rows are epoch-indexed (`TreeKeyId.seq` stamps
    /// the FGK ordinal at write time; a full member re-derives the row's
    /// epoch's group key via `group_key_at`'s edge-walk — see
    /// `full_member_reads_pre_rekey_channel_row_after_rekey` for the
    /// dedicated cross-epoch regression test). This test still asserts
    /// pre-rekey reads BEFORE the rekey and post-rekey reads AFTER it — not
    /// because cross-epoch reads are impossible, but because this test's
    /// purpose is Part B no-harm, not epoch recovery.
    ///
    /// TEETH: Bob reading the POST-rekey rows fails if Part B disturbed
    /// full-member group-key delivery (a full member that lost the new group key
    /// could not derive the new channel keys); the scoped member reading channel
    /// 5 (never granted) would fail the `all channel == 1` assert if the read
    /// boundary regressed.
    #[tokio::test]
    async fn full_members_unaffected_by_part_b() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // A FULL member joins.
        let bob_invite = alice.invite_user().await?;
        let bob = crate::Space::join(transport.clone(), bob_invite, schema()).await?;
        bob.register_table_schema(msgs_schema()?);

        // A scoped member (channel 1 only) also joins, so the rekey exercises
        // the Part B re-grant path alongside full-member group-key delivery.
        let agent_invite = alice.invite_user_scoped(&[1]).await?;
        let agent = crate::Space::join(transport.clone(), agent_invite, schema()).await?;
        agent.register_table_schema(msgs_schema()?);

        // Pre-rekey data in two channels (1 = scoped agent's channel, 5 = not).
        for (ch, body) in [(1i64, "pre ch1"), (5, "pre ch5")] {
            alice
                .table::<Msg>("msgs")
                .insert(&Msg {
                    id: None,
                    channel_id: ch,
                    body: body.into(),
                })
                .execute()
                .await?;
        }

        // Baseline: the full member reads BOTH channels under the current epoch.
        bob.sync().await?;
        let bob_before: Vec<Msg> = bob.table::<Msg>("msgs").select().all().await?;
        for body in ["pre ch1", "pre ch5"] {
            assert!(
                bob_before.iter().any(|m| m.body == body),
                "full member must read '{body}' before the rekey (baseline full read)"
            );
        }

        // A FULL member drives a rekey (mixed recipient set: full members get
        // the group key, the scoped member is excluded + re-granted).
        alice.recover_via_fast_forward().await?;
        alice.rekey().await?;

        // Post-rekey data under the fresh epoch.
        for (ch, body) in [(1i64, "post ch1"), (5, "post ch5")] {
            alice
                .table::<Msg>("msgs")
                .insert(&Msg {
                    id: None,
                    channel_id: ch,
                    body: body.into(),
                })
                .execute()
                .await?;
        }

        // Full member Bob still receives the group key across the rekey and
        // reads the NEW data — unchanged by Part B.
        bob.sync().await?;
        let bob_after: Vec<Msg> = bob.table::<Msg>("msgs").select().all().await?;
        for body in ["post ch1", "post ch5"] {
            assert!(
                bob_after.iter().any(|m| m.body == body),
                "full member must read '{body}' after the rekey \
                 (Part B must not disturb full group-key delivery)"
            );
        }

        // Part A property intact: the scoped member (channel 1) reads its
        // channel's post-rekey message but CANNOT read the un-granted channel 5.
        agent.refresh_scoped_keys().await?;
        let agent_rows: Vec<Msg> = agent.table::<Msg>("msgs").select().all().await?;
        assert!(
            agent_rows.iter().any(|m| m.body == "post ch1"),
            "scoped member must still read its own channel after the rekey"
        );
        assert!(
            agent_rows.iter().all(|m| m.channel_id == 1),
            "scoped member must NOT read the un-granted channel 5 (Part A boundary intact)"
        );
        Ok(())
    }

    // ── Task 5: invariant + regression gates ────────────────────────────
    //
    // Lock-in gates for the epoch-indexed channel-key fix (Tasks 1-4): they
    // are expected to already PASS given the prior tasks' work, not
    // RED->GREEN feature tests. `full_member_reads_pre_rekey_channel_row_after_two_rekeys`
    // (added in Task 3, above) already covers "multi-rekey depth > 1"; the
    // test below extends that one hop further for extra margin rather than
    // duplicating it.

    /// Task 5 gate 1 (multi-rekey depth), extended: a channel row written at
    /// E1 must survive THREE rekeys (E1 -> E2 -> E3 -> E4), exercising
    /// `group_key_at`'s edge-walk at depth 3 (one hop deeper than the
    /// existing two-rekey gate `full_member_reads_pre_rekey_channel_row_after_two_rekeys`).
    #[tokio::test]
    async fn full_member_reads_pre_rekey_channel_row_after_three_rekeys() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (_transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "e1 secret depth3".into(),
            })
            .execute()
            .await?;

        alice.rekey().await?; // E1 -> E2
        alice.rekey().await?; // E2 -> E3
        alice.rekey().await?; // E3 -> E4

        let rows: Vec<Msg> = alice.table::<Msg>("msgs").select().all().await?;
        assert!(
            rows.iter().any(|m| m.body == "e1 secret depth3"),
            "a channel row written at E1 must survive THREE rekeys \
             (E1->E2->E3->E4), exercising the edge-walk at depth 3"
        );
        Ok(())
    }

    /// Task 5 gate 2 — the security-critical lock-in: a member REMOVED at an
    /// E1 -> E2 rekey must not read the E2 channel row, and must obtain no
    /// E2 key at all. Guards against the historical-read fix (Tasks 1-4,
    /// which retain PAST epochs' channel keys for present members)
    /// accidentally reopening the §8 rekey-leak exclusion
    /// (`sdk::users::build_scoped_regrants`'s `removed_uid` filter, "Part
    /// A").
    ///
    /// The channel row under test is written at a NON-GENESIS epoch (E1,
    /// after one standalone rekey) — carried forward from the Task 3
    /// review. This exercises the write-side epoch stamp
    /// (`TreeSpaceKey::current_channel_epoch` / `SimpleLine2SpaceKey::current_epoch`)
    /// against the live chain's NEWEST ordinal rather than the
    /// accidentally-correct genesis 0: the security property under test is
    /// exactly that a rekey landing right after a removal tags NEW writes
    /// at the NEW epoch, so a removed member holding only an OLD epoch's
    /// key cannot read them.
    ///
    /// Charlie (removed) and Dave (survivor) are both scoped to the SAME
    /// channel, isolating "removal breaks access" from "channel-scope
    /// mismatch breaks access" (a different, already-tested property).
    #[tokio::test]
    async fn removed_scoped_member_gets_no_new_epoch_channel_key() -> Result<()> {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Msg {
            id: Option<i64>,
            channel_id: i64,
            body: String,
        }

        let (transport, alice) = create_space().await?;
        alice.create_table(&msgs_schema()?).await?;

        // E(genesis) -> E1: a standalone rekey BEFORE anyone is invited, so
        // the channel row below is written at a NON-GENESIS epoch.
        alice.rekey().await?;

        // Charlie (to be removed) and Dave (survivor), both scoped to
        // channel 1 — granted at E1 (the current epoch at invite time).
        let charlie_invite = alice.invite_user_scoped(&[1]).await?;
        let charlie_uid = charlie_invite.id().expect("scoped invite carries a uid");
        let charlie = crate::Space::join(transport.clone(), charlie_invite, schema()).await?;
        charlie.register_table_schema(msgs_schema()?);

        let dave_invite = alice.invite_user_scoped(&[1]).await?;
        let dave = crate::Space::join(transport.clone(), dave_invite, schema()).await?;
        dave.register_table_schema(msgs_schema()?);

        // Write the channel row at E1 (non-genesis).
        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "e1-secret".into(),
            })
            .execute()
            .await?;

        // Sanity: both scoped members read the E1 row before the removal rekey.
        let charlie_before: Vec<Msg> = charlie.table::<Msg>("msgs").select().all().await?;
        assert!(
            charlie_before.iter().any(|m| m.body == "e1-secret"),
            "Charlie must read the E1 row before removal"
        );
        let dave_before: Vec<Msg> = dave.table::<Msg>("msgs").select().all().await?;
        assert!(
            dave_before.iter().any(|m| m.body == "e1-secret"),
            "Dave must read the E1 row before the rekey"
        );

        // Converge alice's `_users` cache on both members' post-join key
        // rotations before building the removal rekey (same reasoning as
        // the sibling §8 leak tests above).
        alice.recover_via_fast_forward().await?;

        // Remove Charlie: triggers the E1 -> E2 rekey. Part A's
        // `build_scoped_regrants` must exclude Charlie from the re-grant
        // bundle entirely (no channel-1 regrant at E2 for her).
        alice.remove_user(charlie_uid).await?;

        // Alice writes a NEW channel row AFTER removal, at the NEW epoch E2.
        alice
            .table::<Msg>("msgs")
            .insert(&Msg {
                id: None,
                channel_id: 1,
                body: "e2-secret".into(),
            })
            .execute()
            .await?;

        // Dave (still present) refreshes and reads the E2 row: proves the
        // write side stamped the NEWEST epoch (E2), not genesis 0, and
        // Dave's legitimate regrant reaches it.
        dave.refresh_scoped_keys().await?;
        let dave_after: Vec<Msg> = dave.table::<Msg>("msgs").select().all().await?;
        assert!(
            dave_after.iter().any(|m| m.body == "e2-secret"),
            "a still-present scoped member must read the NEW E2 channel row \
             (proves the write side stamped the NEWEST epoch, not genesis 0)"
        );

        // THE security assertion: Charlie (removed) must NOT read the E2
        // row -- a fresh, uncached read (`select().all()` always re-fetches
        // and re-decrypts from ciphertext).
        let charlie_after: Vec<Msg> = charlie.table::<Msg>("msgs").select().all().await?;
        assert!(
            !charlie_after.iter().any(|m| m.body == "e2-secret"),
            "SECURITY: a member REMOVED at the E1->E2 rekey must not read \
             the new E2 channel row -- the historical-read fix must not \
             leak a new epoch's key to a removed member"
        );

        // Mechanistic proof, not just behavioral: the server clears a
        // removed user's delivery slot entirely on removal
        // (`backend/server/src/db.rs`'s remove-member handler, step "Clear
        // the removed user's delivery slot"), so there is no channel key of
        // ANY epoch -- let alone E2 -- left for Charlie to fetch. This
        // directly confirms Part A's removal-exclusion path (slot clearing
        // + `build_scoped_regrants`'s `removed_uid` filter) still holds
        // under the epoch-indexed channel-key fix.
        let server = transport.server_state();
        let slot = server.lock().await.get_delivery_slot(charlie_uid);
        assert!(
            slot.is_none(),
            "SECURITY: a removed member's delivery slot must be cleared -- \
             no channel key material of any epoch should remain fetchable"
        );

        Ok(())
    }

    /// Task 5 gate 3: the ROOT line (non-channel rows -- no `channel_id`
    /// column) is untouched by the epoch-indexed CHANNEL key fix. It
    /// already resolved historical reads via `resolve_d_key`'s pre-existing
    /// edge-walk (the "root-line rows always survived" half of the original
    /// design investigation's asymmetry -- see
    /// `full_member_reads_pre_rekey_channel_row_after_rekey`'s doc comment).
    /// A root-line row written before a rekey must still read after it,
    /// unaffected by any of Tasks 1-4's channel-specific changes.
    #[tokio::test]
    async fn root_line_row_survives_rekey() -> Result<()> {
        let (_transport, alice) = create_space().await?;
        let notes = create_notes_table(&alice).await?;

        notes
            .insert(&SecretNote {
                id: None,
                title: "pre-rekey".into(),
                body: "root line secret".into(),
            })
            .execute()
            .await?;

        alice.rekey().await?;

        let rows: Vec<SecretNote> = notes.select().all().await?;
        assert!(
            rows.iter().any(|n| n.body == "root line secret"),
            "a root-line (non-channel) row must still read after a rekey -- \
             regression guard on the untouched resolve_d_key path"
        );
        Ok(())
    }
}

fn query_param_to_value(param: &QueryParam) -> serde_json::Value {
    match param {
        QueryParam::Null => serde_json::Value::Null,
        QueryParam::Integer(i) => serde_json::Value::Number((*i).into()),
        QueryParam::Real(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        QueryParam::Text(s) => serde_json::Value::String(s.clone()),
        QueryParam::Blob(b) => {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            serde_json::Value::String(STANDARD.encode(b))
        }
        QueryParam::Boolean(b) => serde_json::Value::Bool(*b),
    }
}
