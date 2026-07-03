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

/// Sub-sequence for per-channel data keys. Fixed at 0: a channel's key is
/// `derive(group key, channel)`, and epoch rotation is already carried by the
/// group key inside that derivation — so the channel key needs no separate root
/// sequence. Crucially, this means encrypting a channel row does NOT require the
/// root line's `current_key_id`, which a **scoped** member (no group key) cannot
/// obtain — letting scoped agents post to their channels, not only read them.
const CHANNEL_SUBSEQ: u64 = 0;

/// Derive the encryption key for a row in `channel` (L2 read scoping, whitepaper
/// §4.3/§5.1): the channel's data key is derived from the group key and the
/// channel — `TreeKeyId{channel, seq}` in the ciphertext header. A full member
/// derives it from the group key; a member scoped away from `channel` cannot,
/// so it can't read the row.
pub(crate) async fn channel_encryption_key(
    space: &Space,
    channel: i64,
) -> Result<EncryptionKey> {
    let builder = space.retention_builder();
    let km = space.key_manager.lock().await;
    let key_id = TreeKeyId::new(channel, CHANNEL_SUBSEQ);
    km.data_key_for_key_id(&key_id, &builder)
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
    let km = space.key_manager.lock().await;
    let builder = space.retention_builder();
    let resolver = |key_id: TreeKeyId| {
        let km = &km;
        let builder = &builder;
        async move {
            km.data_key_for_key_id(&key_id, builder)
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
