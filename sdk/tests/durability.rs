//! End-to-end: create a space + data, simulate a server restart by building a
//! fresh SpaceState that replays from the same SQLite store, and assert the
//! rebuilt root matches.
//!
//! Run with:
//!   cargo test -p encrypted-spaces-sdk --features local-transport,testing --test durability
//!
//! Bootstrap-schema variant (Task 4 brief, Step 6 fallback). The `items` table
//! is created at space-init by passing the schema to BOTH `LocalTransport::new`
//! and the rebuild `SpaceState::init_server`. This mirrors production, where
//! tables come from the bootstrap schema file rather than the test-only
//! `Space::create_table` (which, on a `LocalTransport`, mutates server storage
//! out-of-band and *resets* the changelog baseline to change 0 — a subsequent
//! insert would re-use `change_id = 1` and collide with the persisted
//! create-space change at `change_id = 1`). Bootstrapping the table at init
//! keeps `change_id`s monotonic for the whole run, which is the invariant the
//! durable store's `PRIMARY KEY (space_id, change_id)` assumes.
//!
//! Because the server starts at the post-bootstrap root (internal tables +
//! `items`), the client is created with `Space::create` against that exact root
//! (and the same schema), so the create-space change anchors correctly and the
//! client doesn't see `StateDiverged`.

#![cfg(all(feature = "local-transport", feature = "testing"))]

use std::sync::Arc;

use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::db::SpaceState;
use encrypted_spaces_backend_server::persistence::{ChangeStore, SqliteChangeStore};
use encrypted_spaces_sdk::{
    ApplicationSchema, ColumnType, LocalTransport, SchemaBuilder, Space,
};

#[tokio::test]
async fn server_state_survives_restart_via_sqlite() {
    std::env::set_var("RISC0_DEV_MODE", "1");

    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ChangeStore> =
        Arc::new(SqliteChangeStore::open(&dir.path().join("halyard.db")).unwrap());

    // The application table is bootstrapped at space-init on BOTH the live and
    // the restored server, so the changelog is anchored at the same post-schema
    // root in each and `change_id`s stay monotonic across the whole run.
    let schema = SchemaBuilder::new("items")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("label", ColumnType::String)
        .unwrap()
        .plaintext()
        .build()
        .unwrap();
    let schemas = [schema.clone()];

    // 1. Stand up an in-process server with a small FF batch so a proof is
    //    generated, and inject our SQLite store *before* any change is made so
    //    the create-space change (change_id 1) is also persisted.
    let transport = LocalTransport::new(&schemas, None, Some(2)).await.unwrap();
    transport.set_server_change_store(store.clone()).await;

    let (space_id, root_before) = {
        // Anchor the client to the server's post-bootstrap root and schema so
        // the create-space change applies against the same commitment the
        // server is at (no `StateDiverged`).
        let server_root = transport.get_root_hash().await.unwrap();
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema.clone()], server_root),
        )
        .await
        .unwrap();

        let items = space.table::<serde_json::Value>("items");
        for i in 0..4 {
            items
                .insert(&serde_json::json!({ "id": null, "label": format!("item-{i}") }))
                .execute()
                .await
                .unwrap();
        }

        let guard = transport.server_state();
        let st = guard.lock().await;
        (st.space_id, st.db.root_hash())
    };

    // 2. Simulate a restart: brand-new SpaceState for the same space_id, with
    //    the SAME bootstrap schema, same store, then replay.
    let mut restored = SpaceState::init_server(
        Some(&schemas.to_vec()),
        Some(SpaceInitConfig {
            space_id,
            artifact_path: None,
            verbose_logfile: None,
            bootstrap_data: BootstrapDataSource::None,
        }),
        Some(2),
    )
    .await
    .unwrap();
    restored.change_store = store.clone();
    restored.rehydrate_from_store().await.unwrap();

    // 3. The rebuilt root must match the live root before "restart".
    assert_eq!(
        root_before,
        restored.db.root_hash(),
        "rehydrated root must equal pre-restart root"
    );
    assert!(
        restored.changelog.num_changes() >= 4,
        "expected the replayed inserts (plus the create-space change)"
    );
    assert_eq!(
        restored.changelog.proven_up_to, 4,
        "persisted proven_up_to should be restored"
    );
    assert!(
        restored.ff_proof.is_some(),
        "persisted FF proof should be loaded on rehydrate"
    );

    // Regression: rehydrate must restore the cached MMR head
    // `proven_clc_state` alongside `proven_up_to`, not leave it `None`.
    // The pre-fix code assigned `changelog.ff_proof` / `proven_up_to`
    // directly (bypassing `set_ff_proof`), leaving `proven_clc_state ==
    // None` while `proven_up_to == 4` -- an internally inconsistent state.
    assert!(
        restored.changelog.proven_clc_state().is_some(),
        "rehydrate must restore proven_clc_state when proven_up_to > 0"
    );
    restored
        .changelog
        .validate_mmr_state()
        .expect("rehydrated changelog must be internally consistent");
}

/// Follow-up A (fail-loud root guard, spec §5.5): if a persisted change's
/// recorded post-change root no longer matches the root rebuilt by replay
/// — i.e. the on-disk store was corrupted or tampered — `rehydrate_from_store`
/// must return `Err` rather than silently serving a divergent space.
///
/// We tamper `new_root` (leaving the change `entry` decodable) so replay
/// succeeds end-to-end and only the root guard can catch the divergence.
#[tokio::test]
async fn rehydrate_root_guard_rejects_tampered_store() {
    std::env::set_var("RISC0_DEV_MODE", "1");

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("halyard.db");
    let store: Arc<dyn ChangeStore> = Arc::new(SqliteChangeStore::open(&db_path).unwrap());

    let schema = SchemaBuilder::new("items")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("label", ColumnType::String)
        .unwrap()
        .plaintext()
        .build()
        .unwrap();
    let schemas = [schema.clone()];

    // Stand up a live server and accept a few changes so real rows (with their
    // correct post-change roots) land in the SQLite store.
    let transport = LocalTransport::new(&schemas, None, Some(2)).await.unwrap();
    transport.set_server_change_store(store.clone()).await;

    let space_id = {
        let server_root = transport.get_root_hash().await.unwrap();
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema.clone()], server_root),
        )
        .await
        .unwrap();
        let items = space.table::<serde_json::Value>("items");
        for i in 0..4 {
            items
                .insert(&serde_json::json!({ "id": null, "label": format!("item-{i}") }))
                .execute()
                .await
                .unwrap();
        }
        transport.server_state().lock().await.space_id
    };

    // Tamper the persisted post-change root for the highest change_id (the row
    // whose `new_root` becomes `last_root`, the value the guard checks). The
    // entry stays decodable, so replay reproduces the true final root, which
    // now disagrees with the recorded (corrupted) one — exactly what the guard
    // exists to catch.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let n = conn
            .execute(
                "UPDATE changes SET new_root = ?1
                 WHERE space_id = ?2
                   AND change_id = (SELECT MAX(change_id) FROM changes WHERE space_id = ?2)",
                rusqlite::params![&[0xFFu8; 32][..], space_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(n, 1, "expected to tamper exactly one persisted change row");
    }

    // A fresh server rehydrating from the tampered store must refuse to serve.
    let mut restored = SpaceState::init_server(
        Some(&schemas.to_vec()),
        Some(SpaceInitConfig {
            space_id,
            artifact_path: None,
            verbose_logfile: None,
            bootstrap_data: BootstrapDataSource::None,
        }),
        Some(2),
    )
    .await
    .unwrap();
    restored.change_store = store.clone();

    let err = restored
        .rehydrate_from_store()
        .await
        .expect_err("tampered post-change root must fail the rehydrate root guard");
    assert!(
        err.to_string().contains("root guard"),
        "expected a root-guard mismatch error, got: {err}"
    );
}
