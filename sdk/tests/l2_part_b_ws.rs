//! L2 Part B CROWN JEWEL over the *real* [`WebSocketTransport`] talking to the
//! *real* server (`http::handle_request`), not the auto-verifying
//! `LocalTransport`.
//!
//! The Part B retention property — a *scoped* member keeps reading NEW messages
//! in its channel across a group rekey — is validated under `LocalTransport` by
//! `sdk/src/crypto.rs::scoped_member_reads_new_message_after_{rekey,
//! standalone_rekey}`. `LocalTransport` drives the real server *logic*
//! in-process, but production uses `WebSocketTransport` + a network round-trip:
//! the founder's rekey (with its bundled scoped re-grants) and the agent's
//! `refresh_scoped_keys` both cross the wire, and the server's re-deposited
//! `ScopedDeliveryEnvelope` is fetched back over the agent's own authenticated
//! WS connection. This test re-runs the crown-jewel scenario end to end over
//! that production transport.
//!
//! Unlike `l2_rekey_leak_ws.rs` (which needs no app tables — it inspects the
//! delivery slot directly), reading a NEW *message* requires a real
//! channel-scoped table. Over `WebSocketTransport` there is no
//! `Space::create_table` (a `LocalTransport`-only helper); tables come from the
//! bootstrap schema (whitepaper/`basic_ws` pattern). So the server is started
//! with `BootstrapDataSource::SchemaFile(fixtures/l2_msgs.kdl)`, and the clients
//! anchor to that same post-bootstrap root — computed at runtime from a
//! throwaway `LocalTransport::from_schema_file(<same file>)`, which bootstraps
//! identically and so yields the identical merk root.
//!
//! Run with:
//!   cargo test -p encrypted-spaces-sdk --features local-transport,testing \
//!     --test l2_part_b_ws -- --nocapture

#![cfg(all(feature = "local-transport", feature = "testing"))]

use std::net::SocketAddr;
use std::sync::Arc;

use encrypted_spaces_backend_server::app_config::{AppConfig, BootstrapDataSource};
use encrypted_spaces_backend_server::http::handle_request;
use encrypted_spaces_backend_server::websocket::new_connection_registry;

use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport, Space, WebSocketTransport};

use hyper::service::service_fn;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Bootstrap schema for the channel-scoped `msgs` table.
// ---------------------------------------------------------------------------

/// KDL bytes for the app schema, baked in so the clients parse the identical
/// table definition the server bootstrapped from.
const MSGS_KDL: &[u8] = include_bytes!("fixtures/l2_msgs.kdl");
/// Filesystem path to the same fixture, for `from_schema_file` (root compute)
/// and the server's `SchemaFile` bootstrap.
const MSGS_KDL_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/l2_msgs.kdl");

/// A channel-scoped message: plaintext `channel_id` (the L2 routing key) + an
/// encrypted `body`. Mirrors the `Msg` used by the LocalTransport crown-jewel.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Msg {
    id: Option<i64>,
    channel_id: i64,
    body: String,
}

// ---------------------------------------------------------------------------
// In-process WS server harness (copied from `sdk/tests/l2_rekey_leak_ws.rs`,
// parameterized to bootstrap the `msgs` table from a schema file).
// ---------------------------------------------------------------------------

/// Holds the live server so its accept loop and shutdown watch stay alive for
/// the duration of a test. Dropping it flips the shutdown watch, which makes
/// the accept loop exit.
struct TestServer {
    url: String,
    _shutdown: watch::Sender<bool>,
}

/// Bind an ephemeral `127.0.0.1` port and serve each accepted connection with
/// hyper, dispatching to `http::handle_request` exactly as `main.rs`'s
/// `run_http_server` does. Returns the `ws://127.0.0.1:PORT/ws` URL.
///
/// The server bootstraps every new space from `schema_path`, so the lazily
/// created space carries the `msgs` table and its root matches the root the
/// clients anchor to (see [`bootstrap_root`]).
async fn start_test_server(schema_path: &str) -> TestServer {
    let app_cfg = Arc::new(AppConfig {
        verbose_logfile: None,
        space_root: None,
        bootstrap_data: BootstrapDataSource::SchemaFile(schema_path.to_string()),
        max_req_per_sec: 0,
        trusted_proxies: vec![],
    });
    let registry = new_connection_registry();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("ws://{addr}/ws");

    let accept_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut accept_shutdown = accept_shutdown;
        loop {
            tokio::select! {
                biased;
                res = accept_shutdown.changed() => {
                    if res.is_err() || *accept_shutdown.borrow() {
                        break;
                    }
                }
                accept = listener.accept() => {
                    let (tcp, peer) = match accept {
                        Ok(pair) => pair,
                        Err(_) => continue,
                    };
                    let app_cfg_conn = app_cfg.clone();
                    let reg_conn = registry.clone();
                    let conn_shutdown = shutdown_rx.clone();
                    let peer_ip = peer.ip();
                    // Test server has no connection limiter; pass an empty permit slot.
                    let permit_slot = std::sync::Arc::new(
                        std::sync::Mutex::new(None::<encrypted_spaces_backend_server::conn_limiter::ConnPermit>),
                    );
                    tokio::spawn(async move {
                        let _ = hyper::server::conn::Http::new()
                            .http1_only(true)
                            .http1_keep_alive(true)
                            .serve_connection(
                                tcp,
                                service_fn(move |req| {
                                    handle_request(
                                        req,
                                        peer_ip,
                                        app_cfg_conn.clone(),
                                        reg_conn.clone(),
                                        conn_shutdown.clone(),
                                        permit_slot.clone(),
                                    )
                                }),
                            )
                            .with_upgrades()
                            .await;
                    });
                }
            }
        }
    });

    TestServer {
        url,
        _shutdown: shutdown_tx,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init() {
    std::env::set_var("RISC0_DEV_MODE", "1");
    let _ = env_logger::builder().is_test(true).try_init();
}

/// Compute the post-bootstrap merk root for `schema_path` by standing up a
/// throwaway in-process `LocalTransport` from the SAME schema file. Both the WS
/// server and this throwaway funnel through `SpaceState::init_server` with the
/// identical `SchemaFile` bootstrap, so they land on the identical root — which
/// the WS clients then anchor to. (There is no `get_root_hash` on
/// `WebSocketTransport`; this is how the `basic_ws` demo's hard-coded
/// `APP_DATA_COMMITMENT` would be regenerated.)
async fn bootstrap_root(schema_path: &str) -> [u8; 32] {
    let throwaway = LocalTransport::from_schema_file(schema_path)
        .await
        .expect("bootstrap a throwaway local server from the schema file");
    throwaway
        .get_root_hash()
        .await
        .expect("read the post-bootstrap root hash")
}

/// The application schema the WS clients create/join with: the `msgs` table
/// parsed from `MSGS_KDL`, anchored at the server's bootstrapped `root`.
fn app_schema(root: [u8; 32]) -> ApplicationSchema {
    ApplicationSchema::for_testing_from_bytes(MSGS_KDL, root)
}

// ---------------------------------------------------------------------------
// Test — L2 Part B crown jewel over the real WebSocketTransport
// ---------------------------------------------------------------------------
//
// Single `#[tokio::test]` (one runtime). The server's request dispatcher is a
// process-global `Lazy` worker spawned on the runtime that first initializes
// it; a second `#[tokio::test]` would get a fresh runtime where that worker is
// already dead. Keeping to one test sidesteps that global-singleton lifecycle
// issue (see the note in `l2_rekey_leak_ws.rs` / `verified_auth.rs`).

#[tokio::test]
async fn scoped_member_reads_new_message_after_rekey_over_ws() {
    init();

    // Compute the bootstrapped root, then start the WS server on the SAME
    // schema file so its lazily created space lands on that exact root.
    let root = bootstrap_root(MSGS_KDL_PATH).await;
    let server = start_test_server(MSGS_KDL_PATH).await;

    // 1. Founder creates the space over its own real WebSocketTransport,
    //    anchored to the bootstrapped root (which carries the `msgs` table).
    let founder_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect founder transport");
    let alice = Space::create(founder_transport, app_schema(root))
        .await
        .expect("founder Space::create over WS");

    // 2. Founder scoped-invites an agent to channel 1 only (no group key).
    let invite = alice
        .invite_user_scoped(&[1])
        .await
        .expect("founder issues a channel-1 scoped invite over WS");

    // 3. Agent joins over its OWN real WebSocketTransport, with the same app
    //    schema (so it holds the `msgs` table definition). It bootstraps
    //    holding only channel 1's subtree key.
    let agent_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect agent transport");
    let agent = Space::join(agent_transport, invite, app_schema(root))
        .await
        .expect("scoped agent Space::join over WS");
    assert!(
        !agent.holds_group_key().await,
        "scoped agent must bootstrap without the group key"
    );

    // 4. Converge the founder's `_users` view on the agent's post-join key
    //    rotation before rekeying (same MVE-race reasoning as the leak test).
    alice
        .sync()
        .await
        .expect("founder converges on the agent's post-join rotation");

    // 5. Founder forces a real standalone group rekey (new group-key epoch).
    //    Every channel's subtree key rotates; the Part B re-delivery must
    //    re-derive + re-deposit the scoped agent's channel-1 key against the
    //    NEW epoch — all over the real WS round-trip.
    alice.rekey().await.expect("founder standalone rekey over WS");

    // 6. Founder posts a NEW channel-1 message under the fresh epoch.
    alice
        .table::<Msg>("msgs")
        .insert(&Msg {
            id: None,
            channel_id: 1,
            body: "post-rekey ch1 over WS".into(),
        })
        .execute()
        .await
        .expect("founder posts a NEW ch1 message over WS");

    // 7. THE CROWN JEWEL over WS: the scoped agent fetches its server-refreshed
    //    channel key over its own authenticated WS connection and reads the NEW
    //    message. If Part B's re-delivery/refresh did not survive the real
    //    transport, the agent's channel key would be stale and this read would
    //    return zero matching rows.
    //
    //    Over the real transport the agent runs a background broadcast listener
    //    that fast-forwards on the rekey/insert broadcasts. That can be in
    //    flight when we call `refresh_scoped_keys`, whose internal `sync()` then
    //    hits the re-entrancy guard (`FastForwardRequired`). It is transient:
    //    back off and retry until the background FF settles and the explicit
    //    refresh (which fetches + installs the refreshed channel key) succeeds.
    let mut last_err: Option<String> = None;
    let mut refreshed = false;
    for attempt in 0..40u32 {
        match agent.refresh_scoped_keys().await {
            Ok(()) => {
                refreshed = true;
                break;
            }
            Err(e) => {
                last_err = Some(e.to_string());
                eprintln!("refresh_scoped_keys attempt {attempt} deferred: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        }
    }
    assert!(
        refreshed,
        "scoped agent must refresh its channel key over WS within the retry budget; \
         last error: {last_err:?}"
    );
    let rows: Vec<Msg> = agent
        .table::<Msg>("msgs")
        .select()
        .all()
        .await
        .expect("agent reads msgs over WS");
    assert!(
        rows.iter().any(|m| m.body == "post-rekey ch1 over WS"),
        "scoped agent must read a NEW ch1 message after a rekey over the real WebSocketTransport"
    );
    // Isolation still holds over WS: the agent decrypts ONLY its channel.
    assert!(
        rows.iter().all(|m| m.channel_id == 1),
        "scoped agent must read ONLY its granted channel over WS"
    );
    // And it remains scoped — never escalated to a group-key holder.
    assert!(
        !agent.holds_group_key().await,
        "scoped agent must still hold no group key after the rekey over WS"
    );

    eprintln!(
        "L2 Part B crown jewel over WebSocketTransport: PASS — scoped agent read a NEW \
         channel-1 message after a real rekey + refresh over the wire"
    );
}
