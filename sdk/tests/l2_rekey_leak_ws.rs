//! Production-path proof of the §8 rekey-leak fix over the *real*
//! [`WebSocketTransport`] talking to the *real* server (`http::handle_request`),
//! not the auto-verifying `LocalTransport`.
//!
//! `LocalTransport` drives the real server *logic* in-process, but production
//! uses `WebSocketTransport` + a network round-trip and the server's
//! recipient-filtering on the wire. The §8 leak-closure invariant — after a
//! group rekey, a *scoped* member's key-delivery slot must NOT contain a
//! group-key envelope — is validated under `LocalTransport` by
//! `sdk/src/crypto.rs::scoped_member_slot_has_no_group_key_after_rekey`. This
//! test re-runs the same scenario over the production transport.
//!
//! ## Why the assertion is a *malicious fetch*, not `holds_group_key()`
//!
//! An HONEST scoped client ignores the group-key delivery slot entirely
//! (`sync_group_key` short-circuits to `AlreadyCurrent` for a scoped tree), so
//! `holds_group_key()` stays `false` *even if the server leaked a group key into
//! the slot*. It therefore cannot, on its own, detect the leak. The real threat
//! is a *malicious* scoped client that fetches and decrypts a `GkDeliveryEnvelope`
//! from its own delivery slot. So the meaningful production-path assertion is to
//! perform exactly that fetch over WS — using the agent's own authenticated WS
//! connection — and prove the bytes the real server deposited are still a
//! `ScopedDeliveryEnvelope` and do NOT deserialize as a `GkDeliveryEnvelope`.
//! (`Space::fetch_my_key_delivery` is a `#[cfg(any(test, feature = "testing"))]`
//! hook, sibling to `holds_group_key`, that runs the transport's real
//! `fetch_my_key_delivery` over the agent's own connection.)
//!
//! Run with:
//!   cargo test -p encrypted-spaces-sdk --features local-transport,testing \
//!     --test l2_rekey_leak_ws -- --nocapture

#![cfg(all(feature = "local-transport", feature = "testing"))]

use std::net::SocketAddr;
use std::sync::Arc;

use encrypted_spaces_backend_server::app_config::{AppConfig, BootstrapDataSource};
use encrypted_spaces_backend_server::http::handle_request;
use encrypted_spaces_backend_server::websocket::new_connection_registry;

use encrypted_spaces_sdk::testing::initial_internal_data_commitment;
use encrypted_spaces_sdk::{ApplicationSchema, Space, WebSocketTransport};

use encrypted_spaces_key_manager::{GkDeliveryEnvelope, ScopedDeliveryEnvelope};

use hyper::service::service_fn;
use tokio::net::TcpListener;
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// In-process WS server harness (copied from `sdk/tests/verified_auth.rs`)
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
/// The server runs with `BootstrapDataSource::None`, so each space is created
/// lazily at the empty internal-schemas root — matching
/// `initial_internal_data_commitment()`, which the clients anchor to.
async fn start_test_server() -> TestServer {
    let app_cfg = Arc::new(AppConfig {
        verbose_logfile: None,
        space_root: None,
        bootstrap_data: BootstrapDataSource::None,
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

/// Empty-schema application anchored at the server's lazy-create root. No app
/// tables are needed: a scoped invite derives its channel subtree key straight
/// from the group key (Cryptree, whitepaper §4.3), and `rekey()` operates on
/// `_users`. (`Space::create_table` is a LocalTransport-only helper that panics
/// on a `WebSocketTransport`, so it is deliberately avoided here.)
fn empty_schema() -> ApplicationSchema {
    ApplicationSchema::for_testing(vec![], initial_internal_data_commitment())
}

// ---------------------------------------------------------------------------
// Test — §8 leak closed over the real WebSocketTransport
// ---------------------------------------------------------------------------
//
// Single `#[tokio::test]` (one runtime). The server's request dispatcher is a
// process-global `Lazy` worker spawned on the runtime that first initializes
// it; a second `#[tokio::test]` would get a fresh runtime where that worker is
// already dead. Keeping to one test sidesteps that global-singleton lifecycle
// issue (see the note in `verified_auth.rs`).

#[tokio::test]
async fn scoped_member_slot_has_no_group_key_after_rekey_over_ws() {
    init();
    let server = start_test_server().await;

    // 1. Founder creates the space over its own real WebSocketTransport.
    let founder_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect founder transport");
    let alice = Space::create(founder_transport, empty_schema())
        .await
        .expect("founder Space::create over WS");

    // 2. Founder scoped-invites an agent to channel 1 only. The server deposits
    //    a `ScopedDeliveryEnvelope` (channel subtree key, NO group key) in the
    //    agent's delivery slot.
    let invite = alice
        .invite_user_scoped(&[1])
        .await
        .expect("founder issues a channel-1 scoped invite over WS");

    // 3. Agent joins over its OWN real WebSocketTransport. This connection is
    //    now authenticated as the agent (its provisional keypair is rotated to
    //    a permanent one during join). It holds only the channel-1 subtree key.
    let agent_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect agent transport");
    let agent = Space::join(agent_transport, invite, empty_schema())
        .await
        .expect("scoped agent Space::join over WS");

    // Sanity: the honest scoped client holds no group key after join.
    assert!(
        !agent.holds_group_key().await,
        "scoped agent must bootstrap without the group key"
    );

    // 4. Converge the founder's `_users` view over the agent's post-join key
    //    rotation before rekeying. (`sync()` == `recover_via_fast_forward()`.)
    //    Without this the founder could build the rekey against a stale
    //    `_users` snapshot and the server's independent re-fetch would fail MVE
    //    verification — a race unrelated to the §8 leak under test.
    alice
        .sync()
        .await
        .expect("founder converges on the agent's post-join rotation");

    // 5. Founder forces a real group rekey (new group-key epoch). The §8 fix
    //    must exclude the scoped agent from group-key delivery: its slot must
    //    keep the ScopedDeliveryEnvelope and never be overwritten with a GK.
    alice.rekey().await.expect("founder rekey over WS");

    // 6. MALICIOUS-FETCH-OVER-WS (the load-bearing assertion): using the agent's
    //    own authenticated WS connection, fetch its server-side delivery slot —
    //    exactly what a malicious scoped client would do to try to recover a
    //    group key. This is a real WS round-trip to the server's
    //    `FetchMyKeyDelivery` handler, proving what the PRODUCTION server
    //    actually deposited for the scoped member after the rekey.
    let bytes = agent
        .fetch_my_key_delivery()
        .await
        .expect("agent fetch_my_key_delivery over WS")
        .expect("scoped member has a delivery slot from its invite");

    assert!(
        serde_json::from_slice::<GkDeliveryEnvelope>(&bytes).is_err(),
        "SECURITY LEAK over WS: scoped member's slot deserializes as a GroupKey \
         envelope after rekey — a malicious scoped client could recover the group key"
    );
    assert!(
        serde_json::from_slice::<ScopedDeliveryEnvelope>(&bytes).is_ok(),
        "scoped member's slot should still hold its ScopedDeliveryEnvelope over WS"
    );

    // 7. Belt-and-suspenders: the client-observable property also holds — an
    //    honest agent still holds no group key after the rekey.
    assert!(
        !agent.holds_group_key().await,
        "scoped agent must still hold no group key after the rekey"
    );

    eprintln!(
        "§8 rekey-leak fix over WebSocketTransport: PASS — malicious fetch returned a \
         ScopedDeliveryEnvelope, not a GkDeliveryEnvelope"
    );
}
