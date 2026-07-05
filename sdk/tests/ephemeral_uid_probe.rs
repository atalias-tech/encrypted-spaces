//! `ephemeral_uid_probe` — security-oracle test for the ephemeral relay's
//! server-attested uid (companion to `verified_auth.rs`'s auth-handshake
//! oracle; reuses its in-process real-`WebSocketTransport`-vs-real-server
//! harness). Exercises the *real* dispatch path in
//! `backend/server/src/websocket.rs` (Task C1's two gaps):
//!
//!   1. A verified connection sends an Ephemeral frame claiming another
//!      user's identity (a forged `uid`). The server must not trust the
//!      client-asserted uid: it overwrites `Ephemeral.uid` with the
//!      connection's own server-verified uid before relaying, so peers see
//!      the sender's REAL uid, never the forged one.
//!   2. An unverified (bootstrap/anonymous) connection sends an Ephemeral
//!      frame. The server must not relay it at all — Ephemeral frames
//!      require a verified connection, mirroring the DbRequest gate at
//!      `handle_db_request` (websocket.rs).
//!
//! Companion regression: `halyard-agent/examples/ephemeral_probe.rs` (in the
//! app tree) exercises the honest single-sender typing-relay path over a
//! real standalone server and must keep passing unmodified by this fix.
//!
//! Run with:
//!   cargo test -p encrypted-spaces-sdk --features local-transport,testing \
//!     --test ephemeral_uid_probe -- --nocapture --test-threads=1

#![cfg(all(feature = "local-transport", feature = "testing"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use encrypted_spaces_backend_server::app_config::{AppConfig, BootstrapDataSource};
use encrypted_spaces_backend_server::http::handle_request;
use encrypted_spaces_backend_server::websocket::new_connection_registry;

use encrypted_spaces_sdk::testing::initial_internal_data_commitment;
use encrypted_spaces_sdk::transport::Transport;
use encrypted_spaces_sdk::{ApplicationSchema, AuthContext, Space, WebSocketTransport};

use hyper::service::service_fn;
use tokio::net::TcpListener;
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// In-process WS server harness — copied from `verified_auth.rs`'s pattern
// (binds an ephemeral port, serves each accepted connection with the real
// `http::handle_request`/`websocket` dispatch, exactly as `main.rs` does).
// See that file for the detailed rationale of why an in-process harness is
// used instead of a hand-rolled mock transport.
// ---------------------------------------------------------------------------

struct TestServer {
    url: String,
    _shutdown: watch::Sender<bool>,
}

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

fn init() {
    std::env::set_var("RISC0_DEV_MODE", "1");
    let _ = env_logger::builder().is_test(true).try_init();
}

/// Empty-schema application anchored at the server's lazy-create root — the
/// ephemeral relay doesn't touch any app table, so no custom schema is needed.
fn empty_schema() -> ApplicationSchema {
    ApplicationSchema::for_testing(vec![], initial_internal_data_commitment())
}

// ---------------------------------------------------------------------------
// Test driver
// ---------------------------------------------------------------------------
//
// Both scenarios run inside a SINGLE `#[tokio::test]` (one runtime), matching
// `verified_auth.rs`'s note on the server dispatcher's process-global `Lazy`
// worker: a second `#[tokio::test]` would get a fresh runtime where that
// worker is already dead. Each scenario uses its own server instance and a
// fresh random `SpaceId`, so they don't interfere with each other.

#[tokio::test]
async fn ephemeral_uid_is_server_attested() {
    init();
    scenario_forged_uid_is_corrected().await;
    scenario_unverified_connection_is_dropped().await;
}

// ---------------------------------------------------------------------------
// Scenario 1 — forged uid on a verified connection is corrected, not relayed
// ---------------------------------------------------------------------------

/// B is a genuinely VERIFIED member (real invite + real join handshake), but
/// sends an Ephemeral frame claiming an arbitrary uid (9999, nobody's real
/// uid). Founder A must observe B's REAL server-verified uid, never 9999.
async fn scenario_forged_uid_is_corrected() {
    let server = start_test_server().await;

    let founder_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect founder transport");
    let a = Space::create(founder_transport, empty_schema())
        .await
        .expect("founder Space::create over WS");
    let mut rx = a.subscribe_ephemeral().expect("A subscribe_ephemeral");

    let invite = a.invite_user().await.expect("founder invites B");

    let b_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect B transport");
    let b = Space::join(b_transport, invite, empty_schema())
        .await
        .expect("B Space::join over WS");
    let b_uid = b.uid().expect("B has a uid");

    let forged_uid: u32 = 9999;
    assert_ne!(
        forged_uid, b_uid,
        "sanity: forged uid must differ from B's real uid"
    );

    // `send_ephemeral_as_uid` is the test-only escape hatch (authentication.rs)
    // that calls the transport directly with an explicit uid, bypassing the
    // production `Space::send_ephemeral`'s honest-uid stamping — i.e. exactly
    // what a malicious or buggy client could attempt on the wire.
    b.send_ephemeral_as_uid(forged_uid, "voice-probe", b"forged")
        .await
        .expect("B send forged ephemeral");

    let evt = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("A should receive an ephemeral event within 5s")
        .expect("ephemeral channel should not error");

    assert_eq!(
        evt.uid, b_uid,
        "server must overwrite Ephemeral.uid with the connection's verified uid \
         ({b_uid}), not relay the client-asserted forged uid ({forged_uid})"
    );
    assert_ne!(
        evt.uid, forged_uid,
        "forged uid must never reach other clients unmodified"
    );

    eprintln!(
        "scenario 1 (forged uid corrected): PASS — A observed uid={} (B's real uid), not {forged_uid}",
        evt.uid
    );
}

// ---------------------------------------------------------------------------
// Scenario 2 — unverified connection's ephemeral frame is dropped
// ---------------------------------------------------------------------------

/// An unverified (anonymous/bootstrap) connection — auth handshake completed
/// with an empty signature, so the server never assigns it a `verified_uid`
/// — sends an Ephemeral frame. It must be dropped: A must observe nothing.
async fn scenario_unverified_connection_is_dropped() {
    let server = start_test_server().await;

    let founder_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect founder transport");
    let a = Space::create(founder_transport, empty_schema())
        .await
        .expect("founder Space::create over WS");
    let mut rx = a.subscribe_ephemeral().expect("A subscribe_ephemeral");
    let space_id = a.id();

    // Raw transport, authenticated with an anonymous auth context (no uid,
    // no signer set) -> the client sends an empty-signature
    // ChallengeResponse -> the server's `perform_auth_challenge` treats this
    // as an unverified bootstrap connection (`verified_uid == None`), same
    // as `scenario_impostor_with_wrong_key_is_rejected` in `verified_auth.rs`
    // uses raw transports to exercise handshake edge cases directly.
    let unverified_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect unverified transport");
    unverified_transport
        .authenticate(&AuthContext::anonymous(space_id))
        .await
        .expect("anonymous handshake completes (unverified, not rejected)");

    unverified_transport
        .send_ephemeral(4242, "voice-probe", b"should not be relayed")
        .await
        .expect("the raw send itself succeeds (server silently drops it server-side)");

    let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        result.is_err(),
        "an unverified connection's Ephemeral frame must be dropped, not relayed \
         to other clients; A should observe nothing within the timeout, got {result:?}"
    );

    eprintln!("scenario 2 (unverified connection dropped): PASS — A observed nothing");
}
