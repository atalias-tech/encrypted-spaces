//! End-to-end verified-client-authentication tests over the *real*
//! [`WebSocketTransport`] talking to the *real* server (`http::handle_request`),
//! not the auto-verifying `LocalTransport`. These are the security oracle for
//! the WS challenge-response handshake:
//!
//! * the server sends a `ChallengeNonce`;
//! * the client signs `auth_challenge_message(space_id, uid, nonce)` with its
//!   `auth_key_pair` and replies `ChallengeResponse { uid, signature }`;
//! * the server verifies that signature against `_users.auth_key` and records a
//!   per-connection `verified_uid`. Unverified connections may run ONLY the
//!   bootstrap `CreateSpace`; every other op is rejected.
//!
//! Scenarios:
//!   1. Founder `Space::create` over WS succeeds and follow-up gated ops (an
//!      `invite_user` write and a `_users` select) succeed.
//!   2. **Impostor rejected** (the key test): a connection that *asserts the
//!      founder's uid* but signs with a *different* keypair must be rejected by
//!      the handshake, so a gated op fails. This must NOT succeed.
//!   3. Join: the founder invites a second user; the invitee `Space::join`s
//!      over WS (provisional-key handshake) and a follow-up op succeeds.
//!
//! Run with:
//!   cargo test -p encrypted-spaces-sdk --features local-transport,testing \
//!     --test verified_auth -- --nocapture --test-threads=1

#![cfg(all(feature = "local-transport", feature = "testing"))]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use encrypted_spaces_backend_server::app_config::{AppConfig, BootstrapDataSource};
use encrypted_spaces_backend_server::http::handle_request;
use encrypted_spaces_backend_server::websocket::new_connection_registry;

use encrypted_spaces_sdk::testing::initial_internal_data_commitment;
use encrypted_spaces_sdk::transport::{Signer, Transport};
use encrypted_spaces_sdk::{ApplicationSchema, AuthContext, Query, Space, WebSocketTransport};

use encrypted_spaces_backend::query::QueryOperation;
use encrypted_spaces_backend::SpaceId;

use hyper::service::service_fn;
use tokio::net::TcpListener;
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// In-process WS server harness
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
                    let (tcp, _) = match accept {
                        Ok(pair) => pair,
                        Err(_) => continue,
                    };
                    let app_cfg_conn = app_cfg.clone();
                    let reg_conn = registry.clone();
                    let conn_shutdown = shutdown_rx.clone();
                    tokio::spawn(async move {
                        let _ = hyper::server::conn::Http::new()
                            .http1_only(true)
                            .http1_keep_alive(true)
                            .serve_connection(
                                tcp,
                                service_fn(move |req| {
                                    handle_request(
                                        req,
                                        app_cfg_conn.clone(),
                                        reg_conn.clone(),
                                        conn_shutdown.clone(),
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

/// Empty-schema application anchored at the server's lazy-create root.
fn empty_schema() -> ApplicationSchema {
    ApplicationSchema::for_testing(vec![], initial_internal_data_commitment())
}

// ---------------------------------------------------------------------------
// Test driver
// ---------------------------------------------------------------------------
//
// All three scenarios run inside a SINGLE `#[tokio::test]` (one runtime). The
// server's request dispatcher is a process-global `Lazy` worker spawned on the
// runtime that first initializes it; a second `#[tokio::test]` gets a fresh
// runtime where that worker is already dead, so its requests fail with
// `request_queue_closed`. Sharing one runtime across the scenarios sidesteps
// that global-singleton lifecycle issue. Each scenario still uses its own server
// instance and a fresh random `SpaceId`, so they don't interfere.

#[tokio::test]
async fn verified_auth_ws_handshake() {
    init();
    scenario_founder_create_and_use().await;
    scenario_impostor_with_wrong_key_is_rejected().await;
    scenario_invitee_joins().await;
}

// ---------------------------------------------------------------------------
// Scenario 1 — founder create + use over the real WebSocketTransport
// ---------------------------------------------------------------------------

async fn scenario_founder_create_and_use() {
    let server = start_test_server().await;

    let transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect founder transport");
    let space = Space::create(transport, empty_schema())
        .await
        .expect("founder Space::create over WS");

    // The founder connection is verified/promoted after CreateSpace. Exercise a
    // follow-up gated WRITE (invite_user → submit_change/AddMember) and a gated
    // READ (select on _users) over that same connection; both must succeed.
    // (`Space::create_table` is a LocalTransport-only test helper that panics on
    // a WebSocketTransport, so the built-in `_users` table is used here — the
    // point is exercising the verified-connection op gate, not the schema.)
    let invitee = space
        .invite_user()
        .await
        .expect("verified founder may invite");
    assert_eq!(
        invitee.status(),
        encrypted_spaces_sdk::UserStatus::Provisional
    );

    let users = space
        .users()
        .select()
        .all()
        .await
        .expect("verified founder may read");
    assert_eq!(users.len(), 2, "founder + freshly invited user");

    eprintln!("scenario 1 (founder create+use over WS): PASS");
}

// ---------------------------------------------------------------------------
// Scenario 2 — impostor rejected (THE KEY TEST / security oracle)
// ---------------------------------------------------------------------------

/// A connection that asserts the founder's uid but signs the challenge with a
/// DIFFERENT keypair must be rejected by the handshake, so a gated op fails.
///
/// The founder is created first (writing the founder's real `auth_key` into
/// `_users`), so the server has a key to verify against. The impostor then
/// opens a *raw* `WebSocketTransport`, installs a fresh ed25519 signer (NOT the
/// founder's key), and authenticates as the founder's uid. The server's
/// challenge verification fails (`Ok(false)`), it closes the connection, and
/// the subsequent gated `select` therefore errors.
async fn scenario_impostor_with_wrong_key_is_rejected() {
    let server = start_test_server().await;

    // 1. Real founder creates the space (their auth_key lands in _users).
    let founder_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect founder transport");
    let space = Space::create(founder_transport, empty_schema())
        .await
        .expect("founder Space::create over WS");
    let space_id: SpaceId = space.id();
    let founder_uid = space.uid().expect("founder uid") as i64;

    // 2. Impostor: raw transport, asserts the founder's uid, but signs with a
    //    fresh ed25519 key that is NOT the founder's auth_key.
    let impostor_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect impostor transport");

    let wrong_signer: Signer = {
        use ed25519_dalek::{Signer as _, SigningKey};
        let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        Arc::new(move |msg: &[u8]| sk.sign(msg).to_bytes().to_vec())
    };
    impostor_transport.set_signer(wrong_signer);

    // `authenticate` opens the WS and runs the challenge handshake. The server
    // sends a nonce; the impostor signs with the wrong key; the server's
    // verification fails and it closes the connection.
    let impostor_auth = AuthContext::new(Some(founder_uid), space_id);
    let _ = impostor_transport.authenticate(&impostor_auth).await;

    // 3. A gated op (select on _users) must FAIL. Whether the failure surfaces
    //    as a closed connection or an explicit auth rejection, it must NOT
    //    succeed — that is the security guarantee. Do NOT weaken this.
    let query = Query::new(
        encrypted_spaces_sdk::USERS_TABLE_NAME.to_string(),
        QueryOperation::Select(vec![]),
    );
    let commitment = space.current_data_commitment();
    let schemas: HashMap<String, encrypted_spaces_sdk::Schema> = HashMap::new();
    let result = impostor_transport
        .select(query, &commitment, &schemas)
        .await;

    assert!(
        result.is_err(),
        "impostor asserting the founder's uid with a wrong signing key MUST be \
         rejected; a gated op must not succeed (it returned Ok)"
    );

    // The genuine founder is unaffected: it can still read on its own verified
    // connection (sanity that the rejection is impostor-specific, not a server
    // outage).
    let founder_rows = space
        .users()
        .select()
        .all()
        .await
        .expect("founder still authorized");
    assert_eq!(founder_rows.len(), 1, "founder should see exactly itself");

    eprintln!("scenario 2 (impostor rejected): PASS — gated op errored as expected");
}

// ---------------------------------------------------------------------------
// Scenario 3 — invitee joins over the real WebSocketTransport
// ---------------------------------------------------------------------------

async fn scenario_invitee_joins() {
    let server = start_test_server().await;

    // Founder creates the space and invites a second user. The invite registers
    // the invitee's provisional auth_key in _users, so the invitee's handshake
    // verifies (their connection arrives already verified) and join's
    // FetchMyKeyDelivery / RefreshKeys run on a verified connection.
    let founder_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect founder transport");
    let space = Space::create(founder_transport, empty_schema())
        .await
        .expect("founder Space::create over WS");

    let invite = space.invite_user().await.expect("founder invites a user");
    let invitee_id = invite.id();

    // Invitee joins over its OWN real WebSocketTransport.
    let invitee_transport = WebSocketTransport::new(&server.url)
        .await
        .expect("connect invitee transport");
    let invitee_space = Space::join(invitee_transport, invite, empty_schema())
        .await
        .expect("invitee Space::join over WS");

    // Follow-up gated op on the invitee's verified connection succeeds.
    let users = invitee_space
        .users()
        .select()
        .all()
        .await
        .expect("invitee reads users");
    assert_eq!(users.len(), 2, "invitee should see founder + itself");
    let me = users
        .iter()
        .find(|u| u.id == invitee_id)
        .expect("invitee present in users");
    assert_eq!(
        me.status,
        encrypted_spaces_sdk::UserStatus::Full,
        "invitee should be Full after join/RefreshKeys"
    );

    eprintln!("scenario 3 (invitee join over WS): PASS");
}

// ---------------------------------------------------------------------------
// Replay / nonce-reuse note
// ---------------------------------------------------------------------------
//
// A standalone replay test (capture a valid ChallengeResponse, reconnect, and
// resend it) is intentionally omitted: the handshake nonce is drawn fresh per
// connection inside `perform_auth_challenge` (server side) and the client signs
// the server-supplied nonce, so a captured response is bound to a nonce the
// server will never reissue. Exercising replay would require a hand-rolled raw
// websocket client that bypasses `WebSocketTransport::connect` (which always
// signs the *current* nonce); that lower-level fixture is out of scope here and
// the freshness property it would test is already covered structurally by the
// per-connection `OsRng` nonce. The impostor test above is the load-bearing
// security oracle.
