// Re-export public types for use as a library for integration tests
pub use db::SpaceState;
pub use encrypted_spaces_backend::SpaceId;

pub mod app_config;
pub mod conn_limiter;
pub mod db;
pub mod file_store;
pub mod http;
pub mod key_delivery;
pub mod persistence;
pub mod websocket;

/// Receiver half of the shutdown watch, mirrored from `main.rs` so the
/// `http` and `websocket` modules resolve `crate::ShutdownRx` when this
/// crate is built as a library (e.g. for the SDK's WS integration tests).
/// `tls`/`persistence` graceful-shutdown wiring lives in the binary; the
/// library only needs the type so `handle_request` is callable.
pub type ShutdownRx = tokio::sync::watch::Receiver<bool>;
