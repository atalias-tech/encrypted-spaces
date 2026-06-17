//! Durable storage for accepted changes + FF proof checkpoints.
//!
//! Stores opaque bytes keyed by `SpaceId`; knows nothing about Merk or
//! changelog semantics. `SqliteChangeStore` is the durable impl (WAL,
//! synchronous=FULL); `NullChangeStore` is an in-memory no-op used when no
//! DB path is configured and in unrelated tests.

use encrypted_spaces_backend::SpaceId;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug)]
pub struct PersistError(pub String);

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "persistence error: {}", self.0)
    }
}
impl std::error::Error for PersistError {}

impl From<rusqlite::Error> for PersistError {
    fn from(e: rusqlite::Error) -> Self {
        PersistError(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct PersistedChangeRow {
    pub change_id: u32,
    pub entry_bytes: Vec<u8>,
    pub hashed_values_bytes: Vec<u8>,
    pub accepted_at: u64,
}

#[derive(Debug, Clone)]
pub struct PersistedSpace {
    /// Ordered ascending by `change_id`.
    pub changes: Vec<PersistedChangeRow>,
    /// Serialized `FFProof` bytes, if a proof checkpoint exists.
    pub ff_proof: Option<Vec<u8>>,
    /// The `proven_up_to` recorded with the proof (0 if no proof).
    pub proven_up_to: usize,
}

pub trait ChangeStore: Send + Sync {
    fn append_change(
        &self,
        space_id: SpaceId,
        change_id: u32,
        entry: &[u8],
        hashed_values: &[u8],
        accepted_at: u64,
    ) -> Result<(), PersistError>;

    fn save_ff_proof(
        &self,
        space_id: SpaceId,
        proven_up_to: usize,
        proof: &[u8],
    ) -> Result<(), PersistError>;

    fn load_space(&self, space_id: SpaceId) -> Result<Option<PersistedSpace>, PersistError>;
}

/// No-op store: nothing is persisted, nothing is ever loaded.
pub struct NullChangeStore;

impl ChangeStore for NullChangeStore {
    fn append_change(
        &self,
        _: SpaceId,
        _: u32,
        _: &[u8],
        _: &[u8],
        _: u64,
    ) -> Result<(), PersistError> {
        Ok(())
    }
    fn save_ff_proof(&self, _: SpaceId, _: usize, _: &[u8]) -> Result<(), PersistError> {
        Ok(())
    }
    fn load_space(&self, _: SpaceId) -> Result<Option<PersistedSpace>, PersistError> {
        Ok(None)
    }
}

pub struct SqliteChangeStore {
    conn: Mutex<Connection>,
}

impl SqliteChangeStore {
    pub fn open(path: &Path) -> Result<Self, PersistError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS changes (
                 space_id      BLOB    NOT NULL,
                 change_id     INTEGER NOT NULL,
                 entry         BLOB    NOT NULL,
                 hashed_values BLOB    NOT NULL,
                 accepted_at   INTEGER NOT NULL,
                 PRIMARY KEY (space_id, change_id)
             );
             CREATE TABLE IF NOT EXISTS ff_proof (
                 space_id     BLOB    PRIMARY KEY,
                 proven_up_to INTEGER NOT NULL,
                 proof        BLOB    NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl ChangeStore for SqliteChangeStore {
    fn append_change(
        &self,
        space_id: SpaceId,
        change_id: u32,
        entry: &[u8],
        hashed_values: &[u8],
        accepted_at: u64,
    ) -> Result<(), PersistError> {
        let conn = self.conn.lock().expect("change store mutex poisoned");
        conn.execute(
            "INSERT INTO changes (space_id, change_id, entry, hashed_values, accepted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                space_id.as_bytes().as_slice(),
                change_id,
                entry,
                hashed_values,
                accepted_at as i64,
            ],
        )?;
        Ok(())
    }

    fn save_ff_proof(
        &self,
        space_id: SpaceId,
        proven_up_to: usize,
        proof: &[u8],
    ) -> Result<(), PersistError> {
        let conn = self.conn.lock().expect("change store mutex poisoned");
        conn.execute(
            "INSERT INTO ff_proof (space_id, proven_up_to, proof) VALUES (?1, ?2, ?3)
             ON CONFLICT(space_id) DO UPDATE SET proven_up_to = ?2, proof = ?3",
            params![space_id.as_bytes().as_slice(), proven_up_to as i64, proof],
        )?;
        Ok(())
    }

    fn load_space(&self, space_id: SpaceId) -> Result<Option<PersistedSpace>, PersistError> {
        let conn = self.conn.lock().expect("change store mutex poisoned");
        let key = space_id.as_bytes().to_vec();

        let mut stmt = conn.prepare(
            "SELECT change_id, entry, hashed_values, accepted_at
             FROM changes WHERE space_id = ?1 ORDER BY change_id ASC",
        )?;
        let rows = stmt
            .query_map(params![key.as_slice()], |row| {
                Ok(PersistedChangeRow {
                    change_id: row.get::<_, i64>(0)? as u32,
                    entry_bytes: row.get(1)?,
                    hashed_values_bytes: row.get(2)?,
                    accepted_at: row.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let proof_row = conn
            .query_row(
                "SELECT proven_up_to, proof FROM ff_proof WHERE space_id = ?1",
                params![key.as_slice()],
                |row| Ok((row.get::<_, i64>(0)? as usize, row.get::<_, Vec<u8>>(1)?)),
            )
            .ok();

        if rows.is_empty() && proof_row.is_none() {
            return Ok(None);
        }
        let (proven_up_to, ff_proof) = match proof_row {
            Some((p, bytes)) => (p, Some(bytes)),
            None => (0, None),
        };
        Ok(Some(PersistedSpace {
            changes: rows,
            ff_proof,
            proven_up_to,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_store_roundtrips_changes_and_proof() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteChangeStore::open(&dir.path().join("test.db")).unwrap();
        let sid = SpaceId::from([7u8; 16]);

        store
            .append_change(sid, 1, b"entry1", b"hv1", 1000)
            .unwrap();
        store
            .append_change(sid, 2, b"entry2", b"hv2", 1001)
            .unwrap();
        store.save_ff_proof(sid, 2, b"proofbytes").unwrap();

        let loaded = store.load_space(sid).unwrap().unwrap();
        assert_eq!(loaded.changes.len(), 2);
        assert_eq!(loaded.changes[0].change_id, 1);
        assert_eq!(loaded.changes[0].entry_bytes, b"entry1");
        assert_eq!(loaded.changes[1].hashed_values_bytes, b"hv2");
        assert_eq!(loaded.proven_up_to, 2);
        assert_eq!(loaded.ff_proof.unwrap(), b"proofbytes");

        // Unknown space → None.
        assert!(store
            .load_space(SpaceId::from([9u8; 16]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn null_store_persists_nothing() {
        let store = NullChangeStore;
        let sid = SpaceId::from([1u8; 16]);
        store.append_change(sid, 1, b"x", b"y", 1).unwrap();
        store.save_ff_proof(sid, 1, b"p").unwrap();
        assert!(store.load_space(sid).unwrap().is_none());
    }
}
