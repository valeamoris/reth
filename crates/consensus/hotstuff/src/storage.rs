//! Crash-safe consensus WAL and per-epoch block QC storage.

use alloy_primitives::{Address, B256};
use reth_fs_util::FsPathError;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use tracing::warn;

use crate::{
    error::HotStuffError,
    types::{EpochChangeCert, HotStuffNodeHeader, QuorumCertificate, TimeoutCertificate},
};

/// Current format version of [`HotStuffPersistedState`].
pub const HOTSTUFF_WAL_VERSION: u32 = 2;

const CONSENSUS_STATE_FILE: &str = "consensus_state.json";
const EPOCH_CERTS_FILE: &str = "epoch_certs.json";

/// Maximum number of active `HotStuff` nodes persisted in a WAL snapshot.
pub const MAX_PERSISTED_ACTIVE_NODES: usize = 64;

/// Maximum number of active QCs persisted in a WAL snapshot.
pub const MAX_PERSISTED_ACTIVE_QCS: usize = 64;

/// Maximum number of historical epoch change certificates persisted on disk.
pub const MAX_PERSISTED_EPOCH_CERTS: usize = 10_000;

/// Crash-recovery snapshot of [`HotStuffCore`](crate::HotStuffCore) safety and liveness state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffPersistedState {
    /// Serialization schema version ([`HOTSTUFF_WAL_VERSION`]).
    pub version: u32,
    /// Active consensus epoch.
    pub epoch: u64,
    /// Current `HotStuff` view.
    pub view: u64,
    /// Highest view in which this node signed a vote (monotonic safety guard).
    pub last_voted_view: u64,
    /// Highest view in which this node proposed as leader.
    pub last_proposed_view: u64,
    /// Highest view in which this node signed a Pacemaker timeout message.
    pub last_timeout_view: u64,
    /// Highest known [`QuorumCertificate`].
    pub high_qc: QuorumCertificate,
    /// Locked [`QuorumCertificate`] enforcing the 2-chain `SafeNode` lock.
    pub locked_qc: QuorumCertificate,
    /// Consensus node hash of the latest committed node.
    pub committed_node_hash: B256,
    /// View of the latest committed node.
    pub committed_view: u64,
    /// Execution block hash of the latest committed real block.
    pub committed_exec_hash: B256,
    /// Execution block number of the latest committed real block.
    pub committed_exec_number: u64,
    /// Active uncommitted `HotStuff` nodes needed to reconstruct 2-chain/3-chain ancestry.
    pub active_nodes: Vec<HotStuffNodeHeader>,
    /// Active QCs referenced by `active_nodes`, `high_qc`, and `locked_qc`.
    pub active_qcs: Vec<QuorumCertificate>,
    /// Timeout certificate for `view - 1` if the active view followed a Pacemaker timeout.
    pub last_tc: Option<TimeoutCertificate>,
    /// Validator lists cached per epoch so crash recovery can still validate historical blocks
    /// even if the execution DB lags behind the WAL.
    #[serde(default)]
    pub epoch_validators: BTreeMap<u64, Vec<Address>>,
}

/// Persisted consensus header and [`QuorumCertificate`] for a certified execution block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockQcRecord {
    /// `HotStuff` node header bound to the execution block.
    pub header: HotStuffNodeHeader,
    /// Quorum certificate certifying `header`.
    pub qc: QuorumCertificate,
}

/// File-backed store persisting consensus WAL state, epoch certificates, and per-block QCs.
#[derive(Debug, Clone)]
pub struct HotStuffStore {
    dir: PathBuf,
}

impl HotStuffStore {
    /// Opens (creating if needed) a [`HotStuffStore`] rooted at `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, HotStuffError> {
        let dir = dir.into();
        reth_fs_util::create_dir_all(&dir)
            .map_err(|err| HotStuffError::Storage(err.to_string()))?;
        Ok(Self { dir })
    }

    /// Returns the root directory of this store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Atomically writes and fsyncs [`HotStuffPersistedState`] to `consensus_state.json`.
    pub fn save_state(&self, state: &HotStuffPersistedState) -> Result<(), HotStuffError> {
        let path = self.dir.join(CONSENSUS_STATE_FILE);
        reth_fs_util::atomic_write_file(&path, |file| serde_json::to_writer(file, state))
            .map_err(|err| HotStuffError::Storage(err.to_string()))?;
        sync_dir(&self.dir)
    }

    /// Loads [`HotStuffPersistedState`] from `consensus_state.json`, returning `Ok(None)` if
    /// no WAL file exists yet.
    pub fn load_state(&self) -> Result<Option<HotStuffPersistedState>, HotStuffError> {
        let path = self.dir.join(CONSENSUS_STATE_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let state: HotStuffPersistedState = reth_fs_util::read_json_file(&path)
            .map_err(|err| HotStuffError::Storage(err.to_string()))?;
        if state.version != HOTSTUFF_WAL_VERSION {
            return Err(HotStuffError::Storage(format!(
                "unsupported HotStuff WAL version {}, expected {HOTSTUFF_WAL_VERSION}",
                state.version
            )));
        }
        Ok(Some(state))
    }

    /// Atomically writes and fsyncs historical [`EpochChangeCert`]s to `epoch_certs.json`.
    pub fn save_epoch_certs(
        &self,
        certs: &BTreeMap<u64, EpochChangeCert>,
    ) -> Result<(), HotStuffError> {
        let bounded: BTreeMap<u64, EpochChangeCert> = if certs.len() > MAX_PERSISTED_EPOCH_CERTS {
            certs
                .iter()
                .rev()
                .take(MAX_PERSISTED_EPOCH_CERTS)
                .map(|(&k, v)| (k, v.clone()))
                .collect()
        } else {
            certs.clone()
        };
        let path = self.dir.join(EPOCH_CERTS_FILE);
        reth_fs_util::atomic_write_file(&path, |file| serde_json::to_writer(file, &bounded))
            .map_err(|err| HotStuffError::Storage(err.to_string()))?;
        sync_dir(&self.dir)
    }

    /// Loads historical [`EpochChangeCert`]s from `epoch_certs.json`.
    pub fn load_epoch_certs(&self) -> Result<BTreeMap<u64, EpochChangeCert>, HotStuffError> {
        let path = self.dir.join(EPOCH_CERTS_FILE);
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        reth_fs_util::read_json_file(&path).map_err(|err| HotStuffError::Storage(err.to_string()))
    }

    /// Appends a certified [`BlockQcRecord`] to the per-epoch JSONL file and flushes it to disk.
    pub fn append_block_qc(&self, record: &BlockQcRecord) -> Result<(), HotStuffError> {
        let path = self.epoch_qc_path(record.header.epoch);
        let existed = path.exists();
        let line =
            serde_json::to_string(record).map_err(|err| HotStuffError::Storage(err.to_string()))?;
        let payload = format!("{line}\n");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| HotStuffError::Storage(FsPathError::open(err, &path).to_string()))?;
        file.write_all(payload.as_bytes())
            .map_err(|err| HotStuffError::Storage(FsPathError::write(err, &path).to_string()))?;
        file.sync_data()
            .map_err(|err| HotStuffError::Storage(FsPathError::fsync(err, &path).to_string()))?;
        if !existed {
            sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// Loads all persisted [`BlockQcRecord`]s for `epoch`, keyed by `exec_block_number`.
    ///
    /// If multiple records exist for the same block height, keeps the one with the highest view.
    /// A truncated trailing line (left behind by an interrupted append during power loss) is
    /// truncated cleanly on disk while preserving earlier valid records.
    pub fn load_epoch_block_qcs(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<u64, BlockQcRecord>, HotStuffError> {
        let path = self.epoch_qc_path(epoch);
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let content = reth_fs_util::read_to_string(&path)
            .map_err(|err| HotStuffError::Storage(err.to_string()))?;
        let mut map: BTreeMap<u64, BlockQcRecord> = BTreeMap::new();
        let mut valid_len = 0usize;
        for (idx, raw_line) in content.split_inclusive('\n').enumerate() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                valid_len += raw_line.len();
                continue;
            }
            match serde_json::from_str::<BlockQcRecord>(trimmed) {
                Ok(record) => {
                    valid_len += raw_line.len();
                    let num = record.header.exec_block_number;
                    let replace =
                        map.get(&num).is_none_or(|existing| record.qc.view > existing.qc.view);
                    if replace {
                        map.insert(num, record);
                    }
                }
                Err(err) if valid_len + raw_line.len() == content.len() => {
                    warn!(
                        target: "consensus::hotstuff",
                        path = %path.display(),
                        line = idx + 1,
                        truncate_len = valid_len,
                        %err,
                        "Truncating incomplete trailing QC record left by crash"
                    );
                    let file = OpenOptions::new().write(true).open(&path).map_err(|open_err| {
                        HotStuffError::Storage(FsPathError::open(open_err, &path).to_string())
                    })?;
                    file.set_len(valid_len as u64).map_err(|trunc_err| {
                        HotStuffError::Storage(FsPathError::write(trunc_err, &path).to_string())
                    })?;
                    file.sync_data().map_err(|sync_err| {
                        HotStuffError::Storage(FsPathError::fsync(sync_err, &path).to_string())
                    })?;
                    break;
                }
                Err(err) => {
                    return Err(HotStuffError::Storage(format!(
                        "corrupt QC record at {} line {}: {err}",
                        path.display(),
                        idx + 1
                    )));
                }
            }
        }
        Ok(map)
    }

    /// Looks up the persisted [`BlockQcRecord`] for `(epoch, block_number)`.
    pub fn load_block_qc(
        &self,
        epoch: u64,
        block_number: u64,
    ) -> Result<Option<BlockQcRecord>, HotStuffError> {
        Ok(self.load_epoch_block_qcs(epoch)?.remove(&block_number))
    }

    fn epoch_qc_path(&self, epoch: u64) -> PathBuf {
        self.dir.join(format!("qcs_epoch_{epoch}.jsonl"))
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), HotStuffError> {
    let file = std::fs::File::open(dir)
        .map_err(|err| HotStuffError::Storage(FsPathError::open(err, dir).to_string()))?;
    file.sync_all().map_err(|err| HotStuffError::Storage(FsPathError::fsync(err, dir).to_string()))
}

#[cfg(not(unix))]
const fn sync_dir(_dir: &Path) -> Result<(), HotStuffError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(epoch: u64, view: u64, block_number: u64, byte: u8) -> BlockQcRecord {
        let header = HotStuffNodeHeader {
            epoch,
            view,
            parent_node_hash: B256::repeat_byte(byte.saturating_sub(1)),
            justify_qc_hash: B256::repeat_byte(byte.saturating_sub(1)),
            exec_block_hash: B256::repeat_byte(byte),
            exec_block_number: block_number,
            proposer: Address::with_last_byte(byte),
            is_nil: false,
        };
        let qc = QuorumCertificate {
            epoch,
            view,
            node_hash: header.node_hash(),
            exec_block_hash: header.exec_block_hash,
            exec_block_number: block_number,
            signatures: Vec::new(),
        };
        BlockQcRecord { header, qc }
    }

    #[test]
    fn wal_save_load_and_version_check() {
        let tmp = tempfile::tempdir().unwrap();
        let store = HotStuffStore::open(tmp.path()).unwrap();
        assert!(store.load_state().unwrap().is_none());

        let genesis_qc = QuorumCertificate::epoch_genesis(0, B256::repeat_byte(0x01), 0);
        let state = HotStuffPersistedState {
            version: HOTSTUFF_WAL_VERSION,
            epoch: 2,
            view: 9,
            last_voted_view: 8,
            last_proposed_view: 7,
            last_timeout_view: 6,
            high_qc: genesis_qc.clone(),
            locked_qc: genesis_qc,
            committed_node_hash: B256::repeat_byte(0x02),
            committed_view: 5,
            committed_exec_hash: B256::repeat_byte(0x03),
            committed_exec_number: 5,
            active_nodes: vec![HotStuffNodeHeader::epoch_genesis(2, B256::repeat_byte(0x01), 0)],
            active_qcs: Vec::new(),
            last_tc: None,
            epoch_validators: BTreeMap::from([(2, vec![Address::with_last_byte(1)])]),
        };

        store.save_state(&state).unwrap();
        let reloaded = store.load_state().unwrap().unwrap();
        assert_eq!(reloaded, state);

        let mut bad_version = state;
        bad_version.version = HOTSTUFF_WAL_VERSION + 1;
        store.save_state(&bad_version).unwrap();
        let err = store.load_state().unwrap_err();
        assert!(matches!(err, HotStuffError::Storage(msg) if msg.contains("unsupported")));
    }

    #[test]
    fn epoch_certs_and_per_epoch_block_qcs_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = HotStuffStore::open(tmp.path()).unwrap();

        let h1 = HotStuffNodeHeader {
            epoch: 0,
            view: 1,
            parent_node_hash: B256::ZERO,
            justify_qc_hash: B256::ZERO,
            exec_block_hash: B256::repeat_byte(0x11),
            exec_block_number: 1,
            proposer: Address::with_last_byte(1),
            is_nil: false,
        };
        let qc1 = QuorumCertificate {
            epoch: 0,
            view: 1,
            node_hash: h1.node_hash(),
            exec_block_hash: h1.exec_block_hash,
            exec_block_number: 1,
            signatures: Vec::new(),
        };
        store.append_block_qc(&BlockQcRecord { header: h1.clone(), qc: qc1.clone() }).unwrap();

        let h2 = HotStuffNodeHeader {
            epoch: 1,
            view: 1,
            parent_node_hash: B256::repeat_byte(0x20),
            justify_qc_hash: B256::repeat_byte(0x21),
            exec_block_hash: B256::repeat_byte(0x22),
            exec_block_number: 4,
            proposer: Address::with_last_byte(2),
            is_nil: false,
        };
        let qc2 = QuorumCertificate {
            epoch: 1,
            view: 1,
            node_hash: h2.node_hash(),
            exec_block_hash: h2.exec_block_hash,
            exec_block_number: 4,
            signatures: Vec::new(),
        };
        store.append_block_qc(&BlockQcRecord { header: h2, qc: qc2.clone() }).unwrap();

        let cert = EpochChangeCert {
            from_epoch: 0,
            boundary_block_hash: B256::repeat_byte(0x33),
            boundary_block_number: 3,
            node0: h1.clone(),
            node1: h1.clone(),
            node2: h1,
            commit_qc: qc1.clone(),
        };
        let mut certs = BTreeMap::new();
        certs.insert(0, cert.clone());
        store.save_epoch_certs(&certs).unwrap();

        let reopened = HotStuffStore::open(tmp.path()).unwrap();
        assert_eq!(reopened.load_epoch_certs().unwrap().get(&0), Some(&cert));
        assert_eq!(reopened.load_block_qc(0, 1).unwrap().unwrap().qc, qc1);
        assert_eq!(reopened.load_block_qc(1, 4).unwrap().unwrap().qc, qc2);
        assert!(reopened.load_block_qc(1, 99).unwrap().is_none());
    }

    #[test]
    fn partial_trailing_qc_record_is_truncated_and_recovered() {
        let tmp = tempfile::tempdir().unwrap();
        let store = HotStuffStore::open(tmp.path()).unwrap();

        let r1 = sample_record(0, 1, 1, 0x11);
        let r2 = sample_record(0, 2, 2, 0x22);
        let r3 = sample_record(0, 3, 3, 0x33);
        store.append_block_qc(&r1).unwrap();
        store.append_block_qc(&r2).unwrap();

        let path = tmp.path().join("qcs_epoch_0.jsonl");
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(br#"{"header":{"epoch":0"#).unwrap();
        drop(f);

        let reopened = HotStuffStore::open(tmp.path()).unwrap();
        let loaded = reopened.load_epoch_block_qcs(0).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get(&1).unwrap(), &r1);
        assert_eq!(loaded.get(&2).unwrap(), &r2);

        // Appending after truncation must succeed cleanly and preserve all 3 records.
        reopened.append_block_qc(&r3).unwrap();
        let loaded_after = reopened.load_epoch_block_qcs(0).unwrap();
        assert_eq!(loaded_after.len(), 3);
        assert_eq!(loaded_after.get(&3).unwrap(), &r3);
    }

    #[test]
    fn corrupt_middle_qc_record_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let store = HotStuffStore::open(tmp.path()).unwrap();

        let r1 = sample_record(0, 1, 1, 0x11);
        let r2 = sample_record(0, 2, 2, 0x22);
        let line1 = serde_json::to_string(&r1).unwrap();
        let line2 = serde_json::to_string(&r2).unwrap();

        let path = tmp.path().join("qcs_epoch_0.jsonl");
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&path).unwrap();
        writeln!(f, "{line1}").unwrap();
        writeln!(f, "{{corrupt-middle-line").unwrap();
        writeln!(f, "{line2}").unwrap();
        drop(f);

        let err = store.load_epoch_block_qcs(0).unwrap_err();
        assert!(matches!(err, HotStuffError::Storage(msg) if msg.contains("corrupt QC record")));
    }
}
