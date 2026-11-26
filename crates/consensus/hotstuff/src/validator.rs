//! Validator set, round-robin leader schedule, and on-chain dynamic epoch registry.

use alloy_primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Encodable;
use parking_lot::RwLock;
use reth_storage_api::{StateProvider, StateProviderFactory};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use crate::{error::HotStuffError, types::MAX_VALIDATORS};

/// Default predeployed system contract address storing the active validator array.
///
/// Storage layout matches Solidity `address[] public validators` at slot `0`, with an optional
/// `address public admin` at slot `1`.
pub const DEFAULT_VALIDATOR_REGISTRY_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000001000");

/// Returns the 4-byte Solidity function selector for `setValidators(address[])`.
pub fn set_validators_selector() -> [u8; 4] {
    let hash = keccak256(b"setValidators(address[])");
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash.0[..4]);
    selector
}

/// Maximum number of historical epochs cached in [`EpochManager`].
const MAX_CACHED_EPOCHS: usize = 128;

/// Ordered validator set for a single `HotStuff` consensus epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    epoch: u64,
    validators: Vec<Address>,
    members: HashSet<Address>,
    hash: B256,
}

impl ValidatorSet {
    /// Creates a new validated [`ValidatorSet`] for `epoch`.
    ///
    /// Rejects empty sets, duplicates, zero addresses, and sets exceeding [`MAX_VALIDATORS`].
    pub fn new(epoch: u64, validators: Vec<Address>) -> Result<Self, HotStuffError> {
        if validators.is_empty() {
            return Err(HotStuffError::InvalidValidatorSet(
                "validator set must not be empty".to_string(),
            ));
        }
        if validators.len() > MAX_VALIDATORS {
            return Err(HotStuffError::InvalidValidatorSet(format!(
                "validator set length {} exceeds max {MAX_VALIDATORS}",
                validators.len()
            )));
        }

        let mut members = HashSet::with_capacity(validators.len());
        for addr in &validators {
            if addr.is_zero() {
                return Err(HotStuffError::InvalidValidatorSet(
                    "validator address must not be zero".to_string(),
                ));
            }
            if !members.insert(*addr) {
                return Err(HotStuffError::InvalidValidatorSet(format!(
                    "duplicate validator address {addr}"
                )));
            }
        }

        let hash = compute_validator_set_hash(epoch, &validators);
        Ok(Self { epoch, validators, members, hash })
    }

    /// Returns the epoch index of this validator set.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the ordered list of validators.
    pub fn validators(&self) -> &[Address] {
        &self.validators
    }

    /// Returns the total number of validators `n`.
    pub const fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns `true` if the validator set is empty (always `false` for valid instances).
    pub const fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Returns the BFT fault tolerance `f = (n - 1) / 3`.
    pub const fn fault_tolerance(&self) -> usize {
        self.validators.len().saturating_sub(1) / 3
    }

    /// Returns the `HotStuff` quorum threshold `2f + 1` (`(2 * n) / 3 + 1`).
    ///
    /// For `n = 1` returns `1`; for `n = 4` returns `3`; for `n = 7` returns `5`.
    pub const fn quorum_size(&self) -> usize {
        (2 * self.validators.len()) / 3 + 1
    }

    /// Returns `true` if `addr` is an active validator in this epoch.
    pub fn contains(&self, addr: &Address) -> bool {
        self.members.contains(addr)
    }

    /// Returns the deterministic round-robin leader for `view`.
    pub fn leader_for_view(&self, view: u64) -> Address {
        let idx = (view as usize) % self.validators.len();
        self.validators[idx]
    }

    /// Returns `keccak256(epoch || rlp(validators))`.
    pub const fn hash(&self) -> B256 {
        self.hash
    }

    /// Returns the first 4 bytes of [`Self::hash`], embedded in Ethereum `header.extra_data`.
    pub fn hash_prefix(&self) -> [u8; 4] {
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&self.hash.0[..4]);
        prefix
    }
}

fn compute_validator_set_hash(epoch: u64, validators: &[Address]) -> B256 {
    let mut buf = Vec::with_capacity(8 + validators.len() * 21);
    buf.extend_from_slice(&epoch.to_be_bytes());
    validators.to_vec().encode(&mut buf);
    keccak256(&buf)
}

/// Computes the storage slot base `keccak256(uint256(0))` for Solidity array slot `0`.
pub fn validator_array_base_slot() -> U256 {
    let slot_zero = B256::ZERO;
    U256::from_be_bytes(keccak256(slot_zero.as_slice()).0)
}

/// Encodes initial storage slots for the `ValidatorRegistry` contract.
///
/// - Slot `0`: `validators.len()`
/// - Slot `keccak256(0) + i`: `validators[i]` (right-aligned 20 bytes)
/// - Slot `1` (when `admin` is `Some`): `admin` (right-aligned 20 bytes)
pub fn encode_validator_registry_storage(
    validators: &[Address],
    admin: Option<Address>,
) -> BTreeMap<B256, B256> {
    let mut storage = BTreeMap::new();
    storage.insert(B256::ZERO, B256::from(U256::from(validators.len())));

    let base = validator_array_base_slot();
    for (idx, addr) in validators.iter().enumerate() {
        let slot = B256::from(base + U256::from(idx));
        storage.insert(slot, addr.into_word());
    }

    if let Some(admin_addr) = admin {
        storage.insert(B256::from(U256::from(1u64)), admin_addr.into_word());
    }

    storage
}

/// Encodes ABI calldata for `setValidators(address[])`.
pub fn encode_set_validators_calldata(validators: &[Address]) -> Bytes {
    let mut out = Vec::with_capacity(4 + 64 + validators.len() * 32);
    out.extend_from_slice(&set_validators_selector());
    // Offset to dynamic array payload: 32 bytes.
    out.extend_from_slice(&B256::from(U256::from(32u64)).0);
    // Array length.
    out.extend_from_slice(&B256::from(U256::from(validators.len())).0);
    // Array elements (right-aligned 20-byte addresses).
    for addr in validators {
        out.extend_from_slice(addr.into_word().as_slice());
    }
    Bytes::from(out)
}

/// Returns minimal deployed EVM runtime bytecode implementing `setValidators(address[])`.
///
/// Storage layout:
/// - Slot `0`: `uint256 length`
/// - Slot `keccak256(0) + i`: `address validators[i]`
/// - Slot `1`: `address admin` (if non-zero, requires `CALLER == admin`; if zero, unrestricted)
///
/// Reverts if calldata is malformed, length is `0` or `> MAX_VALIDATORS`, or `admin != 0` and
/// `CALLER != admin`.
pub fn validator_registry_bytecode() -> Bytes {
    // Small single-use assembler tracking byte offsets so jump targets cannot drift.
    let mut asm = EvmAssembler::default();

    // 1. Check calldata size >= 68 bytes (selector + offset + length).
    asm.push_u8(68);
    asm.op(0x36); // CALLDATASIZE
    asm.op(0x10); // LT (calldatasize < 68)
    asm.jumpi("revert");

    // 2. Check selector == set_validators_selector().
    asm.push_u8(0);
    asm.op(0x35); // CALLDATALOAD
    asm.push_u8(224);
    asm.op(0x1c); // SHR -> 4-byte selector
    asm.push_bytes(&set_validators_selector());
    asm.op(0x14); // EQ
    asm.op(0x15); // ISZERO
    asm.jumpi("revert");

    // 3. Optional admin check: if SLOAD(1) != 0 && SLOAD(1) != CALLER -> revert.
    asm.push_u8(1);
    asm.op(0x54); // SLOAD(1)
    asm.op(0x80); // DUP1
    asm.op(0x15); // ISZERO (admin == 0)
    asm.jumpi("admin_ok");
    asm.op(0x33); // CALLER
    asm.op(0x14); // EQ (admin == caller)
    asm.jumpi("admin_done");
    asm.jump("revert");

    asm.label("admin_ok");
    asm.op(0x50); // POP unused 0 admin
    asm.label("admin_done");

    // 4. Load array offset = CALLDATALOAD(4), require offset == 32 for canonical ABI.
    asm.push_u8(4);
    asm.op(0x35); // CALLDATALOAD(4)
    asm.push_u8(32);
    asm.op(0x14); // EQ
    asm.op(0x15); // ISZERO
    asm.jumpi("revert");

    // 5. Load length = CALLDATALOAD(36), require 1 <= length <= MAX_VALIDATORS.
    asm.push_u8(36);
    asm.op(0x35); // CALLDATALOAD(36) -> [len]
    asm.op(0x80); // DUP1 -> [len, len]
    asm.op(0x15); // ISZERO
    asm.jumpi("revert");
    asm.op(0x80); // DUP1 -> [len, len]
    asm.push_u16(MAX_VALIDATORS as u16);
    asm.op(0x10); // LT (MAX_VALIDATORS < len) -> wait: LT pops a, b and pushes a < b (top <
                  // second). Stack before push: [len, len]; after push MAX: [MAX, len, len]. LT
                  // checks MAX < len.
    asm.jumpi("revert");

    // 6. Verify CALLDATASIZE >= 68 + len * 32.
    asm.op(0x80); // DUP1 -> [len, len]
    asm.push_u8(32);
    asm.op(0x02); // MUL -> [len*32, len]
    asm.push_u8(68);
    asm.op(0x01); // ADD -> [68 + len*32, len]
    asm.op(0x36); // CALLDATASIZE -> [calldatasize, 68 + len*32, len]
    asm.op(0x10); // LT (calldatasize < required) -> [flag, len]
    asm.jumpi("revert");

    // 7. Store length at slot 0.
    asm.op(0x80); // DUP1 -> [len, len]
    asm.push_u8(0);
    asm.op(0x55); // SSTORE(0, len) -> [len]

    // 8. Compute base = keccak256(0) in memory[0..32] and loop i = 0..len.
    asm.push_u8(0);
    asm.push_u8(0);
    asm.op(0x52); // MSTORE(0, 0)
    asm.push_u8(32);
    asm.push_u8(0);
    asm.op(0x20); // KECCAK256(0, 32) -> [base, len]
    asm.push_u8(0); // i = 0 -> [i, base, len]

    asm.label("loop");
    // Stack: [i, base, len]
    asm.op(0x82); // DUP3 (len) -> [len, i, base, len]
    asm.op(0x81); // DUP2 (i) -> [i, len, i, base, len]
    asm.op(0x10); // LT (i < len)
    asm.op(0x15); // ISZERO (i >= len)
    asm.jumpi("done");

    // Load calldata[68 + i*32] and mask to 20-byte address.
    asm.op(0x80); // DUP1 (i) -> [i, i, base, len]
    asm.push_u8(32);
    asm.op(0x02); // MUL -> [i*32, i, base, len]
    asm.push_u8(68);
    asm.op(0x01); // ADD -> [68 + i*32, i, base, len]
    asm.op(0x35); // CALLDATALOAD -> [raw_word, i, base, len]
    asm.push_bytes(&[0xff; 20]); // 20-byte address mask
    asm.op(0x16); // AND -> [addr, i, base, len]

    // Compute storage slot = base + i.
    asm.op(0x82); // DUP3 (base) -> [base, addr, i, base, len]
    asm.op(0x82); // DUP3 (i) -> [i, base, addr, i, base, len]
    asm.op(0x01); // ADD -> [base+i, addr, i, base, len]
    asm.op(0x55); // SSTORE(base+i, addr) -> [i, base, len]

    // i = i + 1
    asm.push_u8(1);
    asm.op(0x01); // ADD -> [i+1, base, len]
    asm.jump("loop");

    asm.label("done");
    asm.op(0x50); // POP i
    asm.op(0x50); // POP base
    asm.op(0x50); // POP len
    asm.op(0x00); // STOP

    asm.label("revert");
    asm.push_u8(0);
    asm.push_u8(0);
    asm.op(0xfd); // REVERT(0, 0)

    Bytes::from(asm.finish())
}

#[derive(Default)]
struct EvmAssembler {
    code: Vec<u8>,
    labels: HashMap<&'static str, usize>,
    fixups: Vec<(usize, &'static str)>,
}

impl EvmAssembler {
    fn op(&mut self, opcode: u8) {
        self.code.push(opcode);
    }

    fn push_u8(&mut self, val: u8) {
        self.code.push(0x60); // PUSH1
        self.code.push(val);
    }

    fn push_u16(&mut self, val: u16) {
        self.code.push(0x61); // PUSH2
        self.code.extend_from_slice(&val.to_be_bytes());
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        assert!((1..=32).contains(&bytes.len()));
        self.code.push(0x60 + (bytes.len() as u8) - 1);
        self.code.extend_from_slice(bytes);
    }

    fn label(&mut self, name: &'static str) {
        self.labels.insert(name, self.code.len());
        self.code.push(0x5b); // JUMPDEST
    }

    fn jump(&mut self, target: &'static str) {
        self.emit_push2_placeholder(target);
        self.code.push(0x56); // JUMP
    }

    fn jumpi(&mut self, target: &'static str) {
        self.emit_push2_placeholder(target);
        self.code.push(0x57); // JUMPI
    }

    fn emit_push2_placeholder(&mut self, target: &'static str) {
        self.code.push(0x61); // PUSH2
        self.fixups.push((self.code.len(), target));
        self.code.extend_from_slice(&[0u8, 0u8]);
    }

    fn finish(mut self) -> Vec<u8> {
        for (offset, label) in self.fixups {
            let target = self.labels[label] as u16;
            self.code[offset..offset + 2].copy_from_slice(&target.to_be_bytes());
        }
        self.code
    }
}

/// Reads the epoch validator set from the on-chain `ValidatorRegistry` contract state.
///
/// If slot `0` is `0` (contract not deployed or uninitialized), falls back to `fallback`
/// validators so genesis/static setups work without deploying a contract.
pub fn read_validator_set_from_state(
    provider: &dyn StateProvider,
    registry: Address,
    epoch: u64,
    fallback: &[Address],
) -> Result<ValidatorSet, HotStuffError> {
    let raw_len = provider
        .storage(registry, B256::ZERO)
        .map_err(|err| HotStuffError::StateProvider(err.to_string()))?;

    let Some(len_val) = raw_len.filter(|v| !v.is_zero()) else {
        return ValidatorSet::new(epoch, fallback.to_vec());
    };

    let len = usize::try_from(len_val).map_err(|_| {
        HotStuffError::InvalidValidatorSet("on-chain validator count overflows usize".to_string())
    })?;
    if len > MAX_VALIDATORS {
        return Err(HotStuffError::InvalidValidatorSet(format!(
            "on-chain validator count {len} exceeds max {MAX_VALIDATORS}"
        )));
    }

    let base = validator_array_base_slot();
    let mut validators = Vec::with_capacity(len);
    for idx in 0..len {
        let slot = B256::from(base + U256::from(idx));
        let word = provider
            .storage(registry, slot)
            .map_err(|err| HotStuffError::StateProvider(err.to_string()))?
            .unwrap_or(U256::ZERO);
        let word_bytes = B256::from(word);
        let addr = Address::from_word(word_bytes);
        validators.push(addr);
    }

    ValidatorSet::new(epoch, validators)
}

#[derive(Debug)]
struct EpochManagerInner {
    epoch_length: u64,
    registry: Address,
    fallback_validators: Vec<Address>,
    epochs: BTreeMap<u64, Arc<ValidatorSet>>,
}

/// Thread-safe manager tracking epoch boundaries and cached per-epoch validator sets.
#[derive(Debug, Clone)]
pub struct EpochManager {
    inner: Arc<RwLock<EpochManagerInner>>,
}

impl EpochManager {
    /// Creates a new [`EpochManager`] initialized with epoch 0's validator set.
    pub fn new(
        epoch_length: u64,
        registry: Address,
        genesis_validators: Vec<Address>,
    ) -> Result<Self, HotStuffError> {
        if epoch_length == 0 {
            return Err(HotStuffError::InvalidValidatorSet(
                "epoch_length must be at least 1".to_string(),
            ));
        }
        let vs0 = Arc::new(ValidatorSet::new(0, genesis_validators.clone())?);
        let mut epochs = BTreeMap::new();
        epochs.insert(0, vs0);

        Ok(Self {
            inner: Arc::new(RwLock::new(EpochManagerInner {
                epoch_length,
                registry,
                fallback_validators: genesis_validators,
                epochs,
            })),
        })
    }

    /// Returns the configured number of execution blocks per epoch.
    pub fn epoch_length(&self) -> u64 {
        self.inner.read().epoch_length
    }

    /// Returns the on-chain `ValidatorRegistry` contract address.
    pub fn registry(&self) -> Address {
        self.inner.read().registry
    }

    /// Maps an Ethereum execution block number `h` to its `HotStuff` consensus epoch.
    ///
    /// Genesis (`h == 0`) maps to epoch `0`; blocks `1..=epoch_length` belong to epoch `0`,
    /// `epoch_length + 1..=2 * epoch_length` to epoch `1`, and so on.
    pub fn epoch_for_block(&self, block_number: u64) -> u64 {
        let len = self.inner.read().epoch_length;
        block_number.saturating_sub(1) / len
    }

    /// Returns the final execution block number belonging to `epoch`.
    pub fn epoch_boundary_block(&self, epoch: u64) -> u64 {
        let len = self.inner.read().epoch_length;
        epoch.saturating_add(1).saturating_mul(len)
    }

    /// Returns the cached [`ValidatorSet`] for `epoch`, if available.
    pub fn validator_set(&self, epoch: u64) -> Option<Arc<ValidatorSet>> {
        self.inner.read().epochs.get(&epoch).cloned()
    }

    /// Inserts or updates a [`ValidatorSet`] for its epoch, enforcing bounded cache retention.
    pub fn insert_epoch(&self, set: ValidatorSet) -> Arc<ValidatorSet> {
        let mut guard = self.inner.write();
        let epoch = set.epoch();
        let arc = Arc::new(set);
        guard.epochs.insert(epoch, Arc::clone(&arc));
        while guard.epochs.len() > MAX_CACHED_EPOCHS {
            let Some(&oldest) = guard.epochs.keys().next() else {
                break;
            };
            guard.epochs.remove(&oldest);
        }
        arc
    }

    /// Loads `target_epoch`'s validator set from the state at `state_block_hash`, caching it.
    pub fn load_epoch_from_provider<P: StateProviderFactory>(
        &self,
        provider: &P,
        target_epoch: u64,
        state_block_hash: B256,
    ) -> Result<Arc<ValidatorSet>, HotStuffError> {
        let (registry, fallback) = {
            let guard = self.inner.read();
            let prev = target_epoch
                .checked_sub(1)
                .and_then(|e| guard.epochs.get(&e))
                .map(|vs| vs.validators().to_vec())
                .unwrap_or_else(|| guard.fallback_validators.clone());
            (guard.registry, prev)
        };

        let state = provider
            .state_by_block_hash(state_block_hash)
            .map_err(|err| HotStuffError::StateProvider(err.to_string()))?;
        let loaded = read_validator_set_from_state(&*state, registry, target_epoch, &fallback)?;
        Ok(self.insert_epoch(loaded))
    }

    /// Returns a snapshot mapping every cached epoch to its ordered validator addresses.
    pub fn snapshot_validators(&self) -> BTreeMap<u64, Vec<Address>> {
        self.inner
            .read()
            .epochs
            .iter()
            .map(|(&epoch, vs)| (epoch, vs.validators().to_vec()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, SignableTransaction, TxLegacy};
    use alloy_primitives::{Signature, TxKind};
    use evm2::{
        bytecode::Bytecode as EvmBytecode,
        evm::{AccountInfo, CacheDB, EmptyDB},
    };
    use reth_chainspec::ChainSpecBuilder;
    use reth_ethereum_primitives::{Block, BlockBody, TransactionSigned};
    use reth_evm::execute::{BasicBlockExecutor, Executor};
    use reth_evm_ethereum::EthEvmConfig;
    use reth_primitives_traits::RecoveredBlock;

    #[test]
    fn validator_set_quorum_and_leaders() {
        let addrs: Vec<_> = (1u8..=4).map(Address::with_last_byte).collect();
        let vs = ValidatorSet::new(0, addrs.clone()).unwrap();
        assert_eq!(vs.quorum_size(), 3);
        assert_eq!(vs.fault_tolerance(), 1);
        assert_eq!(vs.leader_for_view(0), addrs[0]);
        assert_eq!(vs.leader_for_view(1), addrs[1]);
        assert_eq!(vs.leader_for_view(4), addrs[0]);

        let vs_single = ValidatorSet::new(0, vec![addrs[0]]).unwrap();
        assert_eq!(vs_single.quorum_size(), 1);
        assert_eq!(vs_single.fault_tolerance(), 0);
    }

    #[test]
    fn epoch_mapping_boundaries() {
        let addrs = vec![Address::with_last_byte(1)];
        let mgr = EpochManager::new(4, DEFAULT_VALIDATOR_REGISTRY_ADDRESS, addrs).unwrap();
        assert_eq!(mgr.epoch_for_block(0), 0);
        assert_eq!(mgr.epoch_for_block(1), 0);
        assert_eq!(mgr.epoch_for_block(4), 0);
        assert_eq!(mgr.epoch_for_block(5), 1);
        assert_eq!(mgr.epoch_for_block(8), 1);
        assert_eq!(mgr.epoch_boundary_block(0), 4);
        assert_eq!(mgr.epoch_boundary_block(1), 8);
    }

    #[test]
    fn validator_registry_evm_execution_updates_storage() {
        let initial = vec![
            Address::with_last_byte(0x11),
            Address::with_last_byte(0x22),
            Address::with_last_byte(0x33),
            Address::with_last_byte(0x44),
        ];
        let rotated = vec![
            Address::with_last_byte(0x11),
            Address::with_last_byte(0x22),
            Address::with_last_byte(0x33),
            Address::with_last_byte(0x55),
            Address::with_last_byte(0x66),
        ];
        let admin = Address::with_last_byte(0xaa);
        let non_admin = Address::with_last_byte(0xbb);

        let mut db = CacheDB::new(EmptyDB::default());
        let bytecode = validator_registry_bytecode();
        let mut storage = BTreeMap::new();
        for (k, v) in encode_validator_registry_storage(&initial, Some(admin)) {
            storage.insert(U256::from_be_bytes(k.0), U256::from_be_bytes(v.0));
        }

        db.insert_account_info(
            &DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
            AccountInfo::default().with_nonce(1).with_code(EvmBytecode::new_raw(bytecode)),
        );
        for (slot, val) in storage {
            db.insert_account_storage(&DEFAULT_VALIDATOR_REGISTRY_ADDRESS, &slot, &val);
        }
        db.insert_account_info(
            &admin,
            AccountInfo::default().with_balance(U256::from(10u128.pow(18))),
        );
        db.insert_account_info(
            &non_admin,
            AccountInfo::default().with_balance(U256::from(10u128.pow(18))),
        );

        let evm_config =
            EthEvmConfig::new(Arc::new(ChainSpecBuilder::mainnet().london_activated().build()));
        let block_header = Header {
            number: 1,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1),
            ..Default::default()
        };

        let calldata = encode_set_validators_calldata(&rotated);

        let unauth_tx = TransactionSigned::Legacy(
            TxLegacy {
                gas_limit: 500_000,
                gas_price: 1,
                to: TxKind::Call(DEFAULT_VALIDATOR_REGISTRY_ADDRESS),
                input: calldata.clone(),
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );
        let auth_tx = TransactionSigned::Legacy(
            TxLegacy {
                gas_limit: 500_000,
                gas_price: 1,
                to: TxKind::Call(DEFAULT_VALIDATOR_REGISTRY_ADDRESS),
                input: calldata,
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );

        let mut executor = BasicBlockExecutor::new(evm_config, db);
        let block = RecoveredBlock::new_unhashed(
            Block {
                header: block_header,
                body: BlockBody { transactions: vec![unauth_tx, auth_tx], ..Default::default() },
            },
            vec![non_admin, admin],
        );
        let output = executor.execute_one(&block).unwrap();
        assert!(!output.receipts[0].success, "non-admin call must revert");
        assert!(output.receipts[1].success, "admin call must succeed");

        let bundle = executor.into_state();
        assert_eq!(
            bundle.storage(&DEFAULT_VALIDATOR_REGISTRY_ADDRESS, U256::ZERO),
            Some(U256::from(5u64))
        );
        let base = validator_array_base_slot();
        for idx in [3usize, 4usize] {
            let stored = bundle
                .storage(&DEFAULT_VALIDATOR_REGISTRY_ADDRESS, base + U256::from(idx))
                .unwrap();
            assert_eq!(Address::from_word(B256::from(stored)), rotated[idx]);
        }
    }
}
