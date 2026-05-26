//! BDK-backed wallet chain state.
//!
//! Owns the in-memory `LocalChain` + `IndexedTxGraph` driven by `bdk_bitcoind_rpc::Emitter`,
//! and reconstructs them from the persisted `ChangeSet`s in [`WalletStore`].
//!
//! The wallet tracks two flavors of script pubkeys:
//!
//! * HD descriptors (P2WPKH / P2TR external+internal) — wildcard, indexed by
//!   [`KeychainTxOutIndex`].
//! * Fixed scripts for swap multisigs, contract redeem scripts, and fidelity bonds —
//!   non-wildcard, indexed by [`SpkTxOutIndex`].
//!
//! These are combined behind a single [`CoinswapIndexer`] that implements
//! [`bdk_chain::Indexer`], so [`IndexedTxGraph::apply_block_relevant`] can be used as-is.
//!
//! The `SpkTxOutIndex` state is *not* persisted — it is fully reconstructed from the
//! authoritative coinswap stores (`incoming_swapcoins`, `outgoing_swapcoins`,
//! `fidelity_bond`) at load time.

use std::str::FromStr;

use bdk_chain::{
    indexed_tx_graph::IndexedTxGraph,
    indexer::{keychain_txout::KeychainTxOutIndex, spk_txout::SpkTxOutIndex},
    local_chain::LocalChain,
    miniscript::{Descriptor, DescriptorPublicKey},
    ConfirmationBlockTime, Indexer,
};
use bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
    Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
};
use serde::{Deserialize, Serialize};

use crate::wallet::{
    api::KeychainKind,
    error::WalletError,
    storage::AddressType,
};

/// Number of lookahead spks per HD keychain. Higher = more memory but safer against
/// missed-payment situations when the wallet receives bursts of payments past the
/// last revealed index.
pub(crate) const KEYCHAIN_LOOKAHEAD: u32 = 100;

/// Identifies one of the four HD seed keychains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) struct SeedKeychain {
    pub address_type: AddressType,
    pub kind: KeychainKind,
}

impl SeedKeychain {
    pub(crate) fn all() -> [Self; 4] {
        [
            Self {
                address_type: AddressType::P2WPKH,
                kind: KeychainKind::External,
            },
            Self {
                address_type: AddressType::P2WPKH,
                kind: KeychainKind::Internal,
            },
            Self {
                address_type: AddressType::P2TR,
                kind: KeychainKind::External,
            },
            Self {
                address_type: AddressType::P2TR,
                kind: KeychainKind::Internal,
            },
        ]
    }

    /// Account-level hardened derivation path (e.g. `m/84'/1'/0'`).
    pub(crate) fn account_path(self) -> &'static str {
        match self.address_type {
            AddressType::P2WPKH => "m/84'/1'/0'",
            AddressType::P2TR => "m/86'/1'/0'",
        }
    }

    /// Branch index (0 = external, 1 = internal).
    pub(crate) fn branch_index(self) -> u32 {
        match self.kind {
            KeychainKind::External => 0,
            KeychainKind::Internal => 1,
        }
    }

    /// Build the wildcard public descriptor for this keychain from the wallet master xpriv.
    pub(crate) fn descriptor(
        self,
        master_key: &Xpriv,
    ) -> Result<Descriptor<DescriptorPublicKey>, WalletError> {
        let secp = Secp256k1::signing_only();
        let path = DerivationPath::from_str(self.account_path())
            .map_err(|e| WalletError::General(format!("invalid account path: {e}")))?;
        let account_xpriv = master_key
            .derive_priv(&secp, &path)
            .map_err(|e| WalletError::General(format!("derive account xpriv: {e}")))?;
        let account_xpub = Xpub::from_priv(&secp, &account_xpriv);
        let branch = self.branch_index();
        let body = match self.address_type {
            AddressType::P2WPKH => format!("wpkh({account_xpub}/{branch}/*)"),
            AddressType::P2TR => format!("tr({account_xpub}/{branch}/*)"),
        };
        body.parse::<Descriptor<DescriptorPublicKey>>()
            .map_err(|e| WalletError::General(format!("parse descriptor `{body}`: {e}")))
    }
}

/// Identifies a fixed (non-derivable) script tracked alongside the HD keychains.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum WatchKey {
    /// 2-of-2 multisig redeem script (P2WSH) for a swapcoin, keyed by the swap contract txid.
    Swap(Txid),
    /// Contract redeem script (HTLC) for a swapcoin, keyed by the contract txid.
    Contract(Txid),
    /// Fidelity bond timelock script, keyed by its index in `WalletStore::fidelity_bond`.
    Fidelity(u32),
    /// A previously-revealed seed scriptpubkey that has been "swept" (recovered) into the
    /// regular wallet — kept as a watch key so the txout can still be matched after the
    /// originating HD keychain has moved past it.
    Sweep(ScriptBuf),
}

/// Persisted aggregate of all BDK ChangeSets the wallet cares about.
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct BdkChangeSet {
    pub local_chain: bdk_chain::local_chain::ChangeSet,
    pub indexed_tx_graph: bdk_chain::indexed_tx_graph::ChangeSet<
        ConfirmationBlockTime,
        bdk_chain::keychain_txout::ChangeSet,
    >,
}

/// Composite indexer over the HD seed keychains and fixed watch scripts.
///
/// `Indexer::ChangeSet` only carries the [`KeychainTxOutIndex`] change set — the
/// [`SpkTxOutIndex`] is reconstructed from authoritative wallet state at load time
/// and has nothing to persist.
#[derive(Debug)]
pub(crate) struct CoinswapIndexer {
    pub(crate) seed: KeychainTxOutIndex<SeedKeychain>,
    pub(crate) watch: SpkTxOutIndex<WatchKey>,
}

impl CoinswapIndexer {
    pub(crate) fn new() -> Self {
        Self {
            seed: KeychainTxOutIndex::new(KEYCHAIN_LOOKAHEAD, true),
            watch: SpkTxOutIndex::default(),
        }
    }
}

impl Default for CoinswapIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl Indexer for CoinswapIndexer {
    type ChangeSet = bdk_chain::keychain_txout::ChangeSet;

    fn index_txout(&mut self, outpoint: OutPoint, txout: &TxOut) -> Self::ChangeSet {
        let cs = self.seed.index_txout(outpoint, txout);
        self.watch.index_txout(outpoint, txout);
        cs
    }

    fn index_tx(&mut self, tx: &Transaction) -> Self::ChangeSet {
        let cs = self.seed.index_tx(tx);
        self.watch.index_tx(tx);
        cs
    }

    fn apply_changeset(&mut self, changeset: Self::ChangeSet) {
        self.seed.apply_changeset(changeset);
    }

    fn initial_changeset(&self) -> Self::ChangeSet {
        self.seed.initial_changeset()
    }

    fn is_tx_relevant(&self, tx: &Transaction) -> bool {
        self.seed.is_tx_relevant(tx) || self.watch.is_tx_relevant(tx)
    }
}

/// In-memory BDK state held alongside [`WalletStore`].
///
/// Reconstructed from the persisted [`BdkChangeSet`] and from the authoritative
/// swap/fidelity stores on load.
pub(crate) struct BdkChain {
    pub(crate) chain: LocalChain,
    pub(crate) graph: IndexedTxGraph<ConfirmationBlockTime, CoinswapIndexer>,
}

impl BdkChain {
    /// Reconstruct a fresh `BdkChain` from a persisted change set.
    ///
    /// `seed_descriptors` is the iterator of `(SeedKeychain, Descriptor)` pairs to register
    /// with the [`KeychainTxOutIndex`]. `watch_spks` is the iterator of `(WatchKey, ScriptBuf)`
    /// pairs to register with the [`SpkTxOutIndex`].
    ///
    /// If the persisted chain change set is empty, a new chain is initialized from the
    /// given network's genesis hash.
    pub(crate) fn load(
        network: Network,
        persisted: &BdkChangeSet,
        seed_descriptors: impl IntoIterator<Item = (SeedKeychain, Descriptor<DescriptorPublicKey>)>,
        watch_spks: impl IntoIterator<Item = (WatchKey, ScriptBuf)>,
    ) -> Result<Self, WalletError> {
        let chain = if persisted.local_chain.blocks.is_empty() {
            let genesis_hash = bitcoin::constants::genesis_block(network).block_hash();
            let (chain, _genesis_cs) = LocalChain::from_genesis(genesis_hash);
            chain
        } else {
            LocalChain::from_changeset(persisted.local_chain.clone())
                .map_err(|e| WalletError::General(format!("load LocalChain: {e}")))?
        };

        let mut indexer = CoinswapIndexer::new();
        for (kc, desc) in seed_descriptors {
            indexer
                .seed
                .insert_descriptor(kc, desc)
                .map_err(|e| WalletError::General(format!("insert seed descriptor: {e:?}")))?;
        }
        for (k, spk) in watch_spks {
            indexer.watch.insert_spk(k, spk);
        }

        let mut graph =
            IndexedTxGraph::<ConfirmationBlockTime, CoinswapIndexer>::new(indexer);
        graph.apply_changeset(persisted.indexed_tx_graph.clone());

        Ok(Self { chain, graph })
    }

    /// Return the tip block id of the local chain.
    pub(crate) fn tip(&self) -> bdk_chain::BlockId {
        self.chain.tip().block_id()
    }

    /// Reveal HD scripts up to (and including) `target` for the given keychain.
    pub(crate) fn reveal_to(
        &mut self,
        keychain: SeedKeychain,
        target: u32,
    ) -> bdk_chain::keychain_txout::ChangeSet {
        self.graph
            .index
            .seed
            .reveal_to_target(keychain, target)
            .map(|(_, cs)| cs)
            .unwrap_or_default()
    }

    /// Reveal the next unused HD script for the given keychain. Returns `(index, script)`.
    pub(crate) fn reveal_next(
        &mut self,
        keychain: SeedKeychain,
    ) -> Option<(u32, ScriptBuf, bdk_chain::keychain_txout::ChangeSet)> {
        self.graph
            .index
            .seed
            .reveal_next_spk(keychain)
            .map(|((idx, spk), cs)| (idx, spk, cs))
    }

    /// Script for the given (keychain, index) pair, deriving lazily within the lookahead window.
    pub(crate) fn spk_at(&self, keychain: SeedKeychain, index: u32) -> Option<ScriptBuf> {
        self.graph.index.seed.spk_at_index(keychain, index)
    }

    /// Reverse lookup: given a spk, return the (keychain, index) that derived it, if any.
    pub(crate) fn keychain_of_spk(&self, spk: &bitcoin::Script) -> Option<(SeedKeychain, u32)> {
        self.graph
            .index
            .seed
            .index_of_spk(spk)
            .map(|(kc, idx)| (*kc, *idx))
    }

    /// Register a new fixed watch script. Idempotent: re-inserting the same key replaces nothing.
    pub(crate) fn watch(&mut self, key: WatchKey, spk: ScriptBuf) {
        self.graph.index.watch.insert_spk(key, spk);
    }
}
