//! Bitcoin Core RPC connection and BDK-backed wallet sync.
//!
//! The wallet talks to Bitcoin Core as a *node* only — it does not load a Core wallet.
//! Block-by-block chain ingestion is driven by [`bdk_bitcoind_rpc::Emitter`], persisted
//! into the wallet store as BDK `ChangeSet`s.

use std::{convert::TryFrom, thread};

use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_chain::{
    keychain_txout::ChangeSet as KeychainChangeSet, local_chain::CannotConnectError, Merge,
};
use bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;

use crate::utill::HEART_BEAT_INTERVAL;

use super::{chain::SeedKeychain, error::WalletError, Wallet};

/// Configuration parameters for connecting to a Bitcoin node via RPC.
#[derive(Debug, Clone)]
pub struct RPCConfig {
    /// The bitcoin node url
    pub url: String,
    /// The bitcoin node authentication mechanism
    pub auth: Auth,
    /// Identifier used to scope the wallet's local files. Not used for routing RPC calls.
    pub wallet_name: String,
}

const RPC_HOSTPORT: &str = "localhost:18443";

impl Default for RPCConfig {
    fn default() -> Self {
        Self {
            url: RPC_HOSTPORT.to_string(),
            auth: Auth::UserPass("regtestrpcuser".to_string(), "regtestrpcpass".to_string()),
            wallet_name: "random-wallet-name".to_string(),
        }
    }
}

impl TryFrom<&RPCConfig> for Client {
    type Error = WalletError;
    fn try_from(config: &RPCConfig) -> Result<Self, WalletError> {
        // Talk to the node directly — no `/wallet/<name>` suffix; the wallet is BDK-owned.
        let rpc = Client::new(
            format!("http://{}", config.url.as_str()).as_str(),
            config.auth.clone(),
        )?;
        Ok(rpc)
    }
}

/// Persist the wallet to disk at most this often during a long sync.
const PERSIST_EVERY_N_BLOCKS: u32 = 500;

impl Wallet {
    /// Wrapper around Self::sync that also saves the wallet to disk.
    ///
    /// This method first synchronizes the wallet with the Bitcoin Core node,
    /// then persists the wallet state in the disk.
    pub fn sync_and_save(&mut self) -> Result<(), WalletError> {
        log::info!("Sync Started for {:?}", &self.store.file_name);
        self.sync_no_fail();
        self.save_to_disk()?;
        log::info!("Synced & Saved {:?}", &self.store.file_name);
        Ok(())
    }

    /// Sync the wallet with the configured Bitcoin Core node via BDK's Emitter.
    fn sync(&mut self) -> Result<(), WalletError> {
        // Make sure BDK has revealed enough HD scripts to cover all currently-issued
        // external addresses. (Internal scripts are revealed on-demand by the spend path.)
        self.ensure_revealed_to_external_index()?;

        // Pick the starting height. If `last_synced_height` is set we resume from there;
        // otherwise we start from the wallet birthday (or 0 if neither is known).
        let start_height = self
            .store
            .last_synced_height
            .or(self.store.wallet_birthday)
            .unwrap_or(0) as u32;

        let last_cp = self.bdk.chain.tip();
        let mut emitter = Emitter::new(&self.rpc, last_cp, start_height, NO_EXPECTED_MEMPOOL_TXS);

        let mut tip_height: u32 = self
            .store
            .last_synced_height
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;

        let mut blocks_since_persist: u32 = 0;

        loop {
            let event = match emitter.next_block() {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(e) => return Err(WalletError::Rpc(e)),
            };
            let height = event.block_height();

            let chain_cs = self.bdk.chain.apply_update(event.checkpoint).map_err(
                |e: CannotConnectError| {
                    WalletError::General(format!("LocalChain::apply_update: {e}"))
                },
            )?;
            let graph_cs = self.bdk.graph.apply_block_relevant(&event.block, height);

            self.store.bdk.local_chain.merge(chain_cs);
            self.store.bdk.indexed_tx_graph.merge(graph_cs);

            tip_height = height;
            blocks_since_persist += 1;

            if blocks_since_persist >= PERSIST_EVERY_N_BLOCKS {
                self.store.last_synced_height = Some(tip_height as u64);
                self.save_to_disk()?;
                blocks_since_persist = 0;
            }
        }

        // Mempool ingest.
        let mempool = emitter.mempool().map_err(WalletError::Rpc)?;
        if !mempool.update.is_empty() {
            let mempool_cs = self
                .bdk
                .graph
                .batch_insert_relevant_unconfirmed(mempool.update);
            self.store.bdk.indexed_tx_graph.merge(mempool_cs);
        }

        self.store.last_synced_height = Some(tip_height as u64);

        // Refresh the legacy `utxo_cache` shim so existing call sites see up-to-date UTXOs.
        self.refresh_utxo_cache_from_bdk()?;

        // Ensure `external_index` doesn't lag behind addresses that actually saw payments
        // (e.g. on a wallet restored from an older backup). We bump it past the highest
        // *used* external index across both HD address types — never past spk indices we
        // only revealed via the lookahead window, which would over-eagerly advance the
        // counter on every sync.
        let max_used = SeedKeychain::all()
            .iter()
            .filter(|kc| kc.kind == super::api::KeychainKind::External)
            .filter_map(|kc| self.bdk.graph.index.seed.last_used_index(*kc))
            .map(|i| i + 1)
            .max()
            .unwrap_or(0);
        self.store.external_index = self.store.external_index.max(max_used);

        self.refresh_offer_maxsize_cache()?;

        Ok(())
    }

    /// Reveal HD scripts up to (and including) `external_index` for every HD keychain.
    /// `external_index` is the next-to-issue index, so we reveal `external_index` itself
    /// to ensure the lookahead window straddles it.
    fn ensure_revealed_to_external_index(&mut self) -> Result<(), WalletError> {
        let target = self.store.external_index;
        for kc in SeedKeychain::all() {
            let cs: KeychainChangeSet = self.bdk.reveal_to(kc, target);
            self.store.bdk.indexed_tx_graph.indexer.merge(cs);
        }
        Ok(())
    }

    /// Keep retrying sync until success and log failure.
    // This is useful to handle transient RPC errors.
    fn sync_no_fail(&mut self) {
        while let Err(e) = self.sync() {
            log::error!("Blockchain sync failed. Retrying. | {e:?}");
            thread::sleep(HEART_BEAT_INTERVAL);
        }
    }

    /// Verify the SPV proof for a transaction.
    pub fn verify_tx_out_proof(
        &self,
        expected_txid: &bitcoin::Txid,
        proof_hex: &str,
    ) -> Result<(), WalletError> {
        let proof_txids: Vec<bitcoin::Txid> = self
            .rpc
            .call("verifytxoutproof", &[json!(proof_hex)])
            .map_err(WalletError::Rpc)?;

        if proof_txids != vec![*expected_txid] {
            return Err(WalletError::MerkleProofInvalid {
                expected: *expected_txid,
                got: proof_txids,
            });
        }

        Ok(())
    }
}
