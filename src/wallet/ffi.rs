//! FFI-compatible types for the Taker module.
//!
//! This module provides Foreign Function Interface (FFI) compatible data structures
//! for exposing swap functionality and reporting to other languages.

use crate::{
    security::{load_sensitive_struct, KeyMaterial, SerdeJson},
    utill::{get_taker_dir, parse_checked_address, MIN_FEE_RATE},
    wallet::{AddressType, Destination, RPCConfig, Wallet, WalletBackup, WalletError},
};
use bitcoin::{Amount, OutPoint, Txid};
use serde::{Deserialize, Serialize};

/// A wallet-owned summary record of an incoming transaction. Replaces the bitcoincore-rpc
/// `ListTransactionResult` shape that the wallet used to return when Bitcoin Core was the
/// UTXO source. Carries only the fields the GUI actually surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingTx {
    /// The transaction id.
    pub txid: Txid,
    /// Sum of values paid to scripts the wallet owns in this tx.
    pub amount: Amount,
    /// Confirmations of the tx (0 if unconfirmed).
    pub confirmations: u32,
}
use std::path::{Path, PathBuf};

pub use super::report::{
    MakerFeeInfo, MakerReport, RecoveryReport, SwapRole, SwapStatus, TakerReport,
};

/// Restores a wallet from an encrypted or unencrypted JSON backup file for GUI/FFI applications.
///
/// This is a non-interactive restore method designed for programmatic use via FFI bindings.
/// Unlike `restore_wallet`, this function accepts a path to a JSON backup file and handles both
/// encrypted and unencrypted backups using [`load_sensitive_struct`].
///
/// # Behavior
///
/// 1. Reads and parses the JSON backup file into a [`WalletBackup`] structure
/// 2. If encrypted, decrypts using the provided password and preserves encryption material
/// 3. Constructs the wallet path: `{data_dir_or_default}/wallets/{wallet_file_name_or_default}`
/// 4. Calls [`Wallet::restore`] to reconstruct the wallet with all UTXOs and metadata
///
/// # Parameters
///
/// - `data_dir`: Target directory, defaults to `~/.coinswap/taker`
/// - `wallet_file_name`: Restored wallet filename, defaults to name from backup if empty
/// - `backup_file_path`: Path to the JSON file containing the wallet backup (encrypted or plain)
/// - `password`: Required if backup is encrypted, ignored otherwise
pub fn restore_wallet_gui_app(
    data_dir: Option<PathBuf>,
    wallet_file_name: Option<String>,
    rpc_config: RPCConfig,
    backup_file_path: PathBuf,
    password: Option<String>,
) {
    let (backup, encryption_material) = load_sensitive_struct::<WalletBackup, SerdeJson>(
        &backup_file_path,
        Some(password.unwrap_or_default()),
    );
    let restored_wallet_filename = wallet_file_name.unwrap_or("".to_string());

    let restored_wallet_path = data_dir
        .clone()
        .unwrap_or(get_taker_dir())
        .join("wallets")
        .join(restored_wallet_filename);

    if let Err(e) = Wallet::restore(
        &backup,
        &restored_wallet_path,
        &rpc_config,
        encryption_material,
    ) {
        log::error!("Wallet restore failed: {e:?}");
    } else {
        println!("Wallet restore succeeded!");
    }
}

impl Wallet {
    /// Creates a wallet backup for GUI/FFI applications with optional encryption.
    ///
    /// This is a ffi-only wrapper around [`Wallet::backup`] that handles encryption
    /// material generation internally based on whether a password is provided.
    ///
    /// # Behavior
    ///
    /// - If `password` is `Some(pwd)` and not empty: Creates encrypted backup using the password
    /// - If `password` is `None` or empty string: Creates unencrypted backup (logs warning)
    /// - The backup is written as a `.json` file at the specified path
    ///
    /// # Parameters
    ///
    /// - `destination_path`: Destination file path for the backup (`.json`)
    /// - `password`: Optional password for encryption. Use `None` or empty string for plaintext backup
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Encrypted backup
    /// wallet.backup_gui_app("/path/to/backup".to_string(), Some("my_password".to_string()))?;
    ///
    /// // Unencrypted backup
    /// wallet.backup_gui_app("/path/to/backup".to_string(), None)?;
    pub fn backup_wallet_gui_app(
        &self,
        destination_path: String,
        password: Option<String>,
    ) -> Result<(), WalletError> {
        let km = KeyMaterial::new_from_password(password);
        let backup_path = Path::new(&destination_path);
        self.backup(backup_path, km)?;

        Ok(())
    }

    /// Checks whether wallet is encrypted or not.
    pub fn is_wallet_encrypted(wallet_path: &Path) -> Result<bool, WalletError> {
        if !wallet_path.exists() {
            return Ok(false); // No wallet = not encrypted
        }

        let content = std::fs::read(wallet_path).map_err(WalletError::IO)?;

        // Try to deserialize as EncryptedData using CBOR
        // If it succeeds, the wallet is encrypted
        // If it fails, the wallet is plaintext
        match serde_cbor::from_slice::<crate::security::EncryptedData>(&content) {
            Ok(_) => Ok(true),   // Successfully parsed as EncryptedData = encrypted
            Err(_) => Ok(false), // Failed to parse as EncryptedData = plaintext
        }
    }

    /// Returns a list of recent incoming transactions to the wallet (by default last 10).
    ///
    /// A transaction is "incoming" if any of its outputs pays a script the wallet
    /// recognizes as an HD seed coin or a previously-swept incoming-swap coin. Walks the
    /// full canonical tx history (including transactions whose outputs have since been
    /// spent), sorted most-recent first.
    pub fn get_transactions(
        &self,
        count: Option<usize>,
        skip: Option<usize>,
    ) -> Result<Vec<IncomingTx>, WalletError> {
        use bdk_chain::{CanonicalizationParams, ChainPosition};

        let count = count.unwrap_or(10);
        let skip = skip.unwrap_or(0);

        let tip = self.bdk.chain.tip();
        let tip_height = tip.height();
        let view = self.bdk.graph.canonical_view(
            &self.bdk.chain,
            tip.block_id(),
            CanonicalizationParams::default(),
        );

        // Walk every canonical tx; keep any tx whose outputs pay one of our seed or swept
        // spks, summing the value paid in.
        let mut rows: Vec<(u32, IncomingTx)> = Vec::new();
        for canonical_tx in view.txs() {
            let mut owned_total = Amount::ZERO;
            for txout in canonical_tx.tx.output.iter() {
                let spk = &txout.script_pubkey;
                let is_owned = self.bdk.keychain_of_spk(spk).is_some()
                    || self.store.swept_incoming_swapcoins.contains(spk);
                if is_owned {
                    owned_total += txout.value;
                }
            }
            if owned_total == Amount::ZERO {
                continue;
            }

            let (confirmations, sort_height) = match &canonical_tx.pos {
                ChainPosition::Confirmed { anchor, .. } => {
                    let h = anchor.block_id.height;
                    (tip_height.saturating_sub(h) + 1, h)
                }
                // Unconfirmed → sort to the top (u32::MAX height-key).
                ChainPosition::Unconfirmed { .. } => (0_u32, u32::MAX),
            };
            rows.push((
                sort_height,
                IncomingTx {
                    txid: canonical_tx.txid,
                    amount: owned_total,
                    confirmations,
                },
            ));
        }

        // Sort most-recent first (highest block height → top; unconfirmed first).
        rows.sort_by_key(|(h, _)| std::cmp::Reverse(*h));
        Ok(rows
            .into_iter()
            .map(|(_, tx)| tx)
            .skip(skip)
            .take(count)
            .collect())
    }

    /// Sends specified Amount of Satoshis to an External Address
    pub fn send_to_address(
        &mut self,
        amount: u64,
        address: String,
        fee_rate: Option<f64>,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
    ) -> Result<Txid, WalletError> {
        let amount = Amount::from_sat(amount);

        let addr = parse_checked_address(&address, self.store.network).map_err(|e| {
            log::debug!(
                "Address validation failed for network {:?}: {:?}",
                self.store.network,
                e
            );
            WalletError::General("Invalid address for the current wallet network".to_string())
        })?;

        let coins_to_spend = self.coin_select(
            amount,
            fee_rate.unwrap_or(MIN_FEE_RATE),
            manually_selected_outpoints,
            None,
        )?;

        let outputs = vec![(addr, amount)];
        let destination = Destination::Multi {
            outputs,
            op_return_data: None,
            change_address_type: AddressType::P2TR,
        };

        let tx = self.spend_from_wallet(
            fee_rate.unwrap_or(MIN_FEE_RATE),
            destination,
            &coins_to_spend,
        )?;

        let txid = self.send_tx(&tx)?;
        self.sync_and_save()?;

        Ok(txid)
    }
}
