//! Tests that the funding transaction creation works correctly with varied UTXO distributions.
//!
//! Iterates through a range of target amounts and verifies the resulting funding tx is well-formed:
//! - selected inputs come from the funded UTXO pool (no fabrication)
//! - no duplicate inputs
//! - selected inputs cover the target
//! - some fee is paid (inputs > outputs)
//! - actual feerate is within tolerance of the requested MIN_FEE_RATE
//!
//! Selector-implementation details (which specific UTXOs are picked, how many) are deliberately
//! NOT asserted — those vary between coin-selection algorithms and would couple this test to
//! whichever implementation happened to be in tree when the assertions were written.

use bitcoin::{Address, Amount};
use coinswap::{taker::TakerBehavior, utill::MIN_FEE_RATE, wallet::AddressType};

use super::test_framework::*;

const UTXO_SETS: &[&[u64]] = &[
    &[
        107_831, 91_379, 712_971, 432_441, 301_909, 38_012, 298_092, 9_091,
    ],
    &[109_831, 3_919],
    &[1_946_436],
    &[1_000_000, 1_992_436],
    &[70_000, 800_000, 900_000, 100_000],
    &[46_824, 53_245, 65_658, 35_892],
];

/// Target amounts to fund (in sats), spanning a range of pool/target ratios.
const TARGETS: &[u64] = &[
    54_082, 102_980, 708_742, 500_000, 654_321, 90_000, 10_000, 1_000_000, 999_999, 123_456,
    250_000, 500, 1_500, 2_500,
];

#[test]
fn test_create_funding_txn_with_varied_distributions() {
    // Initialize the test framework with a single taker with Normal behavior, no makers
    let (test_framework, mut takers, _makers, _block_generation_handle) =
        TestFramework::init(vec![], vec![TakerBehavior::Normal], vec![]);

    let bitcoind = &test_framework.bitcoind;
    let taker = &mut takers[0];

    // Fund the taker with the UTXO sets
    for individual_utxo in UTXO_SETS.iter().flat_map(|x| x.iter()) {
        let addr = taker
            .get_wallet()
            .write()
            .unwrap()
            .get_next_external_address(AddressType::P2WPKH)
            .unwrap();
        send_to_address(bitcoind, &addr, Amount::from_sat(*individual_utxo));
        generate_blocks(bitcoind, 1);
    }

    // Sync taker wallet
    taker.get_wallet().write().unwrap().sync_and_save().unwrap();

    // Generate 5 random addresses from the taker's wallet
    let mut destinations: Vec<Address> = Vec::with_capacity(5);
    for _ in 0..5 {
        let addr = taker
            .get_wallet()
            .write()
            .unwrap()
            .get_next_external_address(AddressType::P2WPKH)
            .unwrap();
        destinations.push(addr);
    }

    let funded_pool: std::collections::HashSet<u64> =
        UTXO_SETS.iter().flat_map(|x| x.iter().copied()).collect();
    let total_funded: u64 = UTXO_SETS.iter().flat_map(|x| x.iter()).sum();

    for (i, &target_amount) in TARGETS.iter().enumerate() {
        let target = Amount::from_sat(target_amount);

        let result = taker
            .get_wallet()
            .write()
            .unwrap()
            .create_funding_txes_regular_swaps(
                false,
                target,
                destinations.clone(),
                Amount::from_sat(MIN_FEE_RATE as u64),
                None,
                None,
            )
            .unwrap();

        let tx = &result.funding_txes[0];
        let selected_inputs = tx
            .input
            .iter()
            .map(|txin| {
                taker
                    .get_wallet()
                    .read()
                    .unwrap()
                    .list_all_utxo_spend_info()
                    .iter()
                    .find(|(utxo, _)| {
                        txin.previous_output.txid == utxo.txid()
                            && txin.previous_output.vout == utxo.vout()
                    })
                    .map(|(u, _)| u.amount)
                    .expect("should find utxo")
            })
            .collect::<Vec<_>>();

        let sum_of_inputs = selected_inputs.iter().map(|a| a.to_sat()).sum::<u64>();
        let sum_of_outputs = tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
        let actual_fee = sum_of_inputs - sum_of_outputs;
        let tx_size = tx.weight().to_vbytes_ceil();
        let actual_feerate = actual_fee as f64 / tx_size as f64;

        // No duplicate inputs.
        let unique: std::collections::HashSet<_> =
            selected_inputs.iter().map(|a| a.to_sat()).collect();
        assert_eq!(
            unique.len(),
            selected_inputs.len(),
            "case {}: duplicate UTXO in selection {:?}",
            i,
            selected_inputs
        );

        // Each selected UTXO must come from the actual funded pool.
        for a in &selected_inputs {
            assert!(
                funded_pool.contains(&a.to_sat()),
                "case {}: selector fabricated UTXO {}",
                i,
                a
            );
        }

        // Inputs must cover the target value (fees come on top, asserted below).
        assert!(
            sum_of_inputs >= target.to_sat(),
            "case {}: input sum {} < target {}",
            i,
            sum_of_inputs,
            target.to_sat()
        );

        // Inputs cannot exceed the entire funded pool.
        assert!(
            sum_of_inputs <= total_funded,
            "case {}: input sum {} > total funded {}",
            i,
            sum_of_inputs,
            total_funded
        );

        // No money created: fee is positive (inputs > outputs).
        assert!(
            sum_of_inputs > sum_of_outputs,
            "case {}: inputs {} <= outputs {} (no fee)",
            i,
            sum_of_inputs,
            sum_of_outputs
        );

        // Fee rate is within the expected range (allow up to 2% under MIN_FEE_RATE
        // for rounding, or the absolute-min-fee fallback where fee == MIN_FEE_RATE).
        assert!(
            actual_feerate > MIN_FEE_RATE * 0.98 || actual_fee == MIN_FEE_RATE as u64,
            "case {}: fee rate ({}) is not within tolerance of MIN_FEE_RATE ({})",
            i,
            actual_feerate,
            MIN_FEE_RATE
        );
    }

    test_framework.stop();
}
