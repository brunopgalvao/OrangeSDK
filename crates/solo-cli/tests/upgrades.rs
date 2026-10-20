//! The upgrade parameters of a genesis file (spec 13 §1).

use solo_abi::Decode;
use solo_abi::chain::{GenesisParams, UpgradeParams};
use solo_cli::parse_genesis;

fn upgrades(text: &str) -> UpgradeParams {
    let genesis = parse_genesis(text).unwrap();
    GenesisParams::from_bytes(&genesis.params).unwrap().upgrades
}

#[test]
fn upgrade_parameters() {
    assert_eq!(upgrades(r#"{"chainId": 1}"#), UpgradeParams::default());
    assert_eq!(
        upgrades(
            r#"{"chainId": 1, "governance": "0x1a642f0e3c3af545e7acbd38b07251b3990914f1", "upgradeDelay": 20, "epochBlocks": 100}"#
        ),
        UpgradeParams {
            governance: [
                0x1a, 0x64, 0x2f, 0x0e, 0x3c, 0x3a, 0xf5, 0x45, 0xe7, 0xac, 0xbd, 0x38, 0xb0, 0x72,
                0x51, 0xb3, 0x99, 0x09, 0x14, 0xf1
            ],
            min_delay: 20,
            epoch_blocks: 100,
        }
    );
    let cases = [
        (
            r#"{"chainId": 1, "governance": 5}"#,
            "governance must be a 0x address",
        ),
        (
            r#"{"chainId": 1, "governance": "zz"}"#,
            "governance must be a 0x address",
        ),
        (
            r#"{"chainId": 1, "governance": "0x01"}"#,
            "governance must be a 0x address",
        ),
        (
            r#"{"chainId": 1, "upgradeDelay": -1}"#,
            "upgradeDelay must be a non-negative integer",
        ),
        (
            r#"{"chainId": 1, "epochBlocks": "x"}"#,
            "epochBlocks must be a non-negative integer",
        ),
    ];
    for (text, expected) in cases {
        let message = parse_genesis(text).unwrap_err();
        assert!(message.contains(expected), "{text}: {message}");
    }
}
