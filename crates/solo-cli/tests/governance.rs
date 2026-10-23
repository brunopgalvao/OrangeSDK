//! The governance fields of a genesis file and `solo gov`, the encoder of
//! governance calls (spec 13 §9).

use solo_abi::Decode;
use solo_abi::chain::GenesisParams;
use solo_abi::fees::FeeParams;
use solo_abi::governance::{Call, GOVERNANCE_ADDRESS, GovernanceParams, mode};
use solo_cli::gov::{describe, parse};
use solo_cli::{parse_genesis, run};

fn governance(text: &str) -> GovernanceParams {
    let genesis = parse_genesis(text).unwrap();
    GenesisParams::from_bytes(&genesis.params)
        .unwrap()
        .governance
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn governance_parameters() {
    assert_eq!(governance(r#"{"chainId": 1}"#), GovernanceParams::default());
    assert_eq!(
        governance(r#"{"chainId": 1, "governanceMode": "key"}"#),
        GovernanceParams::default()
    );
    assert_eq!(
        governance(
            r#"{"chainId": 1, "governanceMode": "stake", "votingBlocks": 100, "timelockBlocks": 50,
                "quorumBps": 4000, "proposalDeposit": "1000000000000000000"}"#
        ),
        GovernanceParams {
            mode: mode::STAKE,
            voting_blocks: 100,
            timelock_blocks: 50,
            quorum_bps: 4_000,
            deposit: 1_000_000_000_000_000_000,
        }
    );
    assert_eq!(
        governance(r#"{"chainId": 1, "proposalDeposit": "0x10"}"#).deposit,
        16
    );
    assert_eq!(
        governance(r#"{"chainId": 1, "proposalDeposit": 7}"#).deposit,
        7
    );
    let cases = [
        (
            r#"{"chainId": 1, "governanceMode": "multisig"}"#,
            "governanceMode must be key or stake",
        ),
        (
            r#"{"chainId": 1, "governanceMode": 1}"#,
            "governanceMode must be key or stake",
        ),
        (
            r#"{"chainId": 1, "votingBlocks": -1}"#,
            "votingBlocks must be a non-negative integer",
        ),
        (
            r#"{"chainId": 1, "timelockBlocks": "x"}"#,
            "timelockBlocks must be a non-negative integer",
        ),
        (
            r#"{"chainId": 1, "quorumBps": 1.5}"#,
            "quorumBps must be a non-negative integer",
        ),
        (
            r#"{"chainId": 1, "proposalDeposit": "lots"}"#,
            "proposalDeposit must be a decimal or 0x hex string",
        ),
        (
            r#"{"chainId": 1, "proposalDeposit": -5}"#,
            "proposalDeposit must be a non-negative integer",
        ),
        (
            r#"{"chainId": 1, "proposalDeposit": []}"#,
            "proposalDeposit must be a string or number",
        ),
        // The stake track cannot start without a voting period and a quorum (spec 13 §9.1).
        (
            r#"{"chainId": 1, "governanceMode": "stake", "votingBlocks": 10}"#,
            "governanceMode stake needs votingBlocks and quorumBps above zero",
        ),
        (
            r#"{"chainId": 1, "governanceMode": "stake", "quorumBps": 5000}"#,
            "governanceMode stake needs votingBlocks and quorumBps above zero",
        ),
        (
            r#"{"chainId": 1, "quorumBps": 10001}"#,
            "quorumBps must be at most 10000",
        ),
    ];
    for (text, expected) in cases {
        let message = parse_genesis(text).unwrap_err();
        assert!(message.contains(expected), "{text}: {message}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn gov_encodes_every_call() {
    let target = format!("0x{}", "45".repeat(20));
    let guardian = format!("0x{}", "ab".repeat(20));
    let wrapped = |call: Call| Call::Submit {
        target: GOVERNANCE_ADDRESS,
        data: call.encode(),
    };
    let cases: Vec<(Vec<&str>, Call)> = vec![
        (
            vec!["submit", &target, "0x8456cb59"],
            Call::Submit {
                target: [0x45; 20],
                data: vec![0x84, 0x56, 0xcb, 0x59],
            },
        ),
        (
            vec!["vote", "3", "yes"],
            Call::Vote {
                id: 3,
                support: true,
            },
        ),
        (
            vec!["vote", "4", "no"],
            Call::Vote {
                id: 4,
                support: false,
            },
        ),
        (vec!["execute", "5"], Call::Execute { id: 5 }),
        (vec!["veto", "6"], Call::Veto { id: 6 }),
        (vec!["pause", &target], Call::Pause { target: [0x45; 20] }),
        (
            vec!["set-guardian", &guardian],
            wrapped(Call::SetGuardian {
                guardian: [0xAB; 20],
            }),
        ),
        (
            vec!["set-mode", "stake"],
            wrapped(Call::SetMode { mode: mode::STAKE }),
        ),
        (
            vec!["set-params", "100", "50", "4000", "0x10"],
            wrapped(Call::SetParams {
                voting_blocks: 100,
                timelock_blocks: 50,
                quorum_bps: 4_000,
                deposit: 16,
            }),
        ),
        (
            vec!["set-fee-params", "125", "2", "1000000000", "burn"],
            wrapped(Call::SetFeeParams {
                params: FeeParams::production(),
            }),
        ),
        (
            vec!["set-fee-params", "100", "4", "0x10", &guardian],
            wrapped(Call::SetFeeParams {
                params: FeeParams {
                    denominator: 100,
                    elasticity: 4,
                    min_base_fee: 16,
                    treasury: [0xAB; 20],
                },
            }),
        ),
        (
            vec!["set-fee-params", "0", "0", "0", "burn"],
            wrapped(Call::SetFeeParams {
                params: FeeParams::default(),
            }),
        ),
    ];
    for (args, expected) in cases {
        let call = parse(&words(&args)).unwrap();
        assert_eq!(call, expected, "{args:?}");
        let text = describe(&call);
        assert!(
            text.starts_with("to       0x0000000000000000000000000000000000005010\ncalldata 0x")
        );
        let calldata = format!(
            "\ncalldata {}\ngas      ",
            solo_rpc::methods::data(&call.encode())
        );
        assert!(text.contains(&calldata), "{text}");
        assert_eq!(
            text.contains("\nvalue    0 from the key or a validator"),
            matches!(call, Call::Submit { .. }),
            "{text}"
        );
        let mut full = vec!["solo".to_owned(), "gov".to_owned()];
        full.extend(words(&args));
        run(&full).unwrap();
    }
    // The gas line is the calldata's EIP-7623 floor plus the 50 000 gas
    // surcharge: what a vote uses (spec 13 §9.9), and what `execute` needs.
    let gas_of = |args: &[&str]| -> String {
        let text = describe(&parse(&words(args)).unwrap());
        text.lines()
            .find_map(|l| l.strip_prefix("gas      "))
            .unwrap()
            .to_owned()
    };
    assert_eq!(gas_of(&["vote", "3", "yes"]), "71860");
    assert_eq!(gas_of(&["execute", "5"]), "71510");
}

#[test]
fn gov_names_every_mistake() {
    let target = format!("0x{}", "45".repeat(20));
    // 160 bits of hex: every digit valid, the amount past a `u128`.
    let too_big = format!("0x{}", "f".repeat(40));
    let errors = [
        (vec![], "subcommand missing"),
        (vec!["submit"], "target missing"),
        (vec!["submit", "0x01", "0x"], "target must be a 0x address"),
        (vec!["submit", &target], "calldata missing"),
        (vec!["submit", &target, "zz"], "calldata must be 0x hex"),
        (vec!["vote", "x", "yes"], "proposal id must be a number"),
        (vec!["vote", "1", "maybe"], "vote yes or no"),
        (vec!["execute"], "proposal id missing"),
        (vec!["veto", "-1"], "proposal id must be a number"),
        (vec!["pause", "0x"], "target must be a 0x address"),
        (vec!["set-guardian", "1"], "guardian must be a 0x address"),
        (vec!["set-mode", "key"], "the only mode to set is stake"),
        (vec!["set-params", "1", "2", "3"], "deposit missing"),
        (
            vec!["set-params", "1", "2", "3", "0x"],
            "deposit must be a decimal or 0x hex amount in wei",
        ),
        (
            vec!["set-params", "1", "2", "3", "1e9"],
            "deposit must be a decimal or 0x hex amount in wei",
        ),
        (
            vec!["set-params", "1", "2", "3", &too_big],
            "deposit must be a decimal or 0x hex amount in wei",
        ),
        (
            vec!["set-params", "a", "2", "3", "4"],
            "voting blocks must be a number",
        ),
        (vec!["set-fee-params", "125", "2"], "min base fee missing"),
        (
            vec!["set-fee-params", "125", "2", "1", "0x01"],
            "treasury must be a 0x address",
        ),
        (
            vec!["set-fee-params", "125", "2", &too_big, "burn"],
            "min base fee must be a decimal or 0x hex amount in wei",
        ),
        (
            vec!["set-fee-params", "125", "2", "0x10000000000000000", "burn"],
            "min base fee must be below 2^64 wei",
        ),
        (
            vec!["set-fee-params", "99", "2", "1", "burn"],
            "denominator must be 0 (the market off, with elasticity 0) or 100 to 125",
        ),
        (
            vec!["set-fee-params", "125", "2", "1000000000001", "burn"],
            "minBaseFee must be at most 1000000000000 wei",
        ),
        (
            vec![
                "set-fee-params",
                "125",
                "2",
                "1",
                "0x0000000000000000000000000000000000005354",
            ],
            "treasury must not be the staking address",
        ),
        (
            vec!["set-fee-params", "x", "2", "1", "burn"],
            "denominator must be a number",
        ),
        (vec!["dance"], "unknown subcommand dance"),
    ];
    for (args, expected) in errors {
        let message = parse(&words(&args)).unwrap_err();
        assert!(message.contains(expected), "{args:?}: {message}");
    }
    assert!(
        run(&words(&["solo", "gov", "dance"]))
            .unwrap_err()
            .contains("unknown subcommand")
    );
}
