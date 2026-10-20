//! The harness's own rules: fixture parsing, the comparison and its
//! diagnostics, the expected-failure list, the report, and the runner's
//! failure modes.

use solo_abi::chain::{Log, call_status};
use solo_abi::codec::Seq;
use solo_abi::conformance::Outcome;
use solo_conformance::check::{check, diff};
use solo_conformance::fixture::{self, Account, State, category, hex};
use solo_conformance::suite::{self, Counts, Expectation, Report};
use solo_conformance::{Executed, GUEST, Runner, TestCase};
use solo_host::Backend;
use solo_vm::status::Termination;

const CHAINID: &str =
    include_str!("fixtures/state_tests/istanbul/eip1344_chainid/chainid/chainid.json");
const KERNEL: &[u8] = include_bytes!("../../solo-node/tests/fixtures/kernel.elf");
const HELLO: &[u8] = include_bytes!("../../solo-recompile/tests/fixtures/hello.elf");

/// The chain-id test with a legacy transaction, which passes.
fn base() -> TestCase {
    fixture::parse(CHAINID)
        .unwrap()
        .into_iter()
        .find(|c| c.id.contains("typed_transaction_0"))
        .unwrap()
}

fn executed(case: &TestCase) -> Executed {
    Runner::new(GUEST, Backend::Interpreter)
        .unwrap()
        .run(&case.to_case().unwrap())
        .unwrap()
}

#[test]
fn a_passing_case_and_each_way_to_fail() {
    let case = base();
    let good = executed(&case);
    assert_eq!(good.outcome.status, call_status::SUCCESS);
    assert_eq!(check(&case, &Ok(good.clone())), Ok(()));
    assert_eq!(
        check(&case, &Err(Termination::Trap)),
        Err("the guest ended with Trap".to_string())
    );

    let mut refused = good.clone();
    refused.outcome.status = call_status::INVALID;
    assert_eq!(
        check(&case, &Ok(refused)),
        Err("the transaction was refused; the fixture expects it to run".to_string())
    );
    let mut must_refuse = case.clone();
    must_refuse.expected.exception = Some("TransactionException.INTRINSIC_GAS_TOO_LOW".to_string());
    assert!(check(&must_refuse, &Ok(good.clone())).unwrap_err().starts_with("expected the transaction to be refused (TransactionException.INTRINSIC_GAS_TOO_LOW)"));

    let mut wrong_root = case.clone();
    wrong_root.expected.state_root = [0; 32];
    let why = check(&wrong_root, &Ok(good.clone())).unwrap_err();
    assert!(why.contains("the post-states agree"), "{why}");
    wrong_root.expected.state = None;
    assert!(
        check(&wrong_root, &Ok(good.clone()))
            .unwrap_err()
            .ends_with("the fixture carries no post-state")
    );

    let mut extra_log = good.clone();
    extra_log.outcome.logs = Seq(vec![Log::default()]);
    assert!(
        check(&case, &Ok(extra_log))
            .unwrap_err()
            .contains("(1 logs)")
    );
}

#[test]
fn diff_names_the_first_difference() {
    let address = [0xAA; 20];
    let account = Account {
        balance: [0; 32],
        nonce: 1,
        code: vec![0x00],
        storage: [([1; 32], [2; 32])].into_iter().collect(),
    };
    let one = |a: Account| -> State { [(address, a)].into_iter().collect() };
    let base = one(account.clone());
    let a = hex(&address);
    assert_eq!(
        diff(&base, &State::new()),
        format!("account 0x{a} is missing")
    );
    assert_eq!(
        diff(&State::new(), &base),
        format!("account 0x{a} should not exist")
    );
    let mut b = account.clone();
    b.balance[31] = 1;
    assert!(diff(&base, &one(b)).contains("balance 0x"));
    let mut b = account.clone();
    b.nonce = 2;
    assert_eq!(
        diff(&base, &one(b)),
        format!("account 0x{a}: nonce 2 expected 1")
    );
    let mut b = account.clone();
    b.code = vec![];
    assert_eq!(
        diff(&base, &one(b)),
        format!("account 0x{a}: code of 0 bytes expected 1 bytes")
    );
    let mut b = account.clone();
    b.storage.clear();
    assert_eq!(
        diff(&base, &one(b)),
        format!(
            "account 0x{a}: slot 0x{} is 0 expected 0x{}",
            hex(&[1; 32]),
            hex(&[2; 32])
        )
    );
    let mut b = account;
    b.storage.insert([3; 32], [4; 32]);
    assert_eq!(
        diff(&base, &one(b)),
        format!(
            "account 0x{a}: slot 0x{} is 0x{} expected 0",
            hex(&[3; 32]),
            hex(&[4; 32])
        )
    );
}

#[test]
fn balances_beyond_128_bits_are_reported_not_truncated() {
    let mut case = base();
    case.pre.values_mut().next().unwrap().balance[15] = 1;
    assert!(
        case.to_case()
            .unwrap_err()
            .contains("does not fit the kernel's 128-bit balances")
    );
    let mut runners = [Runner::new(GUEST, Backend::Interpreter).unwrap()];
    let report = suite::run(&[case], &mut runners, &[]);
    assert_eq!(report.failures.len(), 1);
}

#[test]
fn tx_types_and_categories() {
    let cases = fixture::parse(CHAINID).unwrap();
    let types: Vec<u8> = cases.iter().map(TestCase::tx_type).collect();
    assert_eq!(types, [0, 1, 2, 3, 4]);
    let mut empty = base();
    empty.tx.clear();
    assert_eq!(empty.tx_type(), 0);
    assert_eq!(
        category("tests/cancun/eip5656_mcopy/test_mcopy.py::test_x[fork_Osaka]"),
        "cancun/eip5656_mcopy"
    );
    assert_eq!(
        category("tests/static/state_tests/stExample/add11.json::add11[fork_Osaka]"),
        "static/stExample"
    );
    assert_eq!(category("tests/static"), "static/");
    assert_eq!(category("solo"), "solo/");
}

/// A fixture with one field replaced (or removed, for `None`).
fn with(path: &[&str], value: Option<serde_json::Value>) -> Result<Vec<TestCase>, String> {
    let mut json: serde_json::Value = serde_json::from_str(CHAINID).unwrap();
    let name = json.as_object().unwrap().keys().next().unwrap().clone();
    let mut node = &mut json[&name];
    for key in &path[..path.len() - 1] {
        node = match key.parse::<usize>() {
            Ok(i) => &mut node[i],
            Err(_) => &mut node[*key],
        };
    }
    let last = path[path.len() - 1];
    match value {
        Some(v) => node[last] = v,
        None => {
            node.as_object_mut().unwrap().remove(last);
        }
    }
    fixture::parse(&json.to_string())
}

#[test]
fn malformed_fixtures_are_rejected_with_the_reason() {
    use serde_json::json;
    let err = |path: &[&str], value| with(path, value).unwrap_err();
    assert_eq!(
        fixture::parse("[]").unwrap_err(),
        "a fixture file is an object of tests"
    );
    assert!(err(&["env"], None).ends_with("missing field `env`"));
    assert!(
        err(&["env", "currentNumber"], Some(json!(1)))
            .ends_with("field `currentNumber` is not a string")
    );
    assert!(err(&["env", "currentNumber"], Some(json!("1"))).ends_with("`1` lacks the 0x prefix"));
    assert!(err(&["env", "currentNumber"], Some(json!("0xzz"))).ends_with("`0xzz` is not hex"));
    assert!(
        err(
            &["env", "currentNumber"],
            Some(json!("0x010000000000000000"))
        )
        .ends_with("does not fit 8 bytes")
    );
    assert!(err(&["config", "chainid"], Some(json!(1))).ends_with("`chainid` is not a string"));
    assert!(err(&["pre"], Some(json!([]))).ends_with("field `pre` is not an object"));
    assert!(err(&["post", "Osaka"], Some(json!({}))).ends_with("post entries are not an array"));
    assert!(
        err(&["post", "Osaka", "0", "state"], Some(json!([])))
            .ends_with("post state is not an object")
    );
    assert!(
        err(&["post", "Osaka", "0", "expectException"], Some(json!(1)))
            .ends_with("`expectException` is not a string")
    );
    let mut json: serde_json::Value = serde_json::from_str(CHAINID).unwrap();
    for test in json.as_object_mut().unwrap().values_mut() {
        let pre = test["pre"].as_object_mut().unwrap();
        let account = pre.values_mut().next().unwrap();
        account["storage"] = json!({"0x01": 1});
    }
    assert!(
        fixture::parse(&json.to_string())
            .unwrap_err()
            .ends_with("storage value is not a string")
    );

    // A zero slot is the same as an absent one.
    let mut json: serde_json::Value = serde_json::from_str(CHAINID).unwrap();
    for test in json.as_object_mut().unwrap().values_mut() {
        let pre = test["pre"].as_object_mut().unwrap();
        pre.values_mut().next().unwrap()["storage"] = json!({"0x01": "0x00", "0x02": "0x05"});
    }
    let cases = fixture::parse(&json.to_string()).unwrap();
    let storage = &cases[0].pre.values().next().unwrap().storage;
    assert_eq!(storage.len(), 1);
    assert_eq!(storage.values().next().unwrap()[31], 5);

    // Absent pieces with defaults: no chain id means 1; a test without the
    // fork yields no case; a fixture without a post-state still parses.
    let cases = with(&["config"], None).unwrap();
    assert_eq!(cases[0].env.chain_id, 1);
    assert_eq!(
        with(&["post", "Osaka", "0", "state"], None).unwrap()[0]
            .expected
            .state,
        None
    );
    let cases = with(&["post"], Some(json!({"Prague": []}))).unwrap();
    assert_eq!(cases.len(), 4);
    let cases = with(&["post", "Osaka"], Some(json!([{"hash": "0x00", "logs": "0x00", "txbytes": "0xc0"}, {"hash": "0x00", "logs": "0x00", "txbytes": "0x0"}]))).unwrap();
    assert!(cases[0].id.ends_with("#0") && cases[1].id.ends_with("#1"));
    assert_eq!(cases[1].tx, vec![0]);
}

#[test]
fn expectation_lists() {
    let list = suite::expectations("# comment\n\n a | one \ntype:3 | two\nb* | three\n").unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(
        list[0],
        Expectation {
            pattern: "a".into(),
            reason: "one".into()
        }
    );
    assert_eq!(
        suite::expectations("a |").unwrap_err(),
        "line 1: expected `<test id> | <reason>`"
    );
    assert_eq!(
        suite::expectations("x\n | reason").unwrap_err(),
        "line 1: expected `<test id> | <reason>`"
    );
    assert_eq!(
        suite::expectations("a | b\n | reason").unwrap_err(),
        "line 2: expected `<test id> | <reason>`"
    );
}

#[test]
fn listed_cases_that_pass_and_entries_that_excuse_nothing_are_reported() {
    let case = base();
    let list = |pattern: &str| Expectation {
        pattern: pattern.to_string(),
        reason: "r".to_string(),
    };
    let mut runners = [Runner::new(GUEST, Backend::Interpreter).unwrap()];
    let expected = [
        list(&case.id),
        list("tests/never*"),
        list("type:7"),
        list("type:x"),
        list("tests/istanbul*"),
    ];
    let report = suite::run(std::slice::from_ref(&case), &mut runners, &expected);
    assert_eq!(report.unexpected_passes, vec![case.id.clone()]);
    assert_eq!(
        report.unused,
        vec!["tests/never*", "type:7", "type:x", "tests/istanbul*"]
    );
    assert!(!report.ok(true));
    let text = report.to_string();
    assert!(text.contains(&format!("PASS {}: listed as an expected failure", case.id)));
    assert!(text.contains("UNUSED type:7: matches no failing case"));

    // A failing case excused by a prefix entry.
    let mut failing = case.clone();
    failing.expected.logs_hash = [0; 32];
    let report = suite::run(&[failing.clone()], &mut runners, &[list("tests/istanbul*")]);
    assert!(report.ok(false));
    assert_eq!(
        report.total(),
        Counts {
            passed: 0,
            expected: 1,
            failed: 0
        }
    );
    let report = suite::run(&[failing.clone()], &mut runners, &[]);
    assert!(!report.ok(true));
    assert!(
        report
            .to_string()
            .contains(&format!("FAIL {}: logs hash", failing.id))
    );
    assert_eq!(Report::default().total(), Counts::default());
}

#[test]
fn backends_that_disagree_fail_the_case() {
    // `hello` has no conformance export, so its runner ends every case with a
    // different result from the conformance guest's.
    let case = base();
    let mut runners = [
        Runner::new(GUEST, Backend::Interpreter).unwrap(),
        Runner::new(HELLO, Backend::Native).unwrap(),
    ];
    let report = suite::run(std::slice::from_ref(&case), &mut runners, &[]);
    assert_eq!(
        report.failures,
        vec![(
            case.id.clone(),
            "the Native backend disagrees with the Interpreter backend".to_string()
        )]
    );
    let mut hello = Runner::new(HELLO, Backend::Interpreter).unwrap();
    assert_eq!(
        hello.run(&case.to_case().unwrap()),
        Err(Termination::HostError(2))
    );
}

#[test]
fn a_guest_that_is_not_an_elf_is_refused() {
    assert!(
        Runner::new(b"not an elf", Backend::Interpreter)
            .err()
            .unwrap()
            .starts_with("guest ELF")
    );
    // The kernel imports the node's privileged functions, which a bare executor lacks.
    assert_eq!(
        Runner::new(KERNEL, Backend::Interpreter).err().unwrap(),
        "guest module: Invalid(UnresolvedImport)"
    );
}

#[test]
fn outcome_records_are_what_the_guest_returns() {
    let case = base();
    let run = executed(&case);
    assert_eq!(
        run.outcome,
        Outcome {
            status: call_status::SUCCESS,
            gas_used: run.outcome.gas_used,
            logs: Seq(Vec::new())
        }
    );
    assert!(run.outcome.gas_used > 21_000);
}
