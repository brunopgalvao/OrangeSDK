//! Genesis modules in the genesis file (spec 16 §4.1).

use orange_abi::Decode;
use orange_abi::chain::{CallRequest, GenesisParams};
use orange_abi::modules::{capability, designator};
use orange_cli::{dev_key, load_kernel, parse_genesis};
use orange_host::hash::keccak256;
use orange_node::{Node, NodeConfig};

const COUNTER_ELF: &[u8] = include_bytes!("../../orange-node/tests/fixtures/counter.elf");
const MODULE: &str = "0x4242424242424242424242424242424242424242";

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::from("0x");
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    s
}

fn counter() -> Vec<u8> {
    orange_recompile::recompile(
        &orange_recompile::Input::load(COUNTER_ELF).unwrap(),
        &orange_recompile::Options::default(),
    )
    .unwrap()
}

#[test]
fn genesis_files_install_modules() {
    let code = counter();
    let text = format!(
        r#"{{"chainId": 1337, "alloc": {{"{MODULE}": "7"}},
            "modules": [{{"address": "{MODULE}", "code": "{}", "capabilities": 1, "init": "0x0900000000000000"}}]}}"#,
        hex(&code)
    );
    let genesis = parse_genesis(&text).unwrap();
    let install = &genesis.modules.0[0];
    assert_eq!(install.address, [0x42; 20]);
    assert_eq!(install.code_hash, keccak256(&code));
    assert_eq!(install.capabilities, capability::HOOKS);
    assert_eq!(install.init, 9u64.to_le_bytes());
    let params = GenesisParams::from_bytes(&genesis.params).unwrap();
    let account = &params.allocations.0[0];
    assert_eq!((account.balance, &account.code), (7, &code));

    let kernel = load_kernel("../orange-node/tests/fixtures/kernel.elf").unwrap();
    let config = NodeConfig {
        key: Some(dev_key()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(&kernel, &genesis, config).unwrap();
    assert_eq!(
        node.code(&[0x42; 20]).unwrap(),
        designator(&keccak256(&code))
    );
    let r = node
        .call(&CallRequest {
            to: Some([0x42; 20]),
            data: keccak256(b"count()")[..4].to_vec(),
            ..CallRequest::default()
        })
        .unwrap();
    assert_eq!(r.output[31], 9);

    // Defaults, and a module without an alloc entry.
    let text = format!(
        r#"{{"chainId": 1, "modules": [{{"address": "{MODULE}", "code": "{}"}}]}}"#,
        hex(&code)
    );
    let genesis = parse_genesis(&text).unwrap();
    assert_eq!(genesis.modules.0[0].capabilities, 0);
    assert!(genesis.modules.0[0].init.is_empty());
}

#[test]
fn bad_modules_are_named() {
    let cases = [
        (r#""modules": 1"#, "modules must be an array"),
        (r#""modules": [1]"#, "a module must be an object"),
        (
            r#""modules": [{"code": "0x01"}]"#,
            "module address must be 20 bytes",
        ),
        (
            r#""modules": [{"address": "0x01", "code": "0x01"}]"#,
            "module address must be 20 bytes",
        ),
        (
            r#""modules": [{"address": 1, "code": "0x01"}]"#,
            "module address must be 0x hex",
        ),
        (
            &format!(r#""modules": [{{"address": "{MODULE}"}}]"#),
            "module code missing",
        ),
        (
            &format!(r#""modules": [{{"address": "{MODULE}", "code": "0x"}}]"#),
            "module code missing",
        ),
        (
            &format!(
                r#""modules": [{{"address": "{MODULE}", "code": "0x01", "capabilities": -1}}]"#
            ),
            "module capabilities",
        ),
        (
            &format!(r#""modules": [{{"address": "{MODULE}", "code": "0x01", "init": "zz"}}]"#),
            "module init must be 0x hex",
        ),
        (
            &format!(
                r#""alloc": {{"{MODULE}": {{"code": "0x00"}}}}, "modules": [{{"address": "{MODULE}", "code": "0x01"}}]"#
            ),
            "cannot also have alloc code",
        ),
    ];
    for (body, message) in cases {
        let text = format!(r#"{{"chainId": 1, {body}}}"#);
        let error = parse_genesis(&text).unwrap_err();
        assert!(error.contains(message), "{body}: {error}");
    }
}
