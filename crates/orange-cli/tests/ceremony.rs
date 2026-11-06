//! The genesis ceremony of a network of several operators (`orange key
//! generate`, `orange genesis operator|assemble|hash|verify`), every mistake
//! named; the genesis file's bootnodes, an observer's lasting node key and
//! a JSON-RPC without `orange_stop` on running nodes; and `orange snapshot
//! trust-key` against nodes that agree and disagree.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use orange_abi::chain::GenesisParams;
use orange_abi::{Decode, Encode};
use orange_cli::ceremony::{self, CARD_FORMAT, Operator};
use orange_cli::{USAGE, client, load_kernel, parse_genesis, parse_key, run, run_until};
use orange_rpc::methods::data;
use orange_scratch::Scratch;
use serde_json::{Value, json};

const KERNEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../orange-node/tests/fixtures/kernel.elf"
);
const CHAIN_ID: u64 = 7777;

fn args(list: &[&str]) -> Vec<String> {
    std::iter::once("orange")
        .chain(list.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn genesis(list: &[&str]) -> Result<String, String> {
    let mut all = vec!["genesis"];
    all.extend_from_slice(list);
    ceremony::run(&args(&all))
}

fn path(dir: &Scratch, name: &str) -> String {
    dir.join(name).to_str().unwrap().to_owned()
}

fn read_json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn write_json(path: &str, v: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
}

/// The kernel, recompiled once into `dir`.
fn kernel(dir: &Scratch) -> String {
    let kernel = path(dir, "kernel.orange");
    std::fs::write(&kernel, load_kernel(KERNEL).unwrap()).unwrap();
    kernel
}

/// A template as a coordinator writes it: staking with a threshold key,
/// the fee market, key-track governance and an allocation.
fn template() -> Value {
    json!({
        "name": "tangerine",
        "chainId": CHAIN_ID,
        "timestamp": 1_800_000_000u64,
        "slotMs": 1000,
        "alloc": {"0x1a642f0e3c3af545e7acbd38b07251b3990914f1": "1000000000000000000000000"},
        "governance": "0x1a642f0e3c3af545e7acbd38b07251b3990914f1",
        "upgradeDelay": 20,
        "epochBlocks": 600,
        "staking": {"epochBlocks": 600, "dkgPhaseBlocks": 60, "unbondingEpochs": 6, "maxKeyAge": 3},
        "fees": {"denominator": 125, "elasticity": 2, "minBaseFee": "1000000000"},
    })
}

/// Three operators' keys and cards, the first two with bootnode addresses.
fn operators(dir: &Scratch) -> Vec<(String, String)> {
    (0..3)
        .map(|i| {
            let key = path(dir, &format!("op-{i}.key"));
            run(&args(&["key", "generate", "--out", &key])).unwrap();
            let card = path(dir, &format!("op-{i}.json"));
            let chain = CHAIN_ID.to_string();
            let p2p = format!("10.0.0.{}:30333", i + 1);
            let mut list = vec![
                "operator",
                "--key-file",
                &key,
                "--name",
                &format!("op-{i}"),
                "--chain-id",
                &chain,
                "--out",
                &card,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
            if i < 2 {
                list.extend(["--p2p".to_owned(), p2p]);
            }
            let refs: Vec<&str> = list.iter().map(String::as_str).collect();
            let said = genesis(&refs).unwrap();
            assert!(
                said.starts_with(&format!("operator card of op-{i}")),
                "{said}"
            );
            (key, card)
        })
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn operators_assemble_and_verify_a_genesis() {
    let dir = Scratch::dir("ceremony", "flow");
    let kernel = kernel(&dir);
    let ops = operators(&dir);
    let template_path = path(&dir, "template.json");
    write_json(&template_path, &template());
    let assemble = |out: &str, order: &[usize]| {
        let mut list = vec![
            "assemble",
            "--template",
            &template_path,
            "--kernel",
            &kernel,
            "--out",
            out,
            "--bootnode",
            "10.0.0.9:30333",
            "--bootnode",
            "10.0.0.1:30333",
        ];
        for i in order {
            list.extend(["--operator", &ops[*i].1]);
        }
        genesis(&list).unwrap()
    };
    let out = path(&dir, "genesis.json");
    let said = assemble(&out, &[2, 0, 1]);
    let hash = said.rsplit(' ').next().unwrap().to_owned();
    assert!(
        said.starts_with(&format!(
            "genesis of chain {CHAIN_ID} with 3 validators written to {out}\ngenesis hash 0x"
        )),
        "{said}"
    );
    // The order of the cards does not matter: anyone re-assembles the same file.
    let again = path(&dir, "again.json");
    assemble(&again, &[1, 2, 0]);
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&again).unwrap());
    assert_eq!(
        genesis(&["hash", "--genesis", &out, "--kernel", &kernel]),
        Ok(hash.clone())
    );
    // What the genesis holds: the validators sorted, their DKG keys and
    // accounts, the template's own allocation and the bootnodes.
    let v = read_json(&out);
    let keys: Vec<_> = ops
        .iter()
        .map(|(k, _)| parse_key(std::fs::read_to_string(k).unwrap().trim()).unwrap())
        .collect();
    let mut ids: Vec<String> = keys
        .iter()
        .map(|k| data(&orange_node::validator_id(k)))
        .collect();
    ids.sort();
    assert_eq!(v["validators"], json!(ids));
    for key in &keys {
        let id = data(&orange_node::validator_id(key));
        assert_eq!(
            v["staking"]["keys"][&id],
            json!(data(&orange_node::keystore::encryption_key(key)))
        );
        assert_eq!(
            v["alloc"][data(&client::address(key))],
            json!(orange_cli::devnet::OPERATOR_FUNDING)
        );
    }
    assert_eq!(v["alloc"].as_object().unwrap().len(), 4);
    // The cards' addresses in validator order, then the extra ones not on a card.
    let mut cards: Vec<&str> = v["bootnodes"].as_array().unwrap()[..2]
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    cards.sort_unstable();
    assert_eq!(cards, ["10.0.0.1:30333", "10.0.0.2:30333"]);
    assert_eq!(v["bootnodes"][2], json!("10.0.0.9:30333"));
    assert_eq!(v["bootnodes"].as_array().unwrap().len(), 3);
    let parsed = parse_genesis(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(parsed.chain_id, CHAIN_ID);
    // Every operator verifies it with their key, and anyone with the cards.
    for (key, _) in &ops {
        let said = genesis(&[
            "verify",
            "--genesis",
            &out,
            "--kernel",
            &kernel,
            "--hash",
            &hash,
            "--key-file",
            key,
        ])
        .unwrap();
        assert!(said.contains("matches\n  your validator 0x"), "{said}");
        assert!(said.contains(
            "name \"tangerine\", chain id 7777, genesis time 1800000000, slot 1000 ms, 3 validators"
        ));
        assert!(said.contains("staking: epochs of 600 blocks, DKG phases of 60"));
    }
    let said = genesis(&[
        "verify",
        "--genesis",
        &out,
        "--kernel",
        &kernel,
        "--hash",
        &hash,
        "--operator",
        &ops[0].1,
        "--operator",
        &ops[1].1,
    ])
    .unwrap();
    assert!(said.contains("operator op-0 (0x"), "{said}");
    assert!(said.contains("operator op-1 (0x"), "{said}");
    assert!(said.contains("governance \"0x1a642f0e3c3af545e7acbd38b07251b3990914f1\" (key track)"));
    // `--genesis-time` sets the launch time, which changes the chain.
    let later = path(&dir, "later.json");
    let said = genesis(&[
        "assemble",
        "--template",
        &template_path,
        "--kernel",
        &kernel,
        "--out",
        &later,
        "--operator",
        &ops[0].1,
        "--genesis-time",
        "1900000000",
        "--operator-funding",
        "0x10",
    ])
    .unwrap();
    assert!(!said.ends_with(&hash));
    let v = read_json(&later);
    assert_eq!(v["timestamp"], json!(1_900_000_000u64));
    assert_eq!(v["bootnodes"], json!(["10.0.0.1:30333"]));
    assert_eq!(v["alloc"][data(&client::address(&keys[0]))], json!("0x10"));
    // A key file prints its public half.
    run(&args(&["key", "--key-file", &ops[0].0])).unwrap();
}

#[test]
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
fn every_ceremony_mistake_is_named() {
    let dir = Scratch::dir("ceremony", "mistakes");
    let kernel = kernel(&dir);
    let key = path(&dir, "op.key");
    // Keys: a file is never overwritten.
    assert_eq!(
        ceremony::generate_key(&args(&["key", "generate"])),
        Err("--out is required".to_owned())
    );
    ceremony::generate_key(&args(&["key", "generate", "--out", &key])).unwrap();
    assert!(
        ceremony::generate_key(&args(&["key", "generate", "--out", &key]))
            .unwrap_err()
            .ends_with("exists; a key file is never overwritten (move it away first)")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let unwritable = path(&dir, "no/such/dir/key");
    assert!(ceremony::generate_key(&args(&["key", "generate", "--out", &unwritable])).is_err());
    // Cards.
    let card = path(&dir, "card.json");
    let op = |extra: &[&str]| {
        let mut list = vec!["operator"];
        list.extend_from_slice(extra);
        genesis(&list).unwrap_err()
    };
    assert_eq!(op(&[]), "--key-file is required");
    assert_eq!(op(&["--key-file", &key]), "--name is required");
    assert!(op(&["--key-file", &key, "--name", "a b"]).contains("1 to 64 letters"));
    assert!(op(&["--key-file", &key, "--name", &"x".repeat(65)]).contains("1 to 64"));
    assert_eq!(
        op(&["--key-file", &key, "--name", "a"]),
        "--chain-id is required"
    );
    assert_eq!(
        op(&[
            "--key-file",
            &key,
            "--name",
            "a",
            "--chain-id",
            "1",
            "--p2p",
            "0.0.0.0:1"
        ]),
        "--p2p 0.0.0.0:1: expected an ip:port peers can dial or a host:port"
    );
    assert_eq!(
        op(&["--key-file", &key, "--name", "a", "--chain-id", "1"]),
        "--out is required"
    );
    assert!(
        op(&[
            "--key-file",
            &key,
            "--name",
            "a",
            "--chain-id",
            "1",
            "--out",
            &unwritable
        ])
        .starts_with(&unwritable)
    );
    let chain = CHAIN_ID.to_string();
    genesis(&[
        "operator",
        "--key-file",
        &key,
        "--name",
        "op",
        "--chain-id",
        &chain,
        "--out",
        &card,
        "--p2p",
        "10.0.0.1:30333",
    ])
    .unwrap();
    let good = read_json(&card);
    assert_eq!(good["format"], json!(CARD_FORMAT));
    let operator = ceremony::read_card(&good, CHAIN_ID).unwrap();
    assert_eq!(operator.name, "op");
    let bad = |edit: &dyn Fn(&mut Value)| {
        let mut card = good.clone();
        edit(&mut card);
        ceremony::read_card(&card, CHAIN_ID).unwrap_err()
    };
    assert_eq!(
        bad(&|c| c["format"] = json!("x")),
        "format is not orange-operator-1"
    );
    assert_eq!(
        bad(&|c| c["chainId"] = json!(1)),
        "made for chain id 1, not 7777"
    );
    assert_eq!(
        bad(&|c| {
            c.as_object_mut().unwrap().remove("chainId");
        }),
        "made for chain id none, not 7777"
    );
    assert_eq!(
        bad(&|c| {
            c.as_object_mut().unwrap().remove("name");
        }),
        "name missing"
    );
    assert!(bad(&|c| c["name"] = json!("")).contains("1 to 64"));
    assert_eq!(
        bad(&|c| c["p2p"] = json!("nowhere")),
        "p2p must be an ip:port peers can dial or a host:port"
    );
    assert_eq!(
        bad(&|c| c["validator"] = json!("0x00")),
        "validator must be 0x hex of 32 bytes"
    );
    assert_eq!(
        bad(&|c| c["dkgKey"] = json!(7)),
        "dkgKey must be 0x hex of 48 bytes"
    );
    assert_eq!(
        bad(&|c| c["address"] = json!(format!("0x{}", "00".repeat(20)))),
        "address is not the validator's account"
    );
    assert_eq!(
        bad(&|c| c["signature"] = json!("0x")),
        "signature must be 0x hex of 65 bytes"
    );
    // A card edited after signing, or signed for someone else, is refused.
    assert_eq!(
        bad(&|c| c["name"] = json!("other")),
        "signature is not the validator's"
    );
    assert_eq!(
        bad(&|c| {
            c.as_object_mut().unwrap().remove("p2p");
        }),
        "signature is not the validator's"
    );
    // Assembly.
    let template_path = path(&dir, "template.json");
    write_json(&template_path, &template());
    let out = path(&dir, "genesis.json");
    let asm = |extra: &[&str]| {
        let mut list = vec!["assemble"];
        list.extend_from_slice(extra);
        genesis(&list).unwrap_err()
    };
    let nowhere = path(&dir, "nowhere.json");
    assert_eq!(asm(&[]), "--template is required");
    assert!(asm(&["--template", &nowhere]).starts_with(&nowhere));
    let not_json = path(&dir, "not.json");
    std::fs::write(&not_json, "{").unwrap();
    assert_eq!(
        asm(&["--template", &not_json]),
        format!("{not_json}: not valid JSON")
    );
    let array = path(&dir, "array.json");
    write_json(&array, &json!([]));
    assert_eq!(
        asm(&["--template", &array]),
        format!("{array}: not a JSON object")
    );
    assert_eq!(asm(&["--template", &template_path]), "--kernel is required");
    let base = [
        "--template",
        template_path.as_str(),
        "--kernel",
        kernel.as_str(),
    ];
    let with = |extra: &[&str]| {
        let mut list = base.to_vec();
        list.extend_from_slice(extra);
        asm(&list)
    };
    assert_eq!(with(&[]), "--out is required");
    let no_chain = path(&dir, "no-chain.json");
    write_json(&no_chain, &json!({"slotMs": 1}));
    assert_eq!(
        asm(&["--template", &no_chain, "--kernel", &kernel, "--out", &out]),
        format!("{no_chain}: chainId missing")
    );
    assert_eq!(
        with(&["--out", &out]),
        "--operator <card.json> is required, once per validator"
    );
    assert!(with(&["--out", &out, "--operator", &nowhere]).starts_with(&nowhere));
    let wrong_chain = path(&dir, "wrong-chain.json");
    let mut other = good.clone();
    other["chainId"] = json!(1);
    write_json(&wrong_chain, &other);
    assert_eq!(
        with(&["--out", &out, "--operator", &wrong_chain]),
        format!("{wrong_chain}: made for chain id 1, not 7777")
    );
    assert_eq!(
        with(&[
            "--out",
            &out,
            "--operator",
            &card,
            "--operator-funding",
            "lots"
        ]),
        "--operator-funding lots: expected an amount in wei, decimal or 0x hex"
    );
    assert_eq!(
        with(&["--out", &out, "--operator", &card, "--bootnode", "x"]),
        "--bootnode x: expected an ip:port peers can dial or a host:port"
    );
    assert_eq!(
        with(&["--out", &out, "--operator", &card, "--operator", &card]),
        format!("validator {} is on two cards", data(&operator.id))
    );
    assert!(with(&["--out", &unwritable, "--operator", &card]).starts_with(&unwritable));
    // A template that names what the cards name, or that the kernel refuses.
    let mut t = template();
    t["validators"] = json!([]);
    write_json(&template_path, &t);
    assert_eq!(
        with(&["--out", &out, "--operator", &card]),
        "template: names validators; the operators' cards name them"
    );
    let mut t = template();
    t["staking"]["keys"] = json!({});
    write_json(&template_path, &t);
    assert_eq!(
        with(&["--out", &out, "--operator", &card]),
        "template: names staking.keys; the operators' cards name them"
    );
    let mut t = template();
    t["alloc"] = json!([]);
    write_json(&template_path, &t);
    assert_eq!(
        with(&["--out", &out, "--operator", &card]),
        "template: alloc must be an object"
    );
    let mut t = template();
    t["staking"]["dkgPhaseBlocks"] = json!(200);
    write_json(&template_path, &t);
    assert!(
        with(&["--out", &out, "--operator", &card]).contains("four DKG phases must fit an epoch")
    );
    let mut t = template();
    t["bootnodes"] = json!("x");
    write_json(&template_path, &t);
    assert_eq!(
        with(&["--out", &out, "--operator", &card]),
        "genesis: bootnodes must be a list of ip:port addresses peers can dial or host:port names"
    );
    // A template without staking gets no DKG keys; one that funds an
    // operator keeps its amount, whatever the case of its address.
    let mut t = template();
    t.as_object_mut().unwrap().remove("staking");
    let address = data(&operator.address())
        .to_uppercase()
        .replacen("0X", "0x", 1);
    t["alloc"][&address] = json!("5");
    write_json(&template_path, &t);
    genesis(&{
        let mut list = vec!["assemble"];
        list.extend(base);
        list.extend(["--out", &out, "--operator", &card]);
        list
    })
    .unwrap();
    let v = read_json(&out);
    assert!(v.get("staking").is_none());
    // Without staking there are no DKG keys to check, only the set.
    let plain = genesis(&["hash", "--genesis", &out, "--kernel", &kernel]).unwrap();
    let said = genesis(&[
        "verify",
        "--genesis",
        &out,
        "--kernel",
        &kernel,
        "--hash",
        &plain,
        "--key-file",
        &key,
    ])
    .unwrap();
    assert!(said.contains("your validator"), "{said}");
    assert_eq!(v["alloc"][&address], json!("5"));
    assert_eq!(v["alloc"].as_object().unwrap().len(), 2);
    // The library refuses what no file reaches it with.
    assert_eq!(
        ceremony::assemble(&json!([]), &[], "1", &[]),
        Err("template: not a JSON object".to_owned())
    );
    // A template without an allocation gets one.
    assert_eq!(
        ceremony::assemble(&json!({"chainId": 1}), &[], "1", &[]).unwrap()["alloc"],
        json!({})
    );
    assert!(
        ceremony::genesis_hash(b"not a kernel", r#"{"chainId": 1}"#)
            .unwrap_err()
            .starts_with("the kernel refuses this genesis: "),
    );
    // A bootnode may be a name, which nodes resolve at every dial (spec 09
    // §5a.5), and so may a card's p2p address, which its signature covers.
    let named =
        ceremony::bootnodes(&json!({"bootnodes": ["seed.example.org:30333", "10.0.0.1:1"]}));
    let named: Vec<String> = named.unwrap().iter().map(ToString::to_string).collect();
    assert_eq!(named, ["seed.example.org:30333", "10.0.0.1:1"]);
    {
        let key = k256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap();
        let p2p = "orange-0.example.org:30333".parse().ok();
        let card = ceremony::card(&key, "a", 1, p2p.clone()).unwrap();
        assert_eq!(card["p2p"], json!("orange-0.example.org:30333"));
        assert_eq!(ceremony::read_card(&card, 1).unwrap().p2p, p2p);
    }
    assert_eq!(
        ceremony::bootnodes(&json!({"bootnodes": ["0.0.0.0:1"]})),
        Err("genesis: bootnodes must be a list of ip:port addresses peers can dial or host:port names".to_owned())
    );
    // A name is a chain name, and the kernel refuses any other one that
    // reaches it.
    for name in [
        json!("Tangerine"),
        json!(""),
        json!(5),
        json!("x".repeat(33)),
    ] {
        let mut t = template();
        t["name"] = name.clone();
        write_json(&template_path, &t);
        assert_eq!(
            with(&["--out", &out, "--operator", &card]),
            "genesis: name must be 1 to 32 bytes of lower-case letters, digits and '-', starting with a letter",
            "{name}"
        );
    }
    let mut named = parse_genesis(r#"{"chainId": 1, "name": "tangerine"}"#).unwrap();
    let mut params = GenesisParams::from_bytes(&named.params).unwrap();
    assert_eq!(params.name, b"tangerine");
    params.name = b"Not-A-Name".to_vec();
    named.params = params.to_bytes();
    let module = std::fs::read(&kernel).unwrap();
    assert!(orange_node::Node::open(&module, &named, orange_node::NodeConfig::default()).is_err());
    // Verification.
    write_json(&template_path, &template());
    genesis(&{
        let mut list = vec!["assemble"];
        list.extend(base);
        list.extend(["--out", &out, "--operator", &card]);
        list
    })
    .unwrap();
    let hash = genesis(&["hash", "--genesis", &out, "--kernel", &kernel]).unwrap();
    let verify = |extra: &[&str]| {
        let mut list = vec!["verify"];
        list.extend_from_slice(extra);
        genesis(&list).unwrap_err()
    };
    assert_eq!(verify(&[]), "--genesis is required");
    assert!(verify(&["--genesis", &nowhere]).starts_with(&nowhere));
    assert_eq!(verify(&["--genesis", &out]), "--kernel is required");
    let g = ["--genesis", out.as_str(), "--kernel", kernel.as_str()];
    let with = |extra: &[&str]| {
        let mut list = g.to_vec();
        list.extend_from_slice(extra);
        verify(&list)
    };
    assert_eq!(with(&[]), "--hash is required");
    assert_eq!(
        with(&["--hash", "0x12"]),
        "--hash must be 32 bytes of 0x hex"
    );
    let zero = format!("0x{}", "00".repeat(32));
    assert_eq!(
        with(&["--hash", &zero]),
        format!("{out}: genesis hash {hash} is not the published {zero}")
    );
    let stranger = path(&dir, "stranger.key");
    ceremony::generate_key(&args(&["key", "generate", "--out", &stranger])).unwrap();
    assert!(
        with(&["--hash", &hash, "--key-file", &stranger]).contains("is not in the genesis set")
    );
    assert!(with(&["--hash", &hash, "--operator", &nowhere]).starts_with(&nowhere));
    assert_eq!(
        with(&["--hash", &hash, "--operator", &wrong_chain]),
        format!("{wrong_chain}: made for chain id 1, not 7777")
    );
    let stranger_card = path(&dir, "stranger.json");
    genesis(&[
        "operator",
        "--key-file",
        &stranger,
        "--name",
        "s",
        "--chain-id",
        &chain,
        "--out",
        &stranger_card,
    ])
    .unwrap();
    assert!(
        with(&["--hash", &hash, "--operator", &stranger_card])
            .starts_with(&format!("{stranger_card}: validator 0x"))
    );
    // A genesis whose DKG key for a validator is not the one its key
    // derives would leave that validator without a share.
    let mut v = read_json(&out);
    let id = data(&operator.id);
    let theirs = read_json(&stranger_card)["dkgKey"].clone();
    v["staking"]["keys"][&id] = theirs;
    let tampered = path(&dir, "tampered.json");
    write_json(&tampered, &v);
    let hash = genesis(&["hash", "--genesis", &tampered, "--kernel", &kernel]).unwrap();
    assert!(
        verify(&[
            "--genesis",
            &tampered,
            "--kernel",
            &kernel,
            "--hash",
            &hash,
            "--key-file",
            &key
        ])
        .contains("lists another DKG key for validator")
    );
    assert_eq!(
        genesis(&["hash", "--genesis", &out]),
        Err("--kernel is required".to_owned())
    );
    assert_eq!(genesis(&["hash"]), Err("--genesis is required".to_owned()));
    assert_eq!(genesis(&["nonsense"]), Err(USAGE.to_owned()));
    // The devnet's validators are operators too, in node order.
    let k = parse_key(&"51".repeat(32)).unwrap();
    let o = Operator::of_key(&k, "node-0", None);
    assert_eq!(o.address(), client::address(&k));
}

fn free_ports(n: usize) -> Vec<String> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect()
}

/// A validator finds an observer through the genesis file's bootnodes
/// alone; the observer keeps the node key of its file, serves no
/// `orange_stop` (`--no-rpc-stop` wins over `--rpc-stop`), and the node
/// options around them name their mistakes.
#[test]
#[allow(clippy::too_many_lines)]
fn nodes_dial_the_genesis_bootnodes() {
    let dir = Scratch::dir("ceremony", "bootnodes");
    let kernel = kernel(&dir);
    let seed = "61".repeat(32);
    let validator = parse_key(&seed).unwrap();
    let [v_p2p, v_rpc, o_p2p, o_rpc]: [String; 4] = free_ports(4).try_into().unwrap();
    let genesis_path = path(&dir, "genesis.json");
    write_json(
        &genesis_path,
        &json!({
            "name": "tangerine", "chainId": CHAIN_ID, "slotMs": 200, "alloc": {},
            "validators": [data(&orange_node::validator_id(&validator))],
            // The validator's own address, which it skips, and the observer's twice.
            "bootnodes": [v_p2p, o_p2p, o_p2p],
        }),
    );
    let node_key = path(&dir, "node.key");
    ceremony::generate_key(&args(&["key", "generate", "--out", &node_key])).unwrap();
    let base = |p2p: &str, rpc: &str| -> Vec<String> {
        args(&[
            "node",
            "--kernel",
            &kernel,
            "--genesis",
            &genesis_path,
            "--listen",
            p2p,
            "--rpc",
            rpc,
        ])
    };
    let mut observer = base(&o_p2p, &o_rpc);
    observer.extend(
        [
            "--node-key-file",
            &node_key,
            "--rpc-stop",
            "--no-rpc-stop",
            "--data-dir",
            &path(&dir, "obs"),
        ]
        .map(str::to_owned),
    );
    let done = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&done);
    let observer_thread = std::thread::spawn(move || {
        run_until(&observer, |_| !stop.load(Ordering::SeqCst)).unwrap();
    });
    let mut validator_args = base(&v_p2p, &v_rpc);
    validator_args.extend(
        [
            "--key",
            &seed,
            "--data-dir",
            &path(&dir, "val"),
            "--rpc-stop",
        ]
        .map(str::to_owned),
    );
    let validator_thread = std::thread::spawn(move || run_until(&validator_args, |_| true));
    let deadline = Instant::now() + Duration::from_mins(3);
    let connected = loop {
        let peered = |rpc: &str| {
            client::status(rpc).is_ok_and(|s| s.peers >= 1 && s.chain_name == "tangerine")
        };
        if peered(&o_rpc) && peered(&v_rpc) {
            break true;
        }
        if Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // The observer refuses `orange_stop`; the validator takes it.
    let refused = client::call(&o_rpc, "orange_stop", &json!([])).unwrap_err();
    assert!(
        refused.contains("only when started with --rpc-stop"),
        "{refused}"
    );
    client::call(&v_rpc, "orange_stop", &json!([])).unwrap();
    done.store(true, Ordering::SeqCst);
    validator_thread.join().unwrap().unwrap();
    observer_thread.join().unwrap();
    assert!(connected, "the validator and the observer never connected");
    // The node key options.
    let with = |extra: &[&str]| {
        let mut list = base("127.0.0.1:0", "127.0.0.1:0");
        list.extend(extra.iter().map(|s| (*s).to_owned()));
        run(&list).unwrap_err()
    };
    assert_eq!(
        with(&[
            "--key",
            &seed,
            "--node-key-file",
            &node_key,
            "--data-dir",
            &path(&dir, "x")
        ]),
        "--node-key-file is for a node without a consensus key: a validator's node key is its consensus key"
    );
    let nowhere = path(&dir, "nowhere.key");
    assert!(with(&["--node-key-file", &nowhere]).starts_with(&nowhere));
    let bad = path(&dir, "bad.key");
    std::fs::write(&bad, "zz").unwrap();
    assert_eq!(
        with(&["--node-key-file", &bad]),
        "key: expected 64 hex digits"
    );
    assert_eq!(
        run(&args(&[
            "dev",
            "--kernel",
            &kernel,
            "--genesis",
            "g",
            "--node-key-file",
            "k"
        ]))
        .unwrap_err(),
        "orange dev does not take --node-key-file: it runs no peer-to-peer transport; use orange node"
    );
}

/// A JSON-RPC server that answers every `orange_getGroupKey` with `answer`.
fn fake_node(answer: Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = json!({"jsonrpc": "2.0", "id": 1, "result": answer}).to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
    });
    addr
}

#[test]
fn trust_key_needs_every_node_to_agree() {
    let key = |byte: &str| json!({"keyId": "0x2", "groupKey": format!("0x{}", byte.repeat(96))});
    let a = fake_node(key("aa"));
    let b = fake_node(key("aa"));
    let c = fake_node(key("cc"));
    let none = fake_node(Value::Null);
    let trust =
        |list: &str| orange_cli::snapshot::run(&args(&["snapshot", "trust-key", "--rpc", list]));
    // The key set, by id and group key, as --trust-key takes it.
    assert_eq!(
        trust(&format!("{a},{b}")),
        Ok(format!("2:0x{}", "aa".repeat(96)))
    );
    assert_eq!(trust(&a), Ok(format!("2:0x{}", "aa".repeat(96))));
    let no_id = fake_node(json!({"keyId": 2, "groupKey": format!("0x{}", "aa".repeat(96))}));
    assert_eq!(
        trust(&no_id),
        Err(format!("{no_id}: expected a quantity, got 2"))
    );
    let split = trust(&format!("{a}, {c}")).unwrap_err();
    assert!(
        split.starts_with("the nodes report different keys; ask again:"),
        "{split}"
    );
    assert!(split.contains("key set \"0x2\" 0xcccc"), "{split}");
    assert_eq!(
        trust(&none),
        Err(format!(
            "{none}: the chain has adopted no threshold key yet"
        ))
    );
    assert_eq!(trust(","), Err("--rpc names no node".to_owned()));
    assert!(trust("127.0.0.1:1").is_err());
    assert_eq!(
        orange_cli::snapshot::run(&args(&["snapshot", "trust-key"])),
        Err("--rpc <addr,...> is required".to_owned())
    );
}

/// `ops/networks.json`, the registry of launched networks: every entry is
/// named as a genesis names a chain, has a known kind, a chain id and a
/// genesis hash no other entry has, and a launch date.
#[test]
fn the_network_registry_is_well_formed() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ops/networks.json");
    let registry = read_json(path);
    assert!(registry["about"].is_string());
    let networks = registry["networks"].as_array().unwrap();
    let mut ids = Vec::new();
    let mut hashes = Vec::new();
    for n in networks {
        let name = n["name"].as_str().unwrap();
        assert!(
            !name.is_empty() && orange_abi::chain::valid_chain_name(name.as_bytes()),
            "{n}"
        );
        assert!(
            ["devnet", "testnet", "mainnet"].contains(&n["kind"].as_str().unwrap()),
            "{n}"
        );
        let id = n["chainId"].as_u64().unwrap();
        let hash = n["genesisHash"].as_str().unwrap();
        assert_eq!(
            orange_rpc::methods::parse_hex(hash).unwrap().len(),
            32,
            "{n}"
        );
        let date = n["launched"].as_str().unwrap();
        assert!(
            date.len() == 10 && date.as_bytes()[4] == b'-' && date.as_bytes()[7] == b'-',
            "{n}"
        );
        assert!(
            !ids.contains(&id) && !hashes.contains(&hash),
            "{n} repeats a chain id or hash"
        );
        ids.push(id);
        hashes.push(hash);
    }
}

const ORANGE_OPS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ops/testnet/orange-ops");
const REHEARSAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tools/rehearse-testnet.sh"
);

/// `orange-ops` with `args`: its status, stdout and stderr.
fn orange_ops(args: &[&str]) -> (bool, String, String) {
    let out = std::process::Command::new(ORANGE_OPS)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The deploy tooling reads an inventory, renders each host's node.env
/// and the Prometheus configuration, prints what it would run over ssh,
/// and names a malformed inventory's line.
#[test]
fn orange_ops_renders_and_dry_runs_an_inventory() {
    let dir = Scratch::dir("ceremony", "ops");
    let inventory = path(&dir, "inventory");
    std::fs::write(
        &inventory,
        "# hosts\n\
         val-a validator orange@192.0.2.10 192.0.2.10:30333 10.0.0.10:8545 key=a.key\n\
         boot-1 bootnode orange@192.0.2.20 192.0.2.20:30333 10.0.0.20:8545\n\
         rpc-1 rpc local 127.0.0.1:30399 127.0.0.1:8599 join=sync trust=10.0.0.10:8545 public-rpc=1\n",
    )
    .unwrap();
    let (ok, out, _) = orange_ops(&["--inventory", &inventory, "hosts"]);
    assert!(ok && out.lines().count() == 3, "{out}");
    let rendered = path(&dir, "rendered");
    let (ok, _, err) = orange_ops(&["--inventory", &inventory, "render", &rendered]);
    assert!(ok, "{err}");
    let env = std::fs::read_to_string(format!("{rendered}/rpc-1.env")).unwrap();
    for line in [
        "ORANGE_ROLE=rpc",
        "ORANGE_RPC=127.0.0.1:8599",
        "ORANGE_BOOTSTRAP=\"192.0.2.20:30333\"",
        "ORANGE_JOIN=sync",
        "ORANGE_TRUST_FROM=10.0.0.10:8545",
        "ORANGE_PUBLIC_RPC=1",
    ] {
        assert!(env.contains(line), "{line} not in {env}");
    }
    let prometheus = std::fs::read_to_string(format!("{rendered}/prometheus.yml")).unwrap();
    assert!(
        prometheus.contains("targets: [\"10.0.0.10:8545\"]"),
        "{prometheus}"
    );
    assert!(prometheus.contains("alerts.yml"));
    let (ok, out, _) = orange_ops(&[
        "--inventory",
        &inventory,
        "--dry-run",
        "--hosts",
        "val-a",
        "install",
        "--binary",
        "orange",
    ]);
    assert!(ok, "{out}");
    assert!(out.contains("+ scp -q -o BatchMode=yes"), "{out}");
    assert!(out.contains("orange-node.service"), "{out}");
    assert!(out.contains("install-binary"), "{out}");
    let (ok, out, _) = orange_ops(&[
        "--inventory",
        &inventory,
        "--dry-run",
        "--role",
        "rpc",
        "start",
    ]);
    assert!(
        ok && out.contains("ORANGE_SERVICE=process bash") && out.contains(" start"),
        "{out}"
    );
    let (ok, out, _) = orange_ops(&["--inventory", &inventory, "ansible-inventory"]);
    assert!(
        ok && out.contains("[orange_validator]\nval-a ansible_host=192.0.2.10"),
        "{out}"
    );
    for (text, message) in [
        (
            "a validator ssh p2p\n",
            "expected <name> <role> <ssh> <p2p> <rpc>",
        ),
        (
            "a miner ssh p2p rpc\n",
            "role miner is not validator, rpc or bootnode",
        ),
        (
            "a rpc ssh p2p rpc\na rpc ssh p2p rpc\n",
            "host a listed twice",
        ),
        (
            "a rpc ssh p2p rpc colour=red\n",
            "unknown option colour=red",
        ),
        ("# nothing\n", "lists no host"),
    ] {
        std::fs::write(&inventory, text).unwrap();
        let (ok, _, err) = orange_ops(&["--inventory", &inventory, "hosts"]);
        assert!(!ok && err.contains(message), "{text}: {err}");
    }
}

/// The whole rehearsal of ops/testnet/README.md on this machine: the
/// ceremony, deploy, a late joiner, an upgrade, a rolling restart and a
/// short steady state. It takes minutes, so it runs only when
/// `ORANGE_REHEARSE_TESTNET` is set.
#[test]
fn the_testnet_rehearsal_passes_when_asked_for() {
    if std::env::var_os("ORANGE_REHEARSE_TESTNET").is_none() {
        eprintln!("skipped: set ORANGE_REHEARSE_TESTNET=1 to run tools/rehearse-testnet.sh");
        return;
    }
    let dir = Scratch::new("ceremony", "rehearsal");
    let out = std::process::Command::new(REHEARSAL)
        .arg(dir.str())
        .env("ORANGE_BIN", env!("CARGO_BIN_EXE_orange"))
        .env("SOAK", "20")
        .env("LOAD", "0")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stdout.matches("PASS ").count(), 8, "{stdout}");
}
