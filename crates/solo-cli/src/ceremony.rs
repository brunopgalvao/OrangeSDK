//! `solo genesis`: the genesis ceremony of a network whose validators are run
//! by different operators, none of whom sees another's secret key.
//!
//! ```text
//! solo key generate --out <key file>                      # each operator, on their own machine
//! solo genesis operator --key-file <key> --name <name> --chain-id <id> [--p2p <ip:port>] --out <card.json>
//! solo genesis assemble --template <template.json> --kernel <kernel> --operator <card.json>...
//!                       [--bootnode <ip:port>]... [--genesis-time <unix seconds>]
//!                       [--operator-funding <wei>] --out <genesis.json>   # the coordinator
//! solo genesis hash --genesis <genesis.json> --kernel <kernel>
//! solo genesis verify --genesis <genesis.json> --kernel <kernel> --hash <0x genesis hash>
//!                     [--key-file <key>] [--operator <card.json>]...     # every operator
//! ```
//!
//! An operator's consensus key is the one secret of a validator: its id
//! (spec 08 §2) is the hash of its public key, the account it signals and
//! votes from is that id's last 20 bytes (spec 13 §2.2), its node key on the
//! transport is the same key (spec 09 §3), and the encryption key its DKG
//! shares are dealt to is derived from it (spec 15 §2). The threshold key
//! itself is generated on chain by the first DKG, so no BLS secret exists
//! before the chain runs. `solo genesis operator` writes the operator's
//! *card*, the public half alone:
//!
//! ```json
//! {"format": "solo-operator-1", "chainId": 7777, "name": "op-a",
//!  "validator": "0x<32 bytes>", "address": "0x<20 bytes>", "dkgKey": "0x<48 bytes>",
//!  "p2p": "203.0.113.10:30333", "signature": "0x<65 bytes>"}
//! ```
//!
//! signed with the consensus key over [`card_digest`], so the coordinator
//! knows each card comes from the holder of its key and is meant for this
//! chain. `p2p`, optional, is the address the operator's node listens on for
//! peers, listed in the genesis as a bootnode.
//!
//! `assemble` reads a *template*, a genesis file without validators (its
//! chain id, genesis time, slot, fee market, staking epochs, governance and
//! allocations), checks every card, and writes the genesis: the cards'
//! validators sorted by id, each one's DKG key under `staking.keys` when the
//! template has a `staking` object, each one's account funded with
//! `--operator-funding` wei (a thousand ether by default, for its gate
//! signals and votes at the base fee) unless the template funds it, and
//! `bootnodes`: the template's, the cards' `p2p` addresses and any
//! `--bootnode`. Sorting
//! makes the output independent of the order of the cards, so anyone holding
//! the published cards and template assembles the same file. It runs the
//! genesis through the kernel's `kernel_init`, so a genesis the kernel
//! refuses fails here, and prints the *genesis hash*, the chain's identity
//! (spec 20 §3.4), which the coordinator publishes with the file.
//!
//! `verify` is every operator's check before starting a node: the file
//! parses, the kernel accepts it, its genesis hash is the published one,
//! and, with `--key-file`, the operator's validator is in the set with the
//! DKG key its key derives (a validator whose DKG key is wrong would hold
//! no share); with `--operator`, every card given verifies and is in the
//! set with its DKG key. It prints what the genesis sets, for the operator
//! to read before trusting it.
//!
//! `bootnodes` is read by `solo node`, which dials them for peer exchange
//! beside its `--bootstrap` addresses (spec 09 §5a). It is not part of the
//! chain's state, so the genesis hash does not cover it: a bootnode is only
//! a first address to ask, and a peer of another chain fails the handshake
//! (spec 09 §3).

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;

use k256::ecdsa::SigningKey;
use serde_json::{Map, Value, json};
use solo_host::hash::keccak256;
use solo_rpc::methods::{data, parse_hex};

use crate::{arg, args_all, key_argument, load_kernel, parse_genesis};

/// The `format` of an operator card.
pub const CARD_FORMAT: &str = "solo-operator-1";

/// The domain of a card's signature.
pub const CARD_DOMAIN: &[u8] = b"SOLO-OPERATOR";

/// Longest operator name.
pub const MAX_NAME: usize = 64;

/// One validator of a genesis: what a card says, its signature checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    /// A name for people.
    pub name: String,
    /// Validator id.
    pub id: [u8; 32],
    /// DKG encryption key (spec 15 §2), 48 bytes.
    pub dkg_key: Vec<u8>,
    /// The address its node listens on for peers, if it serves as a bootnode.
    pub p2p: Option<SocketAddr>,
}

impl Operator {
    /// The operator holding `key`.
    #[must_use]
    pub fn of_key(key: &SigningKey, name: &str, p2p: Option<SocketAddr>) -> Operator {
        Operator {
            name: name.to_owned(),
            id: solo_node::validator_id(key),
            dkg_key: solo_node::keystore::encryption_key(key).to_vec(),
            p2p,
        }
    }

    /// The account of the validator: the last 20 bytes of its id.
    ///
    /// # Panics
    /// Never: an id is 32 bytes.
    #[must_use]
    pub fn address(&self) -> [u8; 20] {
        self.id[12..].try_into().expect("20 bytes")
    }
}

/// What a card's signature covers: `keccak256("SOLO-OPERATOR" ‖ chain id
/// (u64, big-endian) ‖ name length (u32, big-endian) ‖ name ‖ DKG key ‖
/// p2p address length (u32, big-endian) ‖ p2p address as text)`, the
/// address empty when the card names none.
#[must_use]
pub fn card_digest(chain_id: u64, operator: &Operator) -> [u8; 32] {
    let p2p = operator.p2p.map(|a| a.to_string()).unwrap_or_default();
    let len = |b: &[u8]| u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes();
    keccak256(
        &[
            CARD_DOMAIN,
            &chain_id.to_be_bytes(),
            &len(operator.name.as_bytes()),
            operator.name.as_bytes(),
            &operator.dkg_key,
            &len(p2p.as_bytes()),
            p2p.as_bytes(),
        ]
        .concat(),
    )
}

/// The card of the operator holding `key`, signed.
///
/// # Errors
/// If the name is not a valid name.
pub fn card(
    key: &SigningKey,
    name: &str,
    chain_id: u64,
    p2p: Option<SocketAddr>,
) -> Result<Value, String> {
    check_name(name)?;
    let operator = Operator::of_key(key, name, p2p);
    let signature = solo_node::sign_recoverable(key, &card_digest(chain_id, &operator))
        .ok_or("card: the key cannot sign")?;
    let mut card = json!({
        "format": CARD_FORMAT,
        "chainId": chain_id,
        "name": name,
        "validator": data(&operator.id),
        "address": data(&operator.address()),
        "dkgKey": data(&operator.dkg_key),
        "signature": data(&signature),
    });
    if let Some(p2p) = p2p {
        card["p2p"] = json!(p2p.to_string());
    }
    Ok(card)
}

fn check_name(name: &str) -> Result<(), String> {
    let fine = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    if name.is_empty() || name.len() > MAX_NAME || !name.chars().all(fine) {
        return Err(format!(
            "operator name {name:?}: 1 to {MAX_NAME} letters, digits, '.', '_' or '-'"
        ));
    }
    Ok(())
}

fn hex_field(card: &Value, field: &str, len: usize) -> Result<Vec<u8>, String> {
    card.get(field)
        .and_then(Value::as_str)
        .and_then(|s| parse_hex(s).ok())
        .filter(|b| b.len() == len)
        .ok_or_else(|| format!("{field} must be 0x hex of {len} bytes"))
}

/// Reads a card and checks it: its format, its fields, the chain id it was
/// made for and the signature, which must recover to the validator it names.
///
/// # Errors
/// What is wrong with it.
///
/// # Panics
/// Never: the fields are checked for their lengths first.
pub fn read_card(card: &Value, chain_id: u64) -> Result<Operator, String> {
    if card.get("format").and_then(Value::as_str) != Some(CARD_FORMAT) {
        return Err(format!("format is not {CARD_FORMAT}"));
    }
    let made_for = card.get("chainId").and_then(Value::as_u64);
    if made_for != Some(chain_id) {
        return Err(format!(
            "made for chain id {}, not {chain_id}",
            made_for.map_or("none".to_owned(), |c| c.to_string())
        ));
    }
    let name = card
        .get("name")
        .and_then(Value::as_str)
        .ok_or("name missing")?;
    check_name(name)?;
    let p2p = match card.get("p2p") {
        None => None,
        Some(addr) => Some(
            addr.as_str()
                .and_then(|a| a.parse().ok())
                .filter(solo_node::peers::dialable)
                .ok_or("p2p must be an ip:port peers can dial")?,
        ),
    };
    let operator = Operator {
        name: name.to_owned(),
        id: hex_field(card, "validator", 32)?
            .try_into()
            .expect("32 bytes"),
        dkg_key: hex_field(card, "dkgKey", 48)?,
        p2p,
    };
    if hex_field(card, "address", 20)? != operator.address() {
        return Err("address is not the validator's account".to_owned());
    }
    let signature: [u8; 65] = hex_field(card, "signature", 65)?
        .try_into()
        .expect("65 bytes");
    let signer = solo_node::peers::recover_id(&card_digest(chain_id, &operator), &signature);
    if signer != Some(operator.id) {
        return Err("signature is not the validator's".to_owned());
    }
    Ok(operator)
}

/// The genesis document of `template` with `operators` as its validators:
/// their ids under `validators` in the order given, their DKG keys under
/// `staking.keys` when the template has `staking`, their accounts funded
/// with `funding` wei where the template's `alloc` does not name them, and
/// `bootnodes`, the template's own, their `p2p` addresses and then
/// `extra_bootnodes`, each once, when there are any.
///
/// # Errors
/// If the template is not an object, names validators or DKG keys of its
/// own, or lists an operator twice.
pub fn assemble(
    template: &Value,
    operators: &[Operator],
    funding: &str,
    extra_bootnodes: &[SocketAddr],
) -> Result<Value, String> {
    let mut genesis = template.clone();
    let Some(fields) = genesis.as_object_mut() else {
        return Err("template: not a JSON object".to_owned());
    };
    if fields.contains_key("validators") {
        return Err("template: names validators; the operators' cards name them".to_owned());
    }
    for (i, operator) in operators.iter().enumerate() {
        if operators[..i].iter().any(|o| o.id == operator.id) {
            return Err(format!("validator {} is on two cards", data(&operator.id)));
        }
    }
    let ids: Vec<Value> = operators.iter().map(|o| json!(data(&o.id))).collect();
    fields.insert("validators".to_owned(), Value::Array(ids));
    if let Some(staking) = fields.get_mut("staking").and_then(Value::as_object_mut) {
        if staking.contains_key("keys") {
            return Err("template: names staking.keys; the operators' cards name them".to_owned());
        }
        let keys: Map<String, Value> = operators
            .iter()
            .map(|o| (data(&o.id), json!(data(&o.dkg_key))))
            .collect();
        staking.insert("keys".to_owned(), Value::Object(keys));
    }
    let alloc = fields
        .entry("alloc")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(alloc) = alloc.as_object_mut() else {
        return Err("template: alloc must be an object".to_owned());
    };
    for operator in operators {
        let address = data(&operator.address());
        let named = alloc.keys().any(|a| a.eq_ignore_ascii_case(&address));
        if !named {
            alloc.insert(address, json!(funding));
        }
    }
    let mut bootnodes: Vec<String> = Vec::new();
    let listed = bootnodes_of(template)?;
    let addresses = operators.iter().filter_map(|o| o.p2p);
    for addr in listed
        .into_iter()
        .chain(addresses)
        .chain(extra_bootnodes.iter().copied())
    {
        let addr = addr.to_string();
        if !bootnodes.contains(&addr) {
            bootnodes.push(addr);
        }
    }
    if !bootnodes.is_empty() {
        fields.insert("bootnodes".to_owned(), json!(bootnodes));
    }
    Ok(genesis)
}

/// The `bootnodes` of a genesis document: the addresses `solo node` dials
/// for peer exchange beside its `--bootstrap` ones; none without the field.
///
/// # Errors
/// If it is not a list of `ip:port` addresses peers can dial.
pub fn bootnodes(v: &Value) -> Result<Vec<SocketAddr>, String> {
    bootnodes_of(v)
}

fn bootnodes_of(v: &Value) -> Result<Vec<SocketAddr>, String> {
    let Some(list) = v.get("bootnodes") else {
        return Ok(Vec::new());
    };
    let wrong = || "genesis: bootnodes must be a list of ip:port addresses peers can dial";
    list.as_array()
        .ok_or_else(wrong)?
        .iter()
        .map(|a| {
            a.as_str()
                .and_then(|a| a.parse().ok())
                .filter(solo_node::peers::dialable)
                .ok_or_else(wrong)
        })
        .collect::<Result<_, _>>()
        .map_err(str::to_owned)
}

/// The genesis hash of the chain `genesis_text` describes under `kernel`:
/// what the kernel's `kernel_init` stores as block 0's hash (spec 20 §3.4).
///
/// # Errors
/// If the genesis does not parse or the kernel refuses it.
pub fn genesis_hash(kernel: &[u8], genesis_text: &str) -> Result<[u8; 32], String> {
    let genesis = parse_genesis(genesis_text)?;
    let node = solo_node::Node::open(kernel, &genesis, solo_node::NodeConfig::default())
        .map_err(|e| format!("the kernel refuses this genesis: {e}"))?;
    Ok(node.genesis_hash())
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn json_file(path: &str) -> Result<Value, String> {
    serde_json::from_str(&read(path)?).map_err(|_| format!("{path}: not valid JSON"))
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    arg(args, name).ok_or_else(|| format!("{name} is required"))
}

fn kernel_argument(args: &[String]) -> Result<Vec<u8>, String> {
    load_kernel(&required(args, "--kernel")?)
}

fn p2p_argument(args: &[String], flag: &str) -> Result<Vec<SocketAddr>, String> {
    args_all(args, flag)
        .iter()
        .map(|a| {
            a.parse()
                .ok()
                .filter(solo_node::peers::dialable)
                .ok_or_else(|| format!("{flag} {a}: expected an ip:port peers can dial"))
        })
        .collect()
}

/// `solo genesis operator`.
fn operator_command(args: &[String]) -> Result<String, String> {
    let key = key_argument(args)?.ok_or("--key-file is required")?;
    let name = required(args, "--name")?;
    check_name(&name)?;
    let chain_id = crate::parse_number(args, "--chain-id")?.ok_or("--chain-id is required")?;
    let p2p = p2p_argument(args, "--p2p")?.first().copied();
    let out = required(args, "--out")?;
    let card = card(&key, &name, chain_id, p2p)?;
    let text = serde_json::to_string_pretty(&card).expect("json") + "\n";
    std::fs::write(&out, text).map_err(|e| format!("{out}: {e}"))?;
    Ok(format!(
        "operator card of {name} for chain {chain_id} written to {out}: validator {}, account {}{}",
        card["validator"].as_str().unwrap_or_default(),
        card["address"].as_str().unwrap_or_default(),
        p2p.map_or(String::new(), |a| format!(", bootnode {a}"))
    ))
}

/// `solo genesis assemble`.
fn assemble_command(args: &[String]) -> Result<String, String> {
    let template_path = required(args, "--template")?;
    let mut template = json_file(&template_path)?;
    if !template.is_object() {
        return Err(format!("{template_path}: not a JSON object"));
    }
    let kernel = kernel_argument(args)?;
    let out = required(args, "--out")?;
    if let Some(seconds) = crate::parse_number(args, "--genesis-time")? {
        template["timestamp"] = json!(seconds);
    }
    let chain_id = template
        .get("chainId")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{template_path}: chainId missing"))?;
    let cards = args_all(args, "--operator");
    if cards.is_empty() {
        return Err("--operator <card.json> is required, once per validator".to_owned());
    }
    let mut operators = Vec::new();
    for path in &cards {
        let card = json_file(path)?;
        operators.push(read_card(&card, chain_id).map_err(|e| format!("{path}: {e}"))?);
    }
    operators.sort_by_key(|o| o.id);
    let funding = arg(args, "--operator-funding")
        .unwrap_or_else(|| crate::devnet::OPERATOR_FUNDING.to_owned());
    crate::parse_balance(&json!(funding)).map_err(|_| {
        format!("--operator-funding {funding}: expected an amount in wei, decimal or 0x hex")
    })?;
    let extra = p2p_argument(args, "--bootnode")?;
    let genesis = assemble(&template, &operators, &funding, &extra)?;
    let text = serde_json::to_string_pretty(&genesis).expect("json") + "\n";
    let hash = genesis_hash(&kernel, &text)?;
    std::fs::write(&out, &text).map_err(|e| format!("{out}: {e}"))?;
    Ok(format!(
        "genesis of chain {chain_id} with {} validators written to {out}\ngenesis hash {}",
        operators.len(),
        data(&hash)
    ))
}

/// What a genesis sets, for an operator to read before trusting it.
fn summary(text: &str) -> String {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    let n = |path: &[&str]| {
        path.iter()
            .try_fold(&v, |v, k| v.get(*k))
            .map_or("-".to_owned(), ToString::to_string)
    };
    let validators = v
        .get("validators")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    format!(
        "  name {}, chain id {}, genesis time {}, slot {} ms, {validators} validators\n  staking: epochs of {} blocks, DKG phases of {}, unbonding {} epochs, max key age {}\n  governance {} ({} track), upgrade delay {}\n  fees {}\n  bootnodes {}",
        n(&["name"]),
        n(&["chainId"]),
        n(&["timestamp"]),
        n(&["slotMs"]),
        n(&["staking", "epochBlocks"]),
        n(&["staking", "dkgPhaseBlocks"]),
        n(&["staking", "unbondingEpochs"]),
        n(&["staking", "maxKeyAge"]),
        n(&["governance"]),
        v.get("governanceMode")
            .and_then(Value::as_str)
            .unwrap_or("key"),
        n(&["upgradeDelay"]),
        n(&["fees"]),
        n(&["bootnodes"]),
    )
}

/// Whether the genesis `v` lists validator `id` with DKG key `dkg_key`
/// (where it has a `staking` object, which lists the DKG keys).
fn check_listed(v: &Value, id: &[u8; 32], dkg_key: &[u8], who: &str) -> Result<(), String> {
    let id = data(id);
    let listed = v
        .get("validators")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|i| i.as_str() == Some(id.as_str())));
    if !listed {
        return Err(format!("{who}: validator {id} is not in the genesis set"));
    }
    if let Some(staking) = v.get("staking") {
        let listed = staking.get("keys").and_then(|k| k.get(&id));
        if listed.and_then(Value::as_str) != Some(data(dkg_key).as_str()) {
            return Err(format!(
                "{who}: the genesis lists another DKG key for validator {id}, or none"
            ));
        }
    }
    Ok(())
}

/// `solo genesis verify`.
fn verify_command(args: &[String]) -> Result<String, String> {
    let path = required(args, "--genesis")?;
    let text = read(&path)?;
    let kernel = kernel_argument(args)?;
    let expected = required(args, "--hash")?;
    let expected = parse_hex(&expected)
        .ok()
        .filter(|h| h.len() == 32)
        .ok_or("--hash must be 32 bytes of 0x hex")?;
    let hash = genesis_hash(&kernel, &text)?;
    if hash[..] != expected[..] {
        return Err(format!(
            "{path}: genesis hash {} is not the published {}",
            data(&hash),
            data(&expected)
        ));
    }
    let v: Value = serde_json::from_str(&text).expect("genesis_hash parsed it");
    let mut report = format!("{path}: genesis hash {} matches", data(&hash));
    if let Some(key) = key_argument(args)? {
        let mine = Operator::of_key(&key, "", None);
        check_listed(&v, &mine.id, &mine.dkg_key, "--key-file")?;
        let _ = write!(
            report,
            "\n  your validator {} is in the set",
            data(&mine.id)
        );
    }
    let chain_id = v.get("chainId").and_then(Value::as_u64).unwrap_or_default();
    for card_path in args_all(args, "--operator") {
        let operator = read_card(&json_file(&card_path)?, chain_id)
            .map_err(|e| format!("{card_path}: {e}"))?;
        check_listed(&v, &operator.id, &operator.dkg_key, &card_path)?;
        let _ = write!(
            report,
            "\n  operator {} ({}) is in the set",
            operator.name,
            data(&operator.id)
        );
    }
    report.push('\n');
    report.push_str(&summary(&text));
    Ok(report)
}

/// `solo genesis hash`.
fn hash_command(args: &[String]) -> Result<String, String> {
    let text = read(&required(args, "--genesis")?)?;
    let kernel = kernel_argument(args)?;
    Ok(data(&genesis_hash(&kernel, &text)?))
}

/// `solo key generate --out <file>`: a fresh consensus key, in a file only
/// its owner can read, which it refuses to overwrite.
///
/// # Errors
/// If `--out` is missing or exists, or the file cannot be written.
pub fn generate_key(args: &[String]) -> Result<String, String> {
    let out = required(args, "--out")?;
    if Path::new(&out).exists() {
        return Err(format!(
            "{out}: exists; a key file is never overwritten (move it away first)"
        ));
    }
    let key = solo_node::net::fresh_key()
        .ok()
        .ok_or("key: the operating system gave no randomness")?;
    let hex = data(&key.to_bytes())[2..].to_owned() + "\n";
    crate::devnet::write_secret(Path::new(&out), hex.as_bytes())?;
    Ok(format!(
        "{}\nkey written to {out} (mode 0600); back it up offline, it is the validator",
        crate::describe_key(&key)
    ))
}

/// Runs `solo genesis <subcommand>` and returns what it prints.
///
/// # Errors
/// A message naming the first problem.
pub fn run(args: &[String]) -> Result<String, String> {
    match args.get(2).map_or("", String::as_str) {
        "operator" => operator_command(args),
        "assemble" => assemble_command(args),
        "verify" => verify_command(args),
        "hash" => hash_command(args),
        _ => Err(crate::USAGE.to_owned()),
    }
}
