//! Ethereum state test fixtures (the `state_test` format of
//! execution-spec-tests), read into cases for the pinned fork.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Map, Value};
use solo_abi::chain::{Allocation, StorageSlot};
use solo_abi::codec::Seq;
use solo_abi::conformance::{Case, Env};
use solo_abi::types::Address;

/// The fork whose expectations are read: the one the reference kernel runs.
pub const FORK: &str = "Osaka";

/// An account of a pre- or post-state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Account {
    /// Balance, big-endian.
    pub balance: [u8; 32],
    /// Nonce.
    pub nonce: u64,
    /// Code.
    pub code: Vec<u8>,
    /// Storage, without zero slots.
    pub storage: BTreeMap<[u8; 32], [u8; 32]>,
}

/// A whole state, by address.
pub type State = BTreeMap<Address, Account>;

/// What the fixture expects of a case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// Ethereum state root after the transaction.
    pub state_root: [u8; 32],
    /// `keccak256(rlp(logs))`.
    pub logs_hash: [u8; 32],
    /// The exception the transaction is refused with, if it is invalid.
    pub exception: Option<String>,
    /// The full post-state, when the fixture carries it (for diagnostics).
    pub state: Option<State>,
}

/// One case: a fixture's pre-state and environment with one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCase {
    /// The fixture's name, with `#n` for its n-th expectation when it has several.
    pub id: String,
    /// The group results are reported under, from the test's path.
    pub category: String,
    /// Block environment.
    pub env: Env,
    /// Pre-state.
    pub pre: State,
    /// Signed transaction.
    pub tx: Vec<u8>,
    /// Expected outcome.
    pub expected: Expected,
}

impl TestCase {
    /// The transaction's EIP-2718 type: its first byte when that is below
    /// `0x7f`, 0 for a legacy transaction (an RLP list).
    #[must_use]
    pub fn tx_type(&self) -> u8 {
        match self.tx.first() {
            Some(&t) if t < 0x7f => t,
            _ => 0,
        }
    }

    /// The case as the conformance guest takes it.
    ///
    /// # Errors
    /// The kernel's accounts hold balances below 2^128; a pre-state with a
    /// larger balance cannot be expressed and is reported, never truncated.
    pub fn to_case(&self) -> Result<Case, String> {
        let mut allocations = Vec::new();
        for (address, account) in &self.pre {
            let Some(balance) = balance_u128(&account.balance) else {
                return Err(format!(
                    "pre-state balance of 0x{} does not fit the kernel's 128-bit balances",
                    hex(address)
                ));
            };
            allocations.push(Allocation {
                address: *address,
                balance,
                nonce: account.nonce,
                code: account.code.clone(),
                storage: Seq(account
                    .storage
                    .iter()
                    .map(|(key, value)| StorageSlot {
                        key: *key,
                        value: *value,
                    })
                    .collect()),
            });
        }
        Ok(Case {
            env: self.env.clone(),
            allocations: Seq(allocations),
            tx: self.tx.clone(),
        })
    }
}

fn balance_u128(balance: &[u8; 32]) -> Option<u128> {
    if balance[..16] != [0; 16] {
        return None;
    }
    Some(u128::from_be_bytes(
        balance[16..].try_into().expect("16 bytes"),
    ))
}

/// Lower-case hex without a prefix.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The group a test id is reported under: the fork directory and the EIP
/// directory of its path (`cancun/eip5656_mcopy`), or `static/<suite>` for the
/// ported static tests.
#[must_use]
pub fn category(id: &str) -> String {
    let path = id.split("::").next().unwrap_or(id);
    let parts: Vec<&str> = path.split('/').filter(|p| *p != "tests").collect();
    let parts = if parts.first() == Some(&"static") {
        [parts[0], parts.get(2).copied().unwrap_or("")]
    } else {
        [parts[0], parts.get(1).copied().unwrap_or("")]
    };
    parts.join("/")
}

fn field<'a>(object: &'a Value, name: &str) -> Result<&'a Value, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing field `{name}`"))
}

fn text<'a>(object: &'a Value, name: &str) -> Result<&'a str, String> {
    field(object, name)?
        .as_str()
        .ok_or_else(|| format!("field `{name}` is not a string"))
}

fn object<'a>(object: &'a Value, name: &str) -> Result<&'a Map<String, Value>, String> {
    field(object, name)?
        .as_object()
        .ok_or_else(|| format!("field `{name}` is not an object"))
}

/// Bytes of a `0x` hex string.
fn bytes(s: &str) -> Result<Vec<u8>, String> {
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("`{s}` lacks the 0x prefix"))?;
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).map_err(|_| format!("`{s}` is not hex")))
        .collect()
}

/// A big-endian value of at most `N` bytes, left-padded.
fn word<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let raw = bytes(s)?;
    let raw = &raw[raw.iter().take_while(|b| **b == 0).count()..];
    if raw.len() > N {
        return Err(format!("`{s}` does not fit {N} bytes"));
    }
    let mut out = [0u8; N];
    out[N - raw.len()..].copy_from_slice(raw);
    Ok(out)
}

fn quantity(object: &Value, name: &str) -> Result<u64, String> {
    Ok(u64::from_be_bytes(word(text(object, name)?)?))
}

fn state(value: &Map<String, Value>) -> Result<State, String> {
    let mut out = State::new();
    for (address, account) in value {
        let mut storage = BTreeMap::new();
        for (key, slot) in object(account, "storage")? {
            let slot = word(slot.as_str().ok_or("storage value is not a string")?)?;
            if slot != [0; 32] {
                storage.insert(word(key)?, slot);
            }
        }
        let entry = Account {
            balance: word(text(account, "balance")?)?,
            nonce: quantity(account, "nonce")?,
            code: bytes(text(account, "code")?)?,
            storage,
        };
        out.insert(word(address)?, entry);
    }
    Ok(out)
}

fn env(fixture: &Value) -> Result<Env, String> {
    let env = field(fixture, "env")?;
    let chain_id = match fixture.get("config").and_then(|c| c.get("chainid")) {
        Some(id) => u64::from_be_bytes(word(id.as_str().ok_or("`chainid` is not a string")?)?),
        None => 1,
    };
    Ok(Env {
        chain_id,
        beneficiary: word(text(env, "currentCoinbase")?)?,
        number: quantity(env, "currentNumber")?,
        timestamp: quantity(env, "currentTimestamp")?,
        gas_limit: quantity(env, "currentGasLimit")?,
        base_fee: quantity(env, "currentBaseFee")?,
        prevrandao: word(text(env, "currentRandom")?)?,
        difficulty: word(text(env, "currentDifficulty")?)?,
        excess_blob_gas: quantity(env, "currentExcessBlobGas")?,
    })
}

/// The cases of one fixture file: one per expectation for [`FORK`]. Tests
/// without expectations for the fork yield none.
///
/// # Errors
/// A message naming the test and what is malformed.
pub fn parse(json: &str) -> Result<Vec<TestCase>, String> {
    let file: Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    let tests = file
        .as_object()
        .ok_or("a fixture file is an object of tests")?;
    let mut cases = Vec::new();
    for (name, fixture) in tests {
        parse_test(name, fixture, &mut cases).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(cases)
}

fn parse_test(name: &str, fixture: &Value, cases: &mut Vec<TestCase>) -> Result<(), String> {
    let Some(posts) = object(fixture, "post")?.get(FORK) else {
        return Ok(());
    };
    let posts = posts.as_array().ok_or("post entries are not an array")?;
    let env = env(fixture)?;
    let pre = state(object(fixture, "pre")?)?;
    for (n, post) in posts.iter().enumerate() {
        let state = match post.get("state") {
            Some(s) => Some(state(s.as_object().ok_or("post state is not an object")?)?),
            None => None,
        };
        let exception = match post.get("expectException") {
            Some(e) => Some(
                e.as_str()
                    .ok_or("`expectException` is not a string")?
                    .to_string(),
            ),
            None => None,
        };
        let id = if posts.len() == 1 {
            name.to_string()
        } else {
            format!("{name}#{n}")
        };
        cases.push(TestCase {
            category: category(name),
            id,
            env: env.clone(),
            pre: pre.clone(),
            tx: bytes(text(post, "txbytes")?)?,
            expected: Expected {
                state_root: word(text(post, "hash")?)?,
                logs_hash: word(text(post, "logs")?)?,
                exception,
                state,
            },
        });
    }
    Ok(())
}
