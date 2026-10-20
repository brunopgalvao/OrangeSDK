//! Comparing what a case did with what the fixture expects.

use solo_abi::chain::call_status;
use solo_vm::status::Termination;

use crate::fixture::{Account, State, TestCase, hex};
use crate::mpt::{logs_hash, state_root};
use crate::run::Executed;

/// Checks one execution against the fixture. `Ok` means the case passes:
/// the transaction was refused exactly when the fixture expects an
/// exception, and the post-state root and the logs hash are the expected
/// ones. `Err` says what differs.
///
/// # Errors
/// The first difference found.
pub fn check(case: &TestCase, executed: &Result<Executed, Termination>) -> Result<(), String> {
    let executed = executed
        .as_ref()
        .map_err(|status| format!("the guest ended with {status:?}"))?;
    let refused = executed.outcome.status == call_status::INVALID;
    match (&case.expected.exception, refused) {
        (Some(exception), false) => {
            return Err(format!(
                "expected the transaction to be refused ({exception}); it ran with status {}",
                executed.outcome.status
            ));
        }
        (None, true) => {
            return Err("the transaction was refused; the fixture expects it to run".to_string());
        }
        _ => {}
    }
    if let Some(address) = executed.orphans.first() {
        return Err(format!(
            "storage slots remain under 0x{}, which has no account",
            hex(address)
        ));
    }
    let root = state_root(&executed.post);
    if root != case.expected.state_root {
        let detail = case.expected.state.as_ref().map_or_else(
            || "the fixture carries no post-state".to_string(),
            |state| diff(state, &executed.post),
        );
        return Err(format!(
            "state root 0x{} differs from the expected 0x{}: {detail}",
            hex(&root),
            hex(&case.expected.state_root)
        ));
    }
    let logs = logs_hash(&executed.outcome.logs.0);
    if logs != case.expected.logs_hash {
        return Err(format!(
            "logs hash 0x{} differs from the expected 0x{} ({} logs)",
            hex(&logs),
            hex(&case.expected.logs_hash),
            executed.outcome.logs.0.len()
        ));
    }
    Ok(())
}

/// The first account in which `actual` differs from `expected`.
#[must_use]
pub fn diff(expected: &State, actual: &State) -> String {
    let addresses: std::collections::BTreeSet<_> = expected.keys().chain(actual.keys()).collect();
    for address in addresses {
        let a = hex(address);
        match (expected.get(address), actual.get(address)) {
            (Some(_), None) => return format!("account 0x{a} is missing"),
            (None, Some(_)) => return format!("account 0x{a} should not exist"),
            (Some(e), Some(g)) if e != g => {
                return format!("account 0x{a}: {}", account_diff(e, g));
            }
            _ => {}
        }
    }
    "the post-states agree, so the expected root does not match the fixture's own post-state"
        .to_string()
}

fn account_diff(expected: &Account, actual: &Account) -> String {
    if expected.balance != actual.balance {
        return format!(
            "balance 0x{} expected 0x{}",
            hex(&actual.balance),
            hex(&expected.balance)
        );
    }
    if expected.nonce != actual.nonce {
        return format!("nonce {} expected {}", actual.nonce, expected.nonce);
    }
    if expected.code != actual.code {
        return format!(
            "code of {} bytes expected {} bytes",
            actual.code.len(),
            expected.code.len()
        );
    }
    let show =
        |v: Option<&[u8; 32]>| v.map_or_else(|| "0".to_string(), |v| format!("0x{}", hex(v)));
    let slots: std::collections::BTreeSet<_> = expected
        .storage
        .keys()
        .chain(actual.storage.keys())
        .collect();
    slots
        .into_iter()
        .find_map(|slot| {
            let (e, g) = (expected.storage.get(slot), actual.storage.get(slot));
            (e != g).then(|| format!("slot 0x{} is {} expected {}", hex(slot), show(g), show(e)))
        })
        .unwrap_or_default()
}
