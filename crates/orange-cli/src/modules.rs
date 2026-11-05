//! The `modules` list of a genesis file (spec 16 §4.1): kernel modules
//! installed at genesis.
//!
//! ```json
//! "modules": [{"address": "0x<20 bytes>", "code": "0x<OrangeSDK module>", "capabilities": 1, "init": "0x<bytes>"}]
//! ```
//!
//! `code` is the module itself (the output of `orange-recompile`); it travels
//! as the code of the genesis account at `address`, which may also have an
//! `alloc` entry for its balance. `capabilities` (default 0) and `init`
//! (default empty) are passed to the kernel as they are.

use orange_abi::chain::Allocation;
use orange_abi::types::ModuleInstall;
use serde_json::Value;

fn hex_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<Vec<u8>>, String> {
    fields
        .get(name)
        .map(|v| {
            v.as_str()
                .and_then(|s| orange_rpc::methods::parse_hex(s).ok())
                .ok_or_else(|| format!("genesis: module {name} must be 0x hex"))
        })
        .transpose()
}

/// Parses `modules` and puts each module's code on its account in
/// `allocations`.
///
/// # Errors
/// A message naming the first problem.
pub fn parse_modules(
    v: &Value,
    allocations: &mut Vec<Allocation>,
) -> Result<Vec<ModuleInstall>, String> {
    let entries = match v.get("modules") {
        None => return Ok(Vec::new()),
        Some(Value::Array(entries)) => entries,
        Some(_) => return Err("genesis: modules must be an array".to_owned()),
    };
    let mut installs = Vec::new();
    for entry in entries {
        let Value::Object(fields) = entry else {
            return Err("genesis: a module must be an object".to_owned());
        };
        let address = hex_field(fields, "address")?
            .and_then(|b| <[u8; 20]>::try_from(b).ok())
            .ok_or("genesis: module address must be 20 bytes of 0x hex")?;
        let code = hex_field(fields, "code")?
            .filter(|c| !c.is_empty())
            .ok_or("genesis: module code missing")?;
        let capabilities = match fields.get("capabilities") {
            None => 0,
            Some(c) => c
                .as_u64()
                .ok_or("genesis: module capabilities must be a non-negative integer")?,
        };
        let init = hex_field(fields, "init")?.unwrap_or_default();
        let code_hash = orange_host::hash::keccak256(&code);
        match allocations.iter_mut().find(|a| a.address == address) {
            Some(account) if !account.code.is_empty() => {
                return Err("genesis: a module's account cannot also have alloc code".to_owned());
            }
            Some(account) => account.code = code,
            None => allocations.push(Allocation {
                address,
                code,
                ..Allocation::default()
            }),
        }
        installs.push(ModuleInstall {
            address,
            code_hash,
            capabilities,
            init,
        });
    }
    Ok(installs)
}
