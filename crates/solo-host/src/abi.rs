//! The host ABI functions (spec 05 §4), implemented over an [`Executor`].

use solo_vm::host::{Capability, HostContext};
use solo_vm::isa::Reg;
use solo_vm::status::{HostStatus, Termination};

use crate::executor::{Executor, Flags};
use crate::hash::{blake2b256, keccak256, sha256};
use crate::storage::{MAX_KEY_LEN, MAX_VALUE_LEN, Storage, namespaced};

/// Value `storage_get` and `storage_iter_next` return for "absent" or "end".
pub const ABSENT: u64 = u32::MAX as u64;

/// Host ABI version this crate implements (spec 05 §7).
pub const ABI_VERSION: u64 = 1;

/// One host function: name, handle, and the lowest capability set that may import it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Function {
    /// Import name.
    pub name: &'static str,
    /// Handle passed back on `ecall`.
    pub handle: u32,
    /// Whether the `Sandboxed` set may import it.
    pub sandboxed: bool,
}

/// The functions this executor provides. Privileged-only functions of spec 05
/// (`storage_commit`, `storage_proof`, `sign`, network, time, persistence) are
/// provided by the node host that embeds the executor, not here.
pub const FUNCTIONS: &[Function] = &[
    Function {
        name: "abi_version",
        handle: 1,
        sandboxed: true,
    },
    Function {
        name: "input_len",
        handle: 2,
        sandboxed: true,
    },
    Function {
        name: "input_read",
        handle: 3,
        sandboxed: true,
    },
    Function {
        name: "output_write",
        handle: 4,
        sandboxed: true,
    },
    Function {
        name: "gas_remaining",
        handle: 5,
        sandboxed: true,
    },
    Function {
        name: "storage_get",
        handle: 10,
        sandboxed: true,
    },
    Function {
        name: "storage_set",
        handle: 11,
        sandboxed: true,
    },
    Function {
        name: "storage_delete",
        handle: 12,
        sandboxed: true,
    },
    Function {
        name: "storage_iter_open",
        handle: 13,
        sandboxed: true,
    },
    Function {
        name: "storage_iter_next",
        handle: 14,
        sandboxed: true,
    },
    Function {
        name: "hash_keccak256",
        handle: 20,
        sandboxed: true,
    },
    Function {
        name: "hash_sha256",
        handle: 21,
        sandboxed: true,
    },
    Function {
        name: "hash_blake2b256",
        handle: 22,
        sandboxed: true,
    },
    Function {
        name: "secp256k1_recover",
        handle: 23,
        sandboxed: true,
    },
    Function {
        name: "p256_verify",
        handle: 24,
        sandboxed: true,
    },
    Function {
        name: "bls12381_verify",
        handle: 25,
        sandboxed: true,
    },
    Function {
        name: "bls12381_pairing_check",
        handle: 26,
        sandboxed: true,
    },
    Function {
        name: "invoke",
        handle: 30,
        sandboxed: true,
    },
    Function {
        name: "invoke_output_len",
        handle: 31,
        sandboxed: true,
    },
    Function {
        name: "invoke_output_read",
        handle: 32,
        sandboxed: true,
    },
    Function {
        name: "log_emit",
        handle: 40,
        sandboxed: true,
    },
    Function {
        name: "metric_emit",
        handle: 41,
        sandboxed: true,
    },
];

/// [`resolve`] as a yes/no answer, in the shape [`ModuleCache::insert`] takes.
///
/// [`ModuleCache::insert`]: crate::cache::ModuleCache::insert
#[must_use]
pub fn resolve_bool(name: &str, capability: Capability) -> bool {
    resolve(name, capability).is_some()
}

/// Resolves an import name for a capability set (spec 03 §5.1 rule 9).
#[must_use]
pub fn resolve(name: &str, capability: Capability) -> Option<u32> {
    FUNCTIONS
        .iter()
        .find(|f| f.name == name && (f.sandboxed || capability == Capability::Privileged))
        .map(|f| f.handle)
}

const fn per_32(bytes: u32) -> u64 {
    bytes.div_ceil(32) as u64
}

fn fault() -> Termination {
    Termination::HostError(HostStatus::MemoryFault.code())
}

fn read(ctx: &HostContext<'_>, ptr: u32, len: u32) -> Result<Vec<u8>, Termination> {
    ctx.memory
        .read(ptr, len)
        .map(<[u8]>::to_vec)
        .map_err(|_| fault())
}

fn write(ctx: &mut HostContext<'_>, ptr: u32, data: &[u8]) -> Result<(), Termination> {
    ctx.memory.write(ptr, data).map_err(|_| fault())
}

/// Writes at most `cap` bytes of `data` to `dst` and returns the bytes written.
fn write_truncated(
    ctx: &mut HostContext<'_>,
    dst: u32,
    cap: u32,
    data: &[u8],
) -> Result<u32, Termination> {
    let n = data.len().min(cap as usize);
    write(ctx, dst, &data[..n])?;
    Ok(u32::try_from(n).expect("bounded by cap"))
}

#[allow(clippy::unnecessary_wraps)] // lets call sites `return status(..)` from `Result` functions
fn status(ctx: &mut HostContext<'_>, s: HostStatus) -> Result<(), Termination> {
    ctx.set(Reg::A0, u64::from(s.code()));
    Ok(())
}

/// Dispatches one host call (spec 05 §3).
///
/// # Errors
/// A terminating status (spec 05 §6).
pub fn dispatch<S: Storage>(
    host: &mut Executor<S>,
    handle: u32,
    ctx: &mut HostContext<'_>,
) -> Result<(), Termination> {
    let (a0, a1, a2, a3) = (
        ctx.arg32(Reg::A0),
        ctx.arg32(Reg::A1),
        ctx.arg32(Reg::A2),
        ctx.arg32(Reg::A3),
    );
    match handle {
        1 => {
            ctx.charge(10)?;
            ctx.set(Reg::A0, ABI_VERSION);
        }
        2 => {
            ctx.charge(10)?;
            let len = host.frame().input.len();
            ctx.set(Reg::A0, len as u64);
        }
        3 => {
            ctx.charge(10 + per_32(a2))?;
            let input = &host.frame().input;
            let start = (a1 as usize).min(input.len());
            let end = start.saturating_add(a2 as usize).min(input.len());
            let chunk = input[start..end].to_vec();
            write(ctx, a0, &chunk)?;
            ctx.set(Reg::A0, chunk.len() as u64);
        }
        4 => {
            ctx.charge(10 + per_32(a1))?;
            let data = read(ctx, a0, a1)?;
            host.frame().output = data;
            ctx.set(Reg::A0, 0);
        }
        5 => {
            ctx.charge(10)?;
            let remaining = u64::try_from(*ctx.gas).unwrap_or(0);
            ctx.set(Reg::A0, remaining);
        }
        10..=14 => storage(host, handle, ctx)?,
        20 => hash(ctx, 6, keccak256)?,
        21 => hash(ctx, 6, sha256)?,
        22 => hash(ctx, 4, blake2b256)?,
        23 => secp256k1_recover(ctx)?,
        24 => p256_verify(ctx)?,
        25 => bls12381_verify(ctx)?,
        26 => bls12381_pairing_check(ctx)?,
        30 => invoke(host, ctx)?,
        31 => {
            ctx.charge(10)?;
            let len = host.frame().last_callee_output.len();
            ctx.set(Reg::A0, len as u64);
        }
        32 => {
            ctx.charge(10 + per_32(a2))?;
            let out = &host.frame().last_callee_output;
            let start = (a1 as usize).min(out.len());
            let end = start.saturating_add(a2 as usize).min(out.len());
            let chunk = out[start..end].to_vec();
            write(ctx, a0, &chunk)?;
            ctx.set(Reg::A0, chunk.len() as u64);
        }
        40 => {
            ctx.charge(10 + per_32(a2))?;
            let msg = read(ctx, a1, a2)?;
            host.logs.push((a0, msg));
            ctx.set(Reg::A0, 0);
        }
        41 => {
            ctx.charge(10)?;
            let name = read(ctx, a0, a1)?;
            #[allow(clippy::cast_possible_wrap)]
            let value = ctx.arg(Reg::A2) as i64;
            host.metrics
                .push((String::from_utf8_lossy(&name).into_owned(), value, a3));
            ctx.set(Reg::A0, 0);
        }
        _ => return Err(Termination::HostError(HostStatus::Unavailable.code())),
    }
    Ok(())
}

fn key_of<S: Storage>(
    host: &mut Executor<S>,
    ctx: &HostContext<'_>,
    ptr: u32,
    len: u32,
) -> Result<Option<Vec<u8>>, Termination> {
    if len == 0 || len as usize > MAX_KEY_LEN {
        return Ok(None);
    }
    let key = read(ctx, ptr, len)?;
    let frame = host.frame();
    Ok(Some(match frame.capability {
        Capability::Privileged => key,
        Capability::Sandboxed => namespaced(&frame.namespace, &key),
    }))
}

fn storage<S: Storage>(
    host: &mut Executor<S>,
    handle: u32,
    ctx: &mut HostContext<'_>,
) -> Result<(), Termination> {
    let (a0, a1, a2, a3, a4) = (
        ctx.arg32(Reg::A0),
        ctx.arg32(Reg::A1),
        ctx.arg32(Reg::A2),
        ctx.arg32(Reg::A3),
        ctx.arg32(Reg::A4),
    );
    match handle {
        10 => {
            ctx.charge(200)?;
            let Some(key) = key_of(host, ctx, a0, a1)? else {
                return status(ctx, HostStatus::InvalidArgument);
            };
            match host.state.get(&key) {
                Some(value) => {
                    let n = write_truncated(ctx, a2, a3, &value)?;
                    ctx.charge(per_32(n))?;
                    ctx.set(Reg::A0, value.len() as u64);
                }
                None => ctx.set(Reg::A0, ABSENT),
            }
        }
        11 => {
            ctx.charge(500 + 4 * per_32(a3))?;
            if host.frame().static_call {
                return Err(Termination::HostError(HostStatus::StaticViolation.code()));
            }
            let Some(key) = key_of(host, ctx, a0, a1)? else {
                return status(ctx, HostStatus::InvalidArgument);
            };
            if a3 as usize > MAX_VALUE_LEN {
                return status(ctx, HostStatus::InvalidArgument);
            }
            let value = read(ctx, a2, a3)?;
            host.state.set(&key, &value);
            status(ctx, HostStatus::Ok)?;
        }
        12 => {
            ctx.charge(300)?;
            if host.frame().static_call {
                return Err(Termination::HostError(HostStatus::StaticViolation.code()));
            }
            let Some(key) = key_of(host, ctx, a0, a1)? else {
                return status(ctx, HostStatus::InvalidArgument);
            };
            let existed = host.state.delete(&key);
            let outcome = if existed {
                HostStatus::Ok
            } else {
                HostStatus::NotFound
            };
            status(ctx, outcome)?;
        }
        13 => {
            ctx.charge(300)?;
            if a1 as usize > MAX_KEY_LEN {
                return status(ctx, HostStatus::InvalidArgument);
            }
            let prefix = read(ctx, a0, a1)?;
            let frame = host.frame();
            let full = match frame.capability {
                Capability::Privileged => prefix,
                Capability::Sandboxed => namespaced(&frame.namespace, &prefix),
            };
            let strip = match frame.capability {
                Capability::Privileged => 0,
                Capability::Sandboxed => 32,
            };
            let entries: Vec<(Vec<u8>, Vec<u8>)> = host
                .state
                .scan(&full)
                .into_iter()
                .map(|(k, v)| (k[strip..].to_vec(), v))
                .collect();
            let frame = host.frame();
            frame.iterators.push((entries, 0));
            ctx.set(Reg::A0, (frame.iterators.len() - 1) as u64);
        }
        _ => {
            ctx.charge(200)?;
            let Some((entries, pos)) = host.frame().iterators.get_mut(a0 as usize) else {
                return status(ctx, HostStatus::InvalidArgument);
            };
            let Some((key, value)) = entries.get(*pos).cloned() else {
                ctx.set(Reg::A0, ABSENT);
                ctx.set(Reg::A1, 0);
                return Ok(());
            };
            *pos += 1;
            let kn = write_truncated(ctx, a1, a2, &key)?;
            let vn = write_truncated(ctx, a3, a4, &value)?;
            ctx.charge(per_32(kn + vn))?;
            ctx.set(Reg::A0, key.len() as u64);
            ctx.set(Reg::A1, value.len() as u64);
        }
    }
    Ok(())
}

fn hash(
    ctx: &mut HostContext<'_>,
    per_unit: u64,
    f: fn(&[u8]) -> [u8; 32],
) -> Result<(), Termination> {
    let (src, len, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1), ctx.arg32(Reg::A2));
    ctx.charge(30 + per_unit * per_32(len))?;
    let data = read(ctx, src, len)?;
    write(ctx, dst, &f(&data))?;
    ctx.set(Reg::A0, 0);
    Ok(())
}

fn secp256k1_recover(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let (msg, sig, dst) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1), ctx.arg32(Reg::A2));
    ctx.charge(3_000)?;
    let msg = read(ctx, msg, 32)?;
    let sig = read(ctx, sig, 65)?;
    let v = match sig[64] {
        0 | 27 => Some(0u8),
        1 | 28 => Some(1u8),
        _ => None,
    };
    let Some(v) = v else {
        return status(ctx, HostStatus::InvalidArgument);
    };
    let recovery_id = RecoveryId::new(v == 1, false);
    let recovered = Signature::from_slice(&sig[..64])
        .ok()
        .and_then(|s| VerifyingKey::recover_from_prehash(&msg, &s, recovery_id).ok());
    match recovered {
        Some(key) => {
            let point = key.to_encoded_point(false);
            write(ctx, dst, &point.as_bytes()[1..65])?;
            status(ctx, HostStatus::Ok)
        }
        None => status(ctx, HostStatus::InvalidArgument),
    }
}

fn p256_verify(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let (msg, sig, key) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1), ctx.arg32(Reg::A2));
    ctx.charge(6_900)?;
    let msg = read(ctx, msg, 32)?;
    let sig = read(ctx, sig, 64)?;
    let key = read(ctx, key, 64)?;
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(4);
    sec1.extend_from_slice(&key);
    let valid = VerifyingKey::from_sec1_bytes(&sec1)
        .ok()
        .zip(Signature::from_slice(&sig).ok())
        .is_some_and(|(k, s)| k.verify_prehash(&msg, &s).is_ok());
    ctx.set(Reg::A0, u64::from(!valid));
    Ok(())
}

/// `bls12381_verify` (spec 05 §4.3, spec 12 §3): a G1 signature over a
/// message under a G2 key, hashed to the curve with a caller-chosen tag.
fn bls12381_verify(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (msg, msg_len, sig, key) = (
        ctx.arg32(Reg::A0),
        ctx.arg32(Reg::A1),
        ctx.arg32(Reg::A2),
        ctx.arg32(Reg::A3),
    );
    let (dst, dst_len) = (ctx.arg32(Reg::A4), ctx.arg32(Reg::A5));
    ctx.charge(100_000 + 6 * per_32(msg_len))?;
    let msg = read(ctx, msg, msg_len)?;
    let sig: [u8; 48] = read(ctx, sig, 48)?.try_into().expect("48 bytes read");
    let key: [u8; 96] = read(ctx, key, 96)?.try_into().expect("96 bytes read");
    let dst = read(ctx, dst, dst_len)?;
    let valid = solo_bls::host::verify(&msg, &dst, &sig, &key);
    ctx.set(Reg::A0, u64::from(!valid));
    Ok(())
}

/// `bls12381_pairing_check` (spec 05 §4.3): `count` pairs of a compressed
/// G1 and a compressed G2 point.
fn bls12381_pairing_check(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    let (pairs, count) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1));
    ctx.charge(70_000 + 50_000 * u64::from(count))?;
    let pair = solo_bls::host::PAIR_LENGTH as u64;
    let len = u32::try_from(pair * u64::from(count))
        .ok()
        .ok_or_else(fault)?;
    let data = read(ctx, pairs, len)?;
    let holds = solo_bls::host::pairing_check(&data);
    ctx.set(Reg::A0, u64::from(!holds));
    Ok(())
}

fn invoke<S: Storage>(
    host: &mut Executor<S>,
    ctx: &mut HostContext<'_>,
) -> Result<(), Termination> {
    let (hash_ptr, ns_ptr, in_ptr, in_len) = (
        ctx.arg32(Reg::A0),
        ctx.arg32(Reg::A1),
        ctx.arg32(Reg::A2),
        ctx.arg32(Reg::A3),
    );
    let gas_limit = ctx.arg(Reg::A4);
    let flags = Flags::from_bits(ctx.arg(Reg::A5));
    ctx.charge(2_000)?;
    let code_hash: [u8; 32] = read(ctx, hash_ptr, 32)?.try_into().expect("32 bytes read");
    let namespace: [u8; 32] = read(ctx, ns_ptr, 32)?.try_into().expect("32 bytes read");
    let input = read(ctx, in_ptr, in_len)?;
    let caller = host.frame();
    if caller.static_call && !flags.static_call {
        return Err(Termination::HostError(HostStatus::StaticViolation.code()));
    }
    let capability = if caller.capability == Capability::Privileged && flags.privileged {
        Capability::Privileged
    } else {
        Capability::Sandboxed
    };
    let Ok(limit) = i64::try_from(gas_limit) else {
        return status(ctx, HostStatus::InvalidArgument);
    };
    ctx.charge(gas_limit)?;
    let result = host.call(&code_hash, namespace, &input, limit, capability, flags);
    let refund = i64::try_from(gas_limit - result.gas_used.min(gas_limit)).unwrap_or(0);
    *ctx.gas = ctx.gas.saturating_add(refund);
    let invoke_status = result.invoke_status();
    host.frame().last_callee_output = result.output;
    ctx.set(Reg::A0, u64::from(invoke_status.code()));
    ctx.set(Reg::A1, result.gas_used);
    Ok(())
}
