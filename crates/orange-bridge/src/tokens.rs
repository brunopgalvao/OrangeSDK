//! The canonical token bridge (spec 21): the messages the two token
//! gateways send each other, the addresses of wrapped tokens, the calls a
//! user, an owner or a relayer makes, and the gateways' constructor
//! arguments.
//!
//! A relayer moves token messages as it moves any other: a gateway's
//! messages are ordinary messages of the channel it sends through (spec 17
//! from the OrangeSDK chain, spec 18 from Ethereum). [`TokenMessage::decode`] reads what a
//! message's payload asks the receiving gateway to do, so that tooling can
//! show it or check it before relaying.

use orange_abi::bridge::{Message, OUTBOX_ADDRESS};
use orange_abi::bridge_in::INBOX_ADDRESS;
use orange_abi::types::Address;
use orange_trie::keccak256;

use crate::abi::{self, Value};

/// Message kind: mint the wrapped token of a token locked on the sending chain.
pub const MINT: u8 = 1;
/// Message kind: release a token that a burn of its wrapped token freed.
pub const RELEASE: u8 = 2;
/// Message kind: the sending gateway exists (spec 21 §5.7).
pub const HELLO: u8 = 3;
/// Message kind: give back the value of a cancelled `MINT` or `RELEASE` to
/// its sender (spec 21 §5.5b).
pub const REFUND: u8 = 4;
/// Message kind: a nonce of the receiving gateway's messages is spent in
/// the sending gateway's inbox (spec 21 §5.5c).
pub const SPENT: u8 = 5;
/// The effect of a nonce spent without anything taking effect (spec 21
/// §5.5c): vetoed, delivered elsewhere, or undone.
pub const VOID: [u8; 32] = {
    let mut w = [0; 32];
    w[31] = 1;
    w
};
/// The token address that stands for a chain's native currency.
pub const NATIVE: Address = [0; 20];
/// Bytes of a token's name and symbol that a deposit carries.
pub const MAX_METADATA: usize = 64;

/// What a gateway asks the paired gateway to do (spec 21 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenMessage {
    /// Mint `amount` of the wrapped token of `origin` to `to`; `from`
    /// locked it. The metadata names the wrapped token if this mint
    /// creates it.
    Mint {
        /// The locked token on the sending chain, [`NATIVE`] for its currency.
        origin: Address,
        /// The account that deposited it.
        from: Address,
        /// The recipient on the receiving chain.
        to: Address,
        /// The amount, in the token's own units.
        amount: u128,
        /// The token's name, at most [`MAX_METADATA`] bytes.
        name: Vec<u8>,
        /// The token's symbol, at most [`MAX_METADATA`] bytes.
        symbol: Vec<u8>,
        /// The token's decimals.
        decimals: u8,
    },
    /// Release `amount` of `token`, locked on the receiving chain, to `to`;
    /// `from` burned its wrapped token.
    Release {
        /// The token on the receiving chain, [`NATIVE`] for its currency.
        token: Address,
        /// The account that burned the wrapped token.
        from: Address,
        /// The recipient on the receiving chain.
        to: Address,
        /// The amount.
        amount: u128,
    },
    /// The sending gateway exists; `heard` says whether it has heard from
    /// the receiving gateway, which answers with a `Hello` of its own if
    /// not.
    Hello {
        /// Whether a message of the receiving gateway reached the sender.
        heard: bool,
    },
    /// Give back to `from` the value of message `nonce`, a `MINT` or
    /// `RELEASE` the receiving gateway sent asking exactly this, which the
    /// sending gateway queued and its owner cancelled.
    Refund {
        /// The channel's nonce of the message refunded.
        nonce: u64,
        /// Its kind, [`MINT`] or [`RELEASE`].
        kind: u8,
        /// The token it named: a mint's origin, a release's token.
        token: Address,
        /// Its sender, who gets the value back.
        from: Address,
        /// Its recipient.
        to: Address,
        /// Its amount.
        amount: u128,
    },
    /// Nonce `nonce` of the receiving gateway's messages is spent in the
    /// sending gateway's inbox by a message of identity `effect` (see
    /// [`identity`]), or by nothing that took effect ([`VOID`]).
    Spent {
        /// The nonce spent.
        nonce: u64,
        /// What it was spent by.
        effect: [u8; 32],
    },
}

/// The identity of a message with `payload`, as the gateway that sent it
/// records it in `sent` (spec 21 §5.3): the hash of the first five words of
/// a `MINT`, which leaves out the metadata, and of the whole payload of
/// anything else.
#[must_use]
pub fn identity(payload: &[u8]) -> [u8; 32] {
    let mut kind = [0; 32];
    kind[31] = MINT;
    if payload.len() >= 5 * 32 && payload[..32] == kind {
        return keccak256(&payload[..5 * 32]);
    }
    keccak256(payload)
}

fn word_address(word: &[u8]) -> Address {
    word[12..32].try_into().unwrap_or_default()
}

fn word_u128(word: &[u8]) -> u128 {
    u128::from_be_bytes(word[16..32].try_into().unwrap_or_default())
}

/// The bytes of the dynamic value whose offset is the head word at `at`.
fn tail(payload: &[u8], at: usize) -> Option<Vec<u8>> {
    let offset = usize::try_from(word_u128(payload.get(at..at + 32)?)).ok()?;
    let length = usize::try_from(word_u128(payload.get(offset..offset.checked_add(32)?)?)).ok()?;
    let start = offset + 32;
    Some(payload.get(start..start.checked_add(length)?)?.to_vec())
}

impl TokenMessage {
    /// The payload: `abi.encode(uint8 MINT, address origin, address from,
    /// address to, uint256 amount, string name, string symbol, uint8
    /// decimals)`, `abi.encode(uint8 RELEASE, address token, address
    /// from, address to, uint256 amount)`, `abi.encode(uint8 HELLO, bool
    /// heard)`, `abi.encode(uint8 REFUND, uint64 nonce, uint8 kind,
    /// address token, address from, address to, uint256 amount)` or
    /// `abi.encode(uint8 SPENT, uint64 nonce, bytes32 effect)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            TokenMessage::Mint {
                origin,
                from,
                to,
                amount,
                name,
                symbol,
                decimals,
            } => abi::encode(&[
                Value::uint(u128::from(MINT)),
                Value::address(origin),
                Value::address(from),
                Value::address(to),
                Value::uint(*amount),
                Value::Bytes(name.clone()),
                Value::Bytes(symbol.clone()),
                Value::uint(u128::from(*decimals)),
            ]),
            TokenMessage::Release {
                token,
                from,
                to,
                amount,
            } => abi::encode(&[
                Value::uint(u128::from(RELEASE)),
                Value::address(token),
                Value::address(from),
                Value::address(to),
                Value::uint(*amount),
            ]),
            TokenMessage::Hello { heard } => abi::encode(&[
                Value::uint(u128::from(HELLO)),
                Value::uint(u128::from(*heard)),
            ]),
            TokenMessage::Refund {
                nonce,
                kind,
                token,
                from,
                to,
                amount,
            } => abi::encode(&[
                Value::uint(u128::from(REFUND)),
                Value::uint(u128::from(*nonce)),
                Value::uint(u128::from(*kind)),
                Value::address(token),
                Value::address(from),
                Value::address(to),
                Value::uint(*amount),
            ]),
            TokenMessage::Spent { nonce, effect } => [
                abi::encode(&[
                    Value::uint(u128::from(SPENT)),
                    Value::uint(u128::from(*nonce)),
                ]),
                effect.to_vec(),
            ]
            .concat(),
        }
    }

    /// The message a gateway's payload holds; `None` unless `payload` is
    /// exactly the encoding [`TokenMessage::encode`] gives, which is what a
    /// gateway sends. Amounts above `u128::MAX` do not decode.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<TokenMessage> {
        let word = |i: usize| payload.get(i * 32..i * 32 + 32);
        let kind = word(0)?[31];
        let address = |i: usize| word(i).map(word_address);
        let message = if kind == HELLO {
            TokenMessage::Hello {
                heard: word(1)?[31] != 0,
            }
        } else if kind == MINT {
            TokenMessage::Mint {
                origin: address(1)?,
                from: address(2)?,
                to: address(3)?,
                amount: word_u128(word(4)?),
                name: tail(payload, 5 * 32)?,
                symbol: tail(payload, 6 * 32)?,
                decimals: word(7)?[31],
            }
        } else if kind == REFUND {
            TokenMessage::Refund {
                nonce: u64::from_be_bytes(word(1)?[24..32].try_into().ok()?),
                kind: word(2)?[31],
                token: address(3)?,
                from: address(4)?,
                to: address(5)?,
                amount: word_u128(word(6)?),
            }
        } else if kind == SPENT {
            TokenMessage::Spent {
                nonce: u64::from_be_bytes(word(1)?[24..32].try_into().ok()?),
                effect: word(2)?.try_into().ok()?,
            }
        } else {
            TokenMessage::Release {
                token: address(1)?,
                from: address(2)?,
                to: address(3)?,
                amount: word_u128(word(4)?),
            }
        };
        (message.encode() == payload).then_some(message)
    }
}

/// The address of the wrapped token of `origin` that `gateway` creates
/// (spec 21 §4): `CREATE2` from the gateway with the origin as the salt
/// and `init_code`, `BridgedToken`'s creation code.
#[must_use]
pub fn wrapped_token(gateway: &Address, origin: &Address, init_code: &[u8]) -> Address {
    let mut salt = [0u8; 32];
    salt[12..].copy_from_slice(origin);
    let mut preimage = vec![0xff];
    preimage.extend_from_slice(gateway);
    preimage.extend_from_slice(&salt);
    preimage.extend_from_slice(&keccak256(init_code));
    word_address(&keccak256(&preimage))
}

/// `deposit(token, to, amount)`: bridges `amount` of `token` to `to` on the
/// other chain; for [`NATIVE`] the transaction carries `amount` as value.
#[must_use]
pub fn deposit_calldata(token: &Address, to: &Address, amount: u128) -> Vec<u8> {
    abi::call(
        "deposit(address,address,uint256)",
        &[
            Value::address(token),
            Value::address(to),
            Value::uint(amount),
        ],
    )
}

/// `claim(token, recipient)`: sends what a failed release left owed to
/// `recipient`.
#[must_use]
pub fn claim_calldata(token: &Address, recipient: &Address) -> Vec<u8> {
    abi::call(
        "claim(address,address)",
        &[Value::address(token), Value::address(recipient)],
    )
}

/// `claimTo(token, receiver)`: sends what the caller is owed to `receiver`.
#[must_use]
pub fn claim_to_calldata(token: &Address, receiver: &Address) -> Vec<u8> {
    abi::call(
        "claimTo(address,address)",
        &[Value::address(token), Value::address(receiver)],
    )
}

/// `setLockCap(token, cap)`, by the owner.
#[must_use]
pub fn set_lock_cap_calldata(token: &Address, cap: u128) -> Vec<u8> {
    abi::call(
        "setLockCap(address,uint256)",
        &[Value::address(token), Value::uint(cap)],
    )
}

/// `setMintCap(origin, cap)`, by the owner.
#[must_use]
pub fn set_mint_cap_calldata(origin: &Address, cap: u128) -> Vec<u8> {
    abi::call(
        "setMintCap(address,uint256)",
        &[Value::address(origin), Value::uint(cap)],
    )
}

/// `setReleaseLimit(token, amount, window)`, by the owner: releases of the
/// native `token` up to `amount` at once, refilling at `amount` per
/// `window` seconds; a zero `amount` lifts the limit.
#[must_use]
pub fn set_release_limit_calldata(token: &Address, amount: u128, window: u64) -> Vec<u8> {
    abi::call(
        "setReleaseLimit(address,uint128,uint64)",
        &[
            Value::address(token),
            Value::uint(amount),
            Value::uint(u128::from(window)),
        ],
    )
}

/// `setMintLimit(origin, amount, window)`, by the owner: the same for mints
/// of the wrapped token of `origin`.
#[must_use]
pub fn set_mint_limit_calldata(origin: &Address, amount: u128, window: u64) -> Vec<u8> {
    abi::call(
        "setMintLimit(address,uint128,uint64)",
        &[
            Value::address(origin),
            Value::uint(amount),
            Value::uint(u128::from(window)),
        ],
    )
}

/// `executeQueued(id)`: mints or releases queued transfer `id` once its
/// time has come; anyone may send it.
#[must_use]
pub fn execute_queued_calldata(id: u64) -> Vec<u8> {
    abi::call("executeQueued(uint256)", &[Value::uint(u128::from(id))])
}

/// `freezeQueued(id)`: stops queued transfer `id` alone until the owner
/// unfreezes or cancels it; the guardian or the owner sends it (spec 21 §5.5a).
#[must_use]
pub fn freeze_queued_calldata(id: u64) -> Vec<u8> {
    abi::call("freezeQueued(uint256)", &[Value::uint(u128::from(id))])
}

/// `unfreezeQueued(id)`: lets a frozen transfer be executed again; the owner.
#[must_use]
pub fn unfreeze_queued_calldata(id: u64) -> Vec<u8> {
    abi::call("unfreezeQueued(uint256)", &[Value::uint(u128::from(id))])
}

/// `cancelQueued(id)`: retires queued transfer `id` by undoing its
/// delivery on this side; the owner (spec 21 §5.5a).
#[must_use]
pub fn cancel_queued_calldata(id: u64) -> Vec<u8> {
    abi::call("cancelQueued(uint256)", &[Value::uint(u128::from(id))])
}

/// `refundQueued(id)`: cancels queued transfer `id` as
/// [`cancel_queued_calldata`] does and asks the paired gateway to give its
/// value back to its sender; the owner (spec 21 §5.5b).
#[must_use]
pub fn refund_queued_calldata(id: u64) -> Vec<u8> {
    abi::call("refundQueued(uint256)", &[Value::uint(u128::from(id))])
}

/// `refundSpent(nonce, kind, token, from, to, amount)`: refunds the `MINT`
/// or `RELEASE` the gateway sent as message `nonce`, asking what the
/// arguments say, once the paired gateway reported the nonce spent by
/// something else; anyone may send it (spec 21 §5.5c).
#[must_use]
pub fn refund_spent_calldata(
    nonce: u64,
    kind: u8,
    token: &Address,
    from: &Address,
    to: &Address,
    amount: u128,
) -> Vec<u8> {
    abi::call(
        "refundSpent(uint64,uint8,address,address,address,uint256)",
        &[
            Value::uint(u128::from(nonce)),
            Value::uint(u128::from(kind)),
            Value::address(token),
            Value::address(from),
            Value::address(to),
            Value::uint(amount),
        ],
    )
}

/// `resendSpent(nonce, payload)`: sends again the `REFUND` or `SPENT` the
/// gateway sent as message `nonce` with `payload`, once the paired gateway
/// reported the nonce spent by something else; anyone may send it.
#[must_use]
pub fn resend_spent_calldata(nonce: u64, payload: &[u8]) -> Vec<u8> {
    abi::call(
        "resendSpent(uint64,bytes)",
        &[
            Value::uint(u128::from(nonce)),
            Value::Bytes(payload.to_vec()),
        ],
    )
}

/// `reportVetoed(nonce)` on `TokenGatewayOnEthereum`: tells the gateway on
/// the OrangeSDK chain that `OrangeInbox` vetoed its message `nonce`; anyone may send it.
#[must_use]
pub fn report_vetoed_calldata(nonce: u64) -> Vec<u8> {
    abi::call("reportVetoed(uint64)", &[Value::uint(u128::from(nonce))])
}

/// `reportDelivered(message)` on `TokenGatewayOnEthereum`: tells the gateway
/// on the OrangeSDK chain what `OrangeInbox` delivered as its message `message.nonce`;
/// anyone may send it.
#[must_use]
pub fn report_delivered_calldata(message: &Message) -> Vec<u8> {
    abi::call(
        "reportDelivered((uint64,address,address,uint256,bytes))",
        &[crate::message_value(message)],
    )
}

/// `reportDelivered(message)` on `TokenGatewayOnOrange`: tells the gateway
/// on Ethereum what the OrangeSDK chain's inbox delivered as its message
/// `nonce`, the `EthereumOutbox` message `(nonce, sender, recipient,
/// gasLimit, payload)` (spec 18 §6.1, spec 21 §5.2); anyone may send it.
#[must_use]
pub fn report_delivered_on_orange_calldata(
    nonce: u64,
    sender: &Address,
    recipient: &Address,
    gas_limit: u64,
    payload: &[u8],
) -> Vec<u8> {
    abi::call(
        "reportDelivered((uint64,address,address,uint64,bytes))",
        &[Value::Tuple(vec![
            Value::uint(u128::from(nonce)),
            Value::address(sender),
            Value::address(recipient),
            Value::uint(u128::from(gas_limit)),
            Value::Bytes(payload.to_vec()),
        ])],
    )
}

/// The calldata of a gateway view that takes one address, such as
/// `locked(address)`, `lockCap(address)`, `wrappedToken(address)` or a
/// token's `balanceOf(address)`.
#[must_use]
pub fn address_view(signature: &str, account: &Address) -> Vec<u8> {
    abi::call(signature, &[Value::address(account)])
}

/// The configuration `TokenGatewayOnEthereum` is deployed with (spec 21 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumGatewayConfig {
    /// The OrangeSDK chain's `EthereumOutbox`.
    pub outbox: Address,
    /// The `OrangeInbox` whose deliveries count.
    pub inbox: Address,
    /// The OrangeSDK chain's id.
    pub orange_chain_id: u64,
    /// The paired gateway on the OrangeSDK chain.
    pub orange_gateway: Address,
    /// The owner.
    pub owner: Address,
    /// The guardian.
    pub guardian: Address,
    /// The gas each message gives the gateway on the OrangeSDK chain.
    pub message_gas: u64,
}

impl EthereumGatewayConfig {
    /// The constructor arguments.
    #[must_use]
    pub fn constructor_args(&self) -> Vec<u8> {
        abi::encode(&[
            Value::address(&self.outbox),
            Value::address(&self.inbox),
            Value::uint(u128::from(self.orange_chain_id)),
            Value::address(&self.orange_gateway),
            Value::address(&self.owner),
            Value::address(&self.guardian),
            Value::uint(u128::from(self.message_gas)),
        ])
    }
}

/// The configuration `TokenGatewayOnOrange` is deployed with (spec 21 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrangeGatewayConfig {
    /// The outbox: [`OUTBOX_ADDRESS`] on an OrangeSDK chain.
    pub outbox: Address,
    /// The inbox: [`INBOX_ADDRESS`] on an OrangeSDK chain.
    pub inbox: Address,
    /// The chain the paired gateway is on.
    pub ethereum_chain_id: u64,
    /// The paired gateway on Ethereum.
    pub ethereum_gateway: Address,
    /// The owner.
    pub owner: Address,
    /// The guardian.
    pub guardian: Address,
    /// The name of the chain's currency.
    pub native_name: String,
    /// The symbol of the chain's currency.
    pub native_symbol: String,
}

impl OrangeGatewayConfig {
    /// A configuration with the OrangeSDK chain's outbox and inbox.
    #[must_use]
    pub fn new(
        ethereum_chain_id: u64,
        ethereum_gateway: Address,
        owner: Address,
        guardian: Address,
        native_name: &str,
        native_symbol: &str,
    ) -> OrangeGatewayConfig {
        OrangeGatewayConfig {
            outbox: OUTBOX_ADDRESS,
            inbox: INBOX_ADDRESS,
            ethereum_chain_id,
            ethereum_gateway,
            owner,
            guardian,
            native_name: native_name.to_string(),
            native_symbol: native_symbol.to_string(),
        }
    }

    /// The constructor arguments.
    #[must_use]
    pub fn constructor_args(&self) -> Vec<u8> {
        abi::encode(&[
            Value::address(&self.outbox),
            Value::address(&self.inbox),
            Value::uint(u128::from(self.ethereum_chain_id)),
            Value::address(&self.ethereum_gateway),
            Value::address(&self.owner),
            Value::address(&self.guardian),
            Value::Bytes(self.native_name.as_bytes().to_vec()),
            Value::Bytes(self.native_symbol.as_bytes().to_vec()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint() -> TokenMessage {
        TokenMessage::Mint {
            origin: [1; 20],
            from: [2; 20],
            to: [3; 20],
            amount: 1_000,
            name: b"Test Token".to_vec(),
            symbol: b"TT".to_vec(),
            decimals: 6,
        }
    }

    #[test]
    fn messages_round_trip_and_only_canonical_payloads_decode() {
        let release = TokenMessage::Release {
            token: NATIVE,
            from: [4; 20],
            to: [5; 20],
            amount: u128::MAX,
        };
        let refund = TokenMessage::Refund {
            nonce: u64::MAX,
            kind: MINT,
            token: [6; 20],
            from: [7; 20],
            to: [8; 20],
            amount: 9,
        };
        let hellos = [
            TokenMessage::Hello { heard: false },
            TokenMessage::Hello { heard: true },
        ];
        let spent = TokenMessage::Spent {
            nonce: u64::MAX,
            effect: [0xEF; 32],
        };
        for m in [mint(), release.clone(), refund.clone(), spent.clone()]
            .into_iter()
            .chain(hellos)
        {
            assert_eq!(TokenMessage::decode(&m.encode()), Some(m));
        }
        let payload = mint().encode();
        // 8 head words, then each string's length word and one padded word.
        assert_eq!(payload.len(), 8 * 32 + 2 * 64);
        assert_eq!(payload[31], MINT);
        assert_eq!(release.encode().len(), 5 * 32);
        // Truncated, padded, with dirty high bytes or an amount above u128.
        let mut cases = vec![
            payload[..payload.len() - 1].to_vec(),
            [payload.as_slice(), &[0; 32]].concat(),
            Vec::new(),
        ];
        for at in [0, 32, 4 * 32] {
            let mut dirty = payload.clone();
            dirty[at] = 1;
            cases.push(dirty);
        }
        // Offsets and lengths that point outside the payload.
        for at in [5 * 32, 6 * 32, 8 * 32] {
            let mut far = payload.clone();
            far[at + 31] = 0xFF;
            far[at + 30] = 0xFF;
            cases.push(far);
            let mut huge = payload.clone();
            huge[at + 16..at + 32].fill(0xFF);
            cases.push(huge);
        }
        let mut unknown = release.encode();
        unknown[31] = 6;
        cases.push(unknown);
        // A spent nonce is three words, its nonce a u64.
        let spent = spent.encode();
        assert_eq!(spent.len(), 3 * 32);
        assert_eq!(spent[31], SPENT);
        let mut dirty = spent.clone();
        dirty[32 + 23] = 1;
        cases.push(dirty);
        cases.push(spent[..2 * 32].to_vec());
        // A refund is seven words; its nonce a u64 and its kind a u8.
        let refunded = refund.encode();
        assert_eq!(refunded.len(), 7 * 32);
        assert_eq!(refunded[31], REFUND);
        for at in [32 + 23, 2 * 32 + 30] {
            let mut dirty = refunded.clone();
            dirty[at] = 1;
            cases.push(dirty);
        }
        cases.push(refunded[..6 * 32].to_vec());
        // A hello is two words, its flag 0 or 1.
        let hello = TokenMessage::Hello { heard: true }.encode();
        assert_eq!(hello.len(), 2 * 32);
        let mut flag = hello.clone();
        flag[63] = 2;
        cases.push(flag);
        cases.push(hello[..32].to_vec());
        for case in cases {
            assert_eq!(TokenMessage::decode(&case), None);
        }
    }

    #[test]
    fn identities_are_what_the_sender_records() {
        // A mint's leaves out the metadata; a release's, a refund's and a
        // spent nonce's are the hash of the payload. A payload whose first
        // word is a mint's but too short to be one is hashed whole.
        let payload = mint().encode();
        assert_eq!(identity(&payload), keccak256(&payload[..5 * 32]));
        assert_eq!(VOID[..31], [0; 31]);
        assert_eq!(VOID[31], 1);
        for m in [
            TokenMessage::Release {
                token: NATIVE,
                from: [4; 20],
                to: [5; 20],
                amount: 6,
            },
            TokenMessage::Spent {
                nonce: 7,
                effect: VOID,
            },
        ] {
            let payload = m.encode();
            assert_eq!(identity(&payload), keccak256(&payload));
        }
        assert_eq!(identity(&payload[..4 * 32]), keccak256(&payload[..4 * 32]));
        assert_eq!(identity(&[]), keccak256(&[]));
    }

    #[test]
    fn wrapped_tokens_are_create2_addresses() {
        // The CREATE2 example of EIP-1014: deployer 0, salt 0, init code 0x00.
        assert_eq!(
            wrapped_token(&[0; 20], &[0; 20], &[0]),
            [
                0x4D, 0x1A, 0x2e, 0x2b, 0xB4, 0xF8, 0x8F, 0x02, 0x50, 0xf2, 0x6F, 0xff, 0xf0, 0x98,
                0xB0, 0xb3, 0x0B, 0x26, 0xBF, 0x38
            ]
        );
        assert_ne!(
            wrapped_token(&[0; 20], &[1; 20], &[0]),
            wrapped_token(&[0; 20], &[0; 20], &[0])
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn calls_and_constructor_arguments() {
        assert_eq!(
            &deposit_calldata(&NATIVE, &[1; 20], 5)[..4],
            &abi::selector("deposit(address,address,uint256)")
        );
        // Selectors as solc --hashes prints them, then the arguments in order.
        let release_limit = [0x7c, 0x16, 0x39, 0x7c];
        let mint_limit = [0x24, 0x0a, 0xf9, 0x77];
        let execute_queued = [0x1e, 0xb2, 0x14, 0x9b];
        let two_addresses = [word(&[1; 20]), word(&[2; 20])].concat();
        let address_and_two = [word(&[1; 20]), word(&[2])].concat();
        for (calldata, selector, args) in [
            (
                claim_calldata(&[1; 20], &[2; 20]),
                [0x21, 0xc0, 0xb3, 0x42],
                &two_addresses,
            ),
            (
                claim_to_calldata(&[1; 20], &[2; 20]),
                [0x34, 0xa1, 0xca, 0x89],
                &two_addresses,
            ),
            (
                set_lock_cap_calldata(&[1; 20], 2),
                [0x5f, 0x20, 0x98, 0x57],
                &address_and_two,
            ),
            (
                set_mint_cap_calldata(&[1; 20], 2),
                [0xc0, 0x6a, 0xbe, 0x77],
                &address_and_two,
            ),
            (
                set_release_limit_calldata(&[1; 20], 2, 3),
                release_limit,
                &[word(&[1; 20]), word(&[2]), word(&[3])].concat(),
            ),
            (
                set_mint_limit_calldata(&[1; 20], 2, 3),
                mint_limit,
                &[word(&[1; 20]), word(&[2]), word(&[3])].concat(),
            ),
            (
                execute_queued_calldata(9),
                execute_queued,
                &word(&[9]).to_vec(),
            ),
            (
                freeze_queued_calldata(9),
                [0x58, 0x88, 0xdc, 0x7b],
                &word(&[9]).to_vec(),
            ),
            (
                unfreeze_queued_calldata(9),
                [0x7a, 0xed, 0x6b, 0x98],
                &word(&[9]).to_vec(),
            ),
            (
                cancel_queued_calldata(9),
                [0xb1, 0xfd, 0x65, 0x3e],
                &word(&[9]).to_vec(),
            ),
            (
                refund_queued_calldata(9),
                [0x87, 0x5d, 0x2f, 0x72],
                &word(&[9]).to_vec(),
            ),
            (
                refund_spent_calldata(9, 1, &[2; 20], &[3; 20], &[4; 20], 5),
                [0x4d, 0xcb, 0x3d, 0x0f],
                &[
                    word(&[9]),
                    word(&[1]),
                    word(&[2; 20]),
                    word(&[3; 20]),
                    word(&[4; 20]),
                    word(&[5]),
                ]
                .concat(),
            ),
            (
                resend_spent_calldata(9, &[0xAB]),
                [0x61, 0x10, 0xda, 0x44],
                &[word(&[9]), word(&[0x40]), word(&[1]), padded(&[0xAB])].concat(),
            ),
            (
                report_vetoed_calldata(9),
                [0xd4, 0x9b, 0xf8, 0xff],
                &word(&[9]).to_vec(),
            ),
            (
                report_delivered_calldata(&Message {
                    nonce: 9,
                    sender: [1; 20],
                    recipient: [2; 20],
                    value: 3,
                    payload: vec![0xAB],
                    ..Message::default()
                }),
                [0x00, 0x09, 0xc8, 0xba],
                &[
                    word(&[0x20]),
                    word(&[9]),
                    word(&[1; 20]),
                    word(&[2; 20]),
                    word(&[3]),
                    word(&[0xa0]),
                    word(&[1]),
                    padded(&[0xAB]),
                ]
                .concat(),
            ),
            (
                report_delivered_on_orange_calldata(9, &[1; 20], &[2; 20], 3, &[0xAB]),
                [0xb0, 0xa4, 0x25, 0xb4],
                &[
                    word(&[0x20]),
                    word(&[9]),
                    word(&[1; 20]),
                    word(&[2; 20]),
                    word(&[3]),
                    word(&[0xa0]),
                    word(&[1]),
                    padded(&[0xAB]),
                ]
                .concat(),
            ),
        ] {
            assert_eq!(calldata, [&selector[..], args].concat());
        }
        assert_eq!(
            address_view("balanceOf(address)", &[1; 20])[..4],
            [0x70, 0xa0, 0x82, 0x31]
        );
        let eth = EthereumGatewayConfig {
            outbox: [1; 20],
            inbox: [2; 20],
            orange_chain_id: 3,
            orange_gateway: [4; 20],
            owner: [5; 20],
            guardian: [6; 20],
            message_gas: 7,
        };
        assert_eq!(
            eth.constructor_args(),
            [
                word(&[1; 20]),
                word(&[2; 20]),
                word(&[3]),
                word(&[4; 20]),
                word(&[5; 20]),
                word(&[6; 20]),
                word(&[7]),
            ]
            .concat()
        );
        let orange = OrangeGatewayConfig::new(1, [2; 20], [3; 20], [4; 20], "Orange", "ORANGE");
        assert_eq!(
            (orange.outbox, orange.inbox),
            (OUTBOX_ADDRESS, INBOX_ADDRESS)
        );
        assert_eq!(
            orange.constructor_args(),
            [
                word(&[0x4f, 0x42]),
                word(&[0x45, 0x49]),
                word(&[1]),
                word(&[2; 20]),
                word(&[3; 20]),
                word(&[4; 20]),
                // The two strings' offsets, then each one's length and padded bytes.
                word(&[1, 0x00]),
                word(&[1, 0x40]),
                word(&[6]),
                padded(b"Orange"),
                word(&[6]),
                padded(b"ORANGE"),
            ]
            .concat()
        );
    }

    /// `text` at the high end of a 32-byte word, as ABI bytes are padded.
    fn padded(text: &[u8]) -> [u8; 32] {
        let mut w = [0; 32];
        w[..text.len()].copy_from_slice(text);
        w
    }

    /// `bytes` as the low end of a 32-byte word.
    fn word(bytes: &[u8]) -> [u8; 32] {
        let mut w = [0; 32];
        w[32 - bytes.len()..].copy_from_slice(bytes);
        w
    }
}
