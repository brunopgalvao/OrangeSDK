//! The canonical token bridge (spec 21): the messages the two token
//! gateways send each other, the addresses of wrapped tokens, the calls a
//! user, an owner or a relayer makes, and the gateways' constructor
//! arguments.
//!
//! A relayer moves token messages as it moves any other: a gateway's
//! messages are ordinary messages of the channel it sends through (spec 17
//! from Solo, spec 18 from Ethereum). [`TokenMessage::decode`] reads what a
//! message's payload asks the receiving gateway to do, so that tooling can
//! show it or check it before relaying.

use solo_abi::bridge::OUTBOX_ADDRESS;
use solo_abi::bridge_in::INBOX_ADDRESS;
use solo_abi::types::Address;
use solo_trie::keccak256;

use crate::abi::{self, Value};

/// Message kind: mint the wrapped token of a token locked on the sending chain.
pub const MINT: u8 = 1;
/// Message kind: release a token that a burn of its wrapped token freed.
pub const RELEASE: u8 = 2;
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
    /// decimals)` or `abi.encode(uint8 RELEASE, address token, address
    /// from, address to, uint256 amount)`.
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
        let message = if kind == MINT {
            TokenMessage::Mint {
                origin: address(1)?,
                from: address(2)?,
                to: address(3)?,
                amount: word_u128(word(4)?),
                name: tail(payload, 5 * 32)?,
                symbol: tail(payload, 6 * 32)?,
                decimals: word(7)?[31],
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
    /// The Solo chain's `EthereumOutbox`.
    pub outbox: Address,
    /// The `SoloInbox` whose deliveries count.
    pub inbox: Address,
    /// The Solo chain's id.
    pub solo_chain_id: u64,
    /// The paired gateway on Solo.
    pub solo_gateway: Address,
    /// The owner.
    pub owner: Address,
    /// The guardian.
    pub guardian: Address,
    /// The gas each message gives the gateway on Solo.
    pub message_gas: u64,
}

impl EthereumGatewayConfig {
    /// The constructor arguments.
    #[must_use]
    pub fn constructor_args(&self) -> Vec<u8> {
        abi::encode(&[
            Value::address(&self.outbox),
            Value::address(&self.inbox),
            Value::uint(u128::from(self.solo_chain_id)),
            Value::address(&self.solo_gateway),
            Value::address(&self.owner),
            Value::address(&self.guardian),
            Value::uint(u128::from(self.message_gas)),
        ])
    }
}

/// The configuration `TokenGatewayOnSolo` is deployed with (spec 21 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoloGatewayConfig {
    /// The outbox: [`OUTBOX_ADDRESS`] on a Solo chain.
    pub outbox: Address,
    /// The inbox: [`INBOX_ADDRESS`] on a Solo chain.
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

impl SoloGatewayConfig {
    /// A configuration with the Solo chain's outbox and inbox.
    #[must_use]
    pub fn new(
        ethereum_chain_id: u64,
        ethereum_gateway: Address,
        owner: Address,
        guardian: Address,
        native_name: &str,
        native_symbol: &str,
    ) -> SoloGatewayConfig {
        SoloGatewayConfig {
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
        for m in [mint(), release.clone()] {
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
        unknown[31] = 3;
        cases.push(unknown);
        for case in cases {
            assert_eq!(TokenMessage::decode(&case), None);
        }
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
    fn calls_and_constructor_arguments() {
        assert_eq!(
            &deposit_calldata(&NATIVE, &[1; 20], 5)[..4],
            &abi::selector("deposit(address,address,uint256)")
        );
        // Selectors as solc --hashes prints them, then the arguments in order.
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
            solo_chain_id: 3,
            solo_gateway: [4; 20],
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
        let solo = SoloGatewayConfig::new(1, [2; 20], [3; 20], [4; 20], "Solo", "SOLO");
        assert_eq!((solo.outbox, solo.inbox), (OUTBOX_ADDRESS, INBOX_ADDRESS));
        let padded = |text: &[u8]| {
            let mut w = [0; 32];
            w[..text.len()].copy_from_slice(text);
            w
        };
        assert_eq!(
            solo.constructor_args(),
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
                word(&[4]),
                padded(b"Solo"),
                word(&[4]),
                padded(b"SOLO"),
            ]
            .concat()
        );
    }

    /// `bytes` as the low end of a 32-byte word.
    fn word(bytes: &[u8]) -> [u8; 32] {
        let mut w = [0; 32];
        w[32 - bytes.len()..].copy_from_slice(bytes);
        w
    }
}
