// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// The Ethereum side of the Ethereum-to-Solo message bridge (spec 18 §6.1).
/// Deployed on Ethereum once per Solo chain. Each message's hash is stored
/// in `messages` (storage slot 0), where the Solo light client proves it
/// with an account and storage proof against a finalized state root.
contract EthereumOutbox {
    /// Message hashes by nonce: storage slot 0.
    mapping(uint64 => bytes32) public messages;
    /// The nonce the next message gets: storage slot 1.
    uint64 public nextNonce;
    /// The chain id of the Solo chain the messages are for.
    uint64 public immutable soloChainId;

    /// Message `nonce` from `sender` to `recipient` on Solo.
    event MessageSent(
        uint64 indexed nonce, address indexed sender, address indexed recipient, bytes payload, bytes32 messageHash
    );

    constructor(uint64 chainId) {
        soloChainId = chainId;
    }

    /// Sends `payload` to `recipient` on Solo, where the inbox calls
    /// `recipient.onEthereumMessage(nonce, msg.sender, payload)` once.
    function send(address recipient, bytes calldata payload) external returns (uint64 nonce) {
        nonce = nextNonce++;
        bytes32 messageHash = keccak256(abi.encode(soloChainId, nonce, msg.sender, recipient, payload));
        messages[nonce] = messageHash;
        emit MessageSent(nonce, msg.sender, recipient, payload, messageHash);
    }
}
