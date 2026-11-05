// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// The Ethereum side of the Ethereum-to-Orange message bridge (spec 18 §6.1).
/// Deployed on Ethereum once per Orange chain. Each message's hash is stored
/// in `messages` (storage slot 0), where the Orange light client proves it
/// with an account and storage proof against a finalized state root.
contract EthereumOutbox {
    /// Message hashes by nonce: storage slot 0.
    mapping(uint64 => bytes32) public messages;
    /// The nonce the next message gets: storage slot 1.
    uint64 public nextNonce;
    /// The chain id of the Orange chain the messages are for.
    uint64 public immutable orangeChainId;

    /// Message `nonce` from `sender` to `recipient` on Orange, which gets
    /// `gasLimit` gas to handle it.
    event MessageSent(
        uint64 indexed nonce,
        address indexed sender,
        address indexed recipient,
        uint64 gasLimit,
        bytes payload,
        bytes32 messageHash
    );

    constructor(uint64 chainId) {
        orangeChainId = chainId;
    }

    /// Sends `payload` to `recipient` on Orange, where the inbox calls
    /// `recipient.onEthereumMessage(nonce, msg.sender, payload)` once, with
    /// exactly `gasLimit` gas: no relayer can deliver the message with less.
    function send(address recipient, uint64 gasLimit, bytes calldata payload) external returns (uint64 nonce) {
        nonce = nextNonce++;
        bytes32 messageHash = keccak256(abi.encode(orangeChainId, nonce, msg.sender, recipient, gasLimit, payload));
        messages[nonce] = messageHash;
        emit MessageSent(nonce, msg.sender, recipient, gasLimit, payload, messageHash);
    }
}
