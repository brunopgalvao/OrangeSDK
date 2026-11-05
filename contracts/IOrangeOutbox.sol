// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice The outbox of an Orange chain, the system address 0x0000000000000000000000000000000000004f42
/// (spec 17 §2). Contracts on Orange call it to send a message to another chain.
interface IOrangeOutbox {
    /// @notice Emitted for every message the outbox records.
    event MessageSent(
        uint64 indexed nonce,
        address indexed sender,
        uint64 indexed destChainId,
        address recipient,
        uint256 value,
        bytes32 messageHash,
        bytes payload
    );

    /// @notice Records a message to `recipient` on chain `destChainId` and returns its nonce.
    /// The value sent stays with the outbox.
    function send(uint64 destChainId, address recipient, bytes calldata payload)
        external
        payable
        returns (uint64 nonce);
}
