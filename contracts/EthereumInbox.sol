// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IEthereumLightClient} from "./IEthereumLightClient.sol";
import {IMessageVerifier} from "./IMessageVerifier.sol";

/// What a contract on Solo implements to receive messages from Ethereum.
interface IEthereumMessageReceiver {
    /// Called by the inbox (0x0000000000000000000000000000000000004549) once
    /// per message; `sender` is the account that called the outbox on Ethereum.
    function onEthereumMessage(uint64 nonce, address sender, bytes calldata payload) external;
}

/// The Solo inbox (spec 18 §6). The kernel places this code at
/// 0x0000000000000000000000000000000000004549 at genesis, without running a
/// constructor, so it keeps no immutables and no storage.
contract EthereumInbox {
    IEthereumLightClient internal constant LIGHT_CLIENT =
        IEthereumLightClient(0x000000000000000000000000000000000000454C);
    IMessageVerifier internal constant VERIFIER = IMessageVerifier(0x000000000000000000000000000000000000454D);

    /// Message `nonce` from `sender` on Ethereum reached `recipient`.
    event MessageDelivered(uint64 indexed nonce, address indexed sender, address indexed recipient, uint64 blockNumber);

    /// The light client holds no state root for this execution block.
    error UnknownBlock(uint64 blockNumber);
    /// The state root is not usable before `usableAt` (seconds).
    error TooEarly(uint64 usableAt);
    /// The recipient reverted; the delivery is undone and may be retried.
    error DeliveryFailed(bytes reason);
    /// Too little gas is left to give the recipient the message's `gasLimit`;
    /// the delivery is undone and may be retried with more.
    error InsufficientGas(uint64 gasLimit);

    /// Gas kept back, beyond the 1/64 the EVM withholds, for the work
    /// between the check in `_call` and the call itself.
    uint256 internal constant CALL_RESERVE = 5000;

    /// Delivers message `nonce` once the verifier accepts its proofs against
    /// the light client's state root of execution block `blockNumber`.
    /// Anyone may relay it.
    function deliver(
        uint64 blockNumber,
        uint64 nonce,
        address sender,
        address recipient,
        uint64 gasLimit,
        bytes calldata payload,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof
    ) external {
        VERIFIER.consume(
            _stateRoot(blockNumber), nonce, sender, recipient, gasLimit, payload, accountProof, storageProof
        );
        _call(recipient, gasLimit, abi.encodeCall(IEthereumMessageReceiver.onEthereumMessage, (nonce, sender, payload)));
        emit MessageDelivered(nonce, sender, recipient, blockNumber);
    }

    /// The light client's state root of execution block `blockNumber`, once
    /// the delay has passed.
    function _stateRoot(uint64 blockNumber) internal view returns (bytes32 stateRoot) {
        uint64 usableAt;
        (stateRoot,,, usableAt) = LIGHT_CLIENT.executionRoot(blockNumber);
        if (stateRoot == bytes32(0)) revert UnknownBlock(blockNumber);
        if (block.timestamp < usableAt) revert TooEarly(usableAt);
    }

    /// Calls the recipient with exactly `gasLimit` gas, and reverts the whole
    /// delivery if the recipient has no code (with empty data), if less gas
    /// is left, or if the recipient reverts. The sender chose `gasLimit`, so
    /// a relayer cannot starve the recipient's own calls.
    function _call(address recipient, uint64 gasLimit, bytes memory data) internal {
        if (recipient.code.length == 0) revert();
        if (gasleft() < (uint256(gasLimit) + CALL_RESERVE) * 64 / 63) revert InsufficientGas(gasLimit);
        (bool ok, bytes memory reason) = recipient.call{gas: gasLimit}(data);
        if (!ok) revert DeliveryFailed(reason);
    }
}
