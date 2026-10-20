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
contract SoloInbox {
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

    /// Delivers message `nonce` once the verifier accepts its proofs against
    /// the light client's state root of execution block `blockNumber`.
    /// Anyone may relay it.
    function deliver(
        uint64 blockNumber,
        uint64 nonce,
        address sender,
        address recipient,
        bytes calldata payload,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof
    ) external {
        (bytes32 stateRoot,,, uint64 usableAt) = LIGHT_CLIENT.executionRoot(blockNumber);
        if (stateRoot == bytes32(0)) revert UnknownBlock(blockNumber);
        if (block.timestamp < usableAt) revert TooEarly(usableAt);
        VERIFIER.consume(stateRoot, nonce, sender, recipient, payload, accountProof, storageProof);
        try IEthereumMessageReceiver(recipient).onEthereumMessage(nonce, sender, payload) {}
        catch (bytes memory reason) {
            revert DeliveryFailed(reason);
        }
        emit MessageDelivered(nonce, sender, recipient, blockNumber);
    }
}
