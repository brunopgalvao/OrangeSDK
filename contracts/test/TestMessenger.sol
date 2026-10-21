// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IEthereumMessageReceiver} from "../EthereumInbox.sol";
import {ISoloMessageRecipient} from "../ISoloBridge.sol";

/// @notice Test stand-in for both message channels at once, so that both token gateways run in one
/// EVM: it is the outbox of each (with the `send` of `EthereumOutbox` and of the Solo outbox) and the
/// inbox of each, and delivers whatever the test tells it to, in any order. The test, not this
/// contract, keeps each message to one delivery.
contract TestMessenger {
    uint64 public nextNonce;

    event Sent(uint64 indexed nonce, address indexed sender, address indexed recipient, bytes payload);

    /// @notice `EthereumOutbox.send`.
    function send(address recipient, uint64, bytes calldata payload) external returns (uint64 nonce) {
        nonce = nextNonce++;
        emit Sent(nonce, msg.sender, recipient, payload);
    }

    /// @notice The Solo outbox's `send`.
    function send(uint64, address recipient, bytes calldata payload) external payable returns (uint64 nonce) {
        nonce = nextNonce++;
        emit Sent(nonce, msg.sender, recipient, payload);
    }

    /// @notice Delivers as a `SoloInbox` does.
    function toEthereum(address gateway, uint64 sourceChainId, uint64 nonce, address sender, bytes calldata payload)
        external
    {
        ISoloMessageRecipient(gateway).onSoloMessage(sourceChainId, nonce, sender, 0, payload);
    }

    /// @notice Delivers as the Solo inbox does.
    function toSolo(address gateway, uint64 nonce, address sender, bytes calldata payload) external {
        IEthereumMessageReceiver(gateway).onEthereumMessage(nonce, sender, payload);
    }
}
