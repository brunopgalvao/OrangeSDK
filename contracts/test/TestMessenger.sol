// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {EthereumInbox, IEthereumMessageReceiver} from "../EthereumInbox.sol";
import {IOrangeMessageRecipient} from "../IOrangeBridge.sol";

/// @notice Test stand-in for both message channels at once, so that both token gateways run in one
/// EVM: it is the outbox of each (with the `send` of `EthereumOutbox` and of the Orange outbox) and the
/// inbox of each, and delivers whatever the test tells it to, in any order. The test, not this
/// contract, keeps each message to one delivery.
contract TestMessenger {
    /// @notice `OrangeInbox.Message`.
    struct Message {
        uint64 nonce;
        address sender;
        address recipient;
        uint256 value;
        bytes payload;
    }

    /// @notice `OrangeInbox.Entry`, its status `OrangeInbox.Status`: 2 delivered, 3 vetoed.
    struct Entry {
        bytes32 messageHash;
        uint64 executableAt;
        uint64 height;
        uint8 status;
    }

    uint64 public nextNonce;
    /// @notice What `toEthereum` delivered and `veto` vetoed, as `OrangeInbox.entries` reports it.
    mapping(uint64 nonce => Entry) public entries;

    /// @notice What `toOrange` delivered, as `EthereumInbox.deliveredHash` reports it.
    mapping(uint64 nonce => bytes32) public deliveredHash;

    event Sent(uint64 indexed nonce, address indexed sender, address indexed recipient, bytes payload);

    /// @notice Stands in for `OrangeInbox.hashMessage`.
    function hashMessage(Message memory m) public pure returns (bytes32) {
        return keccak256(abi.encode(m.nonce, m.sender, m.recipient, m.value, m.payload));
    }

    /// @notice Stands in for `EthereumInbox.hashMessage`.
    function hashMessage(EthereumInbox.Message memory m) public view returns (bytes32) {
        return keccak256(abi.encode(uint64(block.chainid), m.nonce, m.sender, m.recipient, m.gasLimit, m.payload));
    }

    /// @notice Vetoes message `nonce` as `OrangeInbox.veto` does.
    function veto(uint64 nonce) external {
        entries[nonce] = Entry(bytes32(0), 0, 0, 3);
    }

    /// @notice `EthereumOutbox.send`.
    function send(address recipient, uint64, bytes calldata payload) external returns (uint64 nonce) {
        nonce = nextNonce++;
        emit Sent(nonce, msg.sender, recipient, payload);
    }

    /// @notice The Orange outbox's `send`.
    function send(uint64, address recipient, bytes calldata payload) external payable returns (uint64 nonce) {
        nonce = nextNonce++;
        emit Sent(nonce, msg.sender, recipient, payload);
    }

    /// @notice Delivers as an `OrangeInbox` does, and records the delivery.
    function toEthereum(address gateway, uint64 sourceChainId, uint64 nonce, address sender, bytes calldata payload)
        external
    {
        IOrangeMessageRecipient(gateway).onOrangeMessage(sourceChainId, nonce, sender, 0, payload);
        entries[nonce] = Entry(hashMessage(Message(nonce, sender, gateway, 0, payload)), 0, 0, 2);
    }

    /// @notice Delivers as the Orange inbox does, with a gas limit of 0 in the message, and records
    /// the delivery.
    function toOrange(address gateway, uint64 nonce, address sender, bytes calldata payload) external {
        IEthereumMessageReceiver(gateway).onEthereumMessage(nonce, sender, payload);
        deliveredHash[nonce] = hashMessage(EthereumInbox.Message(nonce, sender, gateway, 0, payload));
    }
}
