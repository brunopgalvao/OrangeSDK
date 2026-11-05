// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IEthereumMessageReceiver} from "../EthereumInbox.sol";

/// A test recipient on Orange: records the messages the inbox delivers, and
/// reverts while `failing` is set.
contract EthereumMessageRecipient is IEthereumMessageReceiver {
    address internal constant INBOX = 0x0000000000000000000000000000000000004549;

    uint64 public count;
    uint64 public lastNonce;
    address public lastSender;
    bytes public lastPayload;
    bool public failing;
    /// The gas left when the last message arrived.
    uint256 public lastGas;

    function setFailing(bool value) external {
        failing = value;
    }

    function onEthereumMessage(uint64 nonce, address sender, bytes calldata payload) external {
        uint256 gas = gasleft();
        require(msg.sender == INBOX, "not the inbox");
        require(!failing, "failing");
        count += 1;
        lastNonce = nonce;
        lastSender = sender;
        lastPayload = payload;
        lastGas = gas;
    }
}
