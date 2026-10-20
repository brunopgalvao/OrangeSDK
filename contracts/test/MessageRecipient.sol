// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IEthereumMessageReceiver} from "../SoloInbox.sol";

/// A test recipient on Solo: records the messages the inbox delivers, and
/// reverts while `failing` is set.
contract MessageRecipient is IEthereumMessageReceiver {
    address internal constant INBOX = 0x0000000000000000000000000000000000004549;

    uint64 public count;
    uint64 public lastNonce;
    address public lastSender;
    bytes public lastPayload;
    bool public failing;

    function setFailing(bool value) external {
        failing = value;
    }

    function onEthereumMessage(uint64 nonce, address sender, bytes calldata payload) external {
        require(msg.sender == INBOX, "not the inbox");
        require(!failing, "failing");
        count += 1;
        lastNonce = nonce;
        lastSender = sender;
        lastPayload = payload;
    }
}
