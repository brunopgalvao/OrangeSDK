// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ISoloMessageRecipient} from "../ISoloBridge.sol";

/// @notice Test recipient on Ethereum: keeps the last message an inbox delivered, and reverts while told to.
contract MessageRecipient is ISoloMessageRecipient {
    address public immutable inbox;
    bool public rejecting;
    uint256 public received;
    uint64 public lastSourceChainId;
    uint64 public lastNonce;
    address public lastSender;
    uint256 public lastValue;
    bytes public lastPayload;

    constructor(address inbox_) {
        inbox = inbox_;
    }

    function setRejecting(bool rejecting_) external {
        rejecting = rejecting_;
    }

    function onSoloMessage(uint64 sourceChainId, uint64 nonce, address sender, uint256 value, bytes calldata payload)
        external
    {
        require(msg.sender == inbox, "not the inbox");
        require(!rejecting, "rejecting");
        received += 1;
        lastSourceChainId = sourceChainId;
        lastNonce = nonce;
        lastSender = sender;
        lastValue = value;
        lastPayload = payload;
    }
}
