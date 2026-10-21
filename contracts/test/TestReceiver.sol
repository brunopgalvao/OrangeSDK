// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice Test recipient of native currency: refuses it while `rejecting` is set.
contract TestReceiver {
    bool public rejecting;
    uint256 public received;

    function setRejecting(bool value) external {
        rejecting = value;
    }

    receive() external payable {
        require(!rejecting, "rejecting");
        received += msg.value;
    }
}
