// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IOrangeOutbox} from "../IOrangeOutbox.sol";

/// @notice Test contract on Orange: sends through the outbox from a contract, and tries the calls the
/// outbox refuses or that a revert undoes.
contract OutboxCaller {
    IOrangeOutbox public constant OUTBOX = IOrangeOutbox(0x0000000000000000000000000000000000004F42);

    event Sent(uint64 nonce);

    function relay(uint64 destChainId, address recipient, bytes calldata payload) external payable returns (uint64) {
        uint64 nonce = OUTBOX.send{value: msg.value}(destChainId, recipient, payload);
        emit Sent(nonce);
        return nonce;
    }

    function relayThenRevert(uint64 destChainId, address recipient, bytes calldata payload) external {
        OUTBOX.send(destChainId, recipient, payload);
        revert("undone");
    }

    function relayStatic(uint64 destChainId, address recipient, bytes calldata payload)
        external
        view
        returns (bool ok)
    {
        (ok,) = address(OUTBOX).staticcall(abi.encodeCall(IOrangeOutbox.send, (destChainId, recipient, payload)));
    }

    function relayDelegate(uint64 destChainId, address recipient, bytes calldata payload) external returns (bool ok) {
        (ok,) = address(OUTBOX).delegatecall(abi.encodeCall(IOrangeOutbox.send, (destChainId, recipient, payload)));
    }
}
