// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// The contract the node and JSON-RPC tests deploy: storage, events, return
/// data, each kind of failure, and gas refunds.
///
/// Compiled once with solc 0.8.28 (`solc --optimize --bin --bin-runtime
/// Counter.sol`); the bytecode is committed next to this file as
/// `Counter.bin` (creation) and `Counter.bin-runtime` (deployed code).
contract Counter {
    /// Slot 0.
    uint256 public count;
    /// Slot 1.
    address public owner;
    /// Slots 2 to 9.
    uint256[8] public cells;

    event Incremented(address indexed by, uint256 indexed total, uint256 delta);
    event Noted(string text);

    error NotOwner(address caller);

    constructor(uint256 start) {
        count = start;
        owner = msg.sender;
    }

    function increment(uint256 delta) external returns (uint256) {
        count += delta;
        emit Incremented(msg.sender, count, delta);
        return count;
    }

    function note(string calldata text) external {
        emit Noted(text);
    }

    function fail(string calldata reason) external pure {
        revert(reason);
    }

    function guarded() external view returns (address) {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        return owner;
    }

    function divide(uint256 a, uint256 b) external pure returns (uint256) {
        return a / b;
    }

    function halt() external pure {
        assembly {
            invalid()
        }
    }

    function fill(uint256 n) external {
        for (uint256 i = 0; i < n; i++) cells[i] = i + 1;
    }

    function clear(uint256 n) external {
        for (uint256 i = 0; i < n; i++) delete cells[i];
    }
}
