// SPDX-License-Identifier: Apache-2.0
//
// Contracts that crates/solo-node/tests/evm.rs runs on the reference kernel.
// The tests read the committed bytecode next to this file and never call solc;
// after editing, regenerate it with build.sh (solc 0.8.28, no optimizer,
// default EVM version, no metadata hash) and commit both.
pragma solidity 0.8.28;

/// Storage, events, reverts, running out of gas, and receiving value.
contract Store {
    /// Slot 0.
    uint256 public value;
    /// Slot 1: wei received from each sender.
    mapping(address => uint256) public paid;

    event Set(address indexed who, uint256 indexed old, uint256 value);

    constructor(uint256 initial) payable {
        value = initial;
    }

    function set(uint256 v) external {
        emit Set(msg.sender, value, v);
        value = v;
    }

    /// Writes and logs, then reverts: none of it may stick.
    function setAndRevert(uint256 v) external {
        value = v;
        emit Set(msg.sender, 0, v);
        revert("nope");
    }

    /// Writes until the gas runs out.
    function burn() external {
        while (true) {
            value += 1;
        }
    }

    receive() external payable {
        paid[msg.sender] += msg.value;
    }
}

/// What a block looks like from inside the EVM, and two precompiles through Solidity.
contract Probe {
    event Seen(
        uint256 number,
        uint256 timestamp,
        bytes32 parent,
        uint256 chainId,
        address coinbase,
        uint256 basefee,
        uint256 gaslimit,
        uint256 prevrandao
    );

    function record() external {
        emit Seen(
            block.number,
            block.timestamp,
            blockhash(block.number - 1),
            block.chainid,
            block.coinbase,
            block.basefee,
            block.gaslimit,
            block.prevrandao
        );
    }

    function hashOf(uint256 n) external view returns (bytes32) {
        return blockhash(n);
    }

    function current() external view returns (uint256 number, uint256 timestamp, uint256 chainId) {
        return (block.number, block.timestamp, block.chainid);
    }

    function recover(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }

    function sha(bytes calldata data) external pure returns (bytes32) {
        return sha256(data);
    }
}

/// Contracts that make contracts.
contract Factory {
    event Made(address child);

    function make(uint256 v) external returns (address child) {
        child = address(new Store(v));
        emit Made(child);
    }

    function make2(bytes32 salt, uint256 v) external returns (address child) {
        child = address(new Store{salt: salt}(v));
        emit Made(child);
    }

    /// Creates a contract and destroys it in the same transaction, which
    /// removes it (EIP-6780).
    function makeAndDestroy(bytes32 salt, address payable heir) external payable returns (address child) {
        Doomed d = new Doomed{salt: salt, value: msg.value}();
        d.destroy(heir);
        child = address(d);
        emit Made(child);
    }
}

/// Self-destructs on request.
contract Doomed {
    /// Slot 0, written by the constructor.
    uint256 public marker = 7;

    constructor() payable {}

    function destroy(address payable heir) external {
        selfdestruct(heir);
    }
}
