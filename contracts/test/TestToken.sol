// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice Test ERC-20 for the token bridge: anyone mints; it can be told to take a fee on every
/// transfer, to revert transfers, or to call a contract from inside `transferFrom` (a reentrancy
/// attempt), keeping what that call returned.
contract TestToken {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address account => uint256) public balanceOf;
    mapping(address owner => mapping(address spender => uint256)) public allowance;
    /// @notice Fee in basis points burned from every transfer.
    uint256 public feeBps;
    /// @notice Whether transfers revert.
    bool public failing;
    address public hook;
    bytes public hookData;
    /// @notice Whether the last hook call succeeded, and what it returned or reverted with.
    bool public hookSucceeded;
    bytes public hookResult;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function setFee(uint256 bps) external {
        feeBps = bps;
    }

    function setFailing(bool value) external {
        failing = value;
    }

    function setHook(address target, bytes calldata data) external {
        hook = target;
        hookData = data;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        if (hook != address(0)) {
            (hookSucceeded, hookResult) = hook.call(hookData);
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) private {
        require(!failing, "failing");
        uint256 fee = amount * feeBps / 10_000;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
        totalSupply -= fee;
        emit Transfer(from, to, amount - fee);
    }
}
