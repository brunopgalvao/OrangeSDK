// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title Canonical wrapped token of the token bridge (spec 21 §4)
/// @notice An ERC-20 that a token gateway creates with CREATE2 for one token of the other chain,
/// its *origin*, and alone mints and burns. Its address depends only on the gateway and the origin
/// (the constructor takes no arguments), so anyone computes it before it exists; the gateway sets
/// the origin and the metadata once, in the transaction that creates it.
contract BridgedToken {
    /// @notice The gateway that created the token: the only account that mints and burns.
    address public immutable gateway;
    /// @notice The token of the other chain this one stands for; zero for its native currency.
    address public origin;
    string public name;
    string public symbol;
    uint8 public decimals;
    bool public initialized;
    uint256 public totalSupply;
    mapping(address account => uint256) public balanceOf;
    mapping(address owner => mapping(address spender => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error NotGateway();
    error AlreadyInitialized();
    error InsufficientBalance();
    error InsufficientAllowance();
    error ZeroAddress();

    modifier onlyGateway() {
        if (msg.sender != gateway) revert NotGateway();
        _;
    }

    constructor() {
        gateway = msg.sender;
    }

    /// @notice Sets the origin and the metadata, once.
    function initialize(address origin_, string calldata name_, string calldata symbol_, uint8 decimals_)
        external
        onlyGateway
    {
        if (initialized) revert AlreadyInitialized();
        initialized = true;
        origin = origin_;
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    /// @notice Mints `amount` to `to`.
    function mint(address to, uint256 amount) external onlyGateway {
        if (to == address(0)) revert ZeroAddress();
        totalSupply += amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(address(0), to, amount);
    }

    /// @notice Burns `amount` of `from`'s tokens: the gateway does so when `from` bridges them
    /// back, without an allowance.
    function burn(address from, uint256 amount) external onlyGateway {
        uint256 balance = balanceOf[from];
        if (balance < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[from] = balance - amount;
            totalSupply -= amount;
        }
        emit Transfer(from, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /// @notice Moves `amount` from `from` with the caller's allowance; an allowance of
    /// `type(uint256).max` is never decreased.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < amount) revert InsufficientAllowance();
            unchecked {
                allowance[from][msg.sender] = allowed - amount;
            }
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) private {
        if (to == address(0)) revert ZeroAddress();
        uint256 balance = balanceOf[from];
        if (balance < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[from] = balance - amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
