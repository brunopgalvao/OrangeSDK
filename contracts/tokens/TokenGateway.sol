// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {BridgedToken} from "./BridgedToken.sol";

/// @notice The part of ERC-20 a gateway calls on a token it locks.
interface ILockableToken {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title One end of the canonical token bridge (spec 21)
/// @notice A gateway sits on each chain, paired with the gateway of the other chain over a
/// verified message channel. A token *native* to this chain (an ERC-20 here, or the native currency
/// as `NATIVE`) is locked here and minted as a `BridgedToken` there; a `BridgedToken` this gateway
/// created is burned here and the locked token released there. The two subcontracts only send and
/// authenticate messages; everything about value is here.
abstract contract TokenGateway {
    /// @notice Message kind: mint the wrapped token of a token locked on the sending chain.
    uint8 public constant MINT = 1;
    /// @notice Message kind: release a token of the receiving chain that its wrapped token's burn freed.
    uint8 public constant RELEASE = 2;
    /// @notice The token address that stands for the chain's native currency.
    address public constant NATIVE = address(0);
    /// @notice Gas a release gives the token's `transfer`, or the recipient of native currency.
    uint256 public constant TRANSFER_GAS = 100_000;
    /// @notice Gas a release keeps for the value transfer, a new account and the bookkeeping after.
    uint256 public constant TRANSFER_RESERVE = 60_000;
    /// @notice Bytes of a token's name and symbol that a deposit carries; the rest is cut off.
    uint256 public constant MAX_METADATA = 64;

    /// @notice The paired gateway on the other chain: the only sender whose messages count.
    address public immutable remoteGateway;
    /// @notice keccak256 of `BridgedToken`'s creation code, which wrapped token addresses commit to.
    bytes32 public immutable tokenCodeHash;

    /// @notice Sets caps and the guardian, unpauses, and transfers ownership.
    address public owner;
    /// @notice Pauses.
    address public guardian;
    /// @notice Whether deposits, deliveries and claims are stopped.
    bool public paused;
    /// @notice The name a deposit of the native currency carries.
    string public nativeName;
    /// @notice The symbol a deposit of the native currency carries.
    string public nativeSymbol;

    /// @notice Amount of each native token (or the native currency) locked here for wrapped tokens
    /// minted, or about to be minted, on the other chain.
    mapping(address token => uint256) public locked;
    /// @notice The most of each native token that may be locked at once; zero refuses the token.
    mapping(address token => uint256) public lockCap;
    /// @notice The most of each wrapped token (by its origin) that may exist at once; zero
    /// refuses every mint of it.
    mapping(address origin => uint256) public mintCap;
    /// @notice Whether this gateway created the token.
    mapping(address token => bool) public isWrapped;
    /// @notice The origin of each wrapped token this gateway created.
    mapping(address token => address) public originOf;
    /// @notice Releases whose transfer failed, by token and recipient, waiting to be claimed.
    mapping(address token => mapping(address recipient => uint256)) public owed;

    uint256 private transient entered;

    event Deposited(uint64 indexed nonce, address indexed token, address indexed from, address to, uint256 amount);
    event Minted(
        uint64 indexed nonce, address indexed origin, address indexed token, address from, address to, uint256 amount
    );
    event Released(uint64 indexed nonce, address indexed token, address indexed to, address from, uint256 amount);
    event ReleaseFailed(uint64 indexed nonce, address indexed token, address indexed to, address from, uint256 amount);
    event Claimed(address indexed token, address indexed recipient, address receiver, uint256 amount);
    event WrappedTokenCreated(address indexed origin, address indexed token, string name, string symbol, uint8 decimals);
    event LockCapChanged(address indexed token, uint256 cap);
    event MintCapChanged(address indexed origin, uint256 cap);
    event Paused(address indexed by);
    event Unpaused();
    event OwnerChanged(address indexed owner);
    event GuardianChanged(address indexed guardian);

    error NotOwner();
    error NotGuardian();
    error IsPaused();
    error Reentrant();
    error ZeroAddress();
    error ZeroAmount();
    error WrongValue();
    error CapExceeded(address token);
    error BalanceMismatch();
    error TransferFailed();
    error InsufficientGas();
    error NothingOwed();
    error UnknownMessage();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _;
    }

    modifier nonReentrant() {
        if (entered != 0) revert Reentrant();
        entered = 1;
        _;
        entered = 0;
    }

    constructor(
        address remoteGateway_,
        address owner_,
        address guardian_,
        string memory nativeName_,
        string memory nativeSymbol_
    ) {
        if (remoteGateway_ == address(0) || owner_ == address(0) || guardian_ == address(0)) revert ZeroAddress();
        remoteGateway = remoteGateway_;
        tokenCodeHash = keccak256(type(BridgedToken).creationCode);
        owner = owner_;
        guardian = guardian_;
        nativeName = nativeName_;
        nativeSymbol = nativeSymbol_;
    }

    /// @notice Bridges `amount` of `token` to `to` on the other chain and returns the message's
    /// nonce. A wrapped token of this gateway is burned from the caller; any other token is locked:
    /// the native currency as the call's value, an ERC-20 by `transferFrom` with the gateway's
    /// balance growing by exactly `amount`.
    function deposit(address token, address to, uint256 amount)
        external
        payable
        whenNotPaused
        nonReentrant
        returns (uint64 nonce)
    {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        bytes memory payload;
        if (isWrapped[token]) {
            if (msg.value != 0) revert WrongValue();
            BridgedToken(token).burn(msg.sender, amount);
            payload = abi.encode(RELEASE, originOf[token], msg.sender, to, amount);
        } else {
            uint256 total = locked[token] + amount;
            if (total > lockCap[token]) revert CapExceeded(token);
            if (token == NATIVE) {
                if (msg.value != amount) revert WrongValue();
            } else {
                if (msg.value != 0) revert WrongValue();
                uint256 before = ILockableToken(token).balanceOf(address(this));
                _transferIn(token, amount);
                uint256 later = ILockableToken(token).balanceOf(address(this));
                if (later < before || later - before != amount) revert BalanceMismatch();
            }
            locked[token] = total;
            (string memory name, string memory symbol, uint8 decimals) = _metadata(token);
            payload = abi.encode(MINT, token, msg.sender, to, amount, name, symbol, decimals);
        }
        nonce = _send(payload);
        emit Deposited(nonce, token, msg.sender, to, amount);
    }

    /// @notice Sends owed `token` to `recipient`. Anyone may call it; it reverts and the amount
    /// stays owed if the transfer fails again.
    function claim(address token, address recipient) external {
        _claim(token, recipient, recipient);
    }

    /// @notice Sends what the caller is owed of `token` to `receiver` instead.
    function claimTo(address token, address receiver) external {
        _claim(token, msg.sender, receiver);
    }

    /// @notice The address of the wrapped token of `origin`, created or not.
    function wrappedToken(address origin) public view returns (address) {
        bytes32 salt = bytes32(uint256(uint160(origin)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, tokenCodeHash)))));
    }

    /// @notice Stops deposits, deliveries and claims. The guardian or the owner.
    function pause() external {
        if (msg.sender != guardian && msg.sender != owner) revert NotGuardian();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }

    /// @notice Sets how much of the native `token` may be locked; zero refuses new deposits of it.
    function setLockCap(address token, uint256 cap) external onlyOwner {
        lockCap[token] = cap;
        emit LockCapChanged(token, cap);
    }

    /// @notice Sets how much of the wrapped token of `origin` may exist; a mint past it waits.
    function setMintCap(address origin, uint256 cap) external onlyOwner {
        mintCap[origin] = cap;
        emit MintCapChanged(origin, cap);
    }

    function setGuardian(address guardian_) external onlyOwner {
        if (guardian_ == address(0)) revert ZeroAddress();
        guardian = guardian_;
        emit GuardianChanged(guardian_);
    }

    function transferOwnership(address owner_) external onlyOwner {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        emit OwnerChanged(owner_);
    }

    /// @dev Sends `payload` to the paired gateway and returns the channel's nonce.
    function _send(bytes memory payload) internal virtual returns (uint64);

    /// @dev Acts on a message the subcontract authenticated as the paired gateway's. Reverting
    /// leaves the message undelivered, to be delivered again.
    function _receive(uint64 nonce, bytes calldata payload) internal whenNotPaused nonReentrant {
        // The whole first word names the kind, so a word that only ends in a kind is unknown.
        uint256 kind = uint256(bytes32(payload[:32]));
        if (kind == MINT) {
            (, address origin, address from, address to, uint256 amount, string memory name, string memory symbol, uint8 decimals)
            = abi.decode(payload, (uint8, address, address, address, uint256, string, string, uint8));
            address token = _wrapped(origin, name, symbol, decimals);
            if (BridgedToken(token).totalSupply() + amount > mintCap[origin]) revert CapExceeded(origin);
            BridgedToken(token).mint(to, amount);
            emit Minted(nonce, origin, token, from, to, amount);
        } else if (kind == RELEASE) {
            (, address token, address from, address to, uint256 amount) =
                abi.decode(payload, (uint8, address, address, address, uint256));
            locked[token] -= amount;
            if (gasleft() < TRANSFER_GAS * 64 / 63 + TRANSFER_RESERVE) revert InsufficientGas();
            if (_transferOut(token, to, amount)) {
                emit Released(nonce, token, to, from, amount);
            } else {
                owed[token][to] += amount;
                emit ReleaseFailed(nonce, token, to, from, amount);
            }
        } else {
            revert UnknownMessage();
        }
    }

    function _claim(address token, address recipient, address receiver) private whenNotPaused nonReentrant {
        if (receiver == address(0)) revert ZeroAddress();
        uint256 amount = owed[token][recipient];
        if (amount == 0) revert NothingOwed();
        owed[token][recipient] = 0;
        if (gasleft() < TRANSFER_GAS * 64 / 63 + TRANSFER_RESERVE) revert InsufficientGas();
        if (!_transferOut(token, receiver, amount)) revert TransferFailed();
        emit Claimed(token, recipient, receiver, amount);
    }

    /// @dev The wrapped token of `origin`, created with the metadata if it does not exist yet.
    function _wrapped(address origin, string memory name, string memory symbol, uint8 decimals)
        private
        returns (address token)
    {
        token = wrappedToken(origin);
        if (!isWrapped[token]) {
            new BridgedToken{salt: bytes32(uint256(uint160(origin)))}();
            BridgedToken(token).initialize(origin, name, symbol, decimals);
            isWrapped[token] = true;
            originOf[token] = origin;
            emit WrappedTokenCreated(origin, token, name, symbol, decimals);
        }
    }

    /// @dev `transferFrom(msg.sender, this, amount)`, accepting no return data or `true`.
    function _transferIn(address token, uint256 amount) private {
        (bool ok, bytes memory ret) =
            token.call(abi.encodeCall(ILockableToken.transferFrom, (msg.sender, address(this), amount)));
        if (!ok || (ret.length != 0 && (ret.length < 32 || uint256(bytes32(ret)) != 1))) revert TransferFailed();
    }

    /// @dev Sends `amount` of `token` (or the native currency) to `to` with `TRANSFER_GAS`, copying
    /// no return data beyond one word; false if the transfer reverted, returned anything but
    /// nothing or `true`, or the token has no code.
    function _transferOut(address token, address to, uint256 amount) private returns (bool ok) {
        if (token == NATIVE) {
            assembly {
                ok := call(100000, to, amount, 0, 0, 0, 0)
            }
            return ok;
        }
        bytes memory data = abi.encodeWithSelector(0xa9059cbb, to, amount);
        uint256 size;
        uint256 word;
        assembly {
            ok := call(100000, token, 0, add(data, 32), mload(data), 0, 32)
            size := returndatasize()
            word := mload(0)
        }
        if (size == 0) return ok && token.code.length != 0;
        return ok && size >= 32 && word == 1;
    }

    /// @dev What a deposit of `token` tells the other chain about it: the name and symbol (at most
    /// `MAX_METADATA` bytes each, empty if the token does not answer) and the decimals (18 if it
    /// does not answer with a number below 256).
    function _metadata(address token)
        private
        view
        returns (string memory name, string memory symbol, uint8 decimals)
    {
        if (token == NATIVE) return (nativeName, nativeSymbol, 18);
        name = _text(token, 0x06fdde03);
        symbol = _text(token, 0x95d89b41);
        decimals = 18;
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x313ce567));
        if (ok && ret.length == 32 && uint256(bytes32(ret)) < 256) decimals = uint8(uint256(bytes32(ret)));
    }

    /// @dev The string `token` returns for `selector`, ABI-encoded or as a `bytes32`, cut to
    /// `MAX_METADATA` bytes; empty for anything else.
    function _text(address token, bytes4 selector) private view returns (string memory) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(selector));
        if (!ok) return "";
        uint256 start;
        uint256 length;
        if (ret.length == 32) {
            start = 32;
            while (length < 32 && ret[length] != 0) {
                length++;
            }
        } else if (ret.length >= 64) {
            uint256 offset;
            assembly {
                offset := mload(add(ret, 32))
                length := mload(add(ret, 64))
            }
            if (offset != 32 || length > ret.length - 64) return "";
            start = 96;
        }
        if (length > MAX_METADATA) length = MAX_METADATA;
        bytes memory text = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            text[i] = ret[start - 32 + i];
        }
        return string(text);
    }
}
