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
    /// @notice Message kind: the sending gateway exists; its flag says whether it has heard from the
    /// receiving gateway, which answers if it has not.
    uint8 public constant HELLO = 3;
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
    /// @notice Whether a message of the paired gateway has arrived, which proves it exists at its
    /// address; until then nothing may be deposited, as a message to a gateway that does not exist
    /// may be lost with what it carries.
    bool public peerLive;
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

    /// @notice A limit on what the gateway pays out of one token: at most `amount` at once, refilling
    /// at `amount` per `window` seconds. `used` is what has been paid out or scheduled, less what has
    /// refilled since `updated`. A zero `amount` sets no limit.
    struct RateLimit {
        uint128 amount;
        uint64 window;
        uint64 updated;
        uint256 used;
    }

    /// @notice A mint or release over its limit, waiting until `readyAt` for anyone to execute it.
    /// `token` is the origin of a mint, the native token of a release.
    struct Transfer {
        address token;
        uint8 kind;
        uint64 nonce;
        uint64 readyAt;
        address from;
        address to;
        uint256 amount;
    }

    /// @notice The limit on releases of each native token.
    mapping(address token => RateLimit) public releaseLimit;
    /// @notice The limit on mints of each wrapped token, by its origin.
    mapping(address origin => RateLimit) public mintLimit;
    /// @notice Transfers waiting for their limit, by id; executed ones are deleted.
    mapping(uint256 id => Transfer) public queued;
    /// @notice The id the next queued transfer gets.
    uint256 public queuedCount;
    /// @notice Amount of each native token released but waiting in the queue: no longer locked, still
    /// held here.
    mapping(address token => uint256) public releasesQueued;
    /// @notice Amount of each wrapped token (by its origin) waiting in the queue to be minted, which
    /// its mint cap counts.
    mapping(address origin => uint256) public mintsQueued;

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
    event ReleaseLimitChanged(address indexed token, uint128 amount, uint64 window);
    event MintLimitChanged(address indexed origin, uint128 amount, uint64 window);
    event Queued(
        uint256 indexed id, uint64 indexed nonce, uint8 kind, address token, address to, uint256 amount, uint64 readyAt
    );
    event QueueExecuted(uint256 indexed id);
    event PeerConfirmed();
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
    error PeerUnconfirmed();
    error AlreadyConfirmed();
    error BadWindow();
    error NothingQueued();
    error NotReady(uint64 readyAt);

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
        if (!peerLive) revert PeerUnconfirmed();
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

    /// @notice Executes queued transfer `id` once its time has come: mints it, or releases it as a
    /// delivery does (owed if the transfer fails). Anyone may call it.
    function executeQueued(uint256 id) external whenNotPaused nonReentrant {
        Transfer memory t = queued[id];
        if (t.amount == 0) revert NothingQueued();
        if (block.timestamp < t.readyAt) revert NotReady(t.readyAt);
        delete queued[id];
        emit QueueExecuted(id);
        if (t.kind == MINT) {
            mintsQueued[t.token] -= t.amount;
            address token = wrappedToken(t.token);
            BridgedToken(token).mint(t.to, t.amount);
            emit Minted(t.nonce, t.token, token, t.from, t.to, t.amount);
        } else {
            releasesQueued[t.token] -= t.amount;
            _release(t.nonce, t.token, t.from, t.to, t.amount);
        }
    }

    /// @notice Sends the paired gateway a `HELLO` again, while none of its messages has arrived: for a
    /// gateway whose first `HELLO`, or the answer to it, was lost or vetoed. The owner.
    function hello() external onlyOwner {
        if (peerLive) revert AlreadyConfirmed();
        _send(abi.encode(HELLO, false));
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

    /// @notice Limits releases of the native `token` to `amount` at once, refilling at `amount` per
    /// `window` seconds; a zero `amount` lifts the limit. Queued transfers keep their times.
    function setReleaseLimit(address token, uint128 amount, uint64 window) external onlyOwner {
        _setLimit(releaseLimit[token], amount, window);
        emit ReleaseLimitChanged(token, amount, window);
    }

    /// @notice Limits mints of the wrapped token of `origin` in the same way.
    function setMintLimit(address origin, uint128 amount, uint64 window) external onlyOwner {
        _setLimit(mintLimit[origin], amount, window);
        emit MintLimitChanged(origin, amount, window);
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
        if (!peerLive) {
            peerLive = true;
            emit PeerConfirmed();
        }
        if (kind == MINT) {
            (, address origin, address from, address to, uint256 amount, string memory name, string memory symbol, uint8 decimals)
            = abi.decode(payload, (uint8, address, address, address, uint256, string, string, uint8));
            _mint(nonce, origin, from, to, amount, _wrapped(origin, name, symbol, decimals));
        } else if (kind == RELEASE) {
            (, address token, address from, address to, uint256 amount) =
                abi.decode(payload, (uint8, address, address, address, uint256));
            locked[token] -= amount;
            uint64 readyAt = _schedule(releaseLimit[token], amount);
            if (readyAt > block.timestamp) {
                releasesQueued[token] += amount;
                _queue(Transfer(token, RELEASE, nonce, readyAt, from, to, amount));
            } else {
                _release(nonce, token, from, to, amount);
            }
        } else if (kind == HELLO) {
            (, bool heard) = abi.decode(payload, (uint8, bool));
            if (!heard) _send(abi.encode(HELLO, true));
        } else {
            revert UnknownMessage();
        }
    }

    /// @dev Mints `amount` of `token`, the wrapped token of `origin`, to `to`, or queues the mint if its
    /// limit does not allow it now; refuses it over the mint cap, which counts what is queued.
    function _mint(uint64 nonce, address origin, address from, address to, uint256 amount, address token) private {
        uint256 queuedAmount = mintsQueued[origin];
        if (BridgedToken(token).totalSupply() + queuedAmount + amount > mintCap[origin]) revert CapExceeded(origin);
        uint64 readyAt = _schedule(mintLimit[origin], amount);
        if (readyAt > block.timestamp) {
            mintsQueued[origin] = queuedAmount + amount;
            _queue(Transfer(origin, MINT, nonce, readyAt, from, to, amount));
        } else {
            BridgedToken(token).mint(to, amount);
            emit Minted(nonce, origin, token, from, to, amount);
        }
    }

    /// @dev Releases `amount` of `token` to `to`, or owes it if the transfer fails.
    function _release(uint64 nonce, address token, address from, address to, uint256 amount) private {
        if (gasleft() < TRANSFER_GAS * 64 / 63 + TRANSFER_RESERVE) revert InsufficientGas();
        if (_transferOut(token, to, amount)) {
            emit Released(nonce, token, to, from, amount);
        } else {
            owed[token][to] += amount;
            emit ReleaseFailed(nonce, token, to, from, amount);
        }
    }

    /// @dev Takes `amount` out of `limit` now and returns when it may be paid out: now if what is used
    /// with it stays within the limit, else once enough has refilled. Without a limit, now.
    function _schedule(RateLimit storage limit, uint256 amount) private returns (uint64) {
        uint256 cap = limit.amount;
        if (cap == 0) return uint64(block.timestamp);
        uint256 used = _used(limit) + amount;
        limit.used = used;
        limit.updated = uint64(block.timestamp);
        if (used <= cap) return uint64(block.timestamp);
        // Rounded up, so that nothing is paid out before it has refilled.
        return uint64(block.timestamp + ((used - cap) * limit.window + cap - 1) / cap);
    }

    /// @dev What `limit` has used, less what has refilled since it was last brought up to date.
    function _used(RateLimit storage limit) private view returns (uint256) {
        uint256 refilled = (block.timestamp - limit.updated) * limit.amount / limit.window;
        uint256 used = limit.used;
        return used > refilled ? used - refilled : 0;
    }

    function _setLimit(RateLimit storage limit, uint128 amount, uint64 window) private {
        if (amount != 0 && window == 0) revert BadWindow();
        // What was used under the old limit counts against the new one.
        limit.used = limit.amount == 0 ? 0 : _used(limit);
        limit.updated = uint64(block.timestamp);
        limit.amount = amount;
        limit.window = window;
    }

    function _queue(Transfer memory t) private {
        uint256 id = queuedCount++;
        queued[id] = t;
        emit Queued(id, t.nonce, t.kind, t.token, t.to, t.amount, t.readyAt);
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
