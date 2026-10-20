// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ISoloLightClient, ISoloMessageRecipient} from "./ISoloBridge.sol";

/// @title Inbox of Solo messages on Ethereum
/// @notice Follows spec 17 §6. Anyone proves a message of the Solo outbox against a state root the
/// light client holds; after the delay anyone executes it, which delivers it to its recipient once.
/// Deliveries are rate-limited per window in messages and in value. The guardian can pause the
/// inbox and veto a proven message before it is executed; the owner sets the delay, the rate limits
/// and the guardian, unpauses, and hands over ownership. Neither can deliver, alter or replay a
/// message, or change the light client.
contract SoloInbox {
    /// @notice A message as the Solo outbox recorded it; its source chain is the light client's,
    /// its destination this chain.
    struct Message {
        uint64 nonce;
        address sender;
        address recipient;
        uint256 value;
        bytes payload;
    }

    /// @notice Where a nonce stands.
    enum Status {
        None,
        Pending,
        Delivered,
        Vetoed
    }

    /// @notice A proven message: its hash, when it may be executed, and its status.
    struct Entry {
        bytes32 messageHash;
        uint64 executableAt;
        Status status;
    }

    /// @notice The Solo outbox address, whose storage holds the message hashes.
    address public constant OUTBOX = 0x0000000000000000000000000000000000004F42;
    /// @notice The longest delay the owner can set.
    uint64 public constant MAX_DELAY = 30 days;
    /// @notice The version byte of the message encoding.
    uint8 public constant MESSAGE_VERSION = 1;

    /// @notice The light client whose state roots messages are proven against.
    ISoloLightClient public immutable lightClient;
    /// @notice The Solo chain messages come from.
    uint64 public immutable sourceChainId;
    /// @notice The lowest nonce this inbox accepts: a successor inbox starts above every nonce
    /// its predecessor could have delivered.
    uint64 public immutable firstNonce;

    /// @notice Sets the delay, the rate limits and the guardian, unpauses, and transfers ownership.
    address public owner;
    /// @notice Pauses and vetoes.
    address public guardian;
    /// @notice Whether proving and executing are stopped.
    bool public paused;
    /// @notice Seconds between proving a message and executing it.
    uint64 public delay;
    /// @notice Length of a rate-limit window in seconds.
    uint64 public window;
    /// @notice Most messages executed in one window.
    uint64 public maxMessagesPerWindow;
    /// @notice Most value executed in one window, in Solo wei.
    uint256 public maxValuePerWindow;
    /// @notice When the current window began.
    uint64 public windowStart;
    /// @notice Messages executed in the current window.
    uint64 public windowMessages;
    /// @notice Value executed in the current window.
    uint256 public windowValue;

    /// @notice Every proven nonce.
    mapping(uint64 nonce => Entry) public entries;

    event MessageProven(uint64 indexed nonce, bytes32 messageHash, uint64 height, uint64 executableAt);
    event MessageDelivered(uint64 indexed nonce, bytes32 messageHash, address indexed recipient);
    event MessageVetoed(uint64 indexed nonce, bytes32 messageHash);
    event Paused(address indexed by);
    event Unpaused();
    event OwnerChanged(address indexed owner);
    event GuardianChanged(address indexed guardian);
    event DelayChanged(uint64 delay);
    event RateLimitChanged(uint64 window, uint64 maxMessages, uint256 maxValue);

    error NotOwner();
    error NotGuardian();
    error IsPaused();
    error UnknownStateRoot();
    error InvalidProof();
    error ProofTooDeep();
    error NonceBelowFirst();
    error AlreadyProven();
    error NotPending();
    error MessageMismatch();
    error TooEarly();
    error RateLimited();
    error DelayTooLong();
    error InvalidWindow();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _;
    }

    constructor(
        ISoloLightClient lightClient_,
        uint64 firstNonce_,
        address owner_,
        address guardian_,
        uint64 delay_,
        uint64 window_,
        uint64 maxMessages_,
        uint256 maxValue_
    ) {
        if (owner_ == address(0) || guardian_ == address(0)) revert ZeroAddress();
        if (delay_ > MAX_DELAY) revert DelayTooLong();
        if (window_ == 0) revert InvalidWindow();
        lightClient = lightClient_;
        sourceChainId = lightClient_.chainId();
        firstNonce = firstNonce_;
        owner = owner_;
        guardian = guardian_;
        delay = delay_;
        window = window_;
        maxMessagesPerWindow = maxMessages_;
        maxValuePerWindow = maxValue_;
    }

    /// @notice The message hash (spec 17 §3): keccak256 of the packed encoding.
    function hashMessage(Message calldata m) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                MESSAGE_VERSION, sourceChainId, m.nonce, m.sender, uint64(block.chainid), m.recipient, m.value, m.payload
            )
        );
    }

    /// @notice Proves `m` against the state root of Solo block `height` with the sibling hashes of
    /// its binary-trie proof (spec 10 §5), deepest last as `storage_proof` returns them.
    function prove(uint64 height, Message calldata m, bytes32[] calldata siblings) external whenNotPaused {
        if (m.nonce < firstNonce) revert NonceBelowFirst();
        Entry storage e = entries[m.nonce];
        if (e.status != Status.None) revert AlreadyProven();
        bytes32 root = lightClient.stateRoots(height);
        if (root == bytes32(0)) revert UnknownStateRoot();
        bytes32 messageHash = hashMessage(m);
        if (proofRoot(messageHash, m.nonce, siblings) != root) revert InvalidProof();
        uint64 executableAt = uint64(block.timestamp) + delay;
        e.messageHash = messageHash;
        e.executableAt = executableAt;
        e.status = Status.Pending;
        emit MessageProven(m.nonce, messageHash, height, executableAt);
    }

    /// @notice Delivers the proven message `m` to its recipient, once its delay has passed. A
    /// recipient that reverts reverts the execution, and the message stays pending.
    function execute(Message calldata m) external whenNotPaused {
        Entry storage e = entries[m.nonce];
        if (e.status != Status.Pending) revert NotPending();
        bytes32 messageHash = hashMessage(m);
        if (messageHash != e.messageHash) revert MessageMismatch();
        if (block.timestamp < e.executableAt) revert TooEarly();
        consume(m.value);
        e.status = Status.Delivered;
        (bool ok, bytes memory ret) = m.recipient.call(
            abi.encodeCall(ISoloMessageRecipient.onSoloMessage, (sourceChainId, m.nonce, m.sender, m.value, m.payload))
        );
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        emit MessageDelivered(m.nonce, messageHash, m.recipient);
    }

    /// @notice Stops proving and executing. The guardian or the owner.
    function pause() external {
        if (msg.sender != guardian && msg.sender != owner) revert NotGuardian();
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resumes proving and executing.
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }

    /// @notice Drops a proven message that has not been executed; its nonce is never delivered.
    function veto(uint64 nonce) external {
        if (msg.sender != guardian) revert NotGuardian();
        Entry storage e = entries[nonce];
        if (e.status != Status.Pending) revert NotPending();
        e.status = Status.Vetoed;
        emit MessageVetoed(nonce, e.messageHash);
    }

    function setGuardian(address guardian_) external onlyOwner {
        if (guardian_ == address(0)) revert ZeroAddress();
        guardian = guardian_;
        emit GuardianChanged(guardian_);
    }

    /// @notice Sets the delay of messages proven from now on, at most `MAX_DELAY`.
    function setDelay(uint64 delay_) external onlyOwner {
        if (delay_ > MAX_DELAY) revert DelayTooLong();
        delay = delay_;
        emit DelayChanged(delay_);
    }

    function setRateLimit(uint64 window_, uint64 maxMessages_, uint256 maxValue_) external onlyOwner {
        if (window_ == 0) revert InvalidWindow();
        window = window_;
        maxMessagesPerWindow = maxMessages_;
        maxValuePerWindow = maxValue_;
        emit RateLimitChanged(window_, maxMessages_, maxValue_);
    }

    function transferOwnership(address owner_) external onlyOwner {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        emit OwnerChanged(owner_);
    }

    /// @dev Counts one message of `value` against the current window, starting a new one when it is over.
    function consume(uint256 value) private {
        if (block.timestamp >= uint256(windowStart) + window) {
            windowStart = uint64(block.timestamp);
            windowMessages = 0;
            windowValue = 0;
        }
        if (windowMessages >= maxMessagesPerWindow || value > maxValuePerWindow - windowValue) revert RateLimited();
        windowMessages += 1;
        windowValue += value;
    }

    /// @dev The root a proof of the outbox slot of `nonce` holding `messageHash` leads to (spec 10 §5.3).
    function proofRoot(bytes32 messageHash, uint64 nonce, bytes32[] calldata siblings)
        private
        pure
        returns (bytes32 h)
    {
        if (siblings.length > 256) revert ProofTooDeep();
        bytes32 path = keccak256(abi.encodePacked("slot/", OUTBOX, uint256(nonce)));
        h = keccak256(abi.encodePacked(uint8(0), path, keccak256(abi.encodePacked(messageHash))));
        for (uint256 i = siblings.length; i > 0; i--) {
            if ((uint256(path) >> (256 - i)) & 1 == 1) {
                h = keccak256(abi.encodePacked(uint8(1), siblings[i - 1], h));
            } else {
                h = keccak256(abi.encodePacked(uint8(1), h, siblings[i - 1]));
            }
        }
    }
}
