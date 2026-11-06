// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IOrangeLightClient} from "./IOrangeBridge.sol";
import {IOrangeFinalityVerifierV2} from "./IOrangeBridgeV2.sol";

/// @title Light client of an Orange chain with rotating group keys
/// @notice Follows spec 17 §5.3. It holds the chain's current key set: its id and its group key in
/// EIP-2537 encoding. A relayer moves it along the chain's handoffs with `rotate`, each signed by the key
/// it replaces, and submits certified proposals with `submit`, whose anchored state roots it stores. A key
/// is trusted for anchors up to `maxKeyAge` epochs past its own; past that the client refuses its
/// certificates, so that every shareholder of a key it still trusts is still bonded on Orange. The
/// verifier, the chain, the epoch length and the key age are fixed at deployment. Its owner can pause it
/// and, while it is paused, recover it from a rotation that strands it (spec 17 §5.4): `recover` moves it
/// along a handoff out of the key set it held before the current one, signed by that key set.
contract OrangeLightClientV2 is IOrangeLightClient {
    /// @notice The verifier of the certificates this client accepts.
    IOrangeFinalityVerifierV2 public immutable verifier;

    /// @inheritdoc IOrangeLightClient
    uint64 public immutable chainId;

    /// @notice Blocks per epoch on the Orange chain.
    uint64 public immutable epochBlocks;

    /// @notice Epochs past its own that a key set is trusted for (the chain's `max_key_age`).
    uint64 public immutable maxKeyAge;

    /// @notice The id of the current key set: the epoch whose DKG made it.
    uint64 public keyId;

    /// @notice The highest anchored height stored, zero before the first submission.
    uint64 public latestHeight;

    /// @notice The id of the key set held before the current one: the one the last rotation left, or
    /// the starting key set before any rotation.
    uint64 public previousKeyId;

    /// @notice Whether `submit` and `rotate` are stopped.
    bool public paused;

    /// @notice Pauses, unpauses, recovers a stranded client and transfers ownership.
    address public owner;

    /// @dev keccak256 of the previous key set's id (8 bytes) and group key (EIP-2537 encoding).
    bytes32 private previousKeyHash;

    /// @dev The current group key in EIP-2537 encoding.
    bytes private key;

    /// @inheritdoc IOrangeLightClient
    mapping(uint64 height => bytes32 stateRoot) public stateRoots;

    /// @notice A state root was stored for `height` from the certified proposal at `proposalHeight`.
    event StateRootStored(uint64 indexed height, bytes32 stateRoot, uint64 proposalHeight, bytes32 proposalHash);
    /// @notice The current key set moved from `from` to `to`.
    event KeyRotated(uint64 indexed from, uint64 indexed to);
    /// @notice The owner moved the current key set from `stranded` to `to` along the handoff out of
    /// `from`, the key set held before `stranded`.
    event KeyRecovered(uint64 indexed stranded, uint64 indexed from, uint64 indexed to);
    /// @notice The owner paused the client.
    event Paused();
    /// @notice The owner unpaused the client.
    event Unpaused();
    /// @notice Ownership moved to `owner`.
    event OwnerChanged(address indexed owner);

    /// @notice The epoch length or the key age is zero.
    error InvalidParameters();
    /// @notice A key that is not a valid group key.
    error InvalidKey();
    /// @notice The proposal is shorter than its fixed-size prefix.
    error ProposalTooShort();
    /// @notice The proposal carries no anchor.
    error NoAnchor();
    /// @notice The anchor is not below the proposal's own height.
    error AnchorNotBelowProposal();
    /// @notice The anchor is not above the latest stored height.
    error NotMonotonic();
    /// @notice The current key is too old for the anchor, or for a handoff to that key set.
    error KeyExpired();
    /// @notice A rotation to a key set that is not newer than the current one.
    error NotNewer();
    /// @notice The certificate does not verify under the current key.
    error InvalidCertificate();
    /// @notice The client is paused.
    error IsPaused();
    /// @notice The client is not paused.
    error NotPaused();
    /// @notice Only the owner may do this.
    error NotOwner();
    /// @notice A zero owner.
    error ZeroAddress();
    /// @notice The key set named is not the one held before the current one.
    error NotPreviousKey();

    /// @param verifier_ The version-2 verifier.
    /// @param keyId_ The id of the trusted key set to start from.
    /// @param key_ Its group key in EIP-2537 encoding (256 bytes).
    /// @param epochBlocks_ Blocks per epoch on the chain.
    /// @param maxKeyAge_ The chain's `max_key_age`.
    /// @param owner_ The owner: a timelock or multisig, as `OrangeInbox`'s.
    constructor(
        IOrangeFinalityVerifierV2 verifier_,
        uint64 keyId_,
        bytes memory key_,
        uint64 epochBlocks_,
        uint64 maxKeyAge_,
        address owner_
    ) {
        if (epochBlocks_ == 0 || maxKeyAge_ == 0) revert InvalidParameters();
        if (owner_ == address(0)) revert ZeroAddress();
        if (!verifier_.isValidKey(key_)) revert InvalidKey();
        verifier = verifier_;
        chainId = verifier_.chainId();
        epochBlocks = epochBlocks_;
        maxKeyAge = maxKeyAge_;
        keyId = keyId_;
        previousKeyId = keyId_;
        owner = owner_;
        previousKeyHash = keccak256(abi.encodePacked(keyId_, key_));
        key = key_;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice The current group key in EIP-2537 encoding.
    function currentKey() external view returns (bytes memory) {
        return key;
    }

    /// @notice The epoch of the Orange block at `height` (spec 15 §4).
    function epochOf(uint64 height) public view returns (uint64) {
        return height == 0 ? 0 : (height - 1) / epochBlocks;
    }

    /// @notice Moves the current key set to `newKeyId` with group key `newKey` (EIP-2537 encoding), given
    /// the current key's group signature over the rotation message (spec 12 §7) in EIP-2537 encoding.
    function rotate(uint64 newKeyId, bytes calldata newKey, bytes calldata signature) external {
        if (paused) revert IsPaused();
        uint64 current = keyId;
        if (newKeyId <= current) revert NotNewer();
        if (newKeyId > current + maxKeyAge) revert KeyExpired();
        if (!verifier.isValidKey(newKey)) revert InvalidKey();
        bytes memory currentKey_ = key;
        if (!verifier.verifyRotation(currentKey_, newKeyId, newKey, signature)) revert InvalidCertificate();
        keyId = newKeyId;
        previousKeyId = current;
        previousKeyHash = keccak256(abi.encodePacked(current, currentKey_));
        key = newKey;
        emit KeyRotated(current, newKeyId);
    }

    /// @notice Recovers a client that a rotation stranded on a key set the chain never hands off from
    /// (spec 17 §5.4): moves the current key set to `newKeyId` with group key `newKey`, given the group
    /// signature of the key set held before the current one, `fromKeyId` with group key `fromKey`, over
    /// the rotation message to them, as `rotate` would have taken it from that key set. The owner,
    /// while paused. The previous key set stays the one named, as the new key set is its successor.
    function recover(
        uint64 fromKeyId,
        bytes calldata fromKey,
        uint64 newKeyId,
        bytes calldata newKey,
        bytes calldata signature
    ) external onlyOwner {
        if (!paused) revert NotPaused();
        if (keccak256(abi.encodePacked(fromKeyId, fromKey)) != previousKeyHash) revert NotPreviousKey();
        uint64 stranded = keyId;
        if (newKeyId <= stranded) revert NotNewer();
        if (newKeyId > fromKeyId + maxKeyAge) revert KeyExpired();
        if (!verifier.isValidKey(newKey)) revert InvalidKey();
        if (!verifier.verifyRotation(fromKey, newKeyId, newKey, signature)) revert InvalidCertificate();
        keyId = newKeyId;
        key = newKey;
        emit KeyRecovered(stranded, fromKeyId, newKeyId);
    }

    /// @notice Stops `submit` and `rotate`. The owner.
    function pause() external onlyOwner {
        paused = true;
        emit Paused();
    }

    /// @notice Resumes `submit` and `rotate`. The owner.
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }

    /// @notice Moves ownership to `owner_`, never zero. The owner.
    function transferOwnership(address owner_) external onlyOwner {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        emit OwnerChanged(owner_);
    }

    /// @notice Stores the anchor of `proposal`, the canonical encoding of an Orange proposal (spec 08 §4),
    /// whose hash `signature` (the version-2 certificate's group signature in EIP-2537 encoding) certifies
    /// under the current key.
    function submit(bytes calldata proposal, bytes calldata signature) external {
        if (paused) revert IsPaused();
        if (proposal.length < 96) revert ProposalTooShort();
        uint64 height = le64(proposal[8:16]);
        uint64 anchor = le64(proposal[56:64]);
        bytes32 root = bytes32(proposal[64:96]);
        if (anchor == 0) revert NoAnchor();
        if (anchor >= height) revert AnchorNotBelowProposal();
        if (anchor <= latestHeight) revert NotMonotonic();
        uint64 current = keyId;
        if (epochOf(anchor) > current + maxKeyAge) revert KeyExpired();
        bytes32 hash = keccak256(proposal);
        if (!verifier.verify(key, current, height, hash, signature)) revert InvalidCertificate();
        latestHeight = anchor;
        stateRoots[anchor] = root;
        emit StateRootStored(anchor, root, height, hash);
    }

    /// @dev A little-endian 64-bit integer.
    function le64(bytes calldata b) private pure returns (uint64 v) {
        for (uint256 i = 8; i > 0; i--) {
            v = (v << 8) | uint8(b[i - 1]);
        }
    }
}
