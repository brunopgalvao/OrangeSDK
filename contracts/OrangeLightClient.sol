// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IOrangeFinalityVerifier, IOrangeLightClient} from "./IOrangeBridge.sol";

/// @title Light client of an Orange chain on Ethereum
/// @notice Follows spec 17 §4. A relayer submits an Orange proposal with the threshold certificate of
/// its hash; the proposal carries an anchor, the height and state root of an executed block below
/// it, which the certificate's signers checked against their own execution before signing. The
/// client verifies the certificate, reads the anchor and stores the state root by height. Anchors
/// only move forward. It has no owner: its verifier, and so its certificate version and group key,
/// are fixed at deployment.
contract OrangeLightClient is IOrangeLightClient {
    /// @notice The verifier of the certificates this client accepts.
    IOrangeFinalityVerifier public immutable verifier;

    /// @inheritdoc IOrangeLightClient
    uint64 public immutable chainId;

    /// @notice The highest anchored height stored, zero before the first submission.
    uint64 public latestHeight;

    /// @inheritdoc IOrangeLightClient
    mapping(uint64 height => bytes32 stateRoot) public stateRoots;

    /// @notice A state root was stored for `height` from the certified proposal at `proposalHeight`.
    event StateRootStored(uint64 indexed height, bytes32 stateRoot, uint64 proposalHeight, bytes32 proposalHash);

    /// @notice The proposal is shorter than its fixed-size prefix.
    error ProposalTooShort();
    /// @notice The proposal carries no anchor.
    error NoAnchor();
    /// @notice The anchor is not below the proposal's own height.
    error AnchorNotBelowProposal();
    /// @notice The anchor is not above the latest stored height.
    error NotMonotonic();
    /// @notice The certificate does not verify for the proposal.
    error InvalidCertificate();

    constructor(IOrangeFinalityVerifier verifier_) {
        verifier = verifier_;
        chainId = verifier_.chainId();
    }

    /// @notice Stores the anchor of `proposal`, the canonical encoding of an Orange proposal (spec 08 §4),
    /// whose hash `signature` (the certificate's group signature in EIP-2537 encoding) certifies.
    function submit(bytes calldata proposal, bytes calldata signature) external {
        if (proposal.length < 96) revert ProposalTooShort();
        uint64 height = le64(proposal[8:16]);
        uint64 anchor = le64(proposal[56:64]);
        bytes32 root = bytes32(proposal[64:96]);
        if (anchor == 0) revert NoAnchor();
        if (anchor >= height) revert AnchorNotBelowProposal();
        if (anchor <= latestHeight) revert NotMonotonic();
        bytes32 hash = keccak256(proposal);
        if (!verifier.verify(height, hash, signature)) revert InvalidCertificate();
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
