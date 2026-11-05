// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice A verifier of Orange finality certificates of one version (spec 12 §8).
interface IOrangeFinalityVerifier {
    /// @notice The Orange chain whose certificates this verifier accepts.
    function chainId() external view returns (uint64);

    /// @notice Whether `signature` (a G1 point in EIP-2537 encoding, 128 bytes) is the
    /// chain's group signature over the certificate message of `height` and `blockHash`.
    function verify(uint64 height, bytes32 blockHash, bytes calldata signature) external view returns (bool);
}

/// @notice The state roots of an Orange chain that a light client holds (spec 17 §4).
interface IOrangeLightClient {
    /// @notice The Orange chain the roots are of.
    function chainId() external view returns (uint64);

    /// @notice The state root of the Orange block at `height`, zero if the client holds none.
    function stateRoots(uint64 height) external view returns (bytes32);
}

/// @notice What an Ethereum contract implements to receive Orange messages from an inbox (spec 17 §6.3).
interface IOrangeMessageRecipient {
    /// @notice Delivers the message `nonce` that `sender` sent on Orange chain `sourceChainId`
    /// with `value` wei and `payload`. Called by the inbox only.
    function onOrangeMessage(uint64 sourceChainId, uint64 nonce, address sender, uint256 value, bytes calldata payload)
        external;
}
