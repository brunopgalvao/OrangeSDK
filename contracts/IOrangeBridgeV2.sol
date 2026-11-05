// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice A verifier of version-2 Orange finality certificates and rotation certificates (spec 12 §7, §8):
/// it holds no key; the caller passes the key in force.
interface IOrangeFinalityVerifierV2 {
    /// @notice The Orange chain whose certificates this verifier accepts.
    function chainId() external view returns (uint64);

    /// @notice Whether `key` is a usable group key: 256 bytes, the EIP-2537 encoding of a G2 point of the
    /// prime-order subgroup other than the identity, canonically encoded.
    function isValidKey(bytes calldata key) external view returns (bool);

    /// @notice The compressed encoding (96 bytes, spec 12 §2) of `key`, an EIP-2537 G2 point.
    function compress(bytes calldata key) external pure returns (bytes memory);

    /// @notice Whether `signature` (a G1 point in EIP-2537 encoding, 128 bytes) is the group signature of
    /// key set `keyId`, whose key is `key`, over the version-2 certificate message of `height` and `blockHash`.
    function verify(bytes calldata key, uint64 keyId, uint64 height, bytes32 blockHash, bytes calldata signature)
        external
        view
        returns (bool);

    /// @notice Whether `signature` is the group signature of `key` over the rotation message that hands off
    /// to key set `newKeyId` with group key `newKey` (EIP-2537 encoding, assumed valid).
    function verifyRotation(bytes calldata key, uint64 newKeyId, bytes calldata newKey, bytes calldata signature)
        external
        view
        returns (bool);
}
