// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IOrangeFinalityVerifier} from "./IOrangeBridge.sol";

/// @title Verifier of version-1 Orange finality certificates
/// @notice Follows spec 12 §8. The chain id and the group key are fixed at deployment and nothing can
/// change them: the group key never changes on Orange (resharing keeps it, spec 12 §6), and a later
/// certificate version is verified by a new contract, never by changing this one (codex ADR 0013).
/// It has no owner, no storage and no upgrade path.
contract OrangeFinalityVerifierV1 is IOrangeFinalityVerifier {
    /// @notice The certificate version this contract verifies.
    uint8 public constant VERSION = 1;

    /// @inheritdoc IOrangeFinalityVerifier
    uint64 public immutable chainId;

    // The group key in EIP-2537 encoding, 256 bytes as eight words.
    bytes32 private immutable K0;
    bytes32 private immutable K1;
    bytes32 private immutable K2;
    bytes32 private immutable K3;
    bytes32 private immutable K4;
    bytes32 private immutable K5;
    bytes32 private immutable K6;
    bytes32 private immutable K7;

    /// @dev `DST_SIG` of spec 12 §3.
    bytes private constant DST = "ORANGE-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    /// @dev The BLS12-381 base field modulus.
    bytes private constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    /// @dev The negated G2 generator in EIP-2537 encoding.
    bytes private constant NEG_G2 =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa"
        hex"0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    /// @notice The group key is not a canonically encoded G2 point of the prime-order subgroup, or is the identity.
    error InvalidGroupKey();
    /// @notice The signature is not 128 bytes.
    error InvalidSignatureLength();
    /// @notice A precompile failed; only running out of gas makes one fail here.
    error PrecompileFailed();

    /// @param chainId_ The Orange chain id.
    /// @param groupKey The chain's group key in EIP-2537 encoding (256 bytes).
    constructor(uint64 chainId_, bytes memory groupKey) {
        if (groupKey.length != 256 || keccak256(groupKey) == keccak256(new bytes(256))) revert InvalidGroupKey();
        // BLS12_G2MSM checks that the point is on the curve and in the subgroup; a canonical
        // encoding comes back unchanged when multiplied by one.
        (bool ok, bytes memory same) = address(0x0e).staticcall(abi.encodePacked(groupKey, uint256(1)));
        if (!ok || keccak256(same) != keccak256(groupKey)) revert InvalidGroupKey();
        chainId = chainId_;
        bytes32[8] memory w;
        for (uint256 i = 0; i < 8; i++) {
            bytes32 word;
            assembly {
                word := mload(add(add(groupKey, 32), mul(i, 32)))
            }
            w[i] = word;
        }
        (K0, K1, K2, K3, K4, K5, K6, K7) = (w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
    }

    /// @inheritdoc IOrangeFinalityVerifier
    function verify(uint64 height, bytes32 blockHash, bytes calldata signature) external view returns (bool) {
        if (signature.length != 128) revert InvalidSignatureLength();
        bytes memory h = hashToG1(abi.encodePacked(bytes15("ORANGE-FINALITY"), VERSION, chainId, height, blockHash));
        bytes memory input = abi.encodePacked(signature, NEG_G2, h, K0, K1, K2, K3, K4, K5, K6, K7);
        (bool ok, bytes memory out) = address(0x0f).staticcall(input);
        return ok && out.length == 32 && uint256(bytes32(out)) == 1;
    }

    /// @dev `hash_to_curve` with `DST_SIG`: map each half of the uniform bytes to G1 and add.
    function hashToG1(bytes memory message) private view returns (bytes memory) {
        (bytes32 b1, bytes32 b2, bytes32 b3, bytes32 b4) = expandMessageXmd(message);
        (bool ok, bytes memory h) = address(0x0b).staticcall(abi.encodePacked(mapToG1(b1, b2), mapToG1(b3, b4)));
        if (!ok || h.length != 128) revert PrecompileFailed();
        return h;
    }

    /// @dev `expand_message_xmd` with SHA-256 to 128 bytes, as four words.
    function expandMessageXmd(bytes memory message)
        private
        pure
        returns (bytes32 b1, bytes32 b2, bytes32 b3, bytes32 b4)
    {
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), message, uint16(128), uint8(0), DST, uint8(52)));
        b1 = sha256(abi.encodePacked(b0, uint8(1), DST, uint8(52)));
        b2 = sha256(abi.encodePacked(b0 ^ b1, uint8(2), DST, uint8(52)));
        b3 = sha256(abi.encodePacked(b0 ^ b2, uint8(3), DST, uint8(52)));
        b4 = sha256(abi.encodePacked(b0 ^ b3, uint8(4), DST, uint8(52)));
    }

    /// @dev Reduces the 64 bytes `hi ‖ lo` modulo p and maps the field element to G1.
    function mapToG1(bytes32 hi, bytes32 lo) private view returns (bytes memory point) {
        (bool ok, bytes memory u) =
            address(0x05).staticcall(abi.encodePacked(uint256(64), uint256(1), uint256(48), hi, lo, uint8(1), P));
        if (!ok || u.length != 48) revert PrecompileFailed();
        (ok, point) = address(0x10).staticcall(abi.encodePacked(bytes16(0), u));
        if (!ok || point.length != 128) revert PrecompileFailed();
    }
}
