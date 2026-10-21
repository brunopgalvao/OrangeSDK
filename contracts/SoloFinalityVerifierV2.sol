// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ISoloFinalityVerifierV2} from "./ISoloBridgeV2.sol";

/// @title Verifier of version-2 Solo finality certificates and of rotation certificates
/// @notice Follows spec 12 §8 for version 2. Solo's group key rotates every epoch (spec 15 §6.6), so this
/// contract holds no key: the light client passes the key in force with every call. The chain id is fixed
/// at deployment; there is no owner, no storage and no upgrade path (codex ADR 0013).
contract SoloFinalityVerifierV2 is ISoloFinalityVerifierV2 {
    /// @notice The certificate version this contract verifies.
    uint8 public constant VERSION = 2;

    /// @inheritdoc ISoloFinalityVerifierV2
    uint64 public immutable chainId;

    /// @dev `DST_SIG` of spec 12 §3.
    bytes private constant DST = "SOLO-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    /// @dev The BLS12-381 base field modulus.
    bytes private constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    /// @dev (p − 1) / 2 as its high 16 bytes and its low 32 bytes: a field element above it is the
    /// lexicographically larger of a pair of negatives (spec 12 §2).
    uint256 private constant HALF_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    uint256 private constant HALF_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;
    /// @dev The negated G2 generator in EIP-2537 encoding.
    bytes private constant NEG_G2 =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa"
        hex"0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    /// @notice A key or signature of the wrong length.
    error InvalidLength();
    /// @notice A precompile failed; only running out of gas makes one fail here.
    error PrecompileFailed();

    /// @param chainId_ The Solo chain id.
    constructor(uint64 chainId_) {
        chainId = chainId_;
    }

    /// @inheritdoc ISoloFinalityVerifierV2
    function isValidKey(bytes calldata key) external view returns (bool) {
        if (key.length != 256 || keccak256(key) == keccak256(new bytes(256))) return false;
        // BLS12_G2MSM checks that the point is on the curve and in the subgroup; a canonical
        // encoding comes back unchanged when multiplied by one.
        (bool ok, bytes memory same) = address(0x0e).staticcall(abi.encodePacked(key, uint256(1)));
        return ok && keccak256(same) == keccak256(key);
    }

    /// @inheritdoc ISoloFinalityVerifierV2
    function compress(bytes calldata key) public pure returns (bytes memory out) {
        if (key.length != 256) revert InvalidLength();
        // EIP-2537 is x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1, each 16 zero bytes and 48 value bytes; the compressed
        // form is x.c1 ‖ x.c0 with the flags in the top bits: compressed, and y the larger root.
        out = abi.encodePacked(key[80:128], key[16:64]);
        bool larger = uint256(bytes32(key[208:240])) == 0 && uint256(bytes32(key[240:256])) == 0
            ? above(key[144:192])
            : above(key[208:256]);
        out[0] = out[0] | (larger ? bytes1(0xa0) : bytes1(0x80));
    }

    /// @inheritdoc ISoloFinalityVerifierV2
    function verify(bytes calldata key, uint64 keyId, uint64 height, bytes32 blockHash, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return pairing(key, signature, abi.encodePacked(bytes13("SOLO-FINALITY"), VERSION, chainId, keyId, height, blockHash));
    }

    /// @inheritdoc ISoloFinalityVerifierV2
    function verifyRotation(bytes calldata key, uint64 newKeyId, bytes calldata newKey, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return pairing(key, signature, abi.encodePacked(bytes11("SOLO-ROTATE"), uint8(1), chainId, newKeyId, compress(newKey)));
    }

    /// @dev Whether `signature` verifies over `message` under `key`: the pairing check of spec 12 §8.
    function pairing(bytes calldata key, bytes calldata signature, bytes memory message) private view returns (bool) {
        if (signature.length != 128 || key.length != 256) revert InvalidLength();
        bytes memory input = abi.encodePacked(signature, NEG_G2, hashToG1(message), key);
        (bool ok, bytes memory out) = address(0x0f).staticcall(input);
        return ok && out.length == 32 && uint256(bytes32(out)) == 1;
    }

    /// @dev Whether the 48-byte big-endian field element `fp` is above (p − 1) / 2.
    function above(bytes calldata fp) private pure returns (bool) {
        uint256 hi = uint256(uint128(bytes16(fp[0:16])));
        uint256 lo = uint256(bytes32(fp[16:48]));
        return hi > HALF_HI || (hi == HALF_HI && lo > HALF_LO);
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
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), message, uint16(128), uint8(0), DST, uint8(50)));
        b1 = sha256(abi.encodePacked(b0, uint8(1), DST, uint8(50)));
        b2 = sha256(abi.encodePacked(b0 ^ b1, uint8(2), DST, uint8(50)));
        b3 = sha256(abi.encodePacked(b0 ^ b2, uint8(3), DST, uint8(50)));
        b4 = sha256(abi.encodePacked(b0 ^ b3, uint8(4), DST, uint8(50)));
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
