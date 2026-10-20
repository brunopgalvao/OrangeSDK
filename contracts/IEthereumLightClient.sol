// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// The Ethereum light client of a Solo chain (spec 18 §5.1): a native
/// contract at 0x000000000000000000000000000000000000454C running the
/// light-client module. Updates are SSZ-encoded at the Electra format.
interface IEthereumLightClient {
    /// The light client refused an update or a checkpoint; `code` names why (spec 18 §3.7).
    error UpdateRejected(uint8 code);
    /// Only the governance account may do this.
    error NotGovernance();

    /// Applies an SSZ `LightClientUpdate`. Anyone may submit one.
    function submitUpdate(bytes calldata update) external;
    /// Applies an SSZ `LightClientFinalityUpdate`. Anyone may submit one.
    function submitFinalityUpdate(bytes calldata update) external;
    /// Governance: replaces the light client's state with a new SSZ `LightClientBootstrap`,
    /// revoking every execution state root stored before.
    function setCheckpoint(bytes calldata bootstrap) external;
    /// Governance: sets the seconds between storing a state root and its first use.
    function setDelay(uint64 delay) external;

    /// The latest finalized header the light client holds.
    function finalized()
        external
        view
        returns (uint64 slot, bytes32 beaconRoot, uint64 blockNumber, bytes32 blockHash, bytes32 stateRoot);
    /// The execution state root of `blockNumber`, zero if not held or stored before the last
    /// checkpoint, and when it becomes usable.
    function executionRoot(uint64 blockNumber)
        external
        view
        returns (bytes32 stateRoot, bytes32 blockHash, uint64 slot, uint64 usableAt);
    /// The seconds between storing a state root and its first use.
    function delay() external view returns (uint64);
}
