// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// The message verifier of an Orange chain (spec 18 §5.2): a native contract at
/// 0x000000000000000000000000000000000000454D running the verifier module.
/// It proves messages of the `EthereumOutbox`, records each delivered once,
/// and paces and pauses deliveries.
interface IMessageVerifier {
    /// Only the inbox may consume messages.
    error NotInbox();
    /// Only the governance account may do this.
    error NotGovernance();
    /// Deliveries are paused.
    error Paused();
    /// The message was delivered already.
    error AlreadyDelivered(uint64 nonce);
    /// The rate limit's window is full.
    error RateLimited();
    /// The proofs do not show the message in the outbox.
    error BadProof();

    /// Marks message `nonce` delivered once the proofs show it in the outbox
    /// under the Ethereum state root `stateRoot`; the inbox only.
    function consume(
        bytes32 stateRoot,
        uint64 nonce,
        address sender,
        address recipient,
        uint64 gasLimit,
        bytes calldata payload,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof
    ) external;

    /// Governance: stops deliveries.
    function pause() external;
    /// Governance: resumes deliveries.
    function unpause() external;
    /// Governance: sets the rate-limit window (seconds) and the deliveries it allows.
    function setRateLimit(uint64 window, uint64 maxMessages) external;
    /// Governance: gives `recipient` a limit of its own of `maxMessages` deliveries per window,
    /// which its messages count against instead of the shared one; zero returns it to the shared one.
    function setRecipientLimit(address recipient, uint64 maxMessages) external;

    /// Whether message `nonce` was delivered.
    function delivered(uint64 nonce) external view returns (bool);
    /// Whether deliveries are stopped.
    function paused() external view returns (bool);
    /// The rate-limit window and the deliveries it allows.
    function rateLimit() external view returns (uint64 window, uint64 maxMessages);
    /// The deliveries per window `recipient` has of its own, zero if it shares the rate limit.
    function recipientLimit(address recipient) external view returns (uint64 maxMessages);
}
