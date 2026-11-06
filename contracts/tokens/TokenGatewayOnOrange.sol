// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {EthereumInbox, IEthereumMessageReceiver} from "../EthereumInbox.sol";
import {IOrangeOutbox} from "../IOrangeOutbox.sol";
import {TokenGateway} from "./TokenGateway.sol";

/// @title The token gateway deployed on Orange (spec 21 §5.2)
/// @notice Sends through the outbox (0x…4f42, spec 17 §2) to the gateway on Ethereum, and receives
/// from the inbox (0x…4549, spec 18 §6.5) what the gateway on Ethereum sent through `EthereumOutbox`.
/// The chain's own currency is its native currency; it arrives on Ethereum as the wrapped token of
/// origin zero.
contract TokenGatewayOnOrange is TokenGateway, IEthereumMessageReceiver {
    /// @notice The outbox: 0x0000000000000000000000000000000000004f42 on an Orange chain.
    IOrangeOutbox public immutable outbox;
    /// @notice The inbox: 0x0000000000000000000000000000000000004549 on an Orange chain.
    address public immutable inbox;
    /// @notice The chain the paired gateway is on.
    uint64 public immutable ethereumChainId;

    error NotInbox();
    error NotRemoteGateway();

    constructor(
        IOrangeOutbox outbox_,
        address inbox_,
        uint64 ethereumChainId_,
        address ethereumGateway,
        address owner_,
        address guardian_,
        string memory nativeName_,
        string memory nativeSymbol_
    ) TokenGateway(ethereumGateway, owner_, guardian_, nativeName_, nativeSymbol_) {
        if (address(outbox_) == address(0) || inbox_ == address(0)) revert ZeroAddress();
        outbox = outbox_;
        inbox = inbox_;
        ethereumChainId = ethereumChainId_;
        // Tells the paired gateway this one exists (spec 21 §5.7).
        _send(abi.encode(HELLO, false));
    }

    /// @notice A message from Ethereum, delivered by the inbox: only the paired gateway's count.
    function onEthereumMessage(uint64 nonce, address sender, bytes calldata payload) external {
        if (msg.sender != inbox) revert NotInbox();
        if (sender != remoteGateway) revert NotRemoteGateway();
        _receive(nonce, payload);
    }

    /// @notice Tells the paired gateway what the inbox delivered as its message `m.nonce`: a `SPENT`
    /// with the identity of `m` if it came here, else `VOID`. What the gateway on Ethereum sent with
    /// that nonce, if it differs (a forgery took its nonce and was paid out here), never arrives, and
    /// it refunds or sends it again. Anyone may call it, once per nonce.
    function reportDelivered(EthereumInbox.Message calldata m) external returns (uint64) {
        EthereumInbox source = EthereumInbox(inbox);
        bytes32 messageHash = source.deliveredHash(m.nonce);
        if (messageHash != source.hashMessage(m)) revert NotDelivered();
        return _report(m.nonce, m.recipient == address(this) ? _identity(m.payload) : VOID);
    }

    function _send(bytes memory payload) internal override returns (uint64) {
        return outbox.send(ethereumChainId, remoteGateway, payload);
    }
}
