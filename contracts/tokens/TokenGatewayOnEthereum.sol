// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {EthereumOutbox} from "../EthereumOutbox.sol";
import {ISoloMessageRecipient} from "../ISoloBridge.sol";
import {SoloInbox} from "../SoloInbox.sol";
import {TokenGateway} from "./TokenGateway.sol";

/// @title The token gateway deployed on Ethereum (spec 21 §5.1)
/// @notice Sends through the chain's `EthereumOutbox` (spec 18 §6.1) to the gateway on Solo, and
/// receives from a `SoloInbox` (spec 17 §6) what the gateway on Solo sent through the outbox. ETH is
/// its native currency; it arrives on Solo as the wrapped token of origin zero.
contract TokenGatewayOnEthereum is TokenGateway, ISoloMessageRecipient {
    /// @notice The outbox of the Solo chain.
    EthereumOutbox public immutable outbox;
    /// @notice The Solo chain the paired gateway is on.
    uint64 public immutable soloChainId;
    /// @notice The inbox whose deliveries count; the owner moves it to a successor inbox.
    address public inbox;
    /// @notice The gas each message gives the gateway on Solo (spec 18 §6.5).
    uint64 public messageGas;
    /// @notice The least `messageGas`: enough to create a wrapped token, and far more than a
    /// release needs, so that no setting strands the messages sent under it.
    uint64 public constant MIN_MESSAGE_GAS = 1_000_000;
    /// @notice The nonces of the paired gateway's messages reported spent (`reportVetoed`,
    /// `reportDelivered`), each once.
    mapping(uint64 nonce => bool) public reported;

    event InboxChanged(address indexed inbox);
    event MessageGasChanged(uint64 gas);
    event Reported(uint64 indexed nonce, bytes32 effect, uint64 reportNonce);

    error NotInbox();
    error WrongChain();
    error NotRemoteGateway();
    error MessageGasTooLow();
    error NotVetoed();
    error NotDelivered();
    error AlreadyReported();

    constructor(
        EthereumOutbox outbox_,
        address inbox_,
        uint64 soloChainId_,
        address soloGateway,
        address owner_,
        address guardian_,
        uint64 messageGas_
    ) TokenGateway(soloGateway, owner_, guardian_, "Ether", "ETH") {
        if (address(outbox_) == address(0) || inbox_ == address(0)) revert ZeroAddress();
        if (messageGas_ < MIN_MESSAGE_GAS) revert MessageGasTooLow();
        outbox = outbox_;
        inbox = inbox_;
        soloChainId = soloChainId_;
        messageGas = messageGas_;
        // Tells the paired gateway this one exists (spec 21 §5.7).
        _send(abi.encode(HELLO, false));
    }

    /// @notice A message from Solo, delivered by the inbox: only the paired gateway's count, and
    /// they carry no value.
    function onSoloMessage(uint64 sourceChainId, uint64 nonce, address sender, uint256 value, bytes calldata payload)
        external
    {
        if (msg.sender != inbox) revert NotInbox();
        if (sourceChainId != soloChainId) revert WrongChain();
        if (sender != remoteGateway) revert NotRemoteGateway();
        if (value != 0) revert WrongValue();
        _receive(nonce, payload);
    }

    /// @notice Tells the paired gateway that its message `nonce` was vetoed in the inbox, so that
    /// nothing is ever delivered with that nonce: a `SPENT(nonce, VOID)`, after which the gateway on
    /// Solo refunds or sends again what it sent with it. Anyone may call it, once per nonce.
    function reportVetoed(uint64 nonce) external returns (uint64) {
        (,, SoloInbox.Status status) = SoloInbox(inbox).entries(nonce);
        if (status != SoloInbox.Status.Vetoed) revert NotVetoed();
        return _report(nonce, VOID);
    }

    /// @notice Tells the paired gateway what the inbox delivered as its message `m.nonce`: a
    /// `SPENT` with the identity of `m` if it came here, else `VOID`. What the gateway on Solo sent
    /// with that nonce, if it differs (a forgery took its nonce), never arrives, and it refunds or
    /// sends it again. Anyone may call it, once per nonce.
    function reportDelivered(SoloInbox.Message calldata m) external returns (uint64) {
        SoloInbox source = SoloInbox(inbox);
        (bytes32 messageHash,, SoloInbox.Status status) = source.entries(m.nonce);
        if (status != SoloInbox.Status.Delivered || messageHash != source.hashMessage(m)) revert NotDelivered();
        return _report(m.nonce, m.recipient == address(this) ? _identity(m.payload) : VOID);
    }

    /// @notice Moves to a successor inbox (spec 17 §6.4).
    function setInbox(address inbox_) external onlyOwner {
        if (inbox_ == address(0)) revert ZeroAddress();
        inbox = inbox_;
        emit InboxChanged(inbox_);
    }

    /// @notice Sets the gas messages sent from now on give the gateway on Solo, at least
    /// `MIN_MESSAGE_GAS`.
    function setMessageGas(uint64 gas) external onlyOwner {
        if (gas < MIN_MESSAGE_GAS) revert MessageGasTooLow();
        messageGas = gas;
        emit MessageGasChanged(gas);
    }

    function _report(uint64 nonce, bytes32 effect) private returns (uint64 reportNonce) {
        if (reported[nonce]) revert AlreadyReported();
        reported[nonce] = true;
        reportNonce = _sendRecorded(abi.encode(SPENT, nonce, effect));
        emit Reported(nonce, effect, reportNonce);
    }

    function _send(bytes memory payload) internal override returns (uint64) {
        return outbox.send(remoteGateway, messageGas, payload);
    }
}
