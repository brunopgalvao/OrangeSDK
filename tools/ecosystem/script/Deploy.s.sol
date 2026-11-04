// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Token} from "../contracts/Token.sol";

/// The cheatcodes the script uses, declared here so the suite needs no
/// forge-std checkout.
interface Vm {
    function envUint(string calldata name) external view returns (uint256);
    function envAddress(string calldata name) external view returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

/// `forge script`: deploys a token and makes three transfers in one
/// broadcast, so the node's pool takes several transactions of one sender
/// before any of them is mined.
contract Deploy {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (Token token) {
        address to = vm.envAddress("RECIPIENT");
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        token = new Token(1_000_000 ether);
        token.transfer(to, 1 ether);
        token.transfer(to, 2 ether);
        token.approve(to, 3 ether);
        vm.stopBroadcast();
    }
}
