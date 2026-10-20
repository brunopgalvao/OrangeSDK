// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// The example native contract, guest/modules/counter (spec 16).
interface ICounter {
    function count() external view returns (uint256);
    function add(uint256 n) external returns (uint256);
    function fail(uint256 code) external;
    function paid() external payable returns (uint256);
    function spin() external;
    function whoami() external view returns (address);
    error Failed(uint256 code);
}

/// A Solidity contract that calls a native contract the ways the module
/// tests need: return data, reverts caught and propagated, reverts of an
/// enclosing frame, value, static and delegate calls, gas limits, and two
/// calls in one transaction. Built by build.sh in this directory.
///
/// The tests predeploy it at genesis with the native contract's address in
/// slot 0.
contract Caller {
    /// Slot 0: the native contract.
    ICounter public counter;
    /// Slot 1: the last count `addAndStore` saw.
    uint256 public last;

    function addAndStore(uint256 n) external returns (uint256 total) {
        total = counter.add(n);
        last = total;
    }

    function addThenRevert(uint256 n) external {
        counter.add(n);
        revert("undone");
    }

    /// Adds in a frame that reverts, catches it, and reads the count.
    function addInRevertedFrame(uint256 n) external returns (uint256) {
        try this.addThenRevert(n) {} catch {}
        return counter.count();
    }

    function addTwice(uint256 a, uint256 b) external returns (uint256) {
        counter.add(a);
        return counter.add(b);
    }

    function tryFail(uint256 code) external returns (bytes memory) {
        try counter.fail(code) {
            return "";
        } catch (bytes memory reason) {
            return reason;
        }
    }

    function failThrough(uint256 code) external {
        counter.fail(code);
    }

    function pay() external payable returns (uint256) {
        return counter.paid{value: msg.value}();
    }

    function sender() external view returns (address) {
        return counter.whoami();
    }

    function staticAdd(uint256 n) external view returns (bool ok) {
        (ok,) = address(counter).staticcall(abi.encodeCall(ICounter.add, (n)));
    }

    function staticCount() external view returns (bool ok, uint256 value) {
        bytes memory out;
        (ok, out) = address(counter).staticcall(abi.encodeCall(ICounter.count, ()));
        value = abi.decode(out, (uint256));
    }

    function delegateCount() external returns (bool ok) {
        (ok,) = address(counter).delegatecall(abi.encodeCall(ICounter.count, ()));
    }

    function spinWith(uint256 gas) external returns (bool ok) {
        (ok,) = address(counter).call{gas: gas}(abi.encodeCall(ICounter.spin, ()));
    }

    function addWith(uint256 gas, uint256 n) external returns (bool ok) {
        (ok,) = address(counter).call{gas: gas}(abi.encodeCall(ICounter.add, (n)));
    }

    function codeOf() external view returns (uint256 size, bytes32 hash) {
        address c = address(counter);
        assembly {
            size := extcodesize(c)
            hash := extcodehash(c)
        }
    }
}
