// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {SentinelAccount} from "src/accounts/SentinelAccount.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {ERC20Mock} from "./mocks/ERC20Mock.sol";

contract SentinelAccountTest is Test {
    SentinelAccount internal sentinelAccount;
    ERC20Mock internal token;
    address internal owner;

    function setUp() public {
        owner = makeAddr("sentinelOwner");
        EntryPoint entryPoint = new EntryPoint();
        sentinelAccount = new SentinelAccount(entryPoint, owner);
        token = new ERC20Mock();
    }

    function test_ownerCanExecuteCommands() public {
        bytes memory functionData = _getMintTokenFunctionData(address(sentinelAccount), 1e18);
        vm.prank(owner);
        sentinelAccount.execute(address(token), 0, functionData);
        assertEq(token.balanceOf(address(sentinelAccount)), 1e18);
    }

    function test_nonOwnerCannotExecuteCommands() public {
        bytes memory functionData = _getMintTokenFunctionData(address(sentinelAccount), 1e18);
        address user = makeAddr("user");
        vm.prank(user);
        vm.expectRevert(SentinelAccount.InvalidExecutor.selector);
        sentinelAccount.execute(address(token), 0, functionData);
    }

    function _getMintTokenFunctionData(address target, uint256 amount)
        internal
        pure
        returns (bytes memory functionData)
    {
        functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, target, amount);
    }
}
