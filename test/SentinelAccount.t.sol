// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console2} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";
import {ConfigHelper} from "script/ConfigHelper.s.sol";
import {SentinelAccount} from "src/accounts/SentinelAccount.sol";
import {VerifyingPaymaster} from "src/paymasters/VerifyingPaymaster.sol";

import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract SentinelAccountTest is Test {
    ConfigHelper.NetworkConfig networkConfig;
    SentinelAccount sentinelAccount;
    VerifyingPaymaster paymaster;

    ERC20Mock token;

    function setUp() public {
        Deploy deploy = new Deploy();
        (networkConfig, sentinelAccount, paymaster) = deploy.deploySentinelAccountAndPaymaster();
        token = new ERC20Mock();
    }

    function test_ownerCanExecuteCommands() public {
        bytes memory functionData = _getMintTokenFunctionData(address(sentinelAccount), 1e18);
        vm.prank(sentinelAccount.owner());
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
