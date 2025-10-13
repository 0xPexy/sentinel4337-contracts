// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {SentinelAccount} from "src/accounts/SentinelAccount.sol";
import {VerifyingPaymaster} from "src/paymasters/VerifyingPaymaster.sol";
import {ConfigHelper} from "./ConfigHelper.s.sol";

contract Deploy is Script {
    function run() public {
        deploySentinelAccountAndPaymaster();
    }

    function deploySentinelAccountAndPaymaster()
        public
        returns (
            ConfigHelper.NetworkConfig memory networkConfig,
            SentinelAccount sentinelAccount,
            VerifyingPaymaster paymaster
        )
    {
        console2.log("Deploying on chainID:", block.chainid);
        ConfigHelper config = new ConfigHelper();
        networkConfig = config.getConfig();

        vm.startBroadcast(networkConfig.account);
        IEntryPoint entryPoint = IEntryPoint(networkConfig.entryPoint);
        sentinelAccount = new SentinelAccount(entryPoint, networkConfig.account);
        paymaster = new VerifyingPaymaster(entryPoint, networkConfig.policySigner);
        vm.stopBroadcast();

        console2.log("Account deployed:", address(sentinelAccount));
        console2.log("Paymaster deployed:", address(paymaster));
    }
}
