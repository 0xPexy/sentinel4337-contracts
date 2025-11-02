// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {SimpleAccountFactory} from "@account-abstraction/contracts/accounts/SimpleAccountFactory.sol";
import {VerifyingPaymaster} from "src/paymasters/VerifyingPaymaster.sol";
import {ConfigHelper} from "./ConfigHelper.s.sol";

abstract contract DeployBase is Script {
    function _loadConfig() internal returns (ConfigHelper.NetworkConfig memory) {
        ConfigHelper config = new ConfigHelper();
        return config.getConfig();
    }
}

contract DeploySimpleAccountFactory is DeployBase {
    function run() public returns (SimpleAccountFactory factory, ConfigHelper.NetworkConfig memory networkConfig) {
        return deploySimpleAccountFactory();
    }

    function deploySimpleAccountFactory()
        public
        returns (SimpleAccountFactory factory, ConfigHelper.NetworkConfig memory networkConfig)
    {
        console2.log("Deploying SimpleAccountFactory on chainID:", block.chainid);
        networkConfig = _loadConfig();

        vm.startBroadcast();
        console2.log("Broadcast sender:", tx.origin);
        factory = new SimpleAccountFactory(IEntryPoint(networkConfig.entryPoint));
        vm.stopBroadcast();

        console2.log("EntryPoint:", networkConfig.entryPoint);
        console2.log("SimpleAccountFactory deployed:", address(factory));
    }
}

contract DeployVerifyingPaymaster is DeployBase {
    function run() public returns (VerifyingPaymaster paymaster, ConfigHelper.NetworkConfig memory networkConfig) {
        return deployVerifyingPaymaster();
    }

    function deployVerifyingPaymaster()
        public
        returns (VerifyingPaymaster paymaster, ConfigHelper.NetworkConfig memory networkConfig)
    {
        console2.log("Deploying VerifyingPaymaster on chainID:", block.chainid);
        networkConfig = _loadConfig();

        vm.startBroadcast();
        console2.log("Broadcast sender:", tx.origin);
        paymaster = new VerifyingPaymaster(IEntryPoint(networkConfig.entryPoint), networkConfig.policySigner);
        vm.stopBroadcast();

        console2.log("EntryPoint:", networkConfig.entryPoint);
        console2.log("Policy signer:", networkConfig.policySigner);
        console2.log("VerifyingPaymaster deployed:", address(paymaster));
    }
}

contract GetSimpleAccountAddress is Script {
    function run(address factory, address owner, uint256 salt) public view {
        address account = getSimpleAccountAddress(factory, owner, salt);
        console2.log("SimpleAccount address:", account);
    }

    function getSimpleAccountAddress(address factory, address owner, uint256 salt)
        public
        view
        returns (address account)
    {
        SimpleAccountFactory saf = SimpleAccountFactory(factory);
        account = saf.getAddress(owner, salt);
    }
}
