// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

contract ConfigHelper is Script {
    struct NetworkConfig {
        address entryPoint;
        address account;
        address policySigner;
    }

    uint256 constant MAINNET_FORK_CHAINID = 111222111;
    address constant MAINNET_FORK_ACCOUNT = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address constant MAINNET_SIGNER = 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;

    uint256 constant LOCAL_CHAINID = 31337;
    address constant LOCAL_ACCOUNT = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    // PK: 0xf15be32016c90625ac18f07598c5674edeb343fe54e741e1a8edc1c043cef49a
    address constant LOCAL_SIGNER = 0x6A7f3cc53eeE9746bf17e12a61ee69641B116f42;

    mapping(uint256 => NetworkConfig) public networkConfigs;

    error ChainNotConfigured();

    constructor() {
        // networkConfigs[MAINNET_FORK_CHAINID] = getMainnetForkConfig();
        // networkConfigs[LOCAL_CHAINID] = getOrCreateLocalConfig();
    }

    function getConfig() public returns (NetworkConfig memory config) {
        if (block.chainid == MAINNET_FORK_CHAINID) {
            return getMainnetForkConfig();
        }
        if (block.chainid == LOCAL_CHAINID) {
            return getOrCreateLocalConfig();
        }
        revert ChainNotConfigured();
    }

    function getMainnetForkConfig() public pure returns (NetworkConfig memory config) {
        return NetworkConfig({
            entryPoint: 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108,
            account: MAINNET_FORK_ACCOUNT,
            policySigner: MAINNET_SIGNER
        });
    }

    function getOrCreateLocalConfig() public returns (NetworkConfig memory) {
        NetworkConfig memory networkConfig = networkConfigs[LOCAL_CHAINID];
        if (networkConfig.entryPoint != address(0)) {
            return networkConfig;
        }

        vm.startBroadcast(LOCAL_ACCOUNT);
        EntryPoint entryPoint = new EntryPoint();
        vm.stopBroadcast();

        console2.log("EntryPoint deployed:", address(entryPoint));
        return NetworkConfig({entryPoint: address(entryPoint), account: LOCAL_ACCOUNT, policySigner: LOCAL_SIGNER});
    }
}
