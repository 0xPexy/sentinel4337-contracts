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
    address constant LOCAL_SIGNER = 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;

    mapping(uint256 => NetworkConfig) public networkConfigs;

    error ChainNotConfigured();

    constructor() {
        networkConfigs[MAINNET_FORK_CHAINID] = getMainnetForkConfig();
        networkConfigs[LOCAL_CHAINID] = getOrCreateLocalConfig();
    }

    function getConfig() public view returns (NetworkConfig memory config) {
        config = networkConfigs[block.chainid];
        require(config.entryPoint != address(0), ChainNotConfigured());
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
