// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

contract ConfigHelper is Script {
    struct NetworkConfig {
        address entryPoint;
        address policySigner;
    }

    uint256 internal constant MAINNET_FORK_CHAINID = 111222111;
    address internal constant MAINNET_FORK_ENTRYPOINT_V8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address internal constant MAINNET_FORK_SIGNER = 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;

    uint256 internal constant LOCAL_CHAINID = 31337;
    address internal constant DEFAULT_LOCAL_POLICY_SIGNER = 0x6A7f3cc53eeE9746bf17e12a61ee69641B116f42;

    mapping(uint256 => NetworkConfig) private networkConfigs;

    error ChainNotConfigured(uint256 chainId);

    function getConfig() public returns (NetworkConfig memory config) {
        config = networkConfigs[block.chainid];
        if (config.entryPoint != address(0)) {
            return config;
        }

        if (block.chainid == MAINNET_FORK_CHAINID) {
            config = _loadMainnetForkConfig();
        } else if (block.chainid == LOCAL_CHAINID) {
            config = _getOrCreateLocalConfig();
        } else {
            revert ChainNotConfigured(block.chainid);
        }

        networkConfigs[block.chainid] = config;
    }

    function setConfig(uint256 chainId, NetworkConfig memory networkConfig) public {
        networkConfigs[chainId] = networkConfig;
    }

    function _loadMainnetForkConfig() internal pure returns (NetworkConfig memory config) {
        config = NetworkConfig({entryPoint: MAINNET_FORK_ENTRYPOINT_V8, policySigner: MAINNET_FORK_SIGNER});
    }

    function _getOrCreateLocalConfig() internal returns (NetworkConfig memory config) {
        config = networkConfigs[LOCAL_CHAINID];
        if (config.entryPoint != address(0)) {
            return config;
        }

        EntryPoint entryPoint = new EntryPoint();

        console2.log("EntryPoint deployed:", address(entryPoint));

        config = NetworkConfig({entryPoint: address(entryPoint), policySigner: DEFAULT_LOCAL_POLICY_SIGNER});
        networkConfigs[LOCAL_CHAINID] = config;
    }
}
