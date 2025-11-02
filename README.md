# Sentra Contracts

## Overview
- ERC-4337 smart account stack on EntryPoint v0.8.
- Minimal deployment flow built around SimpleAccountFactory and a policy-based VerifyingPaymaster.
- Paymaster enforces offchain policy via an ECDSA signature over constrained fields (validAfter/until, allowed target and function selector) and only accepts 65-byte signatures.

## Contracts
- `SimpleAccountFactory` (from eth-infinitism):
  - Deploys counterfactual `SimpleAccount` proxies via `ERC1967Proxy`.
  - Constructor deploys a single implementation `SimpleAccount` used as the proxy logic (not a user wallet).
- `VerifyingPaymaster` (src/paymasters/VerifyingPaymaster.sol):
  - Validates `PackedUserOperation` with a policy signature and target/selector matching.
  - Emits `Sponsored` on success and returns packed validation data (validAfter/validUntil).

## Prerequisites
- Foundry installed (`forge`, `cast`).
- RPC named `mainnet_fork` configured in `foundry.toml` or override the `--rpc-url` in make targets.
- Dependencies installed. This repo ships with Soldeer config; if needed:
  - `make install`

## Make Targets
- `make deploy_factory`
  - Deploys `SimpleAccountFactory` using `script/Deploy.s.sol:DeploySimpleAccountFactory`.
- `make deploy_paymaster`
  - Deploys `VerifyingPaymaster` using `script/Deploy.s.sol:DeployVerifyingPaymaster`.
- `make verify_factory CONTRACT=0xYourFactory [CHAIN=111222111]`
  - Verifies the deployed `SimpleAccountFactory`.
- `make verify_account CONTRACT=0xYourAccount [CHAIN=111222111]`
  - Verifies a deployed `SimpleAccount` proxy (optional).

You can change the default chain id with `CHAIN=<id>`.

## Scripts
- `script/Deploy.s.sol`
  - `DeploySimpleAccountFactory`: logs chain id, broadcasts deployment of the factory.
  - `DeployVerifyingPaymaster`: broadcasts deployment of the VerifyingPaymaster bound to the configured EntryPoint and policy signer.
  - `GetSimpleAccountAddress`: helper to compute a counterfactual `SimpleAccount` address from `owner` and `salt`.
- `script/ConfigHelper.s.sol`
  - Provides network config (EntryPoint v0.8 address, policy signer).
  - On a local chain, deploys a fresh `EntryPoint` for convenience.

## Testing
- Run all tests:
  - `forge test`
- Integration test highlights (`test/VerifyingPaymaster.t.sol`):
  - Creates a `SimpleAccount` via factory (simulating EntryPoint `SenderCreator`).
  - Funds the `VerifyingPaymaster` and validates policy-signed sponsorship.
  - Executes an ERC20 `mint` call sponsored by the paymaster.

## Notes
- The initial `SimpleAccount` deployed by the factory constructor is the implementation used by proxies; it is not meant to be used as a user wallet directly.
- The paymaster only honors requests whose `callData` target and selector match the policy payload.

## Repository Layout
- `src/paymasters/VerifyingPaymaster.sol` – policy-verifying paymaster.
- `script/Deploy.s.sol` – deployment scripts for factory and paymaster.
- `script/ConfigHelper.s.sol` – per-chain configuration helper (EntryPoint v0.8, policy signer).
- `test/VerifyingPaymaster.t.sol` – end-to-end integration with factory + paymaster.
