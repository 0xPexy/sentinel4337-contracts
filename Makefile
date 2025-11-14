.PHONY: deploy_factory deploy_paymaster fund_account verify verify_factory verify_account verify_paymaster _require_contract _require_name _require_addrs

# Default chain id (custom mainnet fork in foundry.toml). Override with `make CHAIN=<id> ...`
CHAIN ?= 111222111
RPC_URL ?= mainnet_fork
FUND_AMOUNT ?= 0x21e19e0c9bab2400000

install:
	forge soldeer install

# Deploy the ERC-4337 SimpleAccountFactory (EntryPoint v0.8 compatible)
deploy_factory:
	forge script script/Deploy.s.sol:DeploySimpleAccountFactory --rpc-url mainnet_fork --broadcast --account dev1

# Deploy the VerifyingPaymaster (policy-signed sponsor)
deploy_paymaster:
	forge script script/Deploy.s.sol:DeployVerifyingPaymaster --rpc-url mainnet_fork --broadcast --account dev1

# Fund one or more addresses with FUND_AMOUNT wei (default 10,000 ETH).
# Provide ADDRS as a JSON array string to avoid shell escaping issues, e.g.
#   make fund_account ADDRS='["0xabc...","0xdef..."]'
fund_account: _require_addrs
	cast rpc tenderly_setBalance '[$(ADDRS), "$(FUND_AMOUNT)"]' --raw --rpc-url $(RPC_URL)

# Verify the deployed SimpleAccountFactory contract.
# Usage: make verify_factory CONTRACT=0xYourFactory CHAIN=111222111
verify_factory: _require_contract
	FOUNDRY_PROFILE=verify forge verify-contract $(CONTRACT) SimpleAccountFactory --chain-id $(CHAIN) --verifier custom

# Verify a deployed SimpleAccount (counterfactual proxy) if needed.
# Usage: make verify_account CONTRACT=0xYourAccount CHAIN=111222111
verify_account: _require_contract
	FOUNDRY_PROFILE=verify forge verify-contract $(CONTRACT) SimpleAccount --chain-id $(CHAIN) --verifier custom

# Verify the deployed VerifyingPaymaster contract.
# Usage: make verify_paymaster CONTRACT=0xYourPaymaster CHAIN=111222111
verify_paymaster: _require_contract
	FOUNDRY_PROFILE=verify forge verify-contract $(CONTRACT) VerifyingPaymaster --chain-id $(CHAIN) --verifier custom

# Generic verification target. NAME accepts fully-qualified contract identifier, e.g.
#   make verify CONTRACT=0x... NAME=src/paymasters/VerifyingPaymaster.sol:VerifyingPaymaster
verify: _require_contract _require_name
	FOUNDRY_PROFILE=verify forge verify-contract $(CONTRACT) $(NAME) --chain-id $(CHAIN) --verifier custom

# Internal: require CONTRACT to be set
_require_contract:
	@if [ -z "$(CONTRACT)" ]; then \
		echo "Please provide CONTRACT address. e.g., make verify CONTRACT=0xabc... NAME=src/...:Contract"; \
		exit 1; \
	fi

_require_name:
	@if [ -z "$(NAME)" ]; then \
		echo "Please provide NAME (fully-qualified contract identifier)."; \
		exit 1; \
	fi


_require_addrs:
	@if [ -z "$(ADDRS)" ]; then \
		echo "Please provide ADDRS as a JSON array. e.g., make fund_account ADDRS='[\"0xabc\",\"0xdef\"]'"; \
		exit 1; \
	fi
