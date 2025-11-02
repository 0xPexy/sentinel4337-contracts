.PHONY: deploy_factory verify_factory verify_account _require_contract

CHAIN ?= 111222111

deploy_factory:
	forge script script/Deploy.s.sol:DeploySimpleAccountFactory --rpc-url mainnet_fork --broadcast --account dev1

verify_factory: _require_contract
	FOUNDRY_PROFILE=verify forge verify-contract $(CONTRACT) SimpleAccountFactory --chain-id $(CHAIN) --verifier custom

verify_account: _require_contract
	FOUNDRY_PROFILE=verify forge verify-contract $(CONTRACT) SimpleAccount --chain-id $(CHAIN) --verifier custom

_require_contract:
	@if [ -z "$(CONTRACT)" ]; then \
		echo "CONTRACT 주소를 지정하세요. 예: make verify_factory CONTRACT=0xabc..."; \
		exit 1; \
	fi
