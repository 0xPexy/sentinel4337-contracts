// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BaseAccount, PackedUserOperation} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@account-abstraction/contracts/core/Helpers.sol";
import {ECDSA} from "@solady/utils/ECDSA.sol";

contract SentinelAccount is BaseAccount {
    IEntryPoint private immutable _entryPoint = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    address public owner;

    error InvalidExecutor();
    error NonOwner();
    event OwnerChanged(address indexed newOwner);

    constructor(IEntryPoint ep, address _owner) {
        _entryPoint = ep;
        owner = _owner;
        emit OwnerChanged(owner);
    }

    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, NonOwner());
        owner = newOwner;
        emit OwnerChanged(newOwner);
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        if (ECDSA.recover(userOpHash, userOp.signature) != owner) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    /// @dev deposit insufficient amount to EntryPoint(Best Practice)
    function _payPrefund(uint256 missingAccountFunds) internal override {
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(address(entryPoint())).call{value: missingAccountFunds}("");
            require(ok, "FUNDING_FAILED");
        }
    }

    function execute(address target, uint256 value, bytes calldata data) external override {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, InvalidExecutor());
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, string(ret));
    }

    receive() external payable {}
}
