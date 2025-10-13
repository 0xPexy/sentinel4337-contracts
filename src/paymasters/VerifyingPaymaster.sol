// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {
    BasePaymaster,
    IPaymaster,
    IEntryPoint,
    PackedUserOperation
} from "@account-abstraction/contracts/core/BasePaymaster.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {ECDSA} from "@solady/utils/ECDSA.sol";

/// @notice Verify offchain generated sig & deadline
/// - v0.8 BasePaymaster: use _packValidationData, _requireFromEntryPoint
/// - paymasterAndData = abi.encode(paymasterAddr, validUntil, validAfter, policyHash, signature)
contract VerifyingPaymaster is BasePaymaster {
    struct PaymasterData {
        uint48 validUntil; // best practice
        uint48 validAfter; // best practice
        bytes32 policyHash; // off-chain policy hash (minimal version)
        bytes signature;
    }

    address public immutable policySigner; // offchain policy signer

    event Sponsored(bytes32 indexed userOpHash, address indexed sender, uint48 validUntil, uint48 validAfter);
    event Deposit(address indexed from, uint256 amount);

    error InvalidSingatureLength();

    constructor(IEntryPoint ep, address signer) BasePaymaster(ep) {
        policySigner = signer;
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 /*maxCost*/ )
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        // paymasterAndData decoding (starts from PAYMASTER_DATA_OFFSET(52))
        (PaymasterData memory paymasterData, bytes memory sig) =
            parsePaymasterData(userOp.paymasterAndData[PAYMASTER_DATA_OFFSET:]);

        // Only support 65-byte signatures, to avoid potential replay attacks.
        require(sig.length == 65, InvalidSingatureLength());

        // signed msg: userOpHash + policyHash + period
        bytes32 signedMsgHash = getHash(userOpHash, paymasterData);
        address recovered = ECDSA.recover(ECDSA.toEthSignedMessageHash(signedMsgHash), sig);
        bool sigFailed = (recovered != policySigner);

        // pack validation data (0==OK)
        validationData = _packValidationData(sigFailed, paymasterData.validUntil, paymasterData.validAfter);

        // success
        if (!sigFailed) {
            emit Sponsored(userOpHash, userOp.sender, paymasterData.validUntil, paymasterData.validAfter);
        }

        // context to be passed to postOp
        context = "";
    }

    function parsePaymasterData(bytes calldata paymasterAndData)
        public
        pure
        returns (PaymasterData memory paymasterData, bytes calldata signature)
    {
        paymasterData.validUntil = uint48(bytes6(paymasterAndData[0:6]));
        paymasterData.validAfter = uint48(bytes6(paymasterAndData[6:12]));
        paymasterData.policyHash = bytes32(paymasterAndData[12:44]);
        signature = bytes(paymasterAndData[44:]);
    }

    function getHash(bytes32 userOpHash, PaymasterData memory paymasterData) public pure returns (bytes32) {
        return keccak256(
            abi.encode(userOpHash, paymasterData.policyHash, paymasterData.validUntil, paymasterData.validAfter)
        );
    }
}
