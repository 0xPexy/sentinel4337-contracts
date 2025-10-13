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
import "@account-abstraction/contracts/core/UserOperationLib.sol";
/// @notice Verify offchain generated sig & deadline
/// - v0.8 BasePaymaster: use _packValidationData, _requireFromEntryPoint
/// - paymasterAndData = abi.encode(paymasterAddr, validUntil, validAfter, policyHash, signature)

contract VerifyingPaymaster is BasePaymaster {
    struct PaymasterData {
        uint48 validUntil;
        uint48 validAfter;
        address target; // allowed contract
        bytes4 selector; // allowed function
        uint16 subsidyBps; // subsidy ratio (0~10000) 10000=100%
    }

    address public immutable policySigner; // offchain policy signer

    event Sponsored(bytes32 indexed userOpHash, address indexed sender, uint48 validUntil, uint48 validAfter);

    error InvalidSingatureLength();
    error InvalidSubsidy();
    error InvalidTargetOrSelector();

    constructor(IEntryPoint entryPoint, address signer) BasePaymaster(entryPoint) {
        policySigner = signer;
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 /*maxCost*/ )
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        // 1) paymasterAndData decoding (starts from PAYMASTER_DATA_OFFSET(52))
        (PaymasterData memory paymasterData, bytes memory sig) =
            _parsePaymasterData(userOp.paymasterAndData[PAYMASTER_DATA_OFFSET:]);

        // Only support 65-byte signatures, to avoid potential replay attacks
        require(sig.length == 65, InvalidSingatureLength());
        // 2) Extract real target/selector from userOp.callData -> cmp with paymasterData
        (address txTarget, bytes4 txSelector) = _extractTargetAndSelector(userOp.callData);
        if (txTarget != paymasterData.target || txSelector != paymasterData.selector) {
            return ("", _packValidationData(true, 0, 0));
        }
        // 3) 정적 가스필드 포함하여 정책서명 메시지 구성(바꿔치기 방지)
        (, uint256 validationGasLimit, uint256 postOpGasLimit) =
            UserOperationLib.unpackPaymasterStaticFields(userOp.paymasterAndData);
        bytes32 dataHash = getHash(userOpHash, paymasterData, uint128(validationGasLimit), uint128(postOpGasLimit));

        // 4) 정책 서명 검증 (EIP-191)
        address recovered = ECDSA.recover(ECDSA.toEthSignedMessageHash(dataHash), sig);
        bool sigFailed = (recovered != policySigner);

        // pack validation data 
        validationData = _packValidationData(sigFailed, paymasterData.validUntil, paymasterData.validAfter);

        // success
        if (!sigFailed) {
            emit Sponsored(userOpHash, userOp.sender, paymasterData.validUntil, paymasterData.validAfter);
        }

        // context to be passed to postOp
        // TODO: add subsidy for tx
        context = "";
    }

    function _parsePaymasterData(bytes calldata paymasterAndData)
        internal
        pure
        returns (PaymasterData memory paymasterData, bytes calldata signature)
    {
        paymasterData.validUntil = uint48(bytes6(paymasterAndData[0:6]));
        paymasterData.validAfter = uint48(bytes6(paymasterAndData[6:12]));
        paymasterData.target = address(bytes20(paymasterAndData[12:32]));
        paymasterData.selector = bytes4(paymasterAndData[32:36]);
        paymasterData.subsidyBps = uint16(bytes2(paymasterAndData[36:38]));
        signature = bytes(paymasterAndData[38:]);
    }

    function getHash(bytes32 userOpHash, PaymasterData memory p, uint128 validationGasLimit, uint128 postOpGasLimit)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                userOpHash,
                p.target,
                p.selector,
                p.subsidyBps,
                p.validUntil,
                p.validAfter,
                validationGasLimit,
                postOpGasLimit
            )
        );
    }

    function _extractTargetAndSelector(bytes calldata callData)
        internal
        pure
        returns (address target, bytes4 selector)
    {
        if (callData.length < 4) return (address(0), 0x00000000);
        (address t,, bytes memory d) = abi.decode(callData[4:], (address, uint256, bytes));
        target = t;
        if (d.length >= 4) {
            assembly {
                selector := mload(add(d, 32))
            }
        }
    }
}
