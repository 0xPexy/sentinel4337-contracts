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
    // --- constants ---
    // Paymaster data layout sizes used in paymasterAndData prefix (without signature)
    // validUntil(6) | validAfter(6) | target(20) | selector(4) | subsidyBps(2)
    uint256 internal constant PAYMASTER_DATA_SIZE = 6 + 6 + 20 + 4 + 2; // 38

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

    constructor(IEntryPoint _entryPoint, address signer) BasePaymaster(_entryPoint) {
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
        // userOpHash from EntryPoint includes the full paymasterAndData (including policy signature),
        // which creates a circular dependency. Recompute a temporary hash that excludes the policy signature.
        bool sigFailed;
        {
            bytes memory pmDataPrefix = _paymasterDataPrefix(userOp.paymasterAndData);
            PackedUserOperation memory userOpNoPolicySig = userOp;
            userOpNoPolicySig.paymasterAndData = pmDataPrefix;

            bytes32 opHash = entryPoint.getUserOpHash(userOpNoPolicySig);
            bytes32 messageHash = ECDSA.toEthSignedMessageHash(opHash);
            address recovered = ECDSA.recover(messageHash, sig);
            sigFailed = (recovered != policySigner);
        }

        // pack validation data
        validationData = _packValidationData(sigFailed, paymasterData.validUntil, paymasterData.validAfter);

        // success
        if (!sigFailed) {
            emit Sponsored(userOpHash, userOp.sender, paymasterData.validUntil, paymasterData.validAfter);
        }

        // context to be passed to postOp (unused for now)
        context = _buildContext(paymasterData, userOp.sender);
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

    // --- internal helpers ---

    function _paymasterDataPrefix(bytes calldata paymasterAndData) internal pure returns (bytes memory) {
        // prefix until the end of PaymasterData (without trailing signature)
        return paymasterAndData[:PAYMASTER_DATA_OFFSET + PAYMASTER_DATA_SIZE];
    }

    function _recoverPolicySigner(bytes32 dataHash, bytes memory sig) internal view returns (address) {
        return ECDSA.recover(ECDSA.toEthSignedMessageHash(dataHash), sig);
    }

    function _buildContext(PaymasterData memory, /*p*/ address /*sender*/ ) internal pure returns (bytes memory) {
        // hook for future use (e.g., subsidy context)
        return "";
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
