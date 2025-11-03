// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {ConfigHelper} from "script/ConfigHelper.s.sol";
import {VerifyingPaymaster} from "src/paymasters/VerifyingPaymaster.sol";

import {SimpleAccountFactory} from "@account-abstraction/contracts/accounts/SimpleAccountFactory.sol";
import {SimpleAccount} from "@account-abstraction/contracts/accounts/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ISenderCreator} from "@account-abstraction/contracts/interfaces/ISenderCreator.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {ECDSA} from "@solady/utils/ECDSA.sol";

import {ERC20Mock} from "./mocks/ERC20Mock.sol";

contract VerifyingPaymasterIntegrationTest is Test {
    ConfigHelper.NetworkConfig internal networkConfig;

    SimpleAccountFactory internal factory;
    SimpleAccount internal simpleAccount;
    VerifyingPaymaster internal paymaster;
    IEntryPoint internal entryPoint;

    ERC20Mock internal token;

    address internal mockSigner = 0x6A7f3cc53eeE9746bf17e12a61ee69641B116f42;
    uint256 internal mockSignerPk = 0xf15be32016c90625ac18f07598c5674edeb343fe54e741e1a8edc1c043cef49a;

    address internal accountOwner;
    uint256 internal accountOwnerPk;

    address internal depositor = makeAddr("depositor");
    address internal receiver = makeAddr("receiver");

    uint256 internal constant PAYMASTER_DEPOSIT_AMOUNT = 100 ether;
    uint256 internal constant MINT_AMOUNT = 100e18;
    uint256 internal constant ACCOUNT_SALT = 0;

    uint128 internal constant PM_VAL_GAS = 120_000;
    uint128 internal constant POSTOP_GAS = 80_000;
    uint128 internal constant CALL_GAS = 500_000;
    uint128 internal constant VERIF_GAS = 500_000;

    function setUp() public {
        ConfigHelper config = new ConfigHelper();
        networkConfig = config.getConfig();
        entryPoint = IEntryPoint(networkConfig.entryPoint);

        (accountOwner, accountOwnerPk) = makeAddrAndKey("accountOwner");

        _deployCoreContracts();
        simpleAccount = _deploySimpleAccount(accountOwner, ACCOUNT_SALT);

        token = new ERC20Mock();

        hoax(depositor, PAYMASTER_DEPOSIT_AMOUNT);
        paymaster.deposit{value: PAYMASTER_DEPOSIT_AMOUNT}();

        assertEq(paymaster.policySigner(), mockSigner, "policy signer mismatch");
    }

    function test_validatePaymasterUserOp() public {
        bytes memory callData = _getMintOrBurnData(receiver, MINT_AMOUNT, true);
        PackedUserOperation memory userOp = _getPackedUserOp(address(simpleAccount), callData);
        _setPaymasterData(userOp);

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, userOpHash, 0);

        assertEq(context.length, 0);
        assertEq(validationData & ((1 << 160) - 1), 0, "signature validation failed");
        uint48 validUntil = uint48(validationData >> 160);
        uint48 validAfter = uint48(validationData >> 208);

        assertGt(validUntil, block.timestamp);
        assertLe(validAfter, block.timestamp);
    }

    function test_validatePaymasterUserOp_invalidSelector() public {
        bytes memory callData = _getMintOrBurnData(receiver, MINT_AMOUNT, false);
        PackedUserOperation memory userOp = _getPackedUserOp(address(simpleAccount), callData);
        _setPaymasterData(userOp);

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.prank(address(entryPoint));
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, userOpHash, 0);

        assertTrue((validationData & ((1 << 160) - 1)) != 0, "paymaster validation should fail");
    }

    function test_integration_mintWithPaymaster() public {
        bytes memory callData = _getMintOrBurnData(receiver, MINT_AMOUNT, true);
        PackedUserOperation memory userOp = _getPackedUserOp(address(simpleAccount), callData);
        _setPaymasterData(userOp);
        _setUserOpSig(userOp);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        address bundler = makeAddr("bundler");
        vm.prank(bundler);
        entryPoint.handleOps(userOps, payable(bundler));

        assertEq(token.balanceOf(receiver), MINT_AMOUNT, "mint via paymaster failed");
    }

    function _deployCoreContracts() internal {
        factory = new SimpleAccountFactory(entryPoint);
        paymaster = new VerifyingPaymaster(entryPoint, networkConfig.policySigner);
    }

    function _deploySimpleAccount(address owner, uint256 salt) internal returns (SimpleAccount) {
        ISenderCreator senderCreator = entryPoint.senderCreator();
        vm.startPrank(address(senderCreator));
        SimpleAccount created = factory.createAccount(owner, salt);
        vm.stopPrank();
        return created;
    }

    function _getMintOrBurnData(address to, uint256 amount, bool mint) internal view returns (bytes memory callData) {
        bytes4 selector = mint ? ERC20Mock.mint.selector : ERC20Mock.burn.selector;
        bytes memory targetCall = abi.encodeWithSelector(selector, to, amount);
        callData = abi.encodeWithSelector(BaseAccount.execute.selector, address(token), 0, targetCall);
    }

    function _getPackedUserOp(address account, bytes memory callData)
        internal
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp.sender = account;
        userOp.nonce = 0;
        userOp.initCode = "";
        userOp.callData = callData;
        userOp.accountGasLimits = _packAccountGas(VERIF_GAS, CALL_GAS);
        userOp.preVerificationGas = 150_000;
        userOp.gasFees = _packGasFees(1 gwei, 30 gwei);
        userOp.paymasterAndData = "";
        userOp.signature = "";
    }

    function _setPaymasterData(PackedUserOperation memory userOp) internal view {
        VerifyingPaymaster.PaymasterData memory paymasterData = VerifyingPaymaster.PaymasterData({
            validUntil: uint48(block.timestamp + 1 days),
            validAfter: uint48(0),
            target: address(token),
            selector: ERC20Mock.mint.selector
        });

        bytes memory paymasterDataWithoutSig = bytes.concat(
            bytes6(paymasterData.validUntil),
            bytes6(paymasterData.validAfter),
            bytes20(paymasterData.target),
            bytes4(paymasterData.selector)
        );

        bytes memory pmPrefix =
            bytes.concat(bytes20(address(paymaster)), bytes16(PM_VAL_GAS), bytes16(POSTOP_GAS), paymasterDataWithoutSig);

        userOp.paymasterAndData = pmPrefix;

        bytes32 tempHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mockSignerPk, tempHash);
        bytes memory policySig = abi.encodePacked(r, s, v);

        address recovered = ECDSA.recover(tempHash, policySig);
        assertEq(recovered, mockSigner, "invalid policy signature");

        userOp.paymasterAndData = bytes.concat(pmPrefix, policySig);
    }

    function _setUserOpSig(PackedUserOperation memory userOp) internal view {
        bytes32 finalHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountOwnerPk, finalHash);
        userOp.signature = abi.encodePacked(r, s, v);
    }

    function _packAccountGas(uint256 verificationGasLimit, uint256 callGasLimit) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(bytes16(uint128(verificationGasLimit)), bytes16(uint128(callGasLimit))));
    }

    function _packGasFees(uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(bytes16(uint128(maxPriorityFeePerGas)), bytes16(uint128(maxFeePerGas))));
    }
}
