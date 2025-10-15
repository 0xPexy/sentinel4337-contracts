// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console2} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";
import {ConfigHelper} from "script/ConfigHelper.s.sol";
import {SentinelAccount} from "src/accounts/SentinelAccount.sol";
import {VerifyingPaymaster} from "src/paymasters/VerifyingPaymaster.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS} from "@account-abstraction/contracts/core/Helpers.sol";
import {ECDSA} from "@solady/utils/ECDSA.sol";

import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract VerifyingPaymasterTest is Test {
    ConfigHelper.NetworkConfig networkConfig;
    SentinelAccount sentinelAccount;
    VerifyingPaymaster paymaster;
    IEntryPoint entryPoint;

    ERC20Mock token;

    address mockSigner = 0x6A7f3cc53eeE9746bf17e12a61ee69641B116f42;
    uint256 mockSignerPk = 0xf15be32016c90625ac18f07598c5674edeb343fe54e741e1a8edc1c043cef49a;

    address accountOwner;
    uint256 accountOwnerPk;

    address depositor = makeAddr("depositor");
    address receiver = makeAddr("receiver");

    uint256 constant PAYMASTER_DEPOSIT_AMOUNT = 100 ether;
    uint256 constant MINT_AMOUNT = 100e18;

    // gas
    uint128 constant PM_VAL_GAS = 120_000;
    uint128 constant POSTOP_GAS = 80_000;
    uint128 constant CALL_GAS = 500_000;
    uint128 constant VERIF_GAS = 500_000;
    uint128 constant PVERIF_GAS = 120_000;

    function setUp() public {
        Deploy deploy = new Deploy();
        (networkConfig, sentinelAccount, paymaster) = deploy.deploySentinelAccountAndPaymaster();
        entryPoint = IEntryPoint(networkConfig.entryPoint);

        token = new ERC20Mock();

        (accountOwner, accountOwnerPk) = makeAddrAndKey("owner");

        // Make test-owned key control the deployed smart account
        vm.prank(networkConfig.account);
        sentinelAccount.transferOwnership(accountOwner);

        hoax(depositor, PAYMASTER_DEPOSIT_AMOUNT);
        paymaster.deposit{value: PAYMASTER_DEPOSIT_AMOUNT}();

        // sanity: policySigner should match the test's mock signer
        assertEq(paymaster.policySigner(), mockSigner, "policy signer mismatch");
    }

    // ✅ 해피패스: target/selector 일치 → 성공
    function test_validatePaymasterUserOp() public {
        // 1) callData 준비
        bytes memory callData = _getMintOrBurnData(receiver, MINT_AMOUNT, true);

        // 2) PackedUserOperation 준비 (mint 전용, callGas는 검증에 영향 없음)
        PackedUserOperation memory userOp = _getPackedUserOp(receiver, callData);

        // 3) paymasterAndData 조립(프리픽스 → tempHash → 정책서명)
        _setPaymasterData(userOp);

        // 4) EntryPoint 가장해서 호출 (userOpHash는 EP가 내부에서 계산하므로 여기선 참고용으로 전달)
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.prank(address(entryPoint));
        (bytes memory ctx, uint256 vd) = paymaster.validatePaymasterUserOp(userOp, userOpHash, 0);
        // 서명 성공 + 정책 일치 → SIG OK (vd == 0)
        assertEq(vd & ((1 << 160) - 1), 0, "sig validation failed");
        uint48 validUntil = uint48(vd >> 160);
        uint48 validAfter = uint48(vd >> 208);

        assertGt(validUntil, block.timestamp);
        assertLe(validAfter, block.timestamp);
        assertEq(ctx.length, 0);
    }

    //  미스매치: selector가 다르면 리버트
    function test_validatePaymasterUserOp_invalidSelector() public {
        // burn을 호출하는 callData (paymaster 정책은 mint만 허용)
        bytes memory callData = _getMintOrBurnData(receiver, 100, false);

        // 2) PackedUserOperation 준비 (sender는 더미)
        PackedUserOperation memory userOp = _getPackedUserOp(receiver, callData);

        // 3) paymasterAndData 조립(정책은 mint.selector로 서명) → selector 미스매치 유도
        _setPaymasterData(userOp);

        // 4) EntryPoint 가장해서 호출
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.prank(address(entryPoint));
        (, uint256 vd) = paymaster.validatePaymasterUserOp(userOp, userOpHash, 0);
        assertTrue((vd & ((1 << 160) - 1)) != 0);
    }

    function test_mintWithPaymaster() public {
        bytes memory callData = _getMintOrBurnData(receiver, MINT_AMOUNT, true);
        PackedUserOperation memory userOp = _getPackedUserOp(address(sentinelAccount), callData);
        _setPaymasterData(userOp);

        // 7) 최종 userOpHash → 계정 오너 서명(ECDSA over 712 digest)
        _setUserOpSig(userOp);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        // 8) 번들러가 handleOps로 실행
        address mockBundler = makeAddr("mockBundler");
        vm.prank(mockBundler);
        entryPoint.handleOps(userOps, payable(mockBundler));

        // 9) 결과 검증: mint 성공
        assertEq(token.balanceOf(receiver), MINT_AMOUNT, "mint failed");
    }

    // ───────── helpers ─────────

    function _getMintOrBurnData(address to, uint256 amount, bool mint) internal view returns (bytes memory callData) {
        bytes4 selector = mint ? ERC20Mock.mint.selector : ERC20Mock.burn.selector;
        bytes memory innerData = abi.encodeWithSelector(selector, to, amount);
        callData = abi.encodeWithSelector(SentinelAccount.execute.selector, address(token), 0, innerData);
    }

    function _getPackedUserOp(address account, bytes memory callData)
        internal
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp.sender = account;
        userOp.nonce = 0; // 초기 배포형 스마트계정이면 0부터 시작
        userOp.initCode = ""; // 이미 배포됨
        userOp.callData = callData;
        userOp.accountGasLimits = _packAccountGas(VERIF_GAS, CALL_GAS);
        userOp.gasFees = _packGasFees(1 gwei, 30 gwei);
    }

    function _setPaymasterData(PackedUserOperation memory userOp) internal view {
        VerifyingPaymaster.PaymasterData memory paymasterData = VerifyingPaymaster.PaymasterData({
            validUntil: uint48(block.timestamp + 1 days),
            validAfter: uint48(0),
            target: address(token),
            selector: ERC20Mock.mint.selector,
            subsidyBps: 0
        });

        bytes memory paymasterDataWithoutSig = bytes.concat(
            bytes6(paymasterData.validUntil),
            bytes6(paymasterData.validAfter),
            bytes20(paymasterData.target),
            bytes4(paymasterData.selector),
            bytes2(paymasterData.subsidyBps)
        );

        bytes memory pmDataTemp =
            bytes.concat(bytes20(address(paymaster)), bytes16(PM_VAL_GAS), bytes16(POSTOP_GAS), paymasterDataWithoutSig);

        userOp.paymasterAndData = pmDataTemp;

        // 5) userOpHash(임시, 정책서명 제외) → EIP-191 digest → 정책 서명
        bytes32 tempHash = entryPoint.getUserOpHash(userOp);
        bytes32 digest = ECDSA.toEthSignedMessageHash(tempHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mockSignerPk, digest);
        bytes memory policySig = abi.encodePacked(r, s, v);
        // sanity: local recover matches signer
        address rec = ECDSA.recover(digest, policySig);
        assertEq(rec, mockSigner, "local policy signature mismatch");

        // 6) 최종 paymasterAndData (정책서명 65B append)
        userOp.paymasterAndData = bytes.concat(pmDataTemp, policySig);
    }

    function _setUserOpSig(PackedUserOperation memory userOp) internal view {
        bytes32 finalHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountOwnerPk, finalHash);
        userOp.signature = abi.encodePacked(r, s, v);
    }

    // ---- helpers ----

    function _packAccountGas(uint256 verificationGasLimit, uint256 callGasLimit) internal pure returns (bytes32) {
        // v0.8 accountGasLimits는 16바이트+16바이트 packed
        return bytes32(abi.encodePacked(bytes16(uint128(verificationGasLimit)), bytes16(uint128(callGasLimit))));
    }

    function _packGasFees(uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(bytes16(uint128(maxPriorityFeePerGas)), bytes16(uint128(maxFeePerGas))));
    }
}
