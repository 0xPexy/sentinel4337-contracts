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

    address depositor = makeAddr("depositor");

    function setUp() public {
        Deploy deploy = new Deploy();
        (networkConfig, sentinelAccount, paymaster) = deploy.deploySentinelAccountAndPaymaster();
        entryPoint = IEntryPoint(networkConfig.entryPoint);

        token = new ERC20Mock();

        vm.deal(depositor, 100 ether);
    }

    function _encodePaymasterData(uint48 validUntil, uint48 validAfter, bytes32 policyHash, bytes memory sig)
        internal
        pure
        returns (bytes memory)
    {
        // align with VerifyingPaymaster.parsePaymasterData slicing
        return bytes.concat(bytes6(validUntil), bytes6(validAfter), policyHash, sig);
    }

    function test_deposit() public {
        uint256 depositAmount = 1 ether;
        vm.prank(depositor);
        paymaster.deposit{value: depositAmount}();
        uint256 paymasterBalanceInEntryPoint = entryPoint.balanceOf(address(paymaster));
        assertEq(paymasterBalanceInEntryPoint, depositAmount);
    }

    // ✅ 해피패스: target/selector 일치 → 성공
    function test_validate_ok_whenTargetAndSelectorMatch() public {
        // 1) callData = Account.execute(target, value, data) 대신, 예제에선 target의 단일 함수 호출 데이터 자체를 쓴다고 가정
        // 실제 프로젝트에선 account.execute(...) 인코딩을 넣고, 그 안에서 target/selector를 디코딩하세요.
        bytes memory innerData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(0xBEEF), 100);
        bytes memory callData = abi.encodeWithSelector(SentinelAccount.execute.selector, address(token), 0, innerData);

        // 2) PackedUserOperation 준비 (필요한 필드만 채움)
        PackedUserOperation memory userOp;
        userOp.sender = address(0xCAFE); // 테스트용 더미
        userOp.callData = callData;
        userOp.accountGasLimits = _packAccountGas(200_000, 0); // verification, call (대략치)
        userOp.gasFees = _packGasFees(1 gwei, 30 gwei);

        // 3) paymasterAndData = addr(20) | pmValGas(16) | postOpGas(16) | encoded(PaymasterData...) | sig
        uint128 pmValGas = 60_000;
        uint128 postOpGas = 30_000;

        // 정책 데이터 (옵션1: 필요한 필드만)
        VerifyingPaymaster.PaymasterData memory p = VerifyingPaymaster.PaymasterData({
            validUntil: uint48(block.timestamp + 1 days),
            validAfter: uint48(block.timestamp),
            target: address(token),
            selector: ERC20Mock.mint.selector,
            subsidyBps: 0
        });

        bytes32 userOpHash = keccak256("dummy"); // 테스트에선 임의 값 사용(EntryPoint가 넘겨준다고 가정)
        bytes32 m = paymaster.getHash(userOpHash, p, pmValGas, postOpGas); // v0.8: 우리 컨트랙트의 정책해시(옵션1)

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mockSignerPk, ECDSA.toEthSignedMessageHash(m));
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory paymasterAndData = bytes.concat(
            bytes20(address(paymaster)),
            bytes16(pmValGas),
            bytes16(postOpGas),
            // PMD (struct 밖 시그니처!) = 6 | 6 | 20 | 4 | 2
            bytes6(p.validUntil),
            bytes6(p.validAfter),
            bytes20(p.target),
            bytes4(p.selector),
            bytes2(p.subsidyBps),
            sig
        );

        userOp.paymasterAndData = paymasterAndData;

        // 4) EntryPoint 가장해서 호출
        vm.prank(address(entryPoint));
        // maxCost는 테스트에 영향 없음(정책검증 위주)
        (bytes memory ctx, uint256 vd) = paymaster.validatePaymasterUserOp(userOp, userOpHash, 0);
        // 서명 성공 + 정책 일치 → SIG OK (vd == 0)
        assertEq(vd & ((1 << 160) - 1), 0, "sig validation failed");
        uint48 validUntil = uint48(vd >> 160);
        uint48 validAfter = uint48(vd >> 208);

        assertGt(validUntil, block.timestamp);
        assertLe(validAfter, block.timestamp);
        assertEq(ctx.length, 0);
    }

    // ❌ 미스매치: selector가 다르면 리버트
    // function test_revert_whenSelectorMismatch() public {
    //     bytes memory callData = abi.encodeWithSelector(Target.burn.selector, address(0xBEEF), 10);
    //     PackedUserOperation memory uop;
    //     uop.sender = address(0xCAFE);
    //     uop.callData = callData;
    //     uop.accountGasLimits = _packAccountGas(200_000, 0);
    //     uop.gasFees = _packGasFees(1 gwei, 30 gwei);

    //     uint128 pmValGas = 60_000;
    //     uint128 postOpGas = 30_000;

    //     // 정책은 mint만 허용
    //     VerifyingPaymaster.PaymasterData memory p = VerifyingPaymaster.PaymasterData({
    //         validUntil: uint48(block.timestamp + 1 days),
    //         validAfter: uint48(block.timestamp),
    //         policyHash: keccak256(abi.encode(t, Target.mint.selector)),
    //         signature: ""
    //     });

    //     bytes32 userOpHash = keccak256("dummy2");
    //     bytes32 m = pm.getHash(userOpHash, p);
    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(policySK, ECDSA.toEthSignedMessageHash(m));
    //     bytes memory policySig = abi.encodePacked(r, s, v);
    //     bytes memory pmd = abi.encode(p.validUntil, p.validAfter, p.policyHash, policySig);

    //     uop.paymasterAndData =
    //         abi.encodePacked(address(pm), bytes16(uint128(pmValGas)), bytes16(uint128(postOpGas)), pmd);

    //     vm.prank(entryPoint);
    //     vm.expectRevert(VerifyingPaymaster.TargetSelectorMismatch.selector);
    //     pm.validatePaymasterUserOp(uop, userOpHash, 0);
    // }

    // ---- helpers ----

    function _packAccountGas(uint256 verificationGasLimit, uint256 callGasLimit) internal pure returns (bytes32) {
        // v0.8 accountGasLimits는 16바이트+16바이트 packed
        return bytes32(abi.encodePacked(bytes16(uint128(verificationGasLimit)), bytes16(uint128(callGasLimit))));
    }

    function _packGasFees(uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(bytes16(uint128(maxPriorityFeePerGas)), bytes16(uint128(maxFeePerGas))));
    }
}
