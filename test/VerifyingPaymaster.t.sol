// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console2} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";
import {ConfigHelper} from "script/ConfigHelper.s.sol";
import {SentinelAccount} from "src/accounts/SentinelAccount.sol";
import {VerifyingPaymaster} from "src/paymasters/VerifyingPaymaster.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VerifyingPaymasterTest is Test {
    ConfigHelper.NetworkConfig networkConfig;
    SentinelAccount sentinelAccount;
    VerifyingPaymaster paymaster;
    IEntryPoint entryPoint;

    ERC20Mock token;
    address mockSigner;
    uint256 mockSignerPk;

    address depositor = makeAddr("depositor");

    function setUp() public {
        Deploy deploy = new Deploy();
        (networkConfig, sentinelAccount, paymaster) = deploy.deploySentinelAccountAndPaymaster();
        entryPoint = IEntryPoint(networkConfig.entryPoint);

        token = new ERC20Mock();
        (mockSigner, mockSignerPk) = makeAddrAndKey("mockSigner");

        vm.deal(depositor, 100 ether);
    }

    function test_parseAndRecover() public view {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 validAfter = uint48(block.timestamp);
        bytes32 policyHash = keccak256("POLICY_V1");

        // sign the message the same way VerifyingPaymaster.getHash computes it
        bytes32 m = paymaster.getHash(
            bytes32(uint256(1234)),
            VerifyingPaymaster.PaymasterData({
                validUntil: validUntil,
                validAfter: validAfter,
                policyHash: policyHash,
                signature: ""
            })
        );
        // test with OZ library
        bytes32 ethMsg = MessageHashUtils.toEthSignedMessageHash(m);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mockSignerPk, ethMsg);
        bytes memory sig = abi.encodePacked(r, s, v);

        // build paymasterAndData payload that parsePaymasterData expects (starting at PAYMASTER_DATA_OFFSET in real userOp)
        bytes memory encoded = _encodePaymasterData(validUntil, validAfter, policyHash, sig);
        (VerifyingPaymaster.PaymasterData memory pmd, bytes memory parsedSig) = paymaster.parsePaymasterData(encoded);

        assertEq(pmd.validUntil, validUntil, "validUntil");
        assertEq(pmd.validAfter, validAfter, "validAfter");
        assertEq(pmd.policyHash, policyHash, "policyHash");
        assertEq(parsedSig.length, 65, "sig length");

        // recover using the same path as in contract
        address recovered = ECDSA.recover(ethMsg, parsedSig);
        assertEq(recovered, mockSigner, "recovered signer mismatch");
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
}
