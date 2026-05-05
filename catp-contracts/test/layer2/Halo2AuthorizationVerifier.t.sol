// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/layer2/Halo2AuthorizationVerifier.sol";

/// Succeeds or reverts based on `shouldRevert`; reads state only (staticcall-safe).
contract MockHalo2Verifier {
    bool public shouldRevert;

    function setRevert(bool v) external {
        shouldRevert = v;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        if (shouldRevert) revert("mock: invalid proof");
        return "";
    }
}

contract Halo2AuthorizationVerifierTest is Test {
    MockHalo2Verifier mock;
    Halo2AuthorizationVerifier verifier;

    bytes32[] inputs;
    bytes     proof;

    function setUp() public {
        mock     = new MockHalo2Verifier();
        verifier = new Halo2AuthorizationVerifier(address(mock));

        inputs = new bytes32[](13);
        inputs[0] = bytes32(uint256(0xAAAA)); // policyCommitment
        for (uint256 i = 1; i < 13; i++) {
            inputs[i] = bytes32(uint256(0xAAAA + i));
        }
        proof  = hex"deadbeef01020304";
    }

    function test_verify_returnsTrueOnSuccess() public {
        assertTrue(verifier.verify(inputs, proof));
    }

    function test_verify_forwardsPublicInputsAndProof() public {
        bytes memory expected = abi.encodePacked(
            inputs[0],
            inputs[1],
            inputs[2],
            inputs[3],
            inputs[4],
            inputs[5],
            inputs[6],
            inputs[7],
            inputs[8],
            inputs[9],
            inputs[10],
            inputs[11],
            inputs[12],
            proof
        );
        vm.expectCall(address(mock), expected);
        verifier.verify(inputs, proof);
    }

    function test_verify_returnsFalseWhenVerifierReverts() public {
        mock.setRevert(true);
        assertFalse(verifier.verify(inputs, proof));
    }

    function test_verify_revertsOnWrongInputCount() public {
        bytes32[] memory bad = new bytes32[](2);
        vm.expectRevert("Halo2AuthorizationVerifier: expected 13 public inputs");
        verifier.verify(bad, proof);
    }

    function test_constructor_revertsOnZeroAddress() public {
        vm.expectRevert("Halo2AuthorizationVerifier: zero address");
        new Halo2AuthorizationVerifier(address(0));
    }
}
