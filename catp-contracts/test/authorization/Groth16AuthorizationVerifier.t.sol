// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/authorization/ActionData.sol";
import "../../src/authorization/AgentAuthorizer.sol";
import "../../src/authorization/Groth16AuthorizationVerifier.sol";
import "../../src/authorization/Groth16Verifier.sol";
import "./Groth16SmokeFixture.sol";

contract Groth16AuthorizationVerifierTest is Test {
    AgentAuthorizer public authorizer;
    Groth16AuthorizationVerifier public verifier;

    address public delegator = address(0xA);
    address public agent = address(0xB);

    bytes32 public policyCommitment;
    bytes public actionData;
    uint256 public proofTimestamp;
    bytes public proof;

    function setUp() public {
        Groth16Verifier generated = new Groth16Verifier();
        verifier = new Groth16AuthorizationVerifier(address(generated));
        authorizer = new AgentAuthorizer(address(verifier));

        policyCommitment = Groth16SmokeFixture.POLICY_COMMITMENT;
        actionData = Groth16SmokeFixture.ACTION_DATA;
        proofTimestamp = Groth16SmokeFixture.PROOF_TIMESTAMP;
        proof = Groth16SmokeFixture.PROOF;
    }

    function _registerAndWarp() internal {
        vm.warp(proofTimestamp);
        vm.prank(delegator);
        authorizer.registerPolicy(policyCommitment);
    }

    function _publicInputs(uint256 currentSpend) internal view returns (bytes32[] memory pub) {
        (
            ActionData.ActionType actionType,
            bytes32 protocol,
            bytes32 token,
            uint256 value
        ) = abi.decode(actionData, (ActionData.ActionType, bytes32, bytes32, uint256));

        pub = new bytes32[](13);
        pub[0] = policyCommitment;
        pub[1] = bytes32(uint256(uint8(actionType)));
        for (uint256 i = 0; i < 4; i++) {
            pub[2 + i] = _leU64(protocol, i);
            pub[6 + i] = _leU64(token, i);
        }
        pub[10] = bytes32(value);
        pub[11] = bytes32(proofTimestamp);
        pub[12] = bytes32(currentSpend);
    }

    function _leU64(bytes32 word, uint256 limbIndex) internal pure returns (bytes32) {
        uint256 value;
        uint256 offset = limbIndex * 8;
        for (uint256 i = 0; i < 8; i++) {
            value |= uint256(uint8(word[offset + i])) << (8 * i);
        }
        return bytes32(value);
    }

    function _truncateProof() internal view returns (bytes memory shortProof) {
        shortProof = new bytes(proof.length - 1);
        for (uint256 i = 0; i < shortProof.length; i++) {
            shortProof[i] = proof[i];
        }
    }

    function test_constructor_rejectsZeroVerifier() public {
        vm.expectRevert("Groth16AuthorizationVerifier: zero address");
        new Groth16AuthorizationVerifier(address(0));
    }

    function test_constructor_rejectsNonContractVerifier() public {
        vm.expectRevert("Groth16AuthorizationVerifier: verifier not contract");
        new Groth16AuthorizationVerifier(address(0xBEEF));
    }

    function test_verify_rejectsWrongPublicInputCount() public {
        bytes32[] memory pub = new bytes32[](12);

        vm.expectRevert("Groth16AuthorizationVerifier: expected 13 public inputs");
        verifier.verify(pub, proof);
    }

    function test_verify_rejectsWrongProofLength() public {
        vm.expectRevert("Groth16AuthorizationVerifier: expected 256-byte proof");
        verifier.verify(_publicInputs(0), _truncateProof());
    }

    function test_executeAuthorized_acceptsRealGroth16Proof() public {
        _registerAndWarp();

        vm.prank(agent);
        authorizer.executeAuthorized(policyCommitment, actionData, proofTimestamp, proof);

        assertEq(authorizer.getCumulativeSpend(policyCommitment), 500);
    }

    function test_executeAuthorized_rejectsTamperedGroth16Proof() public {
        _registerAndWarp();
        bytes memory tamperedProof = proof;
        tamperedProof[0] = bytes1(uint8(tamperedProof[0]) ^ 1);

        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: invalid proof");
        authorizer.executeAuthorized(policyCommitment, actionData, proofTimestamp, tamperedProof);
    }

    function test_executeAuthorized_rejectsTamperedActionData() public {
        _registerAndWarp();
        bytes memory tamperedAction = actionData;
        tamperedAction[127] = 0xf5; // change value from 500 to 501

        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: invalid proof");
        authorizer.executeAuthorized(policyCommitment, tamperedAction, proofTimestamp, proof);
    }

    function test_executeAuthorized_rejectsInvalidActionEnum() public {
        _registerAndWarp();
        bytes memory invalidAction = actionData;
        invalidAction[31] = 0x04;

        vm.prank(agent);
        vm.expectRevert();
        authorizer.executeAuthorized(policyCommitment, invalidAction, proofTimestamp, proof);
    }

    function test_executeAuthorized_rejectsReplayAfterSpendChanges() public {
        _registerAndWarp();

        vm.prank(agent);
        authorizer.executeAuthorized(policyCommitment, actionData, proofTimestamp, proof);

        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: invalid proof");
        authorizer.executeAuthorized(policyCommitment, actionData, proofTimestamp, proof);
    }
}
