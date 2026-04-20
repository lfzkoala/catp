// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/layer3/MPAVerifier.sol";

contract MPAVerifierTest is Test {
    MPAVerifier mpa;
    address attestor1;
    address attestor2;
    address attestor3;
    bytes32 constant ROUND    = keccak256("round1");
    bytes32 constant COMMIT_A = keccak256("output-a");
    bytes32 constant COMMIT_B = keccak256("output-b");

    function setUp() public {
        attestor1 = makeAddr("attestor1");
        attestor2 = makeAddr("attestor2");
        attestor3 = makeAddr("attestor3");
        mpa = new MPAVerifier();
    }

    function _addAndStake(address a) internal {
        mpa.addAttestor(a);
        vm.deal(a, 1 ether);
        uint256 amount = mpa.STAKE_AMOUNT();
        vm.prank(a);
        mpa.stake{value: amount}();
    }

    function test_addAttestor_success() public {
        mpa.addAttestor(attestor1);
        assertTrue(mpa.isAttestor(attestor1));
        assertEq(mpa.attestorCount(), 1);
    }

    function test_addAttestor_rejectsZero() public {
        vm.expectRevert("MPAVerifier: zero address");
        mpa.addAttestor(address(0));
    }

    function test_addAttestor_rejectsDuplicate() public {
        mpa.addAttestor(attestor1);
        vm.expectRevert("MPAVerifier: already attestor");
        mpa.addAttestor(attestor1);
    }

    function test_removeAttestor_success() public {
        mpa.addAttestor(attestor1);
        mpa.removeAttestor(attestor1);
        assertFalse(mpa.isAttestor(attestor1));
        assertEq(mpa.attestorCount(), 0);
    }

    function test_submitOutput_rejectsNonAttestor() public {
        vm.prank(attestor1);
        vm.expectRevert("MPAVerifier: not attestor");
        mpa.submitOutput(ROUND, COMMIT_A);
    }

    function test_submitOutput_rejectsZeroCommitment() public {
        mpa.addAttestor(attestor1);
        vm.prank(attestor1);
        vm.expectRevert("MPAVerifier: zero commitment");
        mpa.submitOutput(ROUND, bytes32(0));
    }

    function test_submitOutput_rejectsDuplicate() public {
        mpa.addAttestor(attestor1);
        vm.prank(attestor1);
        mpa.submitOutput(ROUND, COMMIT_A);
        vm.prank(attestor1);
        vm.expectRevert("MPAVerifier: already submitted");
        mpa.submitOutput(ROUND, COMMIT_A);
    }

    function test_consensus_reachedAt2of3() public {
        _addAndStake(attestor1);
        _addAndStake(attestor2);
        _addAndStake(attestor3);

        vm.prank(attestor1);
        mpa.submitOutput(ROUND, COMMIT_A);
        vm.prank(attestor2);
        mpa.submitOutput(ROUND, COMMIT_A);

        (bytes32 consensus, bool finalized) = mpa.getConsensus(ROUND);
        assertTrue(finalized);
        assertEq(consensus, COMMIT_A);
    }

    function test_noConsensus_whenSplit() public {
        _addAndStake(attestor1);
        _addAndStake(attestor2);
        _addAndStake(attestor3);

        vm.prank(attestor1);
        mpa.submitOutput(ROUND, COMMIT_A);
        vm.prank(attestor2);
        mpa.submitOutput(ROUND, COMMIT_B);

        (, bool finalized) = mpa.getConsensus(ROUND);
        assertFalse(finalized);
    }

    function test_submitOutput_rejectsAfterFinalized() public {
        _addAndStake(attestor1);
        _addAndStake(attestor2);
        _addAndStake(attestor3);

        vm.prank(attestor1);
        mpa.submitOutput(ROUND, COMMIT_A);
        vm.prank(attestor2);
        mpa.submitOutput(ROUND, COMMIT_A);

        vm.prank(attestor3);
        vm.expectRevert("MPAVerifier: round finalized");
        mpa.submitOutput(ROUND, COMMIT_B);
    }
}
