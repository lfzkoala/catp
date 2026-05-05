// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/layer3/MPAVerifier.sol";
import "../../src/layer3/OptimisticChallenge.sol";

contract OptimisticChallengeTest is Test {
    MPAVerifier         mpa;
    OptimisticChallenge oc;

    address attestor1;
    address attestor2;
    address attestor3;
    address challenger;
    address resolver;

    bytes32 constant ROUND    = keccak256("round1");
    bytes32 constant COMMIT_A = keccak256("output-a");
    bytes32 constant COMMIT_B = keccak256("output-b");

    function setUp() public {
        attestor1  = makeAddr("attestor1");
        attestor2  = makeAddr("attestor2");
        attestor3  = makeAddr("attestor3");
        challenger = makeAddr("challenger");
        resolver   = makeAddr("resolver");
        mpa = new MPAVerifier();
        oc  = new OptimisticChallenge(address(mpa));
        mpa.setChallengeContract(address(oc));
    }

    function _addAndStake(address a) internal {
        mpa.addAttestor(a);
        vm.deal(a, 1 ether);
        uint256 amount = mpa.STAKE_AMOUNT();
        vm.prank(a);
        mpa.stake{value: amount}();
    }

    function _reachConsensus(bytes32 commitment) internal {
        _addAndStake(attestor1);
        _addAndStake(attestor2);
        _addAndStake(attestor3);
        vm.prank(attestor1); mpa.submitOutput(ROUND, commitment);
        vm.prank(attestor2); mpa.submitOutput(ROUND, commitment);
    }

    function test_openChallenge_success() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        (address ch,, uint256 deadline, bool resolved,) = oc.getChallenge(ROUND);
        assertEq(ch, challenger);
        assertGt(deadline, block.timestamp);
        assertFalse(resolved);
    }

    function test_openChallenge_rejectsUnfinalized() public {
        vm.prank(challenger);
        vm.expectRevert("OptimisticChallenge: round not finalized");
        oc.openChallenge(ROUND, COMMIT_B);
    }

    function test_openChallenge_rejectsDuplicate() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        vm.prank(challenger);
        vm.expectRevert("OptimisticChallenge: challenge exists");
        oc.openChallenge(ROUND, COMMIT_B);
    }

    function test_openChallenge_rejectsConsensusClaim() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        vm.expectRevert("OptimisticChallenge: claim equals consensus");
        oc.openChallenge(ROUND, COMMIT_A);
    }

    function test_openChallenge_allowsNewChallengeAfterRejectedResolution() public {
        bytes32 commitC = keccak256("output-c");
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        oc.setResolver(resolver, true);
        vm.prank(resolver);
        oc.resolveChallenge(ROUND, COMMIT_A);

        vm.prank(challenger);
        oc.openChallenge(ROUND, commitC);
        (address ch, bytes32 claimed,, bool resolved,) = oc.getChallenge(ROUND);
        assertEq(ch, challenger);
        assertEq(claimed, commitC);
        assertFalse(resolved);
    }

    function test_openChallenge_allowsNewChallengeAfterExpiredChallenge() public {
        bytes32 commitC = keccak256("output-c");
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        vm.warp(block.timestamp + oc.CHALLENGE_WINDOW() + 1);

        vm.prank(challenger);
        oc.openChallenge(ROUND, commitC);
        (, bytes32 claimed, uint256 deadline, bool resolved,) = oc.getChallenge(ROUND);
        assertEq(claimed, commitC);
        assertGt(deadline, block.timestamp);
        assertFalse(resolved);
    }

    function test_resolveChallenge_upheld() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        uint256 balanceBefore = challenger.balance;
        oc.setResolver(resolver, true);
        vm.prank(resolver);
        oc.resolveChallenge(ROUND, COMMIT_B);
        (,,, bool resolved, bool upheld) = oc.getChallenge(ROUND);
        assertTrue(resolved);
        assertTrue(upheld);
        assertGt(challenger.balance, balanceBefore);
    }

    function test_resolveChallenge_rejectsRepeatedSlashForSameConsensus() public {
        bytes32 commitC = keccak256("output-c");
        _reachConsensus(COMMIT_A);
        oc.setResolver(resolver, true);

        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        vm.prank(resolver);
        oc.resolveChallenge(ROUND, COMMIT_B);

        vm.prank(challenger);
        oc.openChallenge(ROUND, commitC);
        vm.prank(resolver);
        vm.expectRevert("MPAVerifier: commitment already slashed");
        oc.resolveChallenge(ROUND, commitC);
    }

    function test_resolveChallenge_rejected() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        oc.setResolver(resolver, true);
        vm.prank(resolver);
        oc.resolveChallenge(ROUND, COMMIT_A);
        (,,, bool resolved, bool upheld) = oc.getChallenge(ROUND);
        assertTrue(resolved);
        assertFalse(upheld);
    }

    function test_resolveChallenge_rejectsExpired() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        vm.warp(block.timestamp + oc.CHALLENGE_WINDOW() + 1);
        oc.setResolver(resolver, true);
        vm.prank(resolver);
        vm.expectRevert("OptimisticChallenge: window expired");
        oc.resolveChallenge(ROUND, COMMIT_B);
    }

    function test_resolveChallenge_rejectsNoChallenge() public {
        vm.expectRevert("OptimisticChallenge: no challenge");
        oc.resolveChallenge(ROUND, COMMIT_B);
    }

    function test_resolveChallenge_rejectsDuplicate() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        oc.setResolver(resolver, true);
        vm.prank(resolver);
        oc.resolveChallenge(ROUND, COMMIT_B);
        vm.prank(resolver);
        vm.expectRevert("OptimisticChallenge: already resolved");
        oc.resolveChallenge(ROUND, COMMIT_B);
    }

    function test_resolveChallenge_rejectsUnauthorizedResolver() public {
        _reachConsensus(COMMIT_A);
        vm.prank(challenger);
        oc.openChallenge(ROUND, COMMIT_B);
        vm.prank(challenger);
        vm.expectRevert("OptimisticChallenge: not resolver");
        oc.resolveChallenge(ROUND, COMMIT_B);
    }
}
