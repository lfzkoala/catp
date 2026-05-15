// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/authorization/AgentAuthorizer.sol";
import "../../src/authorization/ActionData.sol";
import "./StubVerifier.sol";

contract AgentAuthorizerTest is Test {
    AgentAuthorizer public authorizer;
    address public delegator = address(0xA);
    address public agent     = address(0xB);
    address public attacker  = address(0xC);

    bytes32 public constant POLICY      = keccak256("test-policy");
    bytes   public constant VALID_PROOF = hex"deadbeef";
    uint256 public constant PROOF_TS    = 1_000;

    function setUp() public {
        StubVerifier stub = new StubVerifier();
        authorizer = new AgentAuthorizer(address(stub));
    }

    function _ad(uint256 value) internal pure returns (bytes memory) {
        return ActionData.encode(ActionData.Action({
            actionType: ActionData.ActionType.Swap,
            protocol:   bytes32(uint256(1)),
            token:      bytes32(uint256(2)),
            value:      value
        }));
    }

    // ── registerPolicy ───────────────────────────────────────────────────────
    function test_register_success() public {
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        assertTrue(authorizer.isPolicyActive(POLICY));
    }
    function test_register_emitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit IAgentAuthorizer.PolicyRegistered(POLICY, delegator);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
    }
    function test_register_rejectsZero() public {
        vm.prank(delegator);
        vm.expectRevert("AgentAuthorizer: zero commitment");
        authorizer.registerPolicy(bytes32(0));
    }
    function test_register_rejectsDuplicate() public {
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(delegator);
        vm.expectRevert("AgentAuthorizer: policy already active");
        authorizer.registerPolicy(POLICY);
    }

    // ── revokePolicy ─────────────────────────────────────────────────────────
    function test_revoke_success() public {
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(delegator); authorizer.revokePolicy(POLICY);
        assertFalse(authorizer.isPolicyActive(POLICY));
    }
    function test_revoke_emitsEvent() public {
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.expectEmit(true, true, false, false);
        emit IAgentAuthorizer.PolicyRevoked(POLICY, delegator);
        vm.prank(delegator); authorizer.revokePolicy(POLICY);
    }
    function test_revoke_rejectsNonDelegator() public {
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(attacker);
        vm.expectRevert("AgentAuthorizer: not delegator");
        authorizer.revokePolicy(POLICY);
    }
    function test_revoke_rejectsInactive() public {
        vm.prank(delegator);
        vm.expectRevert("AgentAuthorizer: policy not active");
        authorizer.revokePolicy(POLICY);
    }

    // ── executeAuthorized ────────────────────────────────────────────────────
    function test_execute_success() public {
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(agent); authorizer.executeAuthorized(POLICY, _ad(500), PROOF_TS, VALID_PROOF);
        assertEq(authorizer.getCumulativeSpend(POLICY), 500);
    }
    function test_execute_emitsEvent() public {
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        bytes memory ad = _ad(100);
        vm.expectEmit(true, true, false, true);
        emit IAgentAuthorizer.AuthorizedExecution(POLICY, keccak256(ad), 100);
        vm.prank(agent); authorizer.executeAuthorized(POLICY, ad, PROOF_TS, VALID_PROOF);
    }
    function test_execute_rejectsInactive() public {
        vm.warp(PROOF_TS);
        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: policy not active");
        authorizer.executeAuthorized(POLICY, _ad(100), PROOF_TS, VALID_PROOF);
    }
    function test_execute_rejectsEmptyProof() public {
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: invalid proof");
        authorizer.executeAuthorized(POLICY, _ad(100), PROOF_TS, hex"");
    }
    function test_execute_rejectsAfterRevoke() public {
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(delegator); authorizer.revokePolicy(POLICY);
        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: policy not active");
        authorizer.executeAuthorized(POLICY, _ad(100), PROOF_TS, VALID_PROOF);
    }
    function test_execute_accumulatesSpend() public {
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(agent); authorizer.executeAuthorized(POLICY, _ad(300), PROOF_TS, VALID_PROOF);
        vm.prank(agent); authorizer.executeAuthorized(POLICY, _ad(200), PROOF_TS, VALID_PROOF);
        assertEq(authorizer.getCumulativeSpend(POLICY), 500);
    }

    function test_execute_rejectsFutureProof() public {
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: future proof");
        authorizer.executeAuthorized(POLICY, _ad(100), PROOF_TS + 1, VALID_PROOF);
    }

    function test_execute_rejectsStaleProof() public {
        vm.warp(PROOF_TS + authorizer.PROOF_MAX_AGE() + 1);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: stale proof");
        authorizer.executeAuthorized(POLICY, _ad(100), PROOF_TS, VALID_PROOF);
    }

    function test_execute_rejectsZeroValue() public {
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(agent);
        vm.expectRevert("AgentAuthorizer: zero value");
        authorizer.executeAuthorized(POLICY, _ad(0), PROOF_TS, VALID_PROOF);
    }

    // ── Fuzz ─────────────────────────────────────────────────────────────────
    function testFuzz_registerRevoke(bytes32 c) public {
        vm.assume(c != bytes32(0));
        vm.prank(delegator); authorizer.registerPolicy(c);
        assertTrue(authorizer.isPolicyActive(c));
        vm.prank(delegator); authorizer.revokePolicy(c);
        assertFalse(authorizer.isPolicyActive(c));
    }
    function testFuzz_accumulatesSpend(uint64 v1, uint64 v2) public {
        vm.assume(v1 > 0);
        vm.assume(v2 > 0);
        vm.warp(PROOF_TS);
        vm.prank(delegator); authorizer.registerPolicy(POLICY);
        vm.prank(agent); authorizer.executeAuthorized(POLICY, _ad(v1), PROOF_TS, VALID_PROOF);
        vm.prank(agent); authorizer.executeAuthorized(POLICY, _ad(v2), PROOF_TS, VALID_PROOF);
        assertEq(authorizer.getCumulativeSpend(POLICY), uint256(v1) + uint256(v2));
    }
}
