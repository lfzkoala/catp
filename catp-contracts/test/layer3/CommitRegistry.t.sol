// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/layer3/CommitRegistry.sol";

contract CommitRegistryTest is Test {
    CommitRegistry cr;
    bytes32 constant AGENT = keccak256("agent1");
    bytes32 constant PRE   = keccak256("pre-commit");
    bytes32 constant POST  = keccak256("post-commit");

    function setUp() public {
        cr = new CommitRegistry();
    }

    function test_preCommit_success() public {
        cr.submitPreCommit(AGENT, PRE);
        (bytes32 c, uint256 ts) = cr.getPreCommit(AGENT);
        assertEq(c, PRE);
        assertGt(ts, 0);
    }

    function test_preCommit_rejectsZero() public {
        vm.expectRevert("CommitRegistry: zero commitment");
        cr.submitPreCommit(AGENT, bytes32(0));
    }

    function test_preCommit_rejectsDuplicate() public {
        cr.submitPreCommit(AGENT, PRE);
        vm.expectRevert("CommitRegistry: pre-commit already exists");
        cr.submitPreCommit(AGENT, PRE);
    }

    function test_postCommit_success() public {
        cr.submitPreCommit(AGENT, PRE);
        vm.warp(block.timestamp + cr.MIN_COMMIT_DELAY());
        cr.submitPostCommit(AGENT, POST);
        (bytes32 pre, bytes32 post,) = cr.getPostCommit(AGENT);
        assertEq(pre, PRE);
        assertEq(post, POST);
    }

    function test_postCommit_rejectsWithoutPre() public {
        vm.expectRevert("CommitRegistry: no pre-commit found");
        cr.submitPostCommit(AGENT, POST);
    }

    function test_postCommit_rejectsZero() public {
        cr.submitPreCommit(AGENT, PRE);
        vm.warp(block.timestamp + cr.MIN_COMMIT_DELAY());
        vm.expectRevert("CommitRegistry: zero post-commitment");
        cr.submitPostCommit(AGENT, bytes32(0));
    }

    function test_postCommit_rejectsBeforeDelay() public {
        cr.submitPreCommit(AGENT, PRE);
        vm.expectRevert("CommitRegistry: delay not elapsed");
        cr.submitPostCommit(AGENT, POST);
    }

    function test_postCommit_clearsPreCommit() public {
        cr.submitPreCommit(AGENT, PRE);
        vm.warp(block.timestamp + cr.MIN_COMMIT_DELAY());
        cr.submitPostCommit(AGENT, POST);
        vm.expectRevert("CommitRegistry: no pre-commit found");
        cr.getPreCommit(AGENT);
    }

    function test_postCommit_rejectsDuplicate() public {
        cr.submitPreCommit(AGENT, PRE);
        vm.warp(block.timestamp + cr.MIN_COMMIT_DELAY());
        cr.submitPostCommit(AGENT, POST);
        vm.expectRevert("CommitRegistry: no pre-commit found");
        cr.submitPostCommit(AGENT, POST);
    }
}
