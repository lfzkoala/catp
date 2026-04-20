// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title CommitRegistry
/// @notice CATP Layer 3: pre/post inference commitment registry.
/// @dev Enforces that post-commit follows a pre-commit and minimum delay has elapsed.
contract CommitRegistry {
    uint256 public constant MIN_COMMIT_DELAY = 1; // seconds; increase for production

    struct PreCommit {
        bytes32 commitment;
        uint256 timestamp;
        bool exists;
    }

    struct PostCommit {
        bytes32 preCommitment;
        bytes32 postCommitment;
        uint256 timestamp;
    }

    mapping(bytes32 => PreCommit)  private _preCommits;
    mapping(bytes32 => PostCommit) private _postCommits;

    event PreCommitSubmitted(bytes32 indexed agentId, bytes32 indexed commitment, uint256 timestamp);
    event PostCommitSubmitted(bytes32 indexed agentId, bytes32 indexed preCommitment, bytes32 indexed postCommitment, uint256 timestamp);

    function submitPreCommit(bytes32 agentId, bytes32 commitment) external {
        require(commitment != bytes32(0), "CommitRegistry: zero commitment");
        require(!_preCommits[agentId].exists, "CommitRegistry: pre-commit already exists");
        _preCommits[agentId] = PreCommit({ commitment: commitment, timestamp: block.timestamp, exists: true });
        emit PreCommitSubmitted(agentId, commitment, block.timestamp);
    }

    function submitPostCommit(bytes32 agentId, bytes32 postCommitment) external {
        PreCommit storage pre = _preCommits[agentId];
        require(pre.exists, "CommitRegistry: no pre-commit found");
        require(postCommitment != bytes32(0), "CommitRegistry: zero post-commitment");
        require(!_hasPostCommit(agentId), "CommitRegistry: post-commit already exists");
        require(block.timestamp >= pre.timestamp + MIN_COMMIT_DELAY, "CommitRegistry: delay not elapsed");
        _postCommits[agentId] = PostCommit({
            preCommitment:  pre.commitment,
            postCommitment: postCommitment,
            timestamp:      block.timestamp
        });
        delete _preCommits[agentId];
        emit PostCommitSubmitted(agentId, pre.commitment, postCommitment, block.timestamp);
    }

    function getPreCommit(bytes32 agentId) external view returns (bytes32 commitment, uint256 timestamp) {
        PreCommit storage pre = _preCommits[agentId];
        require(pre.exists, "CommitRegistry: no pre-commit found");
        return (pre.commitment, pre.timestamp);
    }

    function getPostCommit(bytes32 agentId) external view returns (bytes32 preCommitment, bytes32 postCommitment, uint256 timestamp) {
        PostCommit storage post = _postCommits[agentId];
        require(post.postCommitment != bytes32(0), "CommitRegistry: no post-commit found");
        return (post.preCommitment, post.postCommitment, post.timestamp);
    }

    function _hasPostCommit(bytes32 agentId) internal view returns (bool) {
        return _postCommits[agentId].postCommitment != bytes32(0);
    }
}
