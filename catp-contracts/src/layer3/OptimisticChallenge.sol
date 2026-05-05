// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./MPAVerifier.sol";

/// @title OptimisticChallenge
/// @notice CATP Layer 3: challenge window, re-execution submission, and slash distribution.
contract OptimisticChallenge {
    MPAVerifier public immutable mpaVerifier;
    address public owner;

    uint256 public constant CHALLENGE_WINDOW = 1 hours;
    uint256 public constant CHALLENGER_REWARD = 30; // 30% of slashed stake

    struct Challenge {
        address challenger;
        bytes32 claimedCommitment;
        uint256 deadline;
        bool resolved;
        bool upheld;
    }

    mapping(bytes32 => Challenge) private _challenges;
    mapping(address => bool) private _resolvers;

    event ChallengeOpened(bytes32 indexed roundId, address indexed challenger, uint256 deadline);
    event ChallengeResolved(bytes32 indexed roundId, bool upheld, address indexed challenger);
    event ResolverSet(address indexed resolver, bool allowed);

    modifier onlyOwner() {
        require(msg.sender == owner, "OptimisticChallenge: not owner");
        _;
    }

    modifier onlyResolver() {
        require(msg.sender == owner || _resolvers[msg.sender], "OptimisticChallenge: not resolver");
        _;
    }

    constructor(address mpaVerifier_) {
        require(mpaVerifier_ != address(0), "OptimisticChallenge: zero address");
        mpaVerifier = MPAVerifier(mpaVerifier_);
        owner = msg.sender;
    }

    function setResolver(address resolver, bool allowed) external onlyOwner {
        require(resolver != address(0), "OptimisticChallenge: zero address");
        _resolvers[resolver] = allowed;
        emit ResolverSet(resolver, allowed);
    }

    function openChallenge(bytes32 roundId, bytes32 claimedCommitment) external {
        require(claimedCommitment != bytes32(0), "OptimisticChallenge: zero commitment");
        Challenge storage existing = _challenges[roundId];
        require(
            existing.deadline == 0 || existing.resolved || block.timestamp > existing.deadline,
            "OptimisticChallenge: challenge exists"
        );

        (bytes32 consensus, bool finalized) = mpaVerifier.getConsensus(roundId);
        require(finalized, "OptimisticChallenge: round not finalized");
        require(claimedCommitment != consensus, "OptimisticChallenge: claim equals consensus");

        uint256 deadline = block.timestamp + CHALLENGE_WINDOW;
        _challenges[roundId] = Challenge({
            challenger:        msg.sender,
            claimedCommitment: claimedCommitment,
            deadline:          deadline,
            resolved:          false,
            upheld:            false
        });

        emit ChallengeOpened(roundId, msg.sender, deadline);
    }

    function resolveChallenge(bytes32 roundId, bytes32 reExecutionCommitment) external onlyResolver {
        Challenge storage ch = _challenges[roundId];
        require(ch.deadline != 0, "OptimisticChallenge: no challenge");
        require(!ch.resolved, "OptimisticChallenge: already resolved");
        require(block.timestamp <= ch.deadline, "OptimisticChallenge: window expired");

        (bytes32 consensus,) = mpaVerifier.getConsensus(roundId);

        // Upheld when re-execution matches challenger's claim and differs from MPA consensus.
        bool upheld = (reExecutionCommitment == ch.claimedCommitment) && (reExecutionCommitment != consensus);

        ch.resolved = true;
        ch.upheld   = upheld;

        emit ChallengeResolved(roundId, upheld, ch.challenger);

        if (upheld) {
            mpaVerifier.slashCommitment(roundId, consensus, ch.challenger, CHALLENGER_REWARD);
        }
    }

    function getChallenge(bytes32 roundId) external view returns (
        address challenger,
        bytes32 claimedCommitment,
        uint256 deadline,
        bool resolved,
        bool upheld
    ) {
        Challenge storage ch = _challenges[roundId];
        return (ch.challenger, ch.claimedCommitment, ch.deadline, ch.resolved, ch.upheld);
    }

    receive() external payable {}
}
