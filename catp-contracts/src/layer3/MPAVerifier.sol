// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MPAVerifier
/// @notice CATP Layer 3: multi-party attestor output verification with ≥2/3 consensus.
contract MPAVerifier {
    address public owner;
    uint256 public constant STAKE_AMOUNT = 0.1 ether;

    mapping(address => bool)    private _attestors;
    mapping(address => uint256) private _stakes;
    uint256 private _attestorCount;

    struct OutputRound {
        mapping(address => bytes32) submissions;
        mapping(bytes32 => uint256) tally;
        bytes32 consensusCommitment;
        uint256 submissionCount;
        bool finalized;
    }

    mapping(bytes32 => OutputRound) private _rounds;

    event AttestorAdded(address indexed attestor);
    event AttestorRemoved(address indexed attestor);
    event OutputSubmitted(bytes32 indexed roundId, address indexed attestor, bytes32 commitment);
    event ConsensusReached(bytes32 indexed roundId, bytes32 commitment);

    modifier onlyOwner() {
        require(msg.sender == owner, "MPAVerifier: not owner");
        _;
    }

    modifier onlyAttestor() {
        require(_attestors[msg.sender], "MPAVerifier: not attestor");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addAttestor(address attestor) external onlyOwner {
        require(attestor != address(0), "MPAVerifier: zero address");
        require(!_attestors[attestor], "MPAVerifier: already attestor");
        _attestors[attestor] = true;
        _attestorCount++;
        emit AttestorAdded(attestor);
    }

    function removeAttestor(address attestor) external onlyOwner {
        require(_attestors[attestor], "MPAVerifier: not attestor");
        _attestors[attestor] = false;
        _attestorCount--;
        emit AttestorRemoved(attestor);
    }

    function stake() external payable onlyAttestor {
        require(msg.value == STAKE_AMOUNT, "MPAVerifier: wrong stake amount");
        _stakes[msg.sender] += msg.value;
    }

    function submitOutput(bytes32 roundId, bytes32 commitment) external onlyAttestor {
        require(commitment != bytes32(0), "MPAVerifier: zero commitment");
        OutputRound storage round = _rounds[roundId];
        require(round.submissions[msg.sender] == bytes32(0), "MPAVerifier: already submitted");
        require(!round.finalized, "MPAVerifier: round finalized");

        round.submissions[msg.sender] = commitment;
        round.tally[commitment]++;
        round.submissionCount++;

        emit OutputSubmitted(roundId, msg.sender, commitment);

        _tryFinalize(roundId);
    }

    function getConsensus(bytes32 roundId) external view returns (bytes32 commitment, bool finalized) {
        OutputRound storage round = _rounds[roundId];
        return (round.consensusCommitment, round.finalized);
    }

    function isAttestor(address addr) external view returns (bool) {
        return _attestors[addr];
    }

    function attestorCount() external view returns (uint256) {
        return _attestorCount;
    }

    function _tryFinalize(bytes32 roundId) internal {
        OutputRound storage round = _rounds[roundId];
        if (_attestorCount == 0) return;
        uint256 threshold = (_attestorCount * 2 + 2) / 3; // ceil(2/3 * n)
        bytes32 candidate = round.submissions[msg.sender];
        if (round.tally[candidate] >= threshold) {
            round.consensusCommitment = candidate;
            round.finalized = true;
            emit ConsensusReached(roundId, candidate);
        }
    }
}
