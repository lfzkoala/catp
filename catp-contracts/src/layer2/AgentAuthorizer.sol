// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IAgentAuthorizer.sol";
import "./ActionData.sol";

/// @title AgentAuthorizer
/// @notice CATP Layer 2: policy registry and ZK proof verifier.
/// @dev _verifyProof is a stub in Phase 1. Replace with the Halo2 Solidity verifier in Phase 2.
contract AgentAuthorizer is IAgentAuthorizer {
    mapping(bytes32 => address) private _policyDelegators;
    mapping(bytes32 => bool)    private _activePolicies;
    mapping(bytes32 => uint256) private _cumulativeSpend;
    mapping(bytes32 => uint256) private _policyNonces;

    function registerPolicy(bytes32 policyCommitment) external override {
        require(msg.sender != address(0), "AgentAuthorizer: invalid delegator");
        require(policyCommitment != bytes32(0), "AgentAuthorizer: zero commitment");
        require(!_activePolicies[policyCommitment], "AgentAuthorizer: policy already active");
        _policyDelegators[policyCommitment] = msg.sender;
        _activePolicies[policyCommitment] = true;
        emit PolicyRegistered(policyCommitment, msg.sender);
    }

    function revokePolicy(bytes32 policyCommitment) external override {
        require(_activePolicies[policyCommitment], "AgentAuthorizer: policy not active");
        require(_policyDelegators[policyCommitment] == msg.sender, "AgentAuthorizer: not delegator");
        _activePolicies[policyCommitment] = false;
        emit PolicyRevoked(policyCommitment, msg.sender);
    }

    function executeAuthorized(
        bytes32 policyCommitment,
        bytes calldata actionData,
        bytes calldata proof
    ) external override {
        require(_activePolicies[policyCommitment], "AgentAuthorizer: policy not active");
        bytes32 actionHash = keccak256(actionData);
        uint256 currentSpend = _cumulativeSpend[policyCommitment];
        uint256 currentNonce = _policyNonces[policyCommitment];
        require(
            _verifyProof(policyCommitment, actionHash, block.timestamp, currentSpend, currentNonce, proof),
            "AgentAuthorizer: invalid proof"
        );
        uint256 value = _extractValue(actionData);
        _cumulativeSpend[policyCommitment] += value;
        _policyNonces[policyCommitment]++;
        emit AuthorizedExecution(policyCommitment, actionHash, value);
    }

    function isPolicyActive(bytes32 policyCommitment) external view override returns (bool) {
        return _activePolicies[policyCommitment];
    }

    function getCumulativeSpend(bytes32 policyCommitment) external view override returns (uint256) {
        return _cumulativeSpend[policyCommitment];
    }

    /// @dev STUB: accepts any non-empty proof. Replace with Halo2 verifier in Phase 2.
    ///      The real verifier must bind all public inputs including nonce to prevent replay.
    function _verifyProof(
        bytes32, bytes32, uint256, uint256, uint256,
        bytes calldata proof
    ) internal pure virtual returns (bool) {
        return proof.length > 0;
    }

    /// @dev Decode value from ABI-encoded ActionData using full abi.decode (type-safe).
    function _extractValue(bytes calldata actionData) internal pure returns (uint256) {
        if (actionData.length < 128) return 0;
        (, , , uint256 value) = abi.decode(actionData, (ActionData.ActionType, bytes32, bytes32, uint256));
        return value;
    }
}
