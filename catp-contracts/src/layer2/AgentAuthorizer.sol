// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IAgentAuthorizer.sol";

/// @title AgentAuthorizer
/// @notice CATP Layer 2: policy registry and ZK proof verifier.
/// @dev _verifyProof is a stub in Phase 1. Replace with the Halo2 Solidity verifier in Phase 2.
contract AgentAuthorizer is IAgentAuthorizer {
    mapping(bytes32 => address) private _policyDelegators;
    mapping(bytes32 => bool)    private _activePolicies;
    mapping(bytes32 => uint256) private _cumulativeSpend;
    mapping(bytes32 => uint256) private _policyNonces;

    function registerPolicy(bytes32 policyCommitment) external override {
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
        require(
            _verifyProof(policyCommitment, actionHash, block.timestamp, currentSpend, proof),
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
    function _verifyProof(
        bytes32, bytes32, uint256, uint256,
        bytes calldata proof
    ) internal pure virtual returns (bool) {
        return proof.length > 0;
    }

    /// @dev ActionData ABI encoding: abi.encode(ActionType, bytes32, bytes32, uint256)
    ///      ActionType (enum/uint8) is ABI-padded to 32 bytes, so value starts at offset 96.
    function _extractValue(bytes calldata actionData) internal pure returns (uint256) {
        if (actionData.length < 128) return 0;
        return abi.decode(actionData[96:128], (uint256));
    }
}
