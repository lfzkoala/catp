// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IAgentAuthorizer.sol";
import "./IVerifier.sol";
import "./ActionData.sol";

/// @title AgentAuthorizer
/// @notice CATP Layer 2: policy registry and ZK proof verifier.
/// @dev Accepts an IVerifier at construction time. Phase 1 uses a stub verifier;
///      Phase 2 injects the auto-generated Halo2 Solidity verifier.
///      Swapping the verifier requires no changes to authorization logic.
contract AgentAuthorizer is IAgentAuthorizer {
    IVerifier public immutable verifier;

    mapping(bytes32 => address) private _policyDelegators;
    mapping(bytes32 => bool)    private _activePolicies;
    mapping(bytes32 => uint256) private _cumulativeSpend;
    mapping(bytes32 => uint256) private _policyNonces;

    constructor(address verifier_) {
        require(verifier_ != address(0), "AgentAuthorizer: zero verifier");
        verifier = IVerifier(verifier_);
    }

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
        (
            ActionData.ActionType actionType,
            bytes32 protocol,
            bytes32 token,
            uint256 value
        ) = _decodeAction(actionData);

        require(value <= type(uint64).max, "AgentAuthorizer: value too large");
        require(currentSpend <= type(uint64).max, "AgentAuthorizer: spend too large");

        bytes32[] memory pub = new bytes32[](13);
        pub[0] = policyCommitment;
        pub[1] = bytes32(uint256(uint8(actionType)));
        for (uint256 i = 0; i < 4; i++) {
            pub[2 + i] = _leU64(protocol, i);
            pub[6 + i] = _leU64(token, i);
        }
        pub[10] = bytes32(uint256(value));
        pub[11] = bytes32(uint256(block.timestamp));
        pub[12] = bytes32(uint256(currentSpend));
        require(verifier.verify(pub, proof), "AgentAuthorizer: invalid proof");
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

    /// @dev Decode action from ABI-encoded ActionData using full abi.decode (type-safe).
    function _decodeAction(
        bytes calldata actionData
    ) internal pure returns (ActionData.ActionType actionType, bytes32 protocol, bytes32 token, uint256 value) {
        require(actionData.length == 128, "AgentAuthorizer: invalid action data");
        return abi.decode(actionData, (ActionData.ActionType, bytes32, bytes32, uint256));
    }

    function _leU64(bytes32 word, uint256 limbIndex) internal pure returns (bytes32) {
        uint256 value;
        uint256 offset = limbIndex * 8;
        for (uint256 i = 0; i < 8; i++) {
            value |= uint256(uint8(word[offset + i])) << (8 * i);
        }
        return bytes32(value);
    }
}
