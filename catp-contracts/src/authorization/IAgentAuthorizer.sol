// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IAgentAuthorizer {
    event PolicyRegistered(bytes32 indexed policyCommitment, address indexed delegator);
    event PolicyRevoked(bytes32 indexed policyCommitment, address indexed delegator);
    event AuthorizedExecution(bytes32 indexed policyCommitment, bytes32 indexed actionHash, uint256 valueSpent);

    function registerPolicy(bytes32 policyCommitment) external;
    function revokePolicy(bytes32 policyCommitment) external;
    function executeAuthorized(
        bytes32 policyCommitment,
        bytes calldata actionData,
        uint256 currentTimestamp,
        bytes calldata proof
    ) external;
    function isPolicyActive(bytes32 policyCommitment) external view returns (bool);
    function getCumulativeSpend(bytes32 policyCommitment) external view returns (uint256);
}
