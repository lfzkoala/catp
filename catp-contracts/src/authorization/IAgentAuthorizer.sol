// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IAgentAuthorizer {
    event PolicyRegistered(bytes32 indexed policyCommitment, address indexed delegator, address indexed executor);
    event PolicyRevoked(bytes32 indexed policyCommitment, address indexed delegator);
    event AuthorizedExecution(
        bytes32 indexed policyCommitment, bytes32 indexed actionHash, address indexed executor, uint256 valueSpent
    );

    function registerPolicy(bytes32 policyCommitment, address executor) external;
    function revokePolicy(bytes32 policyCommitment) external;
    function executeAuthorized(
        bytes32 policyCommitment,
        bytes calldata actionData,
        uint256 currentTimestamp,
        bytes calldata proof
    ) external;
    function isPolicyActive(bytes32 policyCommitment) external view returns (bool);
    function getPolicyExecutor(bytes32 policyCommitment) external view returns (address);
    function getCumulativeSpend(bytes32 policyCommitment) external view returns (uint256);
}
