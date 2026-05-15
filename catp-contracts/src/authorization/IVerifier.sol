// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IVerifier
/// @notice Universal proof verifier interface for CATP.
/// @dev Production implementations are versioned proof adapters for the target
///      environment. Current EVM authorization deployments use
///      Groth16AuthorizationVerifier.
interface IVerifier {
    function verify(
        bytes32[] calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}
