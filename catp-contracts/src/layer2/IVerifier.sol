// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IVerifier
/// @notice Universal proof verifier interface for CATP.
/// @dev Implementations include StubVerifier for tests, Halo2AuthorizationVerifier
///      for EVM deployments, or any future proof system.
interface IVerifier {
    function verify(
        bytes32[] calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}
