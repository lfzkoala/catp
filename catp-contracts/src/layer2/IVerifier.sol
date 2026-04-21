// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IVerifier
/// @notice Universal proof verifier interface for CATP.
/// @dev Implementations: stub (Phase 1), Halo2 Solidity verifier (Phase 2),
///      or any future proof system. Injected into AgentAuthorizer at deploy time.
interface IVerifier {
    function verify(
        bytes32[] calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}
