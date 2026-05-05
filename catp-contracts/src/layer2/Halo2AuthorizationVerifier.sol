// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IVerifier.sol";

/// @title Halo2AuthorizationVerifier
/// @notice IVerifier wrapper around the auto-generated Halo2Verifier assembly contract.
/// @dev The ProveAuthorization circuit exposes 13 public instance values:
///        [0] policyCommitment, [1] actionType, [2..5] protocol limbs,
///        [6..9] token limbs, [10] actionValue, [11] timestamp, [12] spend.
///      The Halo2Verifier expects calldata: public inputs || proof_bytes
///      where each instance is a 32-byte big-endian Fr field element.
///
///      IMPORTANT: Halo2Verifier.sol is generated from a specific SRS. Both the on-chain
///      verifier and the off-chain prover MUST use the same SRS. For production, regenerate
///      Halo2Verifier.sol and the prover SRS from the Ethereum KZG ceremony (EIP-4844).
contract Halo2AuthorizationVerifier is IVerifier {
    address public immutable halo2Verifier;

    constructor(address halo2Verifier_) {
        require(halo2Verifier_ != address(0), "Halo2AuthorizationVerifier: zero address");
        require(halo2Verifier_.code.length > 0, "Halo2AuthorizationVerifier: verifier not contract");
        halo2Verifier = halo2Verifier_;
    }

    /// @inheritdoc IVerifier
    /// @dev Prepends the 13 public inputs (32 bytes each) to the proof, then forwards
    ///      the concatenated calldata to the Halo2Verifier via staticcall.
    function verify(
        bytes32[] calldata publicInputs,
        bytes calldata proof
    ) external view override returns (bool) {
        require(publicInputs.length == 13, "Halo2AuthorizationVerifier: expected 13 public inputs");
        bytes memory callData = abi.encodePacked(
            publicInputs[0],
            publicInputs[1],
            publicInputs[2],
            publicInputs[3],
            publicInputs[4],
            publicInputs[5],
            publicInputs[6],
            publicInputs[7],
            publicInputs[8],
            publicInputs[9],
            publicInputs[10],
            publicInputs[11],
            publicInputs[12],
            proof
        );
        (bool ok,) = halo2Verifier.staticcall(callData);
        return ok;
    }
}
