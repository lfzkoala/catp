// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IVerifier.sol";

/// @title Halo2AuthorizationVerifier
/// @notice IVerifier wrapper around the auto-generated Halo2Verifier assembly contract.
/// @dev The ProveAuthorization circuit exposes 0 public instance columns; the Halo2Verifier
///      fallback therefore expects raw proof bytes as calldata.
///      If the proof is valid the fallback returns successfully; if invalid it reverts.
///
///      IMPORTANT: Halo2Verifier.sol is generated from a specific SRS. Both the on-chain
///      verifier and the off-chain prover MUST use the same SRS. For production, regenerate
///      Halo2Verifier.sol and the prover SRS from the Ethereum KZG ceremony (EIP-4844).
contract Halo2AuthorizationVerifier is IVerifier {
    address public immutable halo2Verifier;

    constructor(address halo2Verifier_) {
        require(halo2Verifier_ != address(0), "Halo2AuthorizationVerifier: zero address");
        halo2Verifier = halo2Verifier_;
    }

    /// @inheritdoc IVerifier
    /// @dev publicInputs is ignored; all circuit witnesses are private.
    ///      Forwards raw proof bytes to the Halo2Verifier fallback via staticcall.
    function verify(
        bytes32[] calldata,
        bytes calldata proof
    ) external view override returns (bool) {
        (bool ok,) = halo2Verifier.staticcall(proof);
        return ok;
    }
}
