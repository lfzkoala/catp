// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IVerifier.sol";

interface IGroth16Verifier {
    function verifyProof(uint256[8] calldata proof, uint256[13] calldata input) external view;
}

/// @title Groth16AuthorizationVerifier
/// @notice IVerifier wrapper for the authorization_groth16_v1 verifier.
/// @dev The generated gnark verifier reverts on invalid proofs and returns no
///      value on success. This adapter converts CATP's generic proof interface
///      into the generated verifier calldata.
contract Groth16AuthorizationVerifier is IVerifier {
    uint256 public constant VERIFY_GAS_LIMIT = 800_000;

    IGroth16Verifier public immutable groth16Verifier;

    constructor(address groth16Verifier_) {
        require(groth16Verifier_ != address(0), "Groth16AuthorizationVerifier: zero address");
        require(groth16Verifier_.code.length > 0, "Groth16AuthorizationVerifier: verifier not contract");
        groth16Verifier = IGroth16Verifier(groth16Verifier_);
    }

    /// @inheritdoc IVerifier
    function verify(bytes32[] calldata publicInputs, bytes calldata proof) external view override returns (bool) {
        require(publicInputs.length == 13, "Groth16AuthorizationVerifier: expected 13 public inputs");
        require(proof.length == 256, "Groth16AuthorizationVerifier: expected 256-byte proof");

        uint256[13] memory input;
        for (uint256 i = 0; i < 13; i++) {
            input[i] = uint256(publicInputs[i]);
        }

        uint256[8] memory decodedProof = abi.decode(proof, (uint256[8]));

        (bool ok,) = address(groth16Verifier).staticcall{gas: VERIFY_GAS_LIMIT}(
            abi.encodeCall(IGroth16Verifier.verifyProof, (decodedProof, input))
        );
        return ok;
    }
}
