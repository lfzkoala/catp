// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IVerifier.sol";

/// @title StubVerifier
/// @notice Phase 1 stub — accepts any non-empty proof.
/// @dev Replace with the auto-generated Halo2 Solidity verifier in Phase 2.
contract StubVerifier is IVerifier {
    function verify(
        bytes32[] calldata,
        bytes calldata proof
    ) external pure override returns (bool) {
        return proof.length > 0;
    }
}
