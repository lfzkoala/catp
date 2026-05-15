// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "../../src/layer2/IVerifier.sol";

/// @title StubVerifier
/// @notice Test verifier — accepts any non-empty proof.
/// @dev Do not use in production deployments.
contract StubVerifier is IVerifier {
    function verify(
        bytes32[] calldata,
        bytes calldata proof
    ) external pure override returns (bool) {
        return proof.length > 0;
    }
}
