// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../src/layer2/AgentAuthorizer.sol";
import "../src/layer2/Halo2Verifier.sol";
import "../src/layer2/Halo2AuthorizationVerifier.sol";

/// @notice Deploys the Halo2-backed AgentAuthorizer for Phase 2.
/// @dev Requires:
///      1. Halo2Verifier.sol regenerated from a fixed SRS (KZG ceremony for production).
///      2. The prover in catp-circuits/layer2 loaded with the same SRS.
///      Run: forge script script/DeployHalo2Authorizer.s.sol --broadcast --rpc-url $RPC_URL
contract DeployHalo2Authorizer is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        Halo2Verifier halo2 = new Halo2Verifier();
        Halo2AuthorizationVerifier wrapper = new Halo2AuthorizationVerifier(address(halo2));
        AgentAuthorizer authorizer = new AgentAuthorizer(address(wrapper));

        vm.stopBroadcast();

        console.log("Halo2Verifier deployed at:              ", address(halo2));
        console.log("Halo2AuthorizationVerifier deployed at: ", address(wrapper));
        console.log("AgentAuthorizer deployed at:            ", address(authorizer));
    }
}
