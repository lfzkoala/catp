// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../src/authorization/AgentAuthorizer.sol";
import "../src/authorization/Groth16AuthorizationVerifier.sol";
import "../src/authorization/Groth16Verifier.sol";

/// @notice Deploys the compact Groth16-backed AgentAuthorizer for authorization_groth16_v1.
contract DeployGroth16Authorizer is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("CATP_PRIVATE_KEY"));

        Groth16Verifier groth16 = new Groth16Verifier();
        Groth16AuthorizationVerifier wrapper = new Groth16AuthorizationVerifier(address(groth16));
        AgentAuthorizer authorizer = new AgentAuthorizer(address(wrapper));

        vm.stopBroadcast();

        console.log("Groth16Verifier deployed at:              ", address(groth16));
        console.log("Groth16AuthorizationVerifier deployed at: ", address(wrapper));
        console.log("AgentAuthorizer deployed at:              ", address(authorizer));
    }
}
