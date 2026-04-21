// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../src/layer2/AgentAuthorizer.sol";
import "../src/layer2/StubVerifier.sol";

contract DeployAgentAuthorizer is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        StubVerifier stub = new StubVerifier();
        AgentAuthorizer authorizer = new AgentAuthorizer(address(stub));
        vm.stopBroadcast();
        console.log("StubVerifier deployed at:", address(stub));
        console.log("AgentAuthorizer deployed at:", address(authorizer));
    }
}
