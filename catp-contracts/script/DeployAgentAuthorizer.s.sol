// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../src/layer2/AgentAuthorizer.sol";

contract DeployAgentAuthorizer is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        AgentAuthorizer authorizer = new AgentAuthorizer();
        vm.stopBroadcast();
        console.log("AgentAuthorizer deployed at:", address(authorizer));
    }
}
