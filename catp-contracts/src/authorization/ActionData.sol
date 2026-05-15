// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

library ActionData {
    enum ActionType { Swap, Transfer, Deposit, Withdraw }

    struct Action {
        ActionType actionType;
        bytes32 protocol;
        bytes32 token;
        uint256 value;
    }

    function encode(Action memory action) internal pure returns (bytes memory) {
        return abi.encode(action.actionType, action.protocol, action.token, action.value);
    }

    function decode(bytes memory data) internal pure returns (Action memory) {
        (ActionType t, bytes32 p, bytes32 tk, uint256 v) =
            abi.decode(data, (ActionType, bytes32, bytes32, uint256));
        return Action(t, p, tk, v);
    }

    function hash(Action memory action) internal pure returns (bytes32) {
        return keccak256(encode(action));
    }
}
