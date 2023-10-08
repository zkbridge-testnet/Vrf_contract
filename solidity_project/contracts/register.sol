// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Register {
    mapping(address => bytes) private _registrations;
    event Registered(address indexed user, bytes vrfKey);
    constructor() {}
    function register(bytes memory vrfKey) public {
        _registrations[msg.sender] = vrfKey;
        emit Registered(msg.sender, vrfKey);
    }

    function getVRFKey(address user) external view returns (bytes memory) {
        return _registrations[user];
    }
}
