// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Register {
    event Registered(address indexed user, bytes vrfKey);

    mapping(address => bytes) private _registrations;

    function register(bytes memory vrfKey) public {
        _registrations[msg.sender] = vrfKey;
        emit Registered(msg.sender, vrfKey);
    }

    function getVRFKey(address user) public view returns (bytes memory) {
        return _registrations[user];
    }
}
