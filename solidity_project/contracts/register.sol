// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Register {
    mapping(address => bytes) private _registrations;
    event Registered(address indexed user, bytes publicKey);
    constructor() {}
    function register(bytes memory publicKey) public {
        _registrations[msg.sender] = publicKey;
        emit Registered(msg.sender, publicKey);
    }

    function getPublicKey(address user) external view returns (bytes memory) {
        return _registrations[user];
    }
}
