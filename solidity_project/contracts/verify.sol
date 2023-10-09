// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./register.sol";

contract Verify {
    using ECDSA for bytes32;

    event RandomNumberRecorded(bytes32 randomNumber);
    event Committeed(bytes32 messageHash, address applicationAddress);

    Register public registerContract;

    mapping(bytes => bool) public committedHashes;

    constructor(address _registerAddress) {
        registerContract = Register(_registerAddress);
    }

    function commit(
        bytes32 messageHash
    ) external returns (bool) {
        require(
            !committedHashes[abi.encodePacked(messageHash, msg.sender)],
            "Hash already committed"
        );
        require(
            registerContract.getPublicKey(msg.sender).length != 0,
            "Application not registered"
        );
        committedHashes[abi.encodePacked(messageHash, msg.sender)] = true;
        emit Committeed(messageHash, msg.sender);
        return true;
    }

    function batchVerify(
        address applicationAddress,
        bytes32[] memory messageHashes,
        bytes[] memory signatures,
        bytes32[] memory expectedRandoms
    ) external returns (bool) {
        require(
            messageHashes.length == signatures.length &&
            signatures.length == expectedRandoms.length,
            "Invalid input"
        );
        for (uint256 i = 0; i < messageHashes.length; i++) {
            verify(
                applicationAddress,
                messageHashes[i],
                signatures[i],
                expectedRandoms[i]
            );
        }
        return true;
    }

    function verify(
        address applicationAddress,
        bytes32 messageHash,
        bytes memory signature,
        bytes32 expectedRandom
    ) public returns (bool) {
        require(
            committedHashes[abi.encodePacked(messageHash, applicationAddress)],
            "Hash not committed"
        );
        bytes memory registeredKey = registerContract.getPublicKey(
            applicationAddress
        );
        require(
            registeredKey.length != 0,
            "Application not registered"
        );

        address signer = messageHash.toEthSignedMessageHash().recover(signature);
        require(
            signer == publicKeyToAddress(registeredKey),
            "Invalid signature"
        );
        bytes32 computedRandom = keccak256(signature);
        require(computedRandom == expectedRandom, "Invalid random number");
        emit RandomNumberRecorded(computedRandom);
        return true;
    }

    function publicKeyToAddress(
        bytes memory publicKey
    ) internal pure returns (address addr) {
        bytes32 hash = keccak256(publicKey);
        assembly {
            mstore(0, hash)
            addr := mload(0)
        }
    }
}
