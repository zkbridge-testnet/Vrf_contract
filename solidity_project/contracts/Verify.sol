// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./Register.sol";

contract Verify is Register{
    using ECDSA for bytes32;

    event RandomNumberRecorded(bytes32 randomNumber);
    event Committeed(bytes32 RandomSeed, address applicationAddress);

    mapping(bytes => bool) public committedHashes;

    function commit(
        bytes32 randomSeed
    ) external returns (bool) {
        require(
            !committedHashes[abi.encodePacked(randomSeed, msg.sender)],
            "Hash already committed"
        );
        require(
            getVRFKey(msg.sender).length != 0,
            "Application not registered"
        );
        committedHashes[abi.encodePacked(randomSeed, msg.sender)] = true;
        emit Committeed(randomSeed, msg.sender);
        return true;
    }

    function batchVerify(
        address applicationAddress,
        bytes32[] memory randomSeeds,
        bytes[] memory signatures,
        bytes32[] memory expectedRandoms
    ) external returns (bool) {
        require(
            randomSeeds.length == signatures.length &&
            signatures.length == expectedRandoms.length,
            "Invalid input"
        );
        for (uint256 i = 0; i < randomSeeds.length; i++) {
            verify(
                applicationAddress,
                randomSeeds[i],
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
        bytes memory registeredKey = getVRFKey(
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
