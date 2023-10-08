// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./register.sol";

contract Verify {
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
        uint8[] memory v,
        bytes32[] memory expectedRandoms
    ) external returns (bool) {
        require(
            messageHashes.length == signatures.length &&
            signatures.length == v.length &&
            v.length == expectedRandoms.length,
            "Invalid input"
        );
        for (uint256 i = 0; i < messageHashes.length; i++) {
            verify(
                applicationAddress,
                messageHashes[i],
                signatures[i],
                v[i],
                expectedRandoms[i]
            );
        }
        return true;
    }

    function verify(
        address applicationAddress,
        bytes32 messageHash,
        bytes memory signature,
        uint8 v,
        bytes32 expectedRandom
    ) public returns (bool) {
        require(
            committedHashes[abi.encodePacked(messageHash, applicationAddress)],
            "Hash not committed"
        );
        bytes memory registeredKey = registerContract.getPublicKey(
            applicationAddress
        );
        address signer = recoverSigner(messageHash, signature, v);
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

    function recoverSigner(
        bytes32 messageHash,
        bytes memory sig,
        uint8 v
    ) internal pure returns (address) {
        (bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(messageHash, v, r, s);
    }

    function splitSignature(
        bytes memory sig
    ) internal pure returns (bytes32 r, bytes32 s) {
        // Check the signature length
        // - case 65: r,s,v signature (standard)
        // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098)
        if (sig.length == 65) {
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            // solhint-disable-next-line no-inline-assembly
            assembly {
                r := mload(add(sig, 0x20))
                s := mload(add(sig, 0x40))
            }
        } else if (sig.length == 64) {
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            // solhint-disable-next-line no-inline-assembly
            assembly {
                r := mload(add(sig, 0x20))
                s := mload(add(sig, 0x40))
            }
        } else {
            revert("ECDSA: invalid signature length");
        }
        return (r, s);
    }
}
