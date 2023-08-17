// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./register.sol";

contract Verify {
    Register public registerContract;

    constructor(address _registerAddress) {
        registerContract = Register(_registerAddress);
    }
    event RandomNumberRecorded(bytes32 randomNumber);

    function verify(
        address applicationAddress,
        bytes32 messageHash,
        bytes memory signature,
        bytes32 expectedRandom
    ) public returns (bool) {
        bytes memory registeredKey = registerContract.getPublicKey(
            applicationAddress
        );
        address signer = recoverSigner(messageHash, signature);
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
        bytes memory sig
    ) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(messageHash, v, r, s);
    }

    function splitSignature(
        bytes memory sig
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
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
                v := byte(0, mload(add(sig, 0x60)))
            }
        } else if (sig.length == 64) {
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            // solhint-disable-next-line no-inline-assembly
            assembly {
                r := mload(add(sig, 0x20))
                s := and(
                    mload(add(sig, 0x40)),
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                )
                v := add(shr(7, byte(0, mload(add(sig, 0x40)))), 27)
            }
        } else {
            revert("ECDSA: invalid signature length");
        }
        return (v, r, s);
    }
}
