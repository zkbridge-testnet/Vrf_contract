use secp256k1::{PublicKey, ecdsa::Signature, Message};

use sha3::{Keccak256, Digest};
pub struct Proof {
    pub msg : Vec<u8>,
    pub sig : Signature,
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.msg.clone();
        bytes.extend_from_slice(&self.sig.serialize_compact());
        bytes
    }
}

pub fn verify_vrf(pk: &PublicKey, randomness: &[u8], proof: &Proof) -> bool {
    // Verify the BLS signature
    let message_converted = Message::from_slice(proof.msg.as_slice()).unwrap();
    let result = proof.sig.verify(&message_converted, pk);
    if result.is_err() {
        return false;
    }
    
    // Check that the output matches the hash of the proof
    let mut hasher = Keccak256::new();
    hasher.update(proof.sig.serialize_compact());
    let expected_output = hasher.finalize().to_vec();
    
    &expected_output == randomness
}
