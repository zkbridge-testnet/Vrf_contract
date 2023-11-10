use std::env;

use tonic::transport::Channel;
use vrf::vrf_service_client::VrfServiceClient;
use vrf::{{Empty, PublicKey}};
pub mod vrf {
    #![allow(non_snake_case)]
    tonic::include_proto!("vrf");
}

use secp256k1::{PublicKey as secpPublicKey, ecdsa::Signature, Message};

use sha3::{{Keccak256, Digest}};

use crate::vrf::PublicKeyWithInput;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {{
    let args : Vec<String> = env::args().collect();

    // Connect to the gRPC server
    let channel = Channel::from_static("http://34.27.65.206:50051")
        .connect()
        .await?;

    let mut client = VrfServiceClient::new(channel);

    // select modes from args[1]
    let mode = args[1].clone();
    if mode.eq_ignore_ascii_case("gen") {
        // Request a public key
        let empty_request = Empty {};
        let public_key_response = client.generate_keys(empty_request).await?;
        let public_key_data = public_key_response.into_inner().data;
        println!("{}", hex::encode(public_key_data.clone()));
    } else if mode.eq_ignore_ascii_case("verify") {
        let public_key_str = args[2].clone();
        let proof_msg_str = args[3].clone();
        let proof_sig_str = args[4].clone();
        let random_number_str = args[5].clone();

        let bls_public_key = secpPublicKey::from_slice(&hex::decode(public_key_str.clone()).unwrap())?;
        let random_number_data = hex::decode(random_number_str.clone()).unwrap();
        let proof_msg = hex::decode(proof_msg_str.clone()).unwrap();
        let proof_sig = Signature::from_compact(&hex::decode(proof_sig_str.clone()).unwrap())?;
        
        // Verify the random number using the provided public key and proof
        let success = verify_vrf(&bls_public_key, &random_number_data, &proof_msg.clone(), proof_sig);
        println!("Verification: {}", success);
    } else if mode.eq_ignore_ascii_case("getrand") {
        let public_key_str = args[2].clone();
        let public_key_data = hex::decode(public_key_str.clone()).unwrap();
        // Request a random number using the received public key
        let random_number_response = client.generate_random_number(PublicKey { data: public_key_data }).await?;
        let response_data = random_number_response.into_inner();
        let random_number_data = response_data.random_number;
        let proof_msg = response_data.proof_msg;
        let proof_sig_byte = response_data.proof_sig;
        let recovery_id = response_data.recovery_id[0];

        let proof_sig = Signature::from_compact(&proof_sig_byte.clone())?;

        println!("{}", hex::encode(random_number_data.clone()));
        println!("{}", hex::encode(proof_msg.clone()));
        println!("{}", hex::encode(proof_sig.clone().serialize_compact()));
        println!("{}", recovery_id);
    } else if mode.eq_ignore_ascii_case("getrandwithmsg") {
        let public_key_str = args[2].clone();
        let public_key_data = hex::decode(public_key_str.clone()).unwrap();
        let msg_str = args[3].clone();
        let msg_data = hex::decode(msg_str.clone()).unwrap();
        // Request a random number using the received public key
        let random_number_response = client.generate_random_number_with_input_msg( PublicKeyWithInput { key: public_key_data , msg: msg_data}).await?;
        let response_data = random_number_response.into_inner();
        let random_number_data = response_data.random_number;
        let proof_msg = response_data.proof_msg;
        let proof_sig_byte = response_data.proof_sig;
        let recovery_id = response_data.recovery_id[0];

        let proof_sig = Signature::from_compact(&proof_sig_byte.clone())?;


        println!("{}", hex::encode(random_number_data.clone()));
        println!("{}", hex::encode(proof_msg.clone()));
        println!("{}", hex::encode(proof_sig.clone().serialize_compact()));
        println!("{}", recovery_id);
    } else {
        panic!("Invalid mode: {}", mode);
    }
    Ok(())
}}

fn verify_vrf(pk: &secpPublicKey, randomness: &[u8], proof_msg : &[u8], proof_sig : Signature) -> bool {
    // Verify the seckp256k1 signature
    let message_converted = Message::from_slice(&proof_msg).unwrap();
    let result = proof_sig.verify(&message_converted, pk);
    if result.is_err() {
        return false;
    }
    
    // Check that the output matches the hash of the proof
    let mut hasher = Keccak256::new();
    hasher.update(proof_sig.serialize_compact());
    let expected_output = hasher.finalize().to_vec();
    
    &expected_output == randomness
}