import argparse
import configparser
import json
import logging
import os
from web3 import Web3, HTTPProvider, Account

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

config = configparser.ConfigParser()
config.read('config.ini')
w3 = Web3(HTTPProvider(config['WEB3']['ProviderURL']))
with open(config['CONTRACTS']['RegisterABI'], 'r') as f:
    REGISTER_ABI = json.load(f)
with open(config['CONTRACTS']['VerifyABI'], 'r') as f:
    VERIFY_ABI = json.load(f)
REGISTER_ADDRESS = config['CONTRACTS']['RegisterAddress']
VERIFY_ADDRESS = config['CONTRACTS']['VerifyAddress']
PRIVATE_KEY = config["PRIVATE"]["Key"]
if not PRIVATE_KEY:
    logging.error("Private key not found in config.ini.")

vrfClient = config['VRF']['Client']

def register():
    # Get public key from VRF client
    public_key = os.popen(vrfClient + ' gen').read()

    # convert public key into hex
    if public_key.startswith('0x'):
        public_key = public_key[2:]
    # remove 04 from the beginning of the public key
    public_key = public_key[2:]
    logging.info("VRF Public key: %s", public_key)
    public_key = bytes.fromhex(public_key)
    contract = w3.eth.contract(address=REGISTER_ADDRESS, abi=REGISTER_ABI)
    nonce = w3.eth.getTransactionCount(Account.privateKeyToAccount(PRIVATE_KEY).address)
    txn = contract.functions.register(public_key).buildTransaction({
        'chainId': 5611,  # Adjust accordingly based on network
        'gas': 2000000,
        'gasPrice': w3.toWei('2', 'gwei'),
        'nonce': nonce,
    })
    signed_txn = w3.eth.account.signTransaction(txn, PRIVATE_KEY)
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    logging.info("Transaction receipt: %s", receipt)

def get_public_key(address):
    contract = w3.eth.contract(address=REGISTER_ADDRESS, abi=REGISTER_ABI)
    if address.startswith('0x'):
        address = address[2:]
    address_byte = bytes.fromhex(address)
    public_key = contract.functions.getPublicKey(address_byte).call().hex()
    logging.info("Registered public key: %s", public_key)
    return public_key

def verify(application_public_key, message_hash, signature, expected_random):
    contract = w3.eth.contract(address=VERIFY_ADDRESS, abi=VERIFY_ABI)
    if application_public_key.startswith('0x'):
        application_public_key = application_public_key[2:]
    application_public_key_bytes = bytes.fromhex(application_public_key)
    if message_hash.startswith('0x'):
        message_hash = message_hash[2:]
    msg_hash_bytes = bytes.fromhex(message_hash)
    if signature.startswith('0x'):
        signature = signature[2:]
    if expected_random.startswith('0x'):
        expected_random = expected_random[2:]
    signature_bytes = bytes.fromhex(signature)
    expected_random_bytes = bytes.fromhex(expected_random)
    nonce = w3.eth.getTransactionCount(Account.privateKeyToAccount(PRIVATE_KEY).address)
    txn = contract.functions.verify(application_public_key_bytes, msg_hash_bytes, signature_bytes, expected_random_bytes).buildTransaction({
        'chainId': 5611,  # Adjust accordingly based on network
        'gas': 2000000,
        'gasPrice': w3.toWei('2', 'gwei'),
        'nonce': nonce,
    })
    signed_txn = w3.eth.account.signTransaction(txn, PRIVATE_KEY)
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    logging.info("Transaction receipt: %s", receipt)

def gen_rand_verify(application_address):
    # query contract to get public key
    application_public_key = get_public_key(application_address)
    # add 04 to the beginning of the public key
    if application_public_key.startswith('0x'):
        application_public_key = application_public_key[2:]
    if len(application_public_key) == 128:
        application_public_key = '04' + application_public_key
    # invoke client to get random number
    random_number_line = os.popen(vrfClient + ' getrand ' + application_public_key).read()
    random_number_lines = random_number_line.split('\n')
    print(random_number_lines)
    random_number = random_number_lines[0]
    proof_msg = random_number_lines[1]
    proof_sig = random_number_lines[2]

    # onchain
    verify(application_address, proof_msg, proof_sig, random_number)

    logging.info("Random number: %s", random_number)

def main():
    parser = argparse.ArgumentParser(description='Interact with Ethereum smart contracts.')
    subparsers = parser.add_subparsers(dest='command')

    parser_register = subparsers.add_parser('register', help='Register a secp256k1 public key against your Ethereum address.')
    
    parser_getkey = subparsers.add_parser('getkey', help='Retrieve the registered public key for a specific Ethereum address.')
    parser_getkey.add_argument('address', type=str, help='Ethereum address to retrieve the public key for.')

    parser_verify = subparsers.add_parser('verify', help='Verify a message using a registered public key and its signature.')
    parser_verify.add_argument('application_public_key', type=str, help='Public key of the application.')
    parser_verify.add_argument('message_hash', type=str, help='Hash of the message to be verified.')
    parser_verify.add_argument('signature', type=str, help='Signature of the message.')
    parser_verify.add_argument('expected_random', type=str, help='Expected random number, which should be the hash of the message.')

    parser_generate_random_and_verify = subparsers.add_parser('generate_random_and_verify', help='Generate a random number and verify it, random number will be posted on chain.')
    parser_generate_random_and_verify.add_argument('application_deployer_address', type=str, help='Public key of the application.')


    args = parser.parse_args()
    if args.command == 'register':
        register()
    elif args.command == 'getkey':
        get_public_key(args.address)
    elif args.command == 'verify':
        verify(args.application_public_key, args.message_hash, args.signature, args.expected_random)
    elif args.command == 'generate_random_and_verify':
        gen_rand_verify(args.application_deployer_address)
    else:
        logging.error("Invalid command")

if __name__ == '__main__':
    main()
