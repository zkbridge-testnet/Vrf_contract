
# VRF client and contracts

This repository contains Solidity contracts a Rust client and a Python CLI interface to interact with them.

## Solidity Contracts

- `register.sol`: Allows users to register a secp256k1 public key against their Ethereum address.
- `verify.sol`: Provides functionality to verify a message using a registered public key.

### ABI Generation

Before interacting with the contracts using the Python CLI, you need to generate the ABI for the contracts:

1. Ensure you have `solc` and `jq` installed.
2. Run the ABI generation script:

```bash
cd solidity_project
./scripts/generate_abi.sh
```

This will generate the ABI files in the `output/` directory.

### Deployment

The deployment uses `truffle`, we deploy our contracts by using following command:
```bash
truffle migrate --network opbnbTestnet
```

After you successfully deployed, you need to update corresponding `config.ini` entries.

## Rust VRF client

The rust VRF client serves as a backend to Python CLI interface, you need to compile it by using the `build.sh` file in the project root directory.
```bash
./build.sh
```

## Python CLI Interface

A Python CLI interface to interact with the provided smart contracts.

### Configuration

1. Make sure to install the required Python packages:

```bash
pip install -r requirements.txt
```

2. Update the `config.ini` file with the appropriate values:

- `ProviderURL`: Your opBNB RPC URL.
- `RegisterAddress` and `VerifyAddress`: Deployed addresses of the Register and Verify contracts.
- `Key`: Your private key.

### Running the CLI

- To register a VRF key:
  ```bash
  python cli.py register
  ```


- To generate a random number and submit it on-chain:
  ```bash
  python cli.py generate_random_and_verify "APPLICATION DEPLOYER ADDRESS"
  ```

Clarification:
1. VRF uses a different key pair, it is not the same as your wallet key pair.
2. `APPLICATION DEPLOYER ADDRESS` is the public address who made the register call. It usually will be the application developer's public key. The public key should be posted online and accessible by application users.
3. `register` command will be used by the application developer, each applicaiton will have a dedicated key stored on-chain, the application developer can change their key anytime.
4. `generate_random_and_verify` can be used by anyone.

## Examples
We provide a full interaction transcipt here:

```
ubuntu@ip-172-31-1-22:~/vrf_contracts$ cd python_cli/


ubuntu@ip-172-31-1-22:~/vrf_contracts/python_cli$ python3 cli.py register
2023-09-21 13:37:32,201 - INFO - Public key: 795ad30f126d8a82804c3e4025eb72cfe8f3af6d40dd2608f6ff98e9870740af6c6b995f4a329099506d396f6301fb54fbcc63cd7bc47fa86202db5f883c0a43
(Receipt edited to simplify the document)
... 'transactionHash': HexBytes('0x200c7001db401f69aae3ae51e9436862dbf9e703b3d39b4756bcb27f2cde6198'), ...


ubuntu@ip-172-31-1-22:~/vrf_contracts/python_cli$ python3 cli.py generate_random_and_verify 3c9c23B661a0368cb3306B64Ab6Cf0C72d76f35B
2023-09-21 13:38:58,920 - INFO - Registered public key: 795ad30f126d8a82804c3e4025eb72cfe8f3af6d40dd2608f6ff98e9870740af6c6b995f4a329099506d396f6301fb54fbcc63cd7bc47fa86202db5f883c0a43
(Receipt edited to simplify the document)
...'transactionHash': HexBytes('0xd1ad936ffcfec762546c6d18f4467d259ecf93d287d313d35c497a679960e3a3')...
```

You can lookup our example transaction on https://testnet.opbnbscan.com/tx/0xd1ad936ffcfec762546c6d18f4467d259ecf93d287d313d35c497a679960e3a3
## License

This project is licensed under the MIT License.
