
#!/bin/bash
solc --abi --overwrite -o output/ contracts/register.sol
solc --abi --overwrite -o output/ contracts/verify.sol
echo "ABI files generated in output/ directory"