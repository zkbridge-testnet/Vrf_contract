#!/bin/bash

# Install system dependencies
sudo apt update
sudo apt install -y python3-pip protobuf-compiler libprotobuf-dev

# Navigate to the project directory (assuming the script is placed at the root of the project)
cd "$(dirname "$0")"

# Install Python dependencies
pip3 install -r python_cli/requirements.txt

# Compile the rust client
cd rust_client
cargo build --release

cd ..