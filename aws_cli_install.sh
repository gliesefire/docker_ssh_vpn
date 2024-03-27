#!/bin/bash
if [ -f /usr/bin/aws ]; then
  echo "AWS CLI already installed"
  exit 0
fi

# Install AWS CLI
echo "Installing AWS CLI"

# Check if target platform is arm64
if [ "$(uname -m)" = "aarch64" ]; then
    curl -O 'https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip'
    unzip awscli-exe-linux-aarch64.zip
    ./aws/install
    exit 0
# Check if target platform is x86_64
elif [ "$(uname -m)" = "x86_64" ]; then
    curl -O 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip'
    unzip awscli-exe-linux-x86_64.zip
    ./aws/install
    exit 0
# Check if it is amd64
elif [ "$(uname -m)" = "amd64" ]; then
    curl -O 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip'
    unzip awscli-exe-linux-x86_64.zip
    ./aws/install
    exit 0
# Check if it is arm64
else
    echo "Unsupported platform"
    exit 1
fi