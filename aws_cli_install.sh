#!/bin/bash
pushd /tmp || echo "Failed to change directory to /tmp" && exit 1
if [ -f /usr/bin/aws ]; then
  echo "AWS CLI already installed"
  exit 0
fi

# Install AWS CLI
echo "Installing AWS CLI"

# Check if target platform is arm64
if [ "$(uname -m)" = "aarch64" ]; then
    curl -o awscli.zip https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip
# Check if target platform is x86_64
elif [ "$(uname -m)" = "x86_64" ]; then
    curl -o awscli.zip https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
# Check if it is amd64
elif [ "$(uname -m)" = "amd64" ]; then
    curl -o awscli.zip https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
# Check if it is arm64
else
    echo "Unsupported platform"
    exit 1
fi

unzip awscli.zip
./aws/install
rm -rf aws awscli.zip
popd || echo "Failed to change directory to previous directory" && exit 1
exit 0