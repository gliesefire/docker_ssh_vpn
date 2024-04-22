#!/bin/bash

# Add tun device
mkdir /dev/net \
    && mknod /dev/net/tun c 10 200 \
    && chmod 0666 /dev/net/tun

echo "Starting SSH ..."
/usr/sbin/sshd -D &
echo "Starting OpenVPN installation ..."
/usr/local/bin/openvpn-install --headless-mode
echo "Starting AWS CLI Installation ..."
/usr/local/bin/aws_cli_install
# echo "Starting Route53 Update ..."
# /usr/local/bin/update-route53
tail -f /dev/null