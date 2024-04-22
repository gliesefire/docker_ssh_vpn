# Multi-Platform Debian Docker Image for VPN Services

[![ci](https://github.com/gliesefire/docker_ssh_vpn/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gliesefire/docker_ssh_vpn/actions/workflows/ci.yml)

This repository contains the source code for a multi-platform Debian Docker image designed for deployment in AWS environments, specifically tailored for ECS or any similar AWS service. But you should be able to deploy this to any platform supporting container services. This Docker image facilitates the creation of an OpenVPN server, built-in SSH access & automatic IP address updating (for AWS environments only).
Apart from `NET_ADMIN` capabilities, the script (or the docker file) doesn't depend on any privileged stuff being available.
The *only* requirement, is that the container should share the same network namespace as the host, or have some way of interacting with the internet, since you can't enable ipv4 forwarding.

## Features

- **Built-in SSH Access:** Enables logging into the server instance directly, providing ease of management and troubleshooting, even in serverless deployments.
- **Automatic IP Address Update:** Integrated script to update the server's IP address in AWS Route 53 automatically, ensuring the service remains accessible even after on-demand restarts or scaling operations.
- **OpenVPN Server:** Pre-configured OpenVPN server for secure, encrypted VPN tunnels.

## Prerequisites

Before deploying this Docker image, ensure you have the following:

- Docker installed on your local machine or CI/CD environment.
- Access to an AWS account with permissions to manage ECS, Route 53, and other relevant services.

## Deployment

- TODO

## Usage

- Build the image, or you use the pre-built image from [docker_ssh_openvpn](docker.io/gliesefire/docker_ssh_openvpn)
- Deploy and run the image
- SSH into your system, and copy the `/root/client.ovpn` file to your local
- Done!

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

## License

This project is open-sourced under the [MIT License](LICENSE).

## Acknowledgments

- Thanks to the Debian, Docker & OpenVPN communities for their invaluable resources and documentation.
- Thanks to [Nyr](https://github.com/Nyr) for the wonderful [openvpn installation script](https://github.com/Nyr/openvpn-install/openvpn-install.sh)
