# Multi-Platform Debian Docker Image for VPN Services

[![ci](https://github.com/gliesefire/docker_ssh_vpn/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gliesefire/docker_ssh_vpn/actions/workflows/ci.yml)

This repository contains the source code for a multi-platform Debian Docker image designed for deployment in AWS environments, specifically tailored for ECS or any similar AWS service. This Docker image facilitates the creation of a robust VPN server, featuring built-in SSH access, automatic IP address updating, an OpenVPN server, and a WireGuard server, ensuring secure and seamless connectivity.

## Features

- **Built-in SSH Access:** Enables logging into the server instance directly, providing ease of management and troubleshooting, even in serverless deployments.
- **Automatic IP Address Update:** Integrated script to update the server's IP address in AWS Route 53 automatically, ensuring the service remains accessible even after on-demand restarts or scaling operations.
- **OpenVPN Server:** Pre-configured OpenVPN server for secure, encrypted VPN tunnels.
- **WireGuard Server:** Includes a WireGuard server setup for a fast, modern, and secure VPN connection.

## Prerequisites

Before deploying this Docker image, ensure you have the following:

- Docker installed on your local machine or CI/CD environment.
- Access to an AWS account with permissions to manage ECS, Route 53, and other relevant services.

## Deployment

- TODO

## Usage

- TODO

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

## License

This project is open-sourced under the [MIT License](LICENSE).

## Acknowledgments

- Thanks to the Debian, Docker, OpenVPN, and WireGuard communities for their invaluable resources and documentation.