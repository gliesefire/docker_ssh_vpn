docker rm tc
docker image rm docker_ssh_vpn_test:latest
docker build --tag docker_ssh_vpn_test:latest .
docker run -d --name tc -p 2222:22 docker_ssh_vpn_test:latest