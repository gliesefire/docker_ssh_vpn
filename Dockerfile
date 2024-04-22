FROM debian:latest

ENV LC_ALL=C

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Kolkata
ENV ipv4_override=127.0.0.1
ENV ipv6_override=::1
ENV port_override=9999
ENV protocol_override=udp
ENV dns_override=1
ENV KEY_COUNTRY="US"
ENV KEY_PROVINCE="NY"
ENV KEY_CITY="New York"
ENV KEY_ORG="Example Company"
ENV KEY_EMAIL="blahblueblah@example.com"
ENV KEY_EMAIL="blahblueblah@example.com"
ENV KEY_CN=openvpn.example.com
ENV KEY_NAME="server"
ENV KEY_OU="Community"


# Update and install required packages
RUN apt-get update \
    && apt-get install -y openssh-server curl unzip jq \
    && apt-get install -y openvpn-dco-dkms \
    && apt-get install -y wget \
    && apt-get install -y iproute2 \
    && apt-get install -y --no-install-recommends openvpn openssl ca-certificates iptables \
    && apt-get clean

# Copy SSH public key for root user and create SSH directory
RUN mkdir -p /run/sshd \
    && mkdir -p /root/.ssh \
    && chmod 700 /root/.ssh \
    && chown root:root /run/sshd \
    && chmod 755 /run/sshd \
    && touch /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys \
    && echo -n "ssh-rsa AAAAB3NzaC1yc2EAAAADAABAAACAQDJiVaieHoYYC3uTel3AoSIgzwyjAEO0y/nsEc5w5PLG2HNx2WUohFLYa47jg+cQ6mCOlOHtxWgL1EVhc1QPNgyuewNURf5NldUJnVPaY0O5ADigy+J8eZryPDU0LwztOpa8DAsLYT7gZIn7y8pyxD7RRi2iLau5mHrNZNTfoTFDzq8NlE++KIo8MLwvilipe0L3NgUeAF3sCIdY1T/y62BQ8mC33Yys9evznLmacXcdI6GctylkNHjo6r6jQU6pzFCgbAcDncUBWjwmm16f7eesi+jivJTGYaKy6vggzfqcn/grkUUInP4+ZPFzE7zab+iJYoi77+Ve6Z8RjMfXmxRxIqpSbOm8mFKQgOsRMQ84P89nzEW4oZVmViJtLl//qIXNZ5Y2mVDlMML9loiPBTkcCPkUj2JY2n8UNFE+qo1xdaXs4q/KQhh4e5MneGAPb2knuyil0iuf2N0s5DBePdawvMi1Nv9ypG90deaw5p15PLjEYf8C4HAzZzYIIY6k6Bs/au7DHv4g9/kWg+6mqxn5lZZL9IDGEbQCvtP/QQZm2ZV9mPllssNIXhKFDglw9s9Zgd9Xs2BMt+BscO0fzq94AbyZ54Xq4QFLL4kzxnwF9TK25RrdrV3hdWHHtd2j3GBIruTM8/y+q0BCdEuO1i/u5vC9L+EfvJ/BcpGTwhFWQ== glies@Jasmine" | tee -a /root/.ssh/authorized_keys

COPY update-route53.sh /usr/local/bin/update-route53
COPY aws_cli_install.sh /usr/local/bin/aws_cli_install
COPY entrypoint.sh /usr/local/bin/entrypoint
COPY openvpn-install.sh /usr/local/bin/openvpn-install
COPY ./EasyRSA-3.1.7.tgz /tmp/EasyRSA-3.1.7.tgz
COPY ./openvpn-server /etc/init.d/openvpn-server

RUN chmod +x /usr/local/bin/entrypoint \
    && chmod +x /usr/local/bin/aws_cli_install \
    && chmod +x /usr/local/bin/update-route53 \
    && chmod +x /usr/local/bin/openvpn-install \
    && chmod +x /etc/init.d/openvpn-server

CMD ["/usr/local/bin/entrypoint"]