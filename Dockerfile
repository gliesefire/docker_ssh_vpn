FROM debian:latest

# Setup ssh server
RUN apt update && apt install -y openssh-server curl
RUN apt install -y dumb-init
RUN apt clean

RUN echo -n "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDJiVaieHoYYC3uTel3AoSIgzwyjAEO0y/nsEc5w5PLG2HNx2WUohFLYa47jg+cQ6mCOlOHtxWgL1EVhc1QPNgyuewNURf5NldUJnVPaY0O5ADigy+J8eZryPDU0LwztOpa8DAsLYT7gZIn7y8pyxD7RRi2iLau5mHrNZNTfoTFDzq8NlE++KIo8MLwvilipe0L3NgUeAF3sCIdY1T/y62BQ8mC33Yys9evznLmacXcdI6GctylkNHjo6r6jQU6pzFCgbAcDncUBWjwmm16f7eesi+jivJTGYaKy6vggzfqcn/grkUUInP4+ZPFzE7zab+iJYoi77+Ve6Z8RjMfXmxRxIqpSbOm8mFKQgOsRMQ84P89nzEW4oZVmViJtLl//qIXNZ5Y2mVDlMML9loiPBTkcCPkUj2JY2n8UNFE+qo1xdaXs4q/KQhh4e5MneGAPb2knuyil0iuf2N0s5DBePdawvMi1Nv9ypG90deaw5p15PLjEYf8C4HAzZzYIIY6k6Bs/au7DHv4g9/kWg+6mqxn5lZZL9IDGEbQCvtP/QQZm2ZV9mPllssNIXhKFDglw9s9Zgd9Xs2BMt+BscO0fzq94AbyZ54Xq4QFLL4kzxnwF9TK25RrdrV3hdWHHtd2j3GBIruTM8/y+q0BCdEuO1i/u5vC9L+EfvJ/BcpGTwhFWQ== glies@Jasmine" | tee -a /root/.ssh/authorized_keys

RUN sed -i 's/#Port 22/Port 53254/' /etc/ssh/sshd_config
RUN sed -i 's/Port 22/Port 53254/' /etc/ssh/sshd_config
EXPOSE 53254

RUN mkdir /run/sshd
RUN chown root:root /run/sshd
RUN chmod 755 /run/sshd

COPY update-route53.sh /usr/local/bin/update-route53.sh
COPY aws_cli_install.sh /usr/local/bin/aws_cli_install
RUN chmod +x /usr/local/bin/aws_cli_install
RUN chmod +x /usr/local/bin/update-route53.sh

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["sh", "-c", "/usr/sbin/sshd -D && /usr/local/bin/aws_cli_install && /usr/local/bin/update-route53.sh"]