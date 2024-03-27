FROM debian:latest

# Setup ssh server
RUN apt update && apt install -y openssh-server curl
RUN apt install -y dumb-init
RUN apt clean
ARG SSH_PUBLIC_KEY
ARG SSH_PORT_NUMBER

RUN echo -n $SSH_PUBLIC_KEY | tee -a /root/.ssh/authorized_keys

RUN sed -i 's/#Port 22/Port $SSH_PORT_NUMBER/' /etc/ssh/sshd_config
RUN sed -i 's/Port 22/Port $SSH_PORT_NUMBER/' /etc/ssh/sshd_config
EXPOSE $SSH_PORT_NUMBER

RUN mkdir /run/sshd
RUN chown root:root /run/sshd
RUN chmod 755 /run/sshd

COPY update-route53.sh /usr/local/bin/update-route53.sh
COPY aws_cli_install.sh /usr/local/bin/aws_cli_install
RUN chmod +x /usr/local/bin/aws_cli_install
RUN chmod +x /usr/local/bin/update-route53.sh

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

ENV SSH_PORT_NUMBER=$SSH_PORT_NUMBER
CMD ["sh", "-c", "/usr/sbin/sshd -D && /usr/local/bin/aws_cli_install && /usr/local/bin/update-route53.sh"]