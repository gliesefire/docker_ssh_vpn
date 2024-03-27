echo "Starting SSH ..."
/usr/sbin/sshd -D &
echo "Starting AWS CLI ..."
/usr/local/bin/aws_cli_install
echo "Starting Route53 Update ..."
/usr/local/bin/update-route53