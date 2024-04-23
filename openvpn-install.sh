#!/bin/bash
#
# Adapted from https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2024 gliesefire. Released under the MIT License.

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

headless_mode=false
openvpn_server_path="/etc/openvpn/server/"

for arg in "$@"; do
	if [ "$arg" = "--env-variable" ]; then
		headless_mode=true
		break
	fi
done

if [[ ! -t 0 ]] && [[ ! $headless_mode ]]; then
	echo "You can't run this script in non-interactive mode (unless you use --headless)."
	exit 1
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -r -N 999999 -t 0.001

function check_if_kernel_is_supported() {
	if [[ $(uname -r | cut -d "." -f 1) -lt 3 ]]; then
		echo "Your kernel is too old. The minimum kernel version supported by this installer is 3.10."
		exit
	fi
}

function detect_os() {
	# Detect OS
	# $os_version variables aren't always in use, but are kept here for convenience
	if grep -qs "ubuntu" /etc/os-release; then
		os="ubuntu"
		os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
		group_name="nogroup"
	elif [[ -e /etc/debian_version ]]; then
		os="debian"
		os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
		group_name="nogroup"
	elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
		os="centos"
		os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
		group_name="nobody"
	elif [[ -e /etc/fedora-release ]]; then
		os="fedora"
		os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
		group_name="nobody"
	else
		echo "This installer seems to be running on an unsupported distribution.
		Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."exit
	fi
}

function check_if_os_supported() {
	if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
		echo "Ubuntu 18.04 or higher is required to use this installer.
		This version of Ubuntu is too old and unsupported."
		exit
	fi

	if [[ "$os" == "debian" ]]; then
		if grep -q '/sid' /etc/debian_version; then
			echo "Debian Testing and Debian Unstable are unsupported by this installer."
			exit
		fi
		if [[ "$os_version" -lt 9 ]]; then
			echo "Debian 9 or higher is required to use this installer.
			This version of Debian is too old and unsupported."
			exit
		fi
	fi

	if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
		echo "CentOS 7 or higher is required to use this installer.
		This version of CentOS is too old and unsupported."
		exit
	fi
}

function check_if_user_is_su() {
	if [[ "$EUID" -ne 0 ]]; then
		echo "This installer needs to be run with superuser privileges."
		exit
	fi
}

function check_if_tun_available() {
	if [[ ! -e /dev/net/tun ]]; then
		echo "The TUN device is not available. You need to enable TUN before running this installer."
		exit
	fi
}

function check_if_path_includes_bin() {
	if ! grep -q sbin <<<"$PATH"; then
		echo "\$PATH does not include sbin. Try using \"su -\" instead of \"su\"."
		exit
	fi
}

function new_client() {
	client=$2
	initial_client_name=$initial_client_name_override
	[[ -z "$initial_client_name" ]] && initial_client_name_override="client"
	[[ -z "$client" ]] && client=$initial_client_name

	if [[ -z "$client" ]] && [[ ! $headless_mode ]]; then
		prompt=$1 || "Provide a name for the client:"
		echo
		echo "$prompt"
		read -r -p "Name: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$unsanitized_client")

		while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
			echo "$client: invalid name."
			read -r -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$unsanitized_client")
		done
	fi

	echo "Generating client certificate for $client..."

	# Check if certificate generation is to be skipped
	if [[ $3 == 'n' ]]; then
		return
	fi

	# check if client already exists, and if it does, escape the script
	if [[ -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; then
		echo
		echo "The client $client already exists. Skipping client generation."
		exit
	fi

	if ! cd /etc/openvpn/server/easy-rsa/; then
		echo "Could not change directory to /etc/openvpn/server/easy-rsa/"
		exit
	fi

	./easyrsa --batch --days=3650 build-client-full "$client" nopass

	# Generates the custom client.ovpn
	{
		cat /etc/openvpn/server/client-common.txt
		echo "<ca>"
		cat /etc/openvpn/server/easy-rsa/pki/ca.crt
		echo "</ca>"
		echo "<cert>"
		sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
		echo "</cert>"
		echo "<key>"
		cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
		echo "</key>"
		echo "<tls-crypt>"
		sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
		echo "</tls-crypt>"
	} >~/"$client".ovpn

	echo
	echo "$client added. Configuration available in:" ~/"$client.ovpn"
}

function download_pre_req() {
	# Detect some Debian minimal setups where neither curl is not installed
	if ! hash curl 2>/dev/null; then
		echo "curl is required to use this installer."
		read -n1 -r -p "Press any key to install curl and continue..."
		apt-get update
		apt-get install -y curl
	fi
	clear
}

function choose_ipv4() {
	# Get the list of all ipv4 in an array named ipv4s
	readarray -t ipv4s < <(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	# Check for ipv4 override in the environment, and check if that ip is in the list of ipv4s
	if [[ -n "$ipv4_override" ]]; then
		echo "Using IPv4 address provided in the environment: $ipv4_override"
		ip=$ipv4_override
	fi

	if [[ -z $ip ]]; then
		# If system has a single IPv4, it is selected automatically. Else, ask the user
		if [[ ${#ipv4s[@]} -eq 1 ]]; then
			echo "Using IPv4 address: ${ipv4s[0]}"
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
		elif [[ ${#ipv4s[@]} -gt 1 ]] && [[ ! $headless_mode ]]; then
			number_of_ip=${#ipv4s[@]}
			echo
			echo "Which IPv4 address should be used?"
			ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
			read -r -p "IPv4 address [1]: " ip_number
			until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
				echo "$ip_number: invalid selection."
				read -r -p "IPv4 address [1]: " ip_number
			done
			[[ -z "$ip_number" ]] && ip_number="1"
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
		fi
	fi
}

function check_if_ip_is_private() {
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		if [[ $headless_mode ]]; then
			echo "You are running in headless mode. Private IP detection is not possible. Please provide the public IP address via 'ip_override' environment variable."
			exit
		fi

		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<<"$(curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -r -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input. $public_ip, $get_public_ip"
			sleep 2
			read -r -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
}

function choose_ipv6() {
	# Get the list of all ipv6 in an array named ipv6s
	readarray -t ipv6s < <(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')

	# Check for ipv6 override in the environment, and check if that ip is in the list of ipv6s
	if [[ -n "$ipv6_override" && " ${ipv6s[*]} " =~ $ipv6_override ]]; then
		echo "Using IPv6 address provided in the environment: $ipv6_override"
		ip6=$ipv6_override
	fi

	# If system has a single IPv6, it is selected automatically
	if [[ ${#ipv6s[@]} -eq 1 ]]; then
		echo "Using IPv6 address: ${ipv6s[0]}"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ ${#ipv6s[@]} -gt 1 ]] && [[ $headless_mode ]]; then
		number_of_ip6=${#ipv6s[@]}
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -r -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -r -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
}

function choose_protocol() {
	protocol=$protocol_override
	if [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]] && [[ ! $headless_mode ]]; then
		echo
		echo "Which protocol should OpenVPN use?"
		echo "   1) UDP (recommended)"
		echo "   2) TCP"
		read -r -p "Protocol [1]: " protocol
		until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
			echo "$protocol: invalid selection."
			read -r -p "Protocol [1]: " protocol
		done
	fi

	# Default protocol if the user didn't select any, or in headless mode and no protocol override
	if [[ -z "$protocol" ]]; then
		protocol=1
	fi

	echo "Using protocol: $protocol"

	case "$protocol" in
	1 | "")
		protocol=udp
		;;
	2)
		protocol=tcp
		;;
	esac
}

function choose_port() {
	port=$port_override
	if [[ -z "$port" || "$port" =~ ^[0-9]+$ ]] && [[ ! $headless_mode ]]; then
		echo
		echo "What port should OpenVPN listen to?"
		read -r -p "Port [1194]: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: invalid port."
			read -r -p "Port [1194]: " port
		done
		[[ -z "$port" ]] && port="1194"
	fi

	if [[ -z "$port" ]]; then
		port=1194
	fi

	echo "Using port: $port"
}

function choose_dns_server() {
	dns="$dns_server_override"
	if [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]] && [[ ! $headless_mode ]]; then
		echo
		echo "Select a DNS server for the clients:"
		echo "   1) Current system resolvers"
		echo "   2) Google"
		echo "   3) 1.1.1.1"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard"
		read -r -p "DNS server [1]: " dns
		until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
			echo "$dns: invalid selection."
			read -r -p "DNS server [1]: " dns
		done
	fi

	if [[ -z "$dns" ]]; then
		dns=1
	fi

	echo "Using DNS server: $dns"
}

function download_install_openvpn_and_firewall() {
	if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
		firewall="firewalld"
		# We don't want to silently enable firewalld, so we give a subtle warning
		# If the user continues, firewalld will be installed and enabled during setup
		echo "firewalld, which is required to manage routing tables, will also be installed."
	elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
		# iptables is way less invasive than firewalld so no warning is given
		firewall="iptables"
	fi

	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		echo "Running inside a container. Disabling LimitNPROC"
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		printf "[Service]\nLimitNPROC=infinity" >/etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi

	if [[ -e /etc/init.d/openvpn ]]; then
		is_openvpn_installed="enabled"
	else
		is_openvpn_installed="disabled"
	fi

	# If openvpn is installed, then assume that $firewall, openssl & other stuff is also installed
	if [[ "$is_openvpn_installed" != "enabled" ]]; then
		echo "Installing OpenVPN and OpenSSL..."
		if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
			apt-get update &&
				apt-get install -y openssh-server curl unzip jq psmisc &&
				apt-get install -y openvpn-dco-dkms &&
				apt-get install -y iproute2 &&
				apt-get install -y --no-install-recommends openvpn openssl ca-certificates "$firewall" &&
				apt-get clean
		elif [[ "$os" = "centos" ]]; then
			yum install -y epel-release
			yum install -y openvpn openssl ca-certificates tar "$firewall"
		else
			# Else, OS must be Fedora
			dnf install -y openvpn openssl ca-certificates tar "$firewall"
		fi
	else
		echo "OpenVPN is already installed. Skipping installation... (and assuming that $firewall and openssl are already installed)"
	fi

	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
}

function download_install_easy_rsa() {
	if [[ -e /etc/openvpn/server/easy-rsa/ ]]; then
		echo "Easy-RSA is already installed."
		return
	fi

	mkdir -p /etc/openvpn/server/easy-rsa/
	easy_rsa_url="https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.7/EasyRSA-3.1.7.tgz"
	curl -sL "$easy_rsa_url" -o easyrsa.tgz
	if [[ ! -e easyrsa.tgz ]]; then
		echo "Failed to download Easy-RSA. Checking if packaged with the image"
		if [[ -e /tmp/EasyRSA-3.1.7.tgz ]]; then
			cp /tmp/EasyRSA-3.1.7.tgz easyrsa.tgz
		else
			echo "Failed to download Easy-RSA. Exiting..."
			exit
		fi
	fi

	echo "Extracting Easy-RSA..."
	tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1 -f easyrsa.tgz
	rm -f easyrsa.tgz
	chown -R root:root /etc/openvpn/server/easy-rsa/
}

function create_ca_server_certificates() {
	download_install_easy_rsa
	if ! cd /etc/openvpn/server/easy-rsa/; then
		echo "Could not change directory to /etc/openvpn/server/easy-rsa/"
		exit
	fi
	# Create the PKI, set up the CA and the server and client certificates
	echo "Creating PKI..."
	./easyrsa --batch init-pki
	echo "Building CA..."
	./easyrsa --batch build-ca nopass
	echo "Building server certificate..."
	./easyrsa --batch --days=3650 build-server-full server nopass
	echo "Building revoked certificates..."
	./easyrsa --batch --days=3650 gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	echo "Generate key for tls-crypt"
	openvpn --genkey secret /etc/openvpn/server/tc.key
	echo "Generate DH parameters"
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAqU+6A4lcjiTgp4HiF7NRhJ2Rr+F7qJ51oYigdXoTmuSwBJXhmW+i
NULYxI0/i+cK9rw1FYNz/OzCVprHj5i00rsz5qN42oLnXb+QtYDPfVZlC9CZJubf
st64f85Vu5fb48yEVa5p2/Zm7ybaBTd4nsQjXDSc4f21Ei+01dCxLNYFMGWsdRH9
Pz72XYOCjTQ51DGwiLAXYnaWMtWDJ8Q6ZiLNnv6a184bShwFm0NX4yR8zJhmVmRf
82IQhHpA+Rgaxf9uu/NK2+1LkzwHYwOYxZkaZaVgcqlU6u/d5qa4H/9EydpbbY+u
ngQjejhbryjafVzrEnTcG3q4lsdWf6XjbmmxSsmdzMOQfQTtWj9vWkH7YivQiYOm
kMCBB/gj2XrMKEUuru1fnRHwao2efex4bPnbKUyc4DBPdrBhZudin96APjmV4u4e
7Z6LUeXspXphJQ3n22J350JKqDonTbhmAF43A7OWiHk2NFPPkmlPZbn7xXrsFoPa
t6Oe2T8ZIF31JD/4yawP+un80qxzlPVF4956RLv4QyTHFV1BDmTU4D+oMedocqWN
14Xitwokus6S4qgnMnJHb12+55JJ3Mr4OjFHfDvzOV3cQFXsFliRzTF2eCLAT+yG
8ZBCCJ9+qXEs4HJD27clgQM17Oi6MXT/tC97wtV1qyYZid2EaF/XCf8CAQI=
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
}

function generate_server_conf() {
	full_proto="$protocol"4
	# Generate server.conf
	echo "local $ip
port $port
proto $full_proto
dev tun
ca ca.crt
cipher AES-256-GCM
data-ciphers AES-256-GCM
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
auth SHA512
tls-crypt /etc/openvpn/server/tc.key
topology subnet
server 10.8.0.0 255.255.255.0" >/etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >>/etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >>/etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >>/etc/openvpn/server/server.conf
	# DNS

	function set_dns_server_in_conf() {
		case "$dns" in
		1 | "")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read -r line; do
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server/server.conf
			done
			;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server/server.conf
			;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server/server.conf
			;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server/server.conf
			;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server/server.conf
			;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server/server.conf
			;;
		esac
		echo 'push "block-outside-dns"' >>/etc/openvpn/server/server.conf
	}

	set_dns_server_in_conf
	echo "keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >>/etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >>/etc/openvpn/server/server.conf
	fi
}

function add_ip_protocol_port_to_firewall() {
	# Using both permanent and not permanent rules to avoid a firewalld
	# reload.
	# We don't use --add-service=openvpn because that would only work with
	# the default port and protocol.
	firewall-cmd --add-port="$port"/"$protocol"
	firewall-cmd --zone=trusted --add-source=10.8.0.0/24
	firewall-cmd --permanent --add-port="$port"/"$protocol"
	firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
	# Set NAT for the VPN subnet
	firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
	firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
	if [[ -n "$ip6" ]]; then
		firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
		firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
		firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
	fi
}

function add_ip_protocol_port_to_iptables() {
	# Create a service to set up persistent iptables rules
	iptables_path=$(command -v iptables)
	ip6tables_path=$(command -v ip6tables)
	# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
	# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
	if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
		iptables_path=$(command -v iptables-legacy)
		ip6tables_path=$(command -v ip6tables-legacy)
	fi

	echo "#!/bin/sh
### BEGIN INIT INFO
# Provides:          myiptables
# Required-Start:    \$local_fs \$network
# Required-Stop:     \$local_fs \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Sets up iptables rules
### END INIT INFO

case \"\$1\" in
  start)
	echo \"Starting iptables configuration...\"
	$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
	$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
	$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
	$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >/etc/init.d/openvpn-iptables

	if [[ -n "$ip6" ]]; then
		echo "$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >>/etc/init.d/openvpn-iptables
	fi
	echo "
	;;
  stop)
	echo \"Stopping iptables configuration...\"
	$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
	$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
	$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
	$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >>/etc/init.d/openvpn-iptables

	if [[ -n "$ip6" ]]; then
		echo "
	$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
	$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
	$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >>/etc/init.d/openvpn-iptables
	fi

	echo "
	;;
  restart|reload)
	echo \"Restarting iptables configuration...\"
	\$0 stop
	\$0 start
	;;
  *)
	echo \"Usage: \$0 {start|stop|restart|reload}\"
	exit 1
esac

exit 0" >>/etc/init.d/openvpn-iptables
	chmod +x /etc/init.d/openvpn-iptables
	update-rc.d openvpn-iptables defaults
	/etc/init.d/openvpn-iptables start
}

function add_protocol_port_to_selinux() {
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
}

function revoke_existing_client() {
	if [[ $headless_mode ]]; then
		echo "You can't revoke an existing client in headless mode."
		exit
	fi

	# This option could be documented a bit better and maybe even be simplified
	# ...but what can I say, I want some sleep too
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$number_of_clients" = 0 ]]; then
		echo
		echo "There are no existing clients!"
		exit
	fi
	echo
	echo "Select the client to revoke:"
	tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	read -r -p "Client: " client_number
	until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
		echo "$client_number: invalid selection."
		read -r -p "Client: " client_number
	done
	client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
	echo
	read -r -p "Confirm $client revocation? [y/N]: " revoke
	until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
		echo "$revoke: invalid selection."
		read -r -p "Confirm $client revocation? [y/N]: " revoke
	done
	if [[ "$revoke" =~ ^[yY]$ ]]; then
		if ! cd /etc/openvpn/server/easy-rsa/; then
			echo "Could not change directory to /etc/openvpn/server/easy-rsa/"
			exit
		fi
		./easyrsa --batch revoke "$client"
		./easyrsa --batch --days=3650 gen-crl
		rm -f /etc/openvpn/server/crl.pem
		cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
		# CRL is read with each client connection, when OpenVPN is dropped to nobody
		chown nobody:"$group_name" /etc/openvpn/server/crl.pem
		echo
		echo "$client revoked!"
	else
		echo
		echo "$client revocation aborted!"
	fi
}

function remove_firewall_rules() {
	ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
	# Using both permanent and not permanent rules to avoid a firewalld reload.
	firewall-cmd --remove-port="$port"/"$protocol"
	firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
	firewall-cmd --permanent --remove-port="$port"/"$protocol"
	firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
	firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
	firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
	if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
		ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
		firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
		firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
		firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
	fi
}

function remove_iptables_rules() {
	/etc/init.d/openvpn-iptables stop
	rm -f /etc/init.d/openvpn-iptables
}

function generate_client_template {
	echo "client
dev tun
proto $protocol
cipher AES-256-GCM
data-ciphers AES-256-GCM
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3" >/etc/openvpn/server/client-common.txt
}

function remove_selinux_port() {
	port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
	protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
	semanage port -d -t openvpn_port_t -p "$protocol" "$port"
}

function uninstall_openvpn() {
	echo
	read -r -p "Confirm OpenVPN removal? [y/N]: " remove
	until [[ "$remove" =~ ^[yYnN]*$ ]]; do
		echo "$remove: invalid selection."
		read -r -p "Confirm OpenVPN removal? [y/N]: " remove
	done
	if [[ "$remove" =~ ^[yY]$ ]]; then
		if [[ -e "/etc/init.d/firewalld" ]]; then
			remove_firewall_rules
		else
			remove_iptables_rules
		fi

		/etc/init.d/openvpn-server stop
		sed -i '/openvpn-server-start/d' /etc/sudoers
		sed -i '/openvpn-server/d' /etc/sudoers
		rm -f /etc/init.d/openvpn-server
		rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
		rm -f /etc/sysctl.d/99-openvpn-forward.conf
		if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
			rm -rf /etc/openvpn/server
			apt-get remove --purge -y openvpn
		else
			# Else, OS must be CentOS or Fedora
			yum remove -y openvpn
			rm -rf /etc/openvpn/server
		fi
		echo
		echo "OpenVPN removed!"
	else
		echo
		echo "OpenVPN removal aborted!"
	fi
}

function generate_server_service() {
	if [[ -e "/etc/init.d/openvpn-server" ]]; then
		echo "The OpenVPN service is already installed."
		return
	fi

	echo "#!/bin/sh
	# /etc/init.d/openvpn
	### BEGIN INIT INFO
	# Provides:          openvpn
	# Required-Start:    \$local_fs \$network
	# Required-Stop:     \$local_fs \$network
	# Default-Start:     2 3 4 5
	# Default-Stop:      0 1 6
	# Short-Description: OpenVPN Server service
	### END INIT INFO

	case \"\$1\" in
	start)
		if [ -e /var/run/openvpn.pid ]; then
		echo \"OpenVPN is already running\"
		exit 1
		fi

		if [ ! -e /etc/openvpn/server/server.conf ]; then
		echo \"OpenVPN server configuration not found\"
		exit 1
		fi

		cd /etc/openvpn/server
		echo \"Starting OpenVPN\"
		/usr/sbin/openvpn --config /etc/openvpn/server/server.conf
		;;
	stop)
		echo \"Stopping OpenVPN\"
		killall openvpn
		;;
	restart)
		\$0 stop
		\$0 start
		;;
	*)
		echo \"Usage: \$0 {start|stop|restart}\"
		exit 1
	esac

	exit 0" > /etc/init.d/openvpn-server
	chmod +x /etc/init.d/openvpn-server
	echo "#!/bin/bash
/etc/init.d/openvpn-server start" > /tmp/openvpn-server-start.sh
	chmod +x /tmp/openvpn-server-start.sh
	echo "ALL ALL=NOPASSWD: /tmp/openvpn-server-start.sh" | tee -a /etc/sudoers
	echo "ALL ALL=NOPASSWD: /etc/init.d/openvpn-server" | tee -a /etc/sudoers
}

check_if_kernel_is_supported
detect_os
check_if_os_supported
check_if_user_is_su
check_if_tun_available
check_if_path_includes_bin

# Orchestration of the script
if [[ ! -e "/etc/openvpn/server/server.conf" ]]; then

	echo 'Welcome to this OpenVPN road warrior installer!'
	download_pre_req
	echo "Pre-req done"
	choose_ipv4
	echo "Ipv4 selection done"
	check_if_ip_is_private
	choose_ipv6
	choose_protocol
	choose_port
	choose_dns_server
	new_client "Enter a name for the first client:" "$client" "n"
	echo "OpenVPN installation is ready to begin."
	read -n1 -r -p "Press any key to continue..."
	download_install_openvpn_and_firewall
	download_install_easy_rsa

	# Create the PKI, set up the CA, the DH params and the server certificates
	create_ca_server_certificates
	generate_server_conf
	echo "Server configuration generated"

	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn-forward.conf

	# Enable without waiting for a reboot or service restart
	# If you are running in docker container, that too in a non-privileged mode, this will fail
	# Ideally, network namespaces can be enabled in non-privileged mode, but that is not the case
	sysctl -w net.ipv4.ip_forward=1
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >>/etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 >/proc/sys/net/ipv6/conf/all/forwarding
	fi
	if [[ -e /etc/init.d/firewalld ]]; then
		add_ip_protocol_port_to_firewall
	else
		add_ip_protocol_port_to_iptables
	fi
	echo "Firewall rules added to $firewall"

	add_protocol_port_to_selinux
	echo "Port added to SELinux (if present)"

	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"

	# client-common.txt is created so we have a template to add further users later
	generate_client_template
	echo "Client template generated"

	generate_server_service

	# Enable and start the OpenVPN service
	nohup "/tmp/openvpn-server-start.sh" > /dev/null 2>&1 &
	echo "OpenVPN service started"
	# Generates the custom client.ovpn
	new_client "" "$client"
	echo
	echo "Finished!"
	echo
	echo "New clients can be added by running this script again."
else
	if [[ $headless_mode ]]; then
		echo "Please run in an interactive mode to use further options"
		exit
	fi
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -r -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -r -p "Option: " option
	done
	case "$option" in
	1)
		new_client "" ""
		exit
		;;
	2)
		revoke_existing_client
		exit
		;;
	3)
		uninstall_openvpn
		exit
		;;
	4)
		exit
		;;
	esac
fi
