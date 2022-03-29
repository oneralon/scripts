#!/bin/bash

CN="domain.com"
SUBNET="10.15.0.0"
IP=$(dig TXT +short o-o.myaddr.l.google.com @ns1.google.com)

if [ "$EUID" -ne 0 ]
  then echo "The script should be run under root"
  exit
fi

SERVER_CONF="
port 1194
proto udp
dev tun
topology subnet
server $SUBNET 255.255.255.0
ifconfig-pool-persist ipp.txt
script-security 2
cipher AES-256-CBC
tls-server
mute 10
persist-key
persist-tun
max-clients 50
keepalive 10 900
verb 4
"

CLIENT_CONF="
client
dev tun
proto udp
remote $IP 1194
redirect-gateway def1
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
key-direction 1
auth-nocache
cipher AES-256-CBC
data-ciphers AES-256-CBC
mute-replay-warnings
verb 3
"

install () {
  echo "Installing OpenVPN...";

  export CODENAME="$(cat /etc/*release | grep VERSION_CODENAME | cut -d= -f2)"

  apt update && apt install -y apt-transport-https curl gpg ufw

  curl -fsSL https://swupdate.openvpn.net/repos/openvpn-repo-pkg-key.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/openvpn-repo-pkg-keyring.gpg
  curl -fsSL "https://swupdate.openvpn.net/community/openvpn/repos/openvpn-$CODENAME.list" >/etc/apt/sources.list.d/openvpn.list

  apt update && apt install -y openvpn easy-rsa

  cd /etc/openvpn

  mkdir -p client-configs

  if [[ -f "/etc/openvpn/easy-rsa/easyrsa" ]]; then
    cd easy-rsa
  else
    make-cadir easy-rsa && cd easy-rsa
  fi;

  cat <<EOF > /etc/openvpn/easy-rsa/vars
set_var EASYRSA_BATCH        "yes"
set_var EASYRSA_CA_EXPIRE    3650
set_var EASYRSA_CERT_EXPIRE  365
set_var EASYRSA_DN	         "org"
set_var EASYRSA_REQ_CN       "$CN"
set_var EASYRSA_REQ_COUNTRY  "US"
set_var EASYRSA_REQ_PROVINCE "California"
set_var EASYRSA_REQ_CITY     "Los Angeles"
set_var EASYRSA_REQ_ORG      "Curogram Inc."
set_var EASYRSA_REQ_EMAIL    "info@curogram.com"
set_var EASYRSA_REQ_OU       "IT"
EOF

  export EASYRSA_VARS_FILE="/etc/openvpn/easy-rsa/vars"

  ./easyrsa init-pki
  ./easyrsa build-ca
  ./easyrsa gen-dh
  ./easyrsa build-server-full $CN nopass
  ./easyrsa gen-crl
  openvpn --genkey --secret ta.key

  CONFIG="/etc/openvpn/server.conf"

  cat <<EOF > $CONFIG
$SERVER_CONF
dh /etc/openvpn/easy-rsa/pki/dh.pem
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/$CN.crt
key /etc/openvpn/easy-rsa/pki/private/$CN.key
tls-auth /etc/openvpn/easy-rsa/ta.key 0
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem
EOF

cat <<EOF > /etc/systemd/system/iptables-openvpn.service
[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables -A INPUT -i tun+ -j ACCEPT
ExecStart=/sbin/iptables -A FORWARD -i tun+ -j ACCEPT
ExecStart=/sbin/iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=/sbin/iptables -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=/sbin/iptables -t nat -A POSTROUTING -s $SUBNET/24 -o eth0 -j MASQUERADE
ExecStart=/sbin/iptables -A OUTPUT -o tun+ -j ACCEPT
ExecStop=/sbin/iptables -D INPUT -i tun+ -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -i tun+ -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/sbin/iptables -t nat -D POSTROUTING -s $SUBNET/24 -o eth0 -j MASQUERADE
ExecStop=/sbin/iptables -D OUTPUT -o tun+ -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

  sysctl -w net.ipv4.ip_forward=1

  ufw allow ssh
  ufw allow 1194/udp
  ufw enable

  systemctl start openvpn@server

  systemctl enable iptables-openvpn.service
  systemctl start iptables-openvpn.service

  echo "Done, service name is openvpn-session@server.service";
}

remove () {
  echo "Removing OpenVPN...";

  systemctl stop openvpn@server
  systemctl disable openvpn@server

  systemctl stop iptables-openvpn.service
  systemctl disable iptables-openvpn.service

  ufw disable

  apt purge -y openvpn easy-rsa ufw

  rm -rfv /etc/openvpn /etc/systemd/system/iptables-openvpn.service /etc/apt/sources.list.d/openvpn.list
}

client_add () {
  echo "Adding client $1...";

  CONFIG="/etc/openvpn/client-configs/$CN-$1.ovpn"

  if [[ -f $CONFIG ]]; then
    echo "Config ($CONFIG) for $1 exists already";
    exit 1;
  fi

  cd /etc/openvpn/easy-rsa

  ./easyrsa build-client-full $CN-$1 $2

  SERVER_CA=$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
  SERVER_TA=$(cat /etc/openvpn/easy-rsa/ta.key)
  CLIENT_CA=$(cat /etc/openvpn/easy-rsa/pki/issued/$CN-$1.crt)
  CLIENT_KEY=$(cat /etc/openvpn/easy-rsa/pki/private/$CN-$1.key)

  cat <<EOF > $CONFIG
$CLIENT_CONF
<ca>
$SERVER_CA
</ca>
<tls-auth>
$SERVER_TA
</tls-auth>
<cert>
$CLIENT_CA
</cert>
<key>
$CLIENT_KEY
</key>
EOF

  echo "Done. Client config saved in $CONFIG";
}

client_remove () {
  echo "Removing client $1...";

  CONFIG="/etc/openvpn/client-configs/$CN-$1.ovpn"

  cd /etc/openvpn/easy-rsa

  if [[ -f $CONFIG ]]; then
    ./easyrsa revoke $CN-$1 && ./easyrsa gen-crl && rm $CONFIG

    systemctl restart openvpn@server.service

    echo "Done";
  else
    echo "Config ($CONFIG) for $1 doesn't exist";
    exit 1;
  fi
}

case $1 in
  install)
    install
    ;;

  remove)
    read -p "Are you sure to fully remove OpenVPN (y/n)? " choice
    case "$choice" in
      y|Y)
        remove
        ;;
      *)
        echo "Cancelled";
        exit 0;
        ;;
    esac;
    ;;

  client-add)
    if [[ -z "$2" ]]; then
      echo "Empty client name passed";
      exit 1;
    fi

    if [[ -z "$3" ]]; then
      client_add $2 nopass
    else
      client_add $2 $3
    fi
    ;;

  client-remove)
    if [[ -z "$2" ]]; then
      echo "Empty client name passed";
      exit 1;
    fi

    client_remove $2
    ;;

  *)
    echo "The script usage: openvpn COMMAND [...ARGS]";
    echo "  Commands:";
    echo "    install                - installs openvpn with certs generation";
    echo "    remove                 - removes all related packages/files";
    echo "    client-add USER [PASS] - generates client config for new user";
    echo "    client-remove USER     - removes user config and revokes client certs";
    ;;
esac;

