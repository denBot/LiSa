#!/bin/sh

echo "nameserver 8.8.8.8" | cat - /etc/resolv.conf > /tmp/resolv.conf && cat /tmp/resolv.conf > /etc/resolv.conf
echo "precedence ::ffff:0:0/96  100" > /etc/gai.conf

if [ -n "${VPN}" ]; then
  echo "Connecting to VPN."
  openvpn --config "${VPN}/config.ovpn" --daemon
  sleep 3

  if [ $(ip link | grep tun0 | wc -l) -lt 1 ]; then
    echo "Error connecting to VPN."
    exit 2
  fi
fi

echo "ip addr"
ip addr

echo "/etc/hosts"
cat /etc/hosts

echo "/etc/resolv.conf"
cat /etc/resolv.conf

su - lisa -c "API_SUCCESS_URL=\"$API_SUCCESS_URL\" \
              API_FAILURE_URL=\"$API_FAILURE_URL\" \
              VIRUSTOTAL_API_KEY=\"$VIRUSTOTAL_API_KEY\" \
              RABBITMQ_PASS=\"$RABBITMQ_DEFAULT_PASS\" \
              MYSQL_PASS=\"$MYSQL_PASSWORD\" \
              celery -A lisa.web_api.tasks worker --loglevel=info --concurrency=1 -n lisa-worker@%h --without-heartbeat"
