#!/bin/bash

CSV="dhcpd-conf.csv"

function test_config() { FILE="$1"; shift; dhcpd -f -t -q "$@" -cf "$FILE"; }

cd /mnt/morleynas/home

echo "Parsing v4"
./parse_conf.py -t template/dhcpd.template.conf -o gen/dhcpd.conf -s "$CSV" "$@"
echo "Testing v4"
if test_config gen/dhcpd.conf -4; then
  echo "Successful! Copying to /etc/dhcp/dhcpd.conf"
  sudo cp gen/dhcpd.conf /etc/dhcp/dhcpd.conf
else
  echo "Failed! Skipping copy."
fi

echo "Parsing v6"
./parse_conf.py -t template/dhcpd6.template.conf -o gen/dhcpd6.conf -s "$CSV" "$@"
echo "Testing v6"
if test_config gen/dhcpd6.conf -6; then
  echo "Successful! Copying to /etc/dhcp/dhcpd6.conf"
  sudo cp gen/dhcpd6.conf /etc/dhcp/dhcpd6.conf
else
  echo "Failed! Skipping copy."
fi

echo "Restarting service..."
sudo systemctl restart isc-dhcp-server.service
echo "Done"
