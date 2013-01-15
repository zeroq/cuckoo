#!/bin/bash

# Flush IPTABLES
iptables -F
iptables -t nat -F
# Loopack
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
# Default Policy ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Masquerade virtualbox network
iptables -t nat -A POSTROUTING -s 192.168.56.0/24 -j MASQUERADE

#turn on ip forwarding.  Can be done in /etc/syctl.conf - As I said - lazy.
sysctl -w net.ipv4.ip_forward=1
