#!/bin/bash

# Flush IPTABLES
iptables -F
iptables -t nat -F
# Default Policy ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Redirect IPs to local machine
iptables -t nat -A PREROUTING -s 192.168.56.0/24 -j DNAT --to-destination 192.168.56.1

#turn off ip forwarding.
sysctl -w net.ipv4.ip_forward=0
