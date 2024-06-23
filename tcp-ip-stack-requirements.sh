#!/bin/bash

sudo ip link set dev br0 down
sudo ip link set dev tap0i down

sudo ip link del br0
sudo ip link del tap0i

sudo ip link add br0 type bridge

# Create the tap and name it tap0i
sudo ip tuntap add dev tap0i mode tap

# Bring up the interface in promiscuous mode
sudo ip link set tap0i up promisc on

# Set custom MAC of bridge interface for arp resolv
sudo ip link set dev br0 address aa:aa:aa:aa:aa:aa
# Set needle MAC address of tap0, that use in jos-kernel
sudo ip link set dev tap0i address 10:00:00:11:11:11

# Make tap0i a slave of br0
sudo ip link set tap0i master br0

# Give bridge br0 an IP address of 172.16.0.1
sudo ip addr add 172.16.0.1/24 broadcast 172.16.0.255 dev br0

# Make sure everything is up
sudo ip link set dev br0 up
sudo ip link set dev tap0i up
