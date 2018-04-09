#!/bin/bash

sudo ip addr add 10.0.1.1/24 dev tun0
sudo ifconfig tun0 up

sudo route add -net 10.0.20.0 netmask 255.255.255.0 dev tun0

ifconfig
