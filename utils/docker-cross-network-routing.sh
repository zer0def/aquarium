#!/bin/sh -ex

sudo iptables -I DOCKER-ISOLATION-STAGE-2 -i "br-$(docker network inspect k3d-cluster0 | jq -r '.[].Id' | head -c12)" -o "br-$(docker network inspect k3d-cluster1 | jq -r '.[].Id' | head -c12)" -j ACCEPT
sudo iptables -I DOCKER-ISOLATION-STAGE-2 -o "br-$(docker network inspect k3d-cluster0 | jq -r '.[].Id' | head -c12)" -i "br-$(docker network inspect k3d-cluster1 | jq -r '.[].Id' | head -c12)" -j ACCEPT
