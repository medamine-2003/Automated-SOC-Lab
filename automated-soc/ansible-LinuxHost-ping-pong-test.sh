#!/bin/bash
# A simple "Bootstrap" script for your SOC project
HOST="10.0.2.15"
USER="s1_lmrig3l"
PASS="161514"

# 1. Automatically accept the host key and push your SSH key
sshpass -p "$PASS" ssh-copy-id -o StrictHostKeyChecking=no $USER@$HOST

# 2. Now run your Ansible ping/playbook
ansible -i inventory.ini all -m ping
