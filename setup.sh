#!/bin/bash

echo "[!] Sudo needed to copy to /etc/ and /usr/ directories:"
echo "- Pwdlyser.py to /usr/local/bin/"
echo "- Config files to /etc/pwdlyser/"
sudo -H cp pwdlyser.py /usr/local/bin/pwdlyser
sudo -H mkdir /etc/pwdlyser/
sudo -H cp  *.conf /etc/pwdlyser/
