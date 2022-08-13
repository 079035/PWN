#!/bin/bash
sudo apt-get update
#ROPgadget
apt install python3-pip
python3 -m pip install ROPgadget
#GEF
apt install curl
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
#pwntools
apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
