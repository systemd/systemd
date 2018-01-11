#!/bin/bash

# Download and install docker-remote
# Sets up venv folder
# Notes: run with sudo command

# Make sure python3 is installed and install git and virtual environment
sudo apt-get update && sudo apt-get -y install python3 python3-pip git
sudo apt-get install -y $(apt-cache search venv | cut -d' ' -f 1)

# Get the tool from github and install it
git clone https://github.com/CermakM/docker-remote.git

# We need to setup virtual environment here to solve disable_warning issue
python3 -m venv venv
source venv/bin/activate

pushd docker-remote
pip install .
popd
