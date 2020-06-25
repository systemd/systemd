#!/bin/bash

set -e
set -x
set -u

REPO_ROOT=${REPO_ROOT:-$(pwd)}

sudo bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $(lsb_release -cs) main restricted universe multiverse' >>/etc/apt/sources.list"
sudo apt-get update -y
sudo apt-get build-dep systemd -y
sudo apt-get install -y ninja-build python3-pip python3-setuptools quota
# The following should be dropped when debian packaging has been updated to include them
sudo apt-get install -y libfdisk-dev libp11-kit-dev libssl-dev libpwquality-dev
pip3 install meson

cd $REPO_ROOT
export PATH="$HOME/.local/bin/:$PATH"
tools/oss-fuzz.sh
./out/fuzz-unit-file -max_total_time=5
git clean -dxff
