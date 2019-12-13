#!/bin/bash

set -e
set -x
set -u

REPO_ROOT=${REPO_ROOT:-$(pwd)}

sudo bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse' >>/etc/apt/sources.list"
sudo apt-get update -y
sudo apt-get build-dep systemd -y
sudo apt-get install -y ninja-build python3-pip python3-setuptools quota
pip3 install meson

cd $REPO_ROOT
export PATH="$HOME/.local/bin/:$PATH"
tools/oss-fuzz.sh
timeout --preserve-status 5 ./out/fuzz-unit-file
git clean -dxff

wget https://app.fuzzbuzz.io/releases/cli/latest/linux/fuzzbuzz
chmod +x fuzzbuzz
./fuzzbuzz validate
./fuzzbuzz target test fuzz-unit-file --all

git clone https://github.com/google/oss-fuzz /tmp/oss-fuzz
cd /tmp/oss-fuzz
sudo ./infra/helper.py pull_images

# docker doesn't like colons in filenames so let's create a directory
# whose name can be consumed by the -v option.
# https://github.com/google/oss-fuzz/issues/2428
t=$(mktemp -d)
sudo mount --bind "$REPO_ROOT" "$t"

# helper.py is wrapped in script to trick it into thinking it's "interactive"
# See https://github.com/systemd/systemd/pull/12542#issuecomment-491563572
sudo script -e -c "./infra/helper.py build_fuzzers --clean --sanitizer=memory systemd $t"
sudo script -e -c "./infra/helper.py check_build --sanitizer=memory -e ALLOWED_BROKEN_TARGETS_PERCENTAGE=0 systemd"
