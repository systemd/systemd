#!/bin/bash

set -e
set -x

cd $REPO_ROOT
wget https://app.fuzzbuzz.io/releases/cli/latest/linux/fuzzbuzz
chmod +x fuzzbuzz
./fuzzbuzz validate
./fuzzbuzz target test fuzz-unit-file --all

git clone https://github.com/google/oss-fuzz /tmp/oss-fuzz
cd /tmp/oss-fuzz
sudo ./infra/helper.py pull_images
sudo ./infra/helper.py build_fuzzers --clean --sanitizer=memory systemd $REPO_ROOT
sudo ./infra/helper.py check_build --sanitizer=memory systemd
