#!/bin/bash

set -e
set -x
set -u

REPO_ROOT=${REPO_ROOT:-$(pwd)}

cd $REPO_ROOT
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
sudo script -e -c "./infra/helper.py check_build --sanitizer=memory systemd"
