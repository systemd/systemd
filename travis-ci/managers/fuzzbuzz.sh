#!/bin/bash

set -e
set -x

cd $REPO_ROOT
wget https://app.fuzzbuzz.io/releases/cli/latest/linux/fuzzbuzz
chmod +x fuzzbuzz
./fuzzbuzz validate
./fuzzbuzz target test fuzz-unit-file --all
