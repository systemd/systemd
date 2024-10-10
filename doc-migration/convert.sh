#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Array of XML filenames
files=("sd_journal_get_data" "busctl" "systemd" "journalctl" "os-release")

# Directory paths
input_dir="../man"
output_dir="source/docs"

echo "---------------------"
echo "Converting xml to rst"
echo ""
# Iterate over the filenames
for file in "${files[@]}"; do
    echo "------------------"
    python3 main.py --dir ${input_dir} --output ${output_dir} --file "${file}.xml"
done

# Clean and build
rm -rf build

echo "--------------------"
echo "Building Sphinx Docs"
echo "--------------------"
make html
