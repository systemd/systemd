#!/bin/bash

# Array of XML filenames
files=("busctl" "systemd" "journalctl" "os-release")

# Directory paths
input_dir="../man"
output_dir="source"

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
