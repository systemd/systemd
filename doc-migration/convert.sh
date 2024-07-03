#!/bin/bash

# Array of XML filenames
files=("busctl" "systemd" "journalctl")

# Directory paths
input_dir="../man"
output_dir="source"

echo "---------------------"
echo "Converting xml to rst"
echo ""
# Iterate over the filenames
for file in "${files[@]}"; do
    echo "------------------"
    python3 db2rst.py "${input_dir}/${file}.xml" > "${output_dir}/${file}.rst"
done

# Clean and build
rm -rf build

echo "--------------------"
echo "Building Sphinx Docs"
echo "--------------------"
make html
