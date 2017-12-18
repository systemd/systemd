#!/bin/bash

# Apply patches for coverity
# Note: Every patch that is to be applied by this script must be prefixed cov-

# Directory to cd into before applying patches
TARGET_DIR="$1"

# Check environment
[ -z "$CI_PATCH_DIR" ] && echo "ERROR: CI_PATCH_DIR must be set" && exit 1

pushd "$TARGET_DIR"
for p in $CI_PATCH_DIR/cov-*
do
	patch --verbose -p1 < "$p"
done

popd
