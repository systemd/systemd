#!/bin/bash

# Apply patches to the working directory
# Note: Every patch that is to be applied by this script must be prefixed systemd-

TARGET_DIR="$1"

# Check environment
[ -z "$CI_PATCH_DIR" ] && echo "ERROR: CI_PATCH_DIR must be set" && exit 1

pushd "$TARGET_DIR"
for p in $CI_PATCH_DIR/systemd-*
do
	patch --verbose -p1 < "$p"
done

popd
