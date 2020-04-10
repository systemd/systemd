#!/bin/bash
TEST_DESCRIPTION="test honor first shutdown"

if grep -q "Shutdown is already active. Skipping emergency action request" /tmp/honorfirstshutdown.log; then
    echo "$TEST_DESCRIPTION [pass]"
    exit 0
else
    echo "$TEST_DESCRIPTION [fail]"
    exit 1
fi
