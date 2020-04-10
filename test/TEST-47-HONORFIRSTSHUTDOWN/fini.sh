#!/bin/bash
TEST_DESCRIPTION="test honor first shutdown"

if grep -q "EmergencyAction: Shutdown is already active Skipping" /tmp/honorfirstshutdown.log; then
    echo "$TEST_DESCRIPTION [pass]"
    exit 0
else
    echo "$TEST_DESCRIPTION [fail]"
    exit 1
fi
