#!/bin/bash

set -x
set -e

>/failed

for t in test-*.sh; do
        echo "Running $t"; ./$t
done

touch /testok
rm /failed
