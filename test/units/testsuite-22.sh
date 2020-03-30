#!/usr/bin/env bash

set -x
set -e

>/failed

for t in ${0%.sh}.*.sh; do
    echo "Running $t"; ./$t
done

touch /testok
rm /failed
