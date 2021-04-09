#!/usr/bin/env bash

set -eux
set -o pipefail

>/failed

for t in ${0%.sh}.*.sh; do
    echo "Running $t"; ./$t
done

touch /testok
rm /failed
