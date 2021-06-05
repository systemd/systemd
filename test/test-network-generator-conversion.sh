#!/usr/bin/env bash
set -ex

if [[ -n "$1" ]]; then
    generator=$1
elif [[ -x /usr/lib/systemd/systemd-network-generator ]]; then
    generator=/usr/lib/systemd/systemd-network-generator
elif [[ -x /lib/systemd/systemd-network-generator ]]; then
    generator=/lib/systemd/systemd-network-generator
else
    exit 1
fi

src="$(dirname "$0")/testdata/test-network-generator-conversion"

for f in "$src"/test-*.input; do
    echo "*** Running $f"

    (
        out=$(mktemp --tmpdir --directory "test-network-generator-conversion.XXXXXXXXXX")
        trap "rm -rf '$out'" EXIT INT QUIT PIPE

        $generator --root "$out" -- $(cat $f)

        if ! diff -u "$out"/run/systemd/network ${f%.input}.expected; then
            echo "**** Unexpected output for $f"
            exit 1
        fi
    ) || exit 1
done
