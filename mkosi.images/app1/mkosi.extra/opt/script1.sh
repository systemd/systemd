#!/bin/bash
set -e
test -e /usr/lib/os-release
echo baz >"${STATE_DIRECTORY}/foo"
cat /usr/lib/extension-release.d/extension-release.app2
