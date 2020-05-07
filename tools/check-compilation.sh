#!/bin/sh
set -eu

"$@" '-' -o/dev/null </dev/null
