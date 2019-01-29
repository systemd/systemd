#!/bin/bash

set -ex

meson build -Dtests=unsafe -Dsplit-usr=true -Dslow-tests=true
ninja -C build
ninja -C build test
DESTDIR=/var/tmp/inst1 ninja -C build install
