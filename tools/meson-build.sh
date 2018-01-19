#!/bin/sh
set -eux

src="$1"
dst="$2"
target="$3"
options="$4"

[ -d "$dst" ] || meson "$src" "$dst" $options
ninja -C "$dst" "$target"
