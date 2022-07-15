#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

# Exclude following paths from the Coccinelle transformations
EXCLUDED_PATHS=(
    "src/boot/efi/*"
    "src/shared/linux/*"
    "src/basic/linux/*"
    # Symlinked to test-bus-vtable-cc.cc, which causes issues with the IN_SET macro
    "src/libsystemd/sd-bus/test-bus-vtable.c"
    "src/libsystemd/sd-journal/lookup3.c"
)

TOP_DIR="$(git rev-parse --show-toplevel)"
ARGS=()

# Create an array from files tracked by git...
mapfile -t FILES < <(git ls-files ':/*.[ch]')
# ...and filter everything that matches patterns from EXCLUDED_PATHS
for excl in "${EXCLUDED_PATHS[@]}"; do
    # shellcheck disable=SC2206
    FILES=(${FILES[@]//$excl})
done

case "$1" in
    -i)
        ARGS+=(--in-place)
        shift
        ;;
esac

if ! parallel -h >/dev/null; then
    echo 'Please install GNU parallel (package "parallel")'
    exit 1
fi

[[ ${#@} -ne 0 ]] && SCRIPTS=("$@") || SCRIPTS=("$TOP_DIR"/coccinelle/*.cocci)

for script in "${SCRIPTS[@]}"; do
    echo "--x-- Processing $script --x--"
    TMPFILE="$(mktemp)"
    echo "+ spatch --sp-file $script ${ARGS[*]} ..."
    parallel --halt now,fail=1 --keep-order --noswap --max-args=20 \
             spatch --macro-file="$TOP_DIR/coccinelle/macros.h" --sp-file "$script" "${ARGS[@]}" ::: "${FILES[@]}" \
             2>"$TMPFILE" || cat "$TMPFILE"
    echo -e "--x-- Processed $script --x--\n"
done
