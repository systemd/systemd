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
    # Ignore man examples, as they redefine some macros we use internally, which makes Coccinelle complain
    # and ignore code that tries to use the redefined stuff
    "man/*"
)

TOP_DIR="$(git rev-parse --show-toplevel)"
CACHE_DIR="$(dirname "$0")/.coccinelle-cache"
ARGS=()

# Create an array from files tracked by git...
mapfile -t FILES < <(git ls-files ':/*.c')
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

mkdir -p "$CACHE_DIR"
echo "--x-- Using Coccinelle cache directory: $CACHE_DIR"
echo "--x--"
echo "--x-- Note: running spatch for the first time without populated cache takes"
echo "--x--       a _long_ time (15-30 minutes). Also, the cache is quite large"
echo "--x--       (~15 GiB), so make sure you have enough free space."
echo

for script in "${SCRIPTS[@]}"; do
    echo "--x-- Processing $script --x--"
    TMPFILE="$(mktemp)"
    echo "+ spatch --sp-file $script ${ARGS[*]} ..."
    # A couple of notes:
    #
    # 1) Limit this to 10 files at once, as processing the ASTs is _very_ memory hungry - e.g. with 20 files
    # at once one spatch process can take around 2.5 GiB of RAM, which can easily eat up all available RAM
    # when paired together with parallel
    #
    # 2) Make sure spatch can find our includes via -I <dir>, similarly as we do when compiling stuff.
    #    Also, include the system include path as well, since we're not kernel and we make use of the stdlib
    #    (and other libraries).
    #
    # 3) Make sure to include includes from includes (--recursive-includes), but use them only to get type
    # definitions (--include-headers-for-types) - otherwise we'd start formating them as well, which might be
    # unwanted, especially for includes we fetch verbatim from third-parties
    #
    # 4) Explicitly undefine the SD_BOOT symbol, so Coccinelle ignores includes guarded by #if SD_BOOT
    #
    # 5) Use cache, since generating the full AST is _very_ expensive, i.e. the uncached run takes 15 - 30
    # minutes (for one rule(!)), vs 30 - 90 seconds when the cache is populated. One major downside of the
    # cache is that it's quite big - ATTOW the cache takes around 15 GiB, but the performance boost is
    # definitely worth it
    parallel --halt now,fail=1 --keep-order --noswap --max-args=10 \
        spatch --cache-prefix "$CACHE_DIR" \
               -I src \
               -I /usr/include \
               --recursive-includes \
               --include-headers-for-types \
               --undefined SD_BOOT \
               --macro-file-builtins "coccinelle/parsing_hacks.h" \
               --smpl-spacing \
               --sp-file "$script" \
               "${ARGS[@]}" ::: "${FILES[@]}" \
               2>"$TMPFILE" || cat "$TMPFILE"
    rm -f "$TMPFILE"
    echo -e "--x-- Processed $script --x--\n"
done
