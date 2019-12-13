#!/bin/bash -e

# Exclude following paths from the Coccinelle transformations
EXCLUDED_PATHS=(
    "src/boot/efi/*"
    "src/shared/linux/*"
    "src/basic/linux/*"
    # Symlinked to test-bus-vtable-cc.cc, which causes issues with the IN_SET macro
    "src/libsystemd/sd-bus/test-bus-vtable.c"
)

top="$(git rev-parse --show-toplevel)"
iso_defs="$top/coccinelle/systemd-definitions.iso"
args=

# Create an array from files tracked by git...
mapfile -t files < <(git ls-files ':/*.[ch]')
# ...and filter everything that matches patterns from EXCLUDED_PATHS
for excl in "${EXCLUDED_PATHS[@]}"; do
    files=(${files[@]//$excl})
done

case "$1" in
    -i)
        args="$args --in-place"
        shift
        ;;
esac

if ! parallel -h >/dev/null; then
    echo 'Please install GNU parallel (package "parallel")'
    exit 1
fi

for SCRIPT in ${@-$top/coccinelle/*.cocci} ; do
    echo "--x-- Processing $SCRIPT --x--"
    TMPFILE=`mktemp`
    echo "+ spatch --sp-file $SCRIPT $args ..."
    parallel --halt now,fail=1 --keep-order --noswap --max-args=20 \
             spatch --iso-file $iso_defs --sp-file $SCRIPT $args ::: "${files[@]}" \
             2>"$TMPFILE" || cat "$TMPFILE"
    echo -e "--x-- Processed $SCRIPT --x--\n"
done
