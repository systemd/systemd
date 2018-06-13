#!/bin/bash -e

top="$(git rev-parse --show-toplevel)"
files="$(git ls-files ':/*.[ch]')"
args=

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
                 spatch --sp-file $SCRIPT $args ::: $files \
                 2>"$TMPFILE" || cat "$TMPFILE"
        echo -e "--x-- Processed $SCRIPT --x--\n"
done
