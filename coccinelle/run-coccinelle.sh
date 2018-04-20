#!/bin/bash -e

files="$(git ls-files ':/*.[ch]')"
args=

case "$1" in
        -i)
                args="$args --in-place"
                shift
                ;;
esac

for SCRIPT in ${@-coccinelle/*.cocci} ; do
        echo "--x-- Processing $SCRIPT --x--"
        TMPFILE=`mktemp`
        echo "+ spatch --sp-file $SCRIPT $args ..."
        spatch --sp-file $SCRIPT $args $files 2>"$TMPFILE" || cat "$TMPFILE"
        rm "$TMPFILE"
        echo -e "--x-- Processed $SCRIPT --x--\n"
done
