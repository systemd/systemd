#!/bin/bash -e

for SCRIPT in ${@-*.cocci} ; do
        echo "--x-- Processing $SCRIPT --x--"
        TMPFILE=`mktemp`
        spatch --sp-file $SCRIPT --dir $(pwd)/.. 2> "$TMPFILE" || cat "$TMPFILE"
        rm "$TMPFILE"
        echo "--x-- Processed $SCRIPT --x--"
        echo ""
done
