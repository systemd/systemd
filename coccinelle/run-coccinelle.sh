#!/bin/bash -e

for SCRIPT in ${@-*.cocci} ; do
        [ "$SCRIPT" = "empty-if.cocci" ] && continue
        echo "--x-- Processing $SCRIPT --x--"
        TMPFILE=`mktemp`
        spatch --sp-file $SCRIPT --dir $(pwd)/.. 2> "$TMPFILE" || cat "$TMPFILE"
        rm "$TMPFILE"
        echo "--x-- Processed $SCRIPT --x--"
        echo ""
done
