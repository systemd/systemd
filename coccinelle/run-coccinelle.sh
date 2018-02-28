#!/bin/bash -e

for SCRIPT in ${@-*.cocci} ; do
        echo "--x-- Processing: spatch --sp-file $SCRIPT --dir $(pwd)/.. --x--"
        TMPFILE=`mktemp`
        spatch --sp-file $SCRIPT --dir $(pwd)/.. 2> "$TMPFILE" || cat "$TMPFILE"
        rm "$TMPFILE"
        echo "--x-- Processed: spatch --sp-file $SCRIPT --dir $(pwd)/.. --x--"
        echo ""
done
