#!/bin/bash -e

for SCRIPT in ${@-*.cocci} ; do
        echo "--x-- Processing $SCRIPT --x--"
        TMPFILE=`mktemp`
        ( set -x ; spatch --sp-file $SCRIPT --dir $PWD/.. 2> "$TMPFILE" || cat "$TMPFILE" )
        rm "$TMPFILE"
        echo -e "--x-- Processed $SCRIPT --x--\n"
done
