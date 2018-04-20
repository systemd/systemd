#!/bin/bash -e

files="$(git ls-files ':/*.[ch]')"

for SCRIPT in ${@-coccinelle/*.cocci} ; do
        echo "--x-- Processing $SCRIPT --x--"
        TMPFILE=`mktemp`
        echo "+ spatch --sp-file $SCRIPT ..."
        spatch --sp-file $SCRIPT $files 2>"$TMPFILE" || cat "$TMPFILE"
        rm "$TMPFILE"
        echo -e "--x-- Processed $SCRIPT --x--\n"
done
