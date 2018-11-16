#!/bin/sh

set -eu

cd "$@"/docs/
(
        echo -e "# systemd Documentation\n"

        for f in *.md ; do
                if [ "x$f" != "xindex.md" ] ; then
                        t=`grep "^# " "$f" | head -n 1 | sed -e 's/^#\s*//'`
                        u="https://systemd.io/"`echo "$f" | sed -e 's/.md$//'`
                        echo "* [$t]($u)"
                fi
        done
) > index.md
