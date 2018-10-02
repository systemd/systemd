#!/bin/sh

set -eu

cd "$@"/docs/
(
        echo "# systemd Documentation"

        for f in *.md ; do
                if [ "x$f" != "xindex.md" ] ; then
                        t=`grep "^# " "$f" | head -n 1 | sed -e 's/^#\s*//'`
                        echo -e "\n* [$t]($f)"
                fi
        done
) > index.md
