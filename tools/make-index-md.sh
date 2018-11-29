#!/bin/sh

set -eu

cd "$@"/docs/
(
        echo -e "# systemd Documentation\n"

        for f in *.md ; do
                if [ "x$f" != "xindex.md" ] ; then
                        t=`grep "^# " "$f" | head -n 1 | sed -e 's/^#\s*//'`

                        if [ "x$f" = "xCODE_OF_CONDUCT.md" -o "x$f" = "xCONTRIBUTING.md" ] ; then
                                # For some reason GitHub refuses to generate
                                # HTML versions of these two documents,
                                # probably because they are in some way special
                                # in GitHub behaviour (as they are shown as
                                # links in the issue submission form). Let's
                                # work around this limitation by linking to
                                # their repository browser version
                                # instead. This might not even be such a bad
                                # thing, given that the issue submission form
                                # and our index file thus link to the same
                                # version.
                                u="https://github.com/systemd/systemd/blob/master/docs/$f"
                        else
                                u="https://systemd.io/"`echo "$f" | sed -e 's/.md$//'`
                        fi
                        echo "* [$t]($u)"
                fi
        done
) > index.md
