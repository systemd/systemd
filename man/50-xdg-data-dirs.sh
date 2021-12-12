#!/bin/sh
# SPDX-License-Identifier: CC0-1.0

# set the default value
XDG_DATA_DIRS="${XDG_DATA_DIRS:-/usr/local/share/:/usr/share}"

# add a directory if it exists
if [ -d /opt/foo/share ]; then
    XDG_DATA_DIRS="/opt/foo/share:${XDG_DATA_DIRS}"
fi

# write our output
echo "XDG_DATA_DIRS=${XDG_DATA_DIRS}"
