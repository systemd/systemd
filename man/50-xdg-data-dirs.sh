#!/bin/sh
# SPDX-License-Identifier: MIT-0

# set the default value
XDG_DATA_DIRS="${XDG_DATA_DIRS:-/usr/local/share/:/usr/share}"

# add a directory if it exists
if [ -d /opt/foo/share ]; then
    XDG_DATA_DIRS="/opt/foo/share:${XDG_DATA_DIRS}"
fi

# write our output
echo "XDG_DATA_DIRS=${XDG_DATA_DIRS}"
