#!/bin/sh
# Call the udev rule syntax checker on all rules that we ship
#
# (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

# skip if we don't have python
type ${PYTHON:-python} >/dev/null 2>&1 || {
        echo "$0: No $PYTHON installed, skipping udev rule syntax check"
        exit 0
}

$PYTHON $srcdir/test/rule-syntax-check.py
