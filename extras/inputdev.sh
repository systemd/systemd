#!/bin/sh -e
#
# Scans /proc/bus/input/devices for the given device.
#
# (c) 2004 Darren Salt <linux@youmustbejoking.demon.co.uk>
# GPL v2 or later applies.

[ "$1" ] || exit 0

# input device name, less leading "input/"
DEVICE=${1#input/}

# "|"-separated list.
# The first found in the given device's "N:" line will be output.
DEFAULT_KEYWORDS='dvb|saa7134'
KEYWORDS=${2:-$DEFAULT_KEYWORDS}

exec sed -nre '
  /^I:/ {
    : gather
    N
    /\nH:/! b gather
    /'"$DEVICE"'/ {
      s/^.*\nN:[^\n]*("|\b)('"$KEYWORDS"')("|\b)[^\n]*\n.*$/inputdev/
      T
      p
    }
  }
' < /proc/bus/input/devices

