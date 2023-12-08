#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test the "Age" parameter (with age-by) for systemd-tmpfiles.
set -e
set -x

# Test directory structure looks like this:
#   /tmp/ageby/
#   ├── d1
#   │   ├── f1
#   │   ├── f2
#   │   ├── f3
#   │   └── f4
#   ├── d2
#   │   ├── f1
#   │   ├── f2
#   ...

export SYSTEMD_LOG_LEVEL="debug"

rm -rf /tmp/ageby
mkdir -p /tmp/ageby/d{1..4}

# TODO: There is probably a better way to figure this out.
# Test for [bB] age-by arguments only on filesystems that expose
# the creation time. Note that this is _not_ an accurate way to
# check if the filesystem or kernel version don't provide the
# timestamp. But, if the timestamp is visible in "stat" it is a
# good indicator that the test can be run.
TEST_TMPFILES_AGEBY_BTIME=${TEST_TMPFILES_AGEBY_BTIME:-0}
if stat --format "%w" /tmp/ageby 2>/dev/null | grep -qv '^[\?\-]$'; then
    TEST_TMPFILES_AGEBY_BTIME=1
fi

touch -a --date "2 minutes ago" /tmp/ageby/d1/f1
touch -m --date "4 minutes ago" /tmp/ageby/d2/f1

# Create a bunch of other files.
touch /tmp/ageby/d{1,2}/f{2..4}

# For "ctime".
touch /tmp/ageby/d3/f1
chmod +x /tmp/ageby/d3/f1
sleep 1

# For "btime".
touch /tmp/ageby/d4/f1
sleep 1

# More files with recent "{a,b}time" values.
touch /tmp/ageby/d{3,4}/f{2..4}

# Check for cleanup of "f1" in each of "/tmp/d{1..4}".
systemd-tmpfiles --dry-run --clean - <<-EOF
d /tmp/ageby/d1 - - - a:1m -
e /tmp/ageby/d2 - - - m:3m -
D /tmp/ageby/d3 - - - c:2s -
EOF

for d in d{1..3}; do
    test -f "/tmp/ageby/${d}/f1"
done

systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/d1 - - - a:1m -
e /tmp/ageby/d2 - - - m:3m -
D /tmp/ageby/d3 - - - c:2s -
EOF

for d in d{1..3}; do
    test ! -f "/tmp/ageby/${d}/f1"
done

if [[ $TEST_TMPFILES_AGEBY_BTIME -gt 0 ]]; then
    systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/d4 - - - b:1s -
EOF

    test ! -f "/tmp/ageby/d4/f1"
else
    # Remove the file manually.
    rm "/tmp/ageby/d4/f1"
fi

# Check for an invalid "age" and "age-by" arguments.
for a in ':' ':1s' '2:1h' 'nope:42h' '"  :7m"' 'm:' '::' '"+r^w-x:2/h"' 'b ar::64'; do
    systemd-tmpfiles --clean - <<EOF 2>&1 | grep -q -F 'Invalid age'
d /tmp/ageby - - - ${a} -
EOF
done

for d in d{1..4}; do
    for f in f{2..4}; do
        test -f "/tmp/ageby/${d}/${f}"
    done
done

# Check for parsing with whitespace, repeated values
# for "age-by" (valid arguments).
for a in '"  a:24h"' 'cccaab:2h' '" aa : 4h"' '" a A B C c:1h"'; do
    systemd-tmpfiles --clean - <<EOF
d /tmp/ageby - - - ${a} -
EOF
done

for d in d{1..4}; do
    for f in f{2..4}; do
        test -f "/tmp/ageby/${d}/${f}"
    done
done

# Check that all files are removed if the "Age" is
# set to "0" (regardless of "age-by" argument).
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/d1 - - - abc:0 -
e /tmp/ageby/d2 - - - cmb:0 -
EOF

for d in d{1,2}; do
    for f in f{2..4}; do
        test ! -f "/tmp/ageby/${d}/${f}"
    done
done

# Check for combinations:
#   - "/tmp/ageby/d3/f2" has file timestamps that
#     are older than the specified age, it will be
#     removed
#   - "/tmp/ageby/d4/f2", has not aged for the given
#     timestamp combination, it will not be removed
touch -a -m --date "4 minutes ago" /tmp/ageby/d3/f2
touch -a -m --date "8 minutes ago" /tmp/ageby/d4/f2
systemd-tmpfiles --clean - <<-EOF
e /tmp/ageby/d3 - - - am:3m -
D /tmp/ageby/d4 - - - mc:7m -
EOF

test ! -f "/tmp/ageby/d3/f2"
test -f "/tmp/ageby/d4/f2"

# Check that all files are removed if only "Age" is set to 0.
systemd-tmpfiles --clean - <<-EOF
e /tmp/ageby/d3 - - - 0s
d /tmp/ageby/d4 - - - 0s
EOF

for d in d{3,4}; do
    for f in f{2..4}; do
        test ! -f "/tmp/ageby/$d/${f}"
    done
done

# Check "age-by" argument for sub-directories in "/tmp/ageby".
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/ - - - A:1m -
EOF

for d in d{1..4}; do
    test -d "/tmp/ageby/${d}"
done

# Check for combinations.
touch -a -m --date "5 seconds ago" /tmp/ageby/d{1,2}
systemd-tmpfiles --clean - <<-EOF
e /tmp/ageby/ - - - AM:4s -
EOF

for d in d{1,2}; do
    test ! -d "/tmp/ageby/${d}"
done

for d in d{3,4}; do
    test -d "/tmp/ageby/${d}"
done

# Check "btime" for directories.
if [[ $TEST_TMPFILES_AGEBY_BTIME -gt 0 ]]; then
    systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/ - - - B:8s -
EOF

    for d in d{3,4}; do
        test -d "/tmp/ageby/${d}"
    done
fi

# To bump "atime".
touch -a --date "1 second ago" /tmp/ageby/d3
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/ - - - A:2s -
EOF

test -d /tmp/ageby/d3
test ! -d /tmp/ageby/d4

# Check if sub-directories are removed regardless
# of "age-by", when "Age" is set to "0".
systemd-tmpfiles --clean - <<-EOF
D /tmp/ageby/ - - - AM:0 -
EOF

test ! -d /tmp/ageby/d3

# Cleanup the test directory (fail if not empty).
rmdir /tmp/ageby
