#! /bin/bash

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

rm -rf /tmp/ageby/d{1..5}
mkdir -p /tmp/ageby/d{1..5}

touch -a --date "2 minutes ago" /tmp/ageby/d1/f1
touch -m --date "4 minutes ago" /tmp/ageby/d2/f1

# Create a bunch of other files.
touch /tmp/ageby/d{1,2,5}/f{2..4}

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
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/d1 - - - a:1m -
e /tmp/ageby/d2 - - - m:3m -
D /tmp/ageby/d3 - - - c:2s -
d /tmp/ageby/d4 - - - b:1s -
EOF

for d in d{1..4}; do
    test ! -f "/tmp/ageby/${d}/f1"
done

# Check for an invalid "age" and "age-by" arguments.
for a in ':1s' '2:1h' 'nope:42h' '"  :7m"' 'm:' ':' '"+r*w-x:2h"' 'bar:64'; do
    systemd-tmpfiles --clean - <<EOF 2>&1 | grep -q -F 'Invalid age'
d /tmp/ageby/d1 - - - ${a} -
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
d /tmp/ageby/d1 - - - ${a} -
EOF
done

for d in d{1..4}; do
    for f in f{2..4}; do
        test -f "/tmp/ageby/${d}/${f}"
    done
done

# Check that all files are removed if the "Age" is set to
# "0" (regardless of "age-by" argument).
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/d1 - - - abc:0 -
e /tmp/ageby/d2 - - - cmb:0 -
EOF

for d in d{1,2}; do
    for f in f{2..4}; do
        test ! -f "/tmp/ageby/${d}/${f}"
    done
done

# Check for combinations; since "/tmp/ageby/d{3,4}/f2" have
# at least one of the specified file timestamp types older
# than the specifed age, they will be removed.
touch -a --date "4 minutes ago" /tmp/ageby/d3/f2
touch -m --date "8 minutes ago" /tmp/ageby/d4/f2
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/d3 - - - abc:3m -
e /tmp/ageby/d4 - - - mab:7m -
EOF

for d in d{3,4}; do
    test ! -f "/tmp/ageby/${d}/f2"
done

# Check that all files are removed if only "Age" is set.
systemd-tmpfiles --clean - <<-EOF
e /tmp/ageby/d3 - - - 0s
D /tmp/ageby/d4 - - - 0s
d /tmp/ageby/d5 - - - 1s
EOF

for d in d{3..5}; do
    for f in f{2..4}; do
        test ! -f "/tmp/ageby/$d/${f}"
    done
done

# Check that "a" doesn't mean "A" (for directories).
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/ - - - a:2s -
EOF

for f in d{2..5}; do
    test -d "/tmp/ageby/${d}"
done

# To bump "atime".
ls -l /tmp/ageby/d1 1>/dev/null 2>&1

# Check if sub-directories are empty, they are removed.
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/ - - - A:2s -
EOF

test -d /tmp/ageby/d1

for f in d{2..5}; do
    test ! -d "/tmp/ageby/${d}"
done

# Check if sub-directories are removed regardless
# of "age-by", when "Age" is set to "0".
systemd-tmpfiles --clean - <<-EOF
d /tmp/ageby/ - - - Aab:0 -
EOF

test ! -d /tmp/ageby/d1

# Cleanup the test directory (fail if not empty).
rmdir /tmp/ageby
