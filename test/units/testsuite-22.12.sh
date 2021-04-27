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
systemd-tmpfiles --clean - <<EOF
d /tmp/ageby/d1 - - - 1m:atime -
e /tmp/ageby/d2 - - - 3m:mtime -
D /tmp/ageby/d3 - - - 2s:ctime -
d /tmp/ageby/d4 - - - 1s:btime -
EOF

for d in d{1..4}; do
	test ! -f "/tmp/ageby/${d}/f1"
done

# Check for an invalid "age-by" arguments.
for a in '1s:naptime' '2s:' '"3m: "' ':atime'; do
	echo $a
	systemd-tmpfiles --clean - <<-EOF 2>&1 | grep -q 'Invalid age'
	d /tmp/ageby/d1	- - - ${a} -
	EOF
done

for d in d{1..4}; do
	for f in f{2..4}; do
		test -f "/tmp/ageby/${d}/${f}"
	done
done

# Check that all files are removed if the "Age" is set to
# "0" (regardless of "age-by" argument).
systemd-tmpfiles --clean - <<EOF
d /tmp/ageby/d1 - - - 0:atime -
d /tmp/ageby/d2 - - - 0:mtime -
d /tmp/ageby/d3 - - - 0:ctime -
d /tmp/ageby/d4 - - - 0:btime -
EOF

for d in d{1..4}; do
	for f in f{2..4}; do
		test ! -f "/tmp/ageby/${d}/${f}"
	done
done

# Check that all files are removed if only "Age" is set.
systemd-tmpfiles --clean - <<EOF
d /tmp/ageby/d5 - - - 1s
EOF

for f in f{2..4}; do
	test ! -f "/tmp/ageby/d5/${f}"
done

# To bump "atime".
ls -l /tmp/ageby/d1

# Check if sub-directories are empty, they are removed; also check
# if there is any whitespace in the "Age" field, and it is parsed
# correctly.
systemd-tmpfiles --clean - <<EOF
d /tmp/ageby/   - - - "2s: atime  " -
EOF

for f in d{2..5}; do
	test ! -d "/tmp/ageby/${d}"
done

test -d /tmp/ageby/d1

# Check if sub-directories are removed regardless
# of "age-by", when "Age" is set to "0".
systemd-tmpfiles --clean - <<EOF
d /tmp/ageby/   - - - 0:atime -
EOF

test ! -d /tmp/ageby/d1

# Cleanup the test directory.
rm -rf /tmp/ageby
