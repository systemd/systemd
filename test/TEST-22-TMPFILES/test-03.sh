#! /bin/bash
#
# Basic tests for types creating/writing files
#

set -e
set -x

rm -fr /tmp/{f,F,w}
mkdir  /tmp/{f,F,w}
touch /tmp/file-owned-by-root

#
# 'f'
#
systemd-tmpfiles --create - <<EOF
f     /tmp/f/1    0644 - - - -
f     /tmp/f/2    0644 - - - This string should be written
EOF

### '1' should exist and be empty
test -f /tmp/f/1; ! test -s /tmp/f/1
test $(stat -c %U:%G:%a /tmp/f/1) = "root:root:644"

test $(stat -c %U:%G:%a /tmp/f/2) = "root:root:644"
test "$(< /tmp/f/2)" = "This string should be written"

### The perms are supposed to be updated even if the file already exists.
systemd-tmpfiles --create - <<EOF
f     /tmp/f/1    0666 daemon daemon - This string should not be written
EOF

# file should be empty
! test -s /tmp/f/1
test $(stat -c %U:%G:%a /tmp/f/1) = "daemon:daemon:666"

### But we shouldn't try to set perms on an existing file which is not a
### regular one.
mkfifo /tmp/f/fifo
chmod 644 /tmp/f/fifo

! systemd-tmpfiles --create - <<EOF
f     /tmp/f/fifo    0666 daemon daemon - This string should not be written
EOF

test -p /tmp/f/fifo
test $(stat -c %U:%G:%a /tmp/f/fifo) = "root:root:644"

### 'f' should not follow symlinks.
ln -s missing /tmp/f/dangling
ln -s /tmp/file-owned-by-root /tmp/f/symlink

! systemd-tmpfiles --create - <<EOF
f     /tmp/f/dangling    0644 daemon daemon - -
f     /tmp/f/symlink     0644 daemon daemon - -
EOF
! test -e /tmp/f/missing
test $(stat -c %U:%G:%a /tmp/file-owned-by-root) = "root:root:644"

### Handle read-only filesystem gracefully: we shouldn't fail if the target
### already exists and have the correct perms.
mkdir /tmp/f/rw-fs
mkdir /tmp/f/ro-fs

touch /tmp/f/rw-fs/foo
chmod 644 /tmp/f/rw-fs/foo

mount -o bind,ro /tmp/f/rw-fs /tmp/f/ro-fs

systemd-tmpfiles --create - <<EOF
f     /tmp/f/ro-fs/foo    0644 - - - - This string should not be written
EOF
test -f /tmp/f/ro-fs/foo; ! test -s /tmp/f/ro-fs/foo

! systemd-tmpfiles --create - <<EOF
f     /tmp/f/ro-fs/foo    0666 - - - -
EOF
test $(stat -c %U:%G:%a /tmp/f/fifo) = "root:root:644"

! systemd-tmpfiles --create - <<EOF
f     /tmp/f/ro-fs/bar    0644 - - - -
EOF
! test -e /tmp/f/ro-fs/bar

### 'f' shouldn't follow unsafe paths.
mkdir /tmp/f/daemon
ln -s /root /tmp/f/daemon/unsafe-symlink
chown -R --no-dereference daemon:daemon /tmp/f/daemon

! systemd-tmpfiles --create - <<EOF
f     /tmp/f/daemon/unsafe-symlink/exploit    0644 daemon daemon - -
EOF
! test -e /tmp/f/daemon/unsafe-symlink/exploit

#
# 'F'
#
echo "This should be truncated" >/tmp/F/truncated
echo "This should be truncated" >/tmp/F/truncated-with-content

systemd-tmpfiles --create - <<EOF
F     /tmp/F/created                0644 - - - -
F     /tmp/F/created-with-content   0644 - - - new content
F     /tmp/F/truncated              0666 daemon daemon - -
F     /tmp/F/truncated-with-content 0666 daemon daemon - new content
EOF

test -f /tmp/F/created; ! test -s /tmp/F/created
test -f /tmp/F/created-with-content
test "$(< /tmp/F/created-with-content)" = "new content"
test -f /tmp/F/truncated; ! test -s /tmp/F/truncated
test $(stat -c %U:%G:%a /tmp/F/truncated) = "daemon:daemon:666"
test -s /tmp/F/truncated-with-content
test $(stat -c %U:%G:%a /tmp/F/truncated-with-content) = "daemon:daemon:666"

### We shouldn't try to truncate anything but regular files since the behavior is
### unspecified in the other cases.
mkfifo /tmp/F/fifo

! systemd-tmpfiles --create - <<EOF
F     /tmp/F/fifo                0644 - - - -
EOF

test -p /tmp/F/fifo

### 'F' should not follow symlinks.
ln -s missing /tmp/F/dangling
ln -s /tmp/file-owned-by-root /tmp/F/symlink

! systemd-tmpfiles --create - <<EOF
f     /tmp/F/dangling    0644 daemon daemon - -
f     /tmp/F/symlink     0644 daemon daemon - -
EOF
! test -e /tmp/F/missing
test $(stat -c %U:%G:%a /tmp/file-owned-by-root) = "root:root:644"

### Handle read-only filesystem gracefully: we shouldn't fail if the target
### already exists and is empty.
mkdir /tmp/F/rw-fs
mkdir /tmp/F/ro-fs

touch /tmp/F/rw-fs/foo
chmod 644 /tmp/F/rw-fs/foo

mount -o bind,ro /tmp/F/rw-fs /tmp/F/ro-fs

systemd-tmpfiles --create - <<EOF
F     /tmp/F/ro-fs/foo    0644 - - - -
EOF
test -f /tmp/F/ro-fs/foo; ! test -s /tmp/F/ro-fs/foo

echo "truncating is not allowed anymore" >/tmp/F/rw-fs/foo
! systemd-tmpfiles --create - <<EOF
F     /tmp/F/ro-fs/foo    0644 - - - -
EOF

! systemd-tmpfiles --create - <<EOF
F     /tmp/F/ro-fs/foo    0644 - - - - This string should not be written
EOF
test -f /tmp/F/ro-fs/foo; ! test -s /tmp/F/ro-fs/foo

# Trying to change the perms should fail.
>/tmp/F/rw-fs/foo
! systemd-tmpfiles --create - <<EOF
F     /tmp/F/ro-fs/foo    0666 - - - -
EOF
test $(stat -c %U:%G:%a /tmp/F/ro-fs/foo) = "root:root:644"

### Try to create a new file.
! systemd-tmpfiles --create - <<EOF
F     /tmp/F/ro-fs/bar    0644 - - - -
EOF
! test -e /tmp/F/ro-fs/bar

### 'F' shouldn't follow unsafe paths.
mkdir /tmp/F/daemon
ln -s /root /tmp/F/daemon/unsafe-symlink
chown -R --no-dereference daemon:daemon /tmp/F/daemon

! systemd-tmpfiles --create - <<EOF
F     /tmp/F/daemon/unsafe-symlink/exploit    0644 daemon daemon - -
EOF
! test -e /tmp/F/daemon/unsafe-symlink/exploit

#
# 'w'
#
touch /tmp/w/overwritten

### nop if the target does not exist.
systemd-tmpfiles --create - <<EOF
w     /tmp/w/unexistent    0644 - - - new content
EOF
! test -e /tmp/w/unexistent

### no argument given -> fails.
! systemd-tmpfiles --create - <<EOF
w     /tmp/w/unexistent    0644 - - - -
EOF

### write into an empty file.
systemd-tmpfiles --create - <<EOF
w     /tmp/w/overwritten    0644 - - - old content
EOF
test -f /tmp/w/overwritten
test "$(< /tmp/w/overwritten)" = "old content"

### new content is overwritten
systemd-tmpfiles --create - <<EOF
w     /tmp/w/overwritten    0644 - - - new content
EOF
test -f /tmp/w/overwritten
test "$(< /tmp/w/overwritten)" = "new content"

### writing into an 'exotic' file should be allowed.
systemd-tmpfiles --create - <<EOF
w     /dev/null    - - - - new content
EOF

### 'w' follows symlinks
ln -s ./overwritten /tmp/w/symlink
systemd-tmpfiles --create - <<EOF
w     /tmp/w/symlink    - - - - $(readlink -e /tmp/w/symlink)
EOF
readlink -e /tmp/w/symlink
test "$(< /tmp/w/overwritten)" = "/tmp/w/overwritten"

### 'w' shouldn't follow unsafe paths.
mkdir /tmp/w/daemon
ln -s /root /tmp/w/daemon/unsafe-symlink
chown -R --no-dereference daemon:daemon /tmp/w/daemon

! systemd-tmpfiles --create - <<EOF
f     /tmp/w/daemon/unsafe-symlink/exploit    0644 daemon daemon - -
EOF
! test -e /tmp/w/daemon/unsafe-symlink/exploit
