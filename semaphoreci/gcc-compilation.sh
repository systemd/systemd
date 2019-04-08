#!/bin/bash

set -ex

# keep this in sync with setup.sh
CONTAINER=${RELEASE:-buster}-${ARCH:-amd64}
AUTOPKGTESTDIR=${SEMAPHORE_CACHE_DIR:-/tmp}/autopkgtest
# semaphore cannot expose these, but useful for interactive/local runs
ARTIFACTS_DIR=/tmp/artifacts

# add current debian/ packaging
git fetch --depth=1 https://salsa.debian.org/systemd-team/systemd.git master
git checkout FETCH_HEAD debian

# craft changelog
UPSTREAM_VER=$(git describe | sed 's/^v//')
cat << EOF > debian/changelog.new
systemd (${UPSTREAM_VER}-0) UNRELEASED; urgency=low

  * Automatic build for upstream test

 -- systemd test <pkg-systemd-maintainers@lists.alioth.debian.org>  $(date -R)

EOF
cat debian/changelog >> debian/changelog.new
mv debian/changelog.new debian/changelog

# clean out patches
rm -rf debian/patches
# disable autopkgtests which are not for upstream
sed -i '/# NOUPSTREAM/ q' debian/tests/control
# enable more unit tests
sed -i '/^CONFFLAGS =/ s/=/= -Dtests=unsafe -Dsplit-usr=true -Dslow-tests=true /' debian/rules
# no orig tarball
echo '1.0' > debian/source/format

# build source package
dpkg-buildpackage -S -I -I$(basename "$SEMAPHORE_CACHE_DIR") -d -us -uc -nc

# now build the package and run the tests
rm -rf "$ARTIFACTS_DIR"
# autopkgtest exits with 2 for "some tests skipped", accept that
$AUTOPKGTESTDIR/runner/autopkgtest --apt-upgrade --env DEB_BUILD_OPTIONS=noudeb --env TEST_UPSTREAM=1 ../systemd_*.dsc -o "$ARTIFACTS_DIR" -- lxc -s $CONTAINER || [ $? -eq 2 ]
