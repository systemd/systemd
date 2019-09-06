#!/bin/bash

set -eux

# default to Debian testing
DISTRO=${DISTRO:-debian}
RELEASE=${RELEASE:-buster}
BRANCH=${BRANCH:-master}
ARCH=${ARCH:-amd64}
CONTAINER=${RELEASE}-${ARCH}
CACHE_DIR=${SEMAPHORE_CACHE_DIR:=/tmp}
AUTOPKGTEST_DIR="${CACHE_DIR}/autopkgtest"
# semaphore cannot expose these, but useful for interactive/local runs
ARTIFACTS_DIR=/tmp/artifacts
PHASES=(${@:-SETUP RUN})

create_container() {
    # create autopkgtest LXC image; this sometimes fails with "Unable to fetch
    # GPG key from keyserver", so retry a few times
    for retry in $(seq 5); do
        sudo lxc-create -n $CONTAINER -t download -- -d $DISTRO -r $RELEASE -a $ARCH --keyserver hkp://keyserver.ubuntu.com:80 && break
        sleep $((retry*retry))
    done

    # unconfine the container, otherwise some tests fail
    echo 'lxc.apparmor.profile = unconfined' | sudo tee -a /var/lib/lxc/$CONTAINER/config

    sudo lxc-start -n $CONTAINER

    # enable source repositories so that apt-get build-dep works
    sudo lxc-attach -n $CONTAINER -- sh -ex <<EOF
sed 's/^deb/deb-src/' /etc/apt/sources.list >> /etc/apt/sources.list.d/sources.list
# wait until online
while [ -z "\$(ip route list 0/0)" ]; do sleep 1; done
apt-get -q --allow-releaseinfo-change update
apt-get -y dist-upgrade
apt-get install -y eatmydata
apt-get purge --auto-remove -y unattended-upgrades
EOF
    sudo lxc-stop -n $CONTAINER
}

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            # remove semaphore repos, some of them don't work and cause error messages
            sudo rm -f /etc/apt/sources.list.d/*

            # enable backports for latest LXC
            echo 'deb http://archive.ubuntu.com/ubuntu xenial-backports main restricted universe multiverse' | sudo tee -a /etc/apt/sources.list.d/backports.list
            sudo apt-get -q update
            sudo apt-get install -y -t xenial-backports lxc
            sudo apt-get install -y python3-debian git dpkg-dev fakeroot

            [ -d $AUTOPKGTEST_DIR ] || git clone --quiet --depth=1 https://salsa.debian.org/ci-team/autopkgtest.git "$AUTOPKGTEST_DIR"

            create_container
        ;;
        RUN)
            # add current debian/ packaging
            git fetch --depth=1 https://salsa.debian.org/systemd-team/systemd.git $BRANCH
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
            sed -i '/^CONFFLAGS =/ s/=/= --werror -Dtests=unsafe -Dsplit-usr=true -Dslow-tests=true -Dman=true /' debian/rules
            # no orig tarball
            echo '1.0' > debian/source/format

            # build source package
            dpkg-buildpackage -S -I -I$(basename "$CACHE_DIR") -d -us -uc -nc

            # now build the package and run the tests
            rm -rf "$ARTIFACTS_DIR"
            # autopkgtest exits with 2 for "some tests skipped", accept that
            $AUTOPKGTEST_DIR/runner/autopkgtest --env DEB_BUILD_OPTIONS=noudeb \
                                                --env TEST_UPSTREAM=1 ../systemd_*.dsc \
                                                -o "$ARTIFACTS_DIR" \
                                                -- lxc -s $CONTAINER \
                || [ $? -eq 2 ]
        ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
