#!/bin/bash

set -ex

# default to Debian testing
DISTRO=${DISTRO:-debian}
RELEASE=${RELEASE:-buster}
ARCH=${ARCH:-amd64}
CONTAINER=${RELEASE}-${ARCH}

# remove semaphore repos, some of them don't work and cause error messages
sudo rm -f /etc/apt/sources.list.d/*

# enable backports for latest LXC
echo 'deb http://archive.ubuntu.com/ubuntu xenial-backports main restricted universe multiverse' | sudo tee -a /etc/apt/sources.list.d/backports.list
sudo apt-get -q update
sudo apt-get install -y -t xenial-backports lxc
sudo apt-get install -y python3-debian git dpkg-dev fakeroot

AUTOPKGTESTDIR=${SEMAPHORE_CACHE_DIR:-/tmp}/autopkgtest
[ -d $AUTOPKGTESTDIR ] || git clone --quiet --depth=1 https://salsa.debian.org/ci-team/autopkgtest.git "$AUTOPKGTESTDIR"

# TODO: cache container image (though downloading/building it takes < 1 min)
# create autopkgtest LXC image
sudo lxc-create -n $CONTAINER -t download -- -d $DISTRO -r $RELEASE -a $ARCH

# unconfine the container, otherwise some tests fail
echo 'lxc.apparmor.profile = unconfined' | sudo tee -a /var/lib/lxc/$CONTAINER/config

sudo lxc-start -n $CONTAINER

# enable source repositories so that apt-get build-dep works
sudo lxc-attach -n $CONTAINER -- sh -ex <<EOF
sed 's/^deb/deb-src/' /etc/apt/sources.list >> /etc/apt/sources.list.d/sources.list
# wait until online
while [ -z "\$(ip route list 0/0)" ]; do sleep 1; done
apt-get -q update
apt-get -y dist-upgrade
apt-get install -y eatmydata
EOF
sudo lxc-stop -n $CONTAINER
