#!/bin/bash

set -ex

sudo add-apt-repository ppa:upstream-systemd-ci/systemd-ci -y
sudo rm -rf /etc/apt/sources.list.d/beineri* /etc/apt/sources.list.d/google-chrome* /etc/apt/sources.list.d/heroku* /etc/apt/sources.list.d/mongodb* /etc/apt/sources.list.d/webupd8team* /etc/apt/sources.list.d/rwky* /etc/apt/sources.list.d/rethinkdb* /etc/apt/sources.list.d/cassandra* /etc/apt/sources.list.d/cwchien* /etc/apt/sources.list.d/rabbitmq* /etc/apt/sources.list.d/docker* /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv}
sudo bash -c "echo 'deb-src http://de.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse' >>/etc/apt/sources.list"
sudo apt-get update -qq
sudo apt-get build-dep systemd -y
sudo apt-get install --force-yes -y util-linux libmount-dev libblkid-dev liblzma-dev libqrencode-dev libmicrohttpd-dev iptables-dev liblz4-dev libcurl4-gnutls-dev unifont clang-3.6 libasan0 itstool kbd cryptsetup-bin net-tools isc-dhcp-client iputils-ping strace qemu-system-x86 linux-image-virtual mount libgpg-error-dev libxkbcommon-dev python-lxml python3-lxml python3-pip libcap-dev
# curl -s https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
# sudo add-apt-repository -y 'deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty main'
# sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install --force-yes -y gettext python3-evdev python3-pyparsing libmount-dev
# sudo apt-get install -y clang-6.0
sudo sh -c 'echo 01010101010101010101010101010101 >/etc/machine-id'
sudo mount -t tmpfs none /tmp
test -d /run/mount || sudo mkdir /run/mount
sudo adduser --system --no-create-home nfsnobody
sudo rm -f /etc/mtab
git clone https://github.com/ninja-build/ninja
cd ninja
./configure.py --bootstrap
sudo cp ninja /usr/bin/
cd ..
pip3 install --user 'meson == 0.46.1'
