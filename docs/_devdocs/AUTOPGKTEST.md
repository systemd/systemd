---
title: Autopkgtest - Defining tests for Debian packages
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Test description

Full system integration/acceptance testing is done through [autopkgtests](https://salsa.debian.org/ci-team/autopkgtest/-/blob/master/doc/README.package-tests.rst). These test the actual installed binary distribution packages. They are run in QEMU or containers and thus can do intrusive and destructive things such as installing arbitrary packages, modifying arbitrary files in the system (including grub boot parameters), rebooting, or loading kernel modules.

The tests for systemd are defined in the [Debian package's debian/tests](https://salsa.debian.org/systemd-team/systemd/tree/master/debian/tests) directory. For validating a pull request, the Debian package is built using the unpatched code from that PR (via the [checkout-upstream](https://salsa.debian.org/systemd-team/systemd/blob/master/debian/extra/checkout-upstream) script), and the tests run against these built packages. Note that some tests which check Debian specific behaviour are skipped in "test upstream" mode.

# Infrastructure

systemd's GitHub project has webhooks that trigger autopkgtests on Ubuntu 18.04 LTS on three architectures:

* i386: 32 bit x86, little endian, QEMU (OpenStack cloud instance)
* amd64: 64 bit x86, little endian, QEMU (OpenStack cloud instance)
* arm64: 64 bit ARM, little endian, QEMU (OpenStack cloud instance)
* s390x: 64 bit IBM z/Series, big endian, LXC (this architecture is not yet available in Canonical's OpenStack and thus skips some tests)

Please see the [Ubuntu CI infrastructure](https://wiki.ubuntu.com/ProposedMigration/AutopkgtestInfrastructure) documentation for details about how this works.

# Manually retrying/triggering tests on the infrastructure

The current tests are fairly solid by now, but rarely they fail on infrastructure/network issues or race conditions. If you encounter these, please notify @iainlane in the GitHub PR for debugging/fixing those -- transient infrastructure issues are supposed to be detected automatically, and tests auto-retry on those; and flaky tests should of course be fixed properly. But sometimes it is useful to trigger tests on a different Ubuntu release too, for example to test a PR on a newer kernel or against current build/binary dependencies (cgroup changes, util-linux, gcc, etc.).

This can be done using the generic [retry-github-test](https://git.launchpad.net/autopkgtest-cloud/tree/charms/focal/autopkgtest-cloud-worker/autopkgtest-cloud/tools/retry-github-test) script from [Ubuntu's autopkgtest infrastructure](https://git.launchpad.net/autopkgtest-cloud): you need the parameterized URL from the [configured webhooks](https://github.com/systemd/systemd/settings/hooks) and the shared secret (Ubuntu's CI needs to restrict access to avoid DoSing and misuse).

You can use Martin Pitt's [retry-gh-systemd-test](https://piware.de/gitweb/?p=bin.git;a=blob;f=retry-gh-systemd-test) shell wrapper around retry-github-test for that. You need to adjust the path where you put retry-github-test and the file with the shared secret, then you can call it like this:

```sh
$ retry-gh-systemd-test <#PR> <architecture> [release]
```

where `release` defaults to `bionic` (aka Ubuntu 18.04 LTS). For example:

```sh
$ retry-gh-systemd-test 1234 amd64
$ retry-gh-systemd-test 2345 s390x cosmic
```

Please make sure to not trigger unknown [releases](https://launchpad.net/ubuntu/+series) or architectures as they will cause a pending test on the PR which never gets finished.

# Test the code from the PR locally

As soon as a test on the infrastructure finishes, the "Details" link in the PR "checks" section will point to the `log.gz` log. You can download the individual test log, built .debs, and other artifacts that tests leave behind (some dump a complete journal or the udev database on failure) by replacing `/log.gz` with `/artifacts.tar.gz` in that URL. You can then unpack the tarball and use `sudo dpkg -iO binaries/*.deb` to install the debs from the PR into an Ubuntu VM of the same release/architecture for manually testing a PR.

# Run autopkgtests locally

Preparations:

* Get autopkgtest:
  ```sh
    git clone https://salsa.debian.org/ci-team/autopkgtest.git
  ```

* Install necessary dependencies; on Debian/Ubuntu you can simply run `sudo apt install autopkgtest` (instead of the above cloning), on Fedora do `yum install qemu-kvm dpkg-perl`

* Build a test image based on Ubuntu cloud images for the desired release/arch:
  ```sh
    autopkgtest/tools/autopkgtest-buildvm-ubuntu-cloud -r bionic -a amd64
  ```

  This will build `autopkgtest-bionic-amd64.img`. This is normally being used through the `autopkgtest` command (see below), but you can boot this normally in QEMU (using `-snapshot` is highly recommended) to interactively poke around; this provides a easy throw-away test environment.


The most basic mode of operation is to run the tests for the current distro packages:

```sh
autopkgtest/runner/autopkgtest systemd -- qemu autopkgtest-bionic-amd64.img
```

But autopkgtest allows lots of [different modes](https://salsa.debian.org/ci-team/autopkgtest/-/blob/master/doc/README.running-tests.rst) and [options](http://manpages.ubuntu.com/autopkgtest), like running a shell on failure (`-s`), running a single test only (`--test-name`), running the tests from a local checkout of the Debian source tree (possibly with modifications to the test) instead of from the distribution source, or running QEMU with more than one CPU (check the [autopkgtest-virt-qemu manpage](http://manpages.ubuntu.com/autopkgtest-virt-qemu).

A common use case is to check out the Debian packaging git for getting/modifying the tests locally:

```sh
git clone https://salsa.debian.org/systemd-team/systemd.git /tmp/systemd-debian/
```

and running these against the binaries from a PR (see above), running only the `logind` test, getting a shell on failure, showing the boot output, and running with 2 CPUs:

```sh
autopkgtest/runner/autopkgtest --test-name logind /tmp/binaries/*.deb /tmp/systemd-debian/ -s -- \
  qemu --show-boot --cpus 2 /srv/vm/autopkgtest-bionic-amd64.img
```

# Contact

For troubles with the infrastructure, please notify [iainlane](https://github.com/iainlane) in the affected PR.
