---
title: systemd Repository Architecture
category: Contributing
layout: default
---

# Code Map

This section will attempt to provide a high-level overview of the various
components of the systemd repository.

# Source Code

Directories in `src/` provide the implementation of all daemons, libraries and
command-line tools shipped by the project. There are many, and more are
constantly added, so we will not enumerate them all here — the directory
names are self-explanatory.

## Shared Code

You might wonder what kind of common code belongs in `src/shared/` and what
belongs in `src/basic/`. The split is like this: anything that is used to
implement the public shared objects we provide (`sd-bus`, `sd-login`,
`sd-id128`, `nss-systemd`, `nss-mymachines`, `nss-resolve`, `nss-myhostname`,
`pam_systemd`), must be located in `src/basic` (those objects are not allowed
to link to `libsystemd-shared.so`). Conversely, anything which is shared
between multiple components and does not need to be in `src/basic/`, should be
in `src/shared/`.

To summarize:

`src/basic/`
- may be used by all code in the tree
- may not use any code outside of `src/basic/`

`src/libsystemd/`
- may be used by all code in the tree, except for code in `src/basic/`
- may not use any code outside of `src/basic/`, `src/libsystemd/`

`src/shared/`
- may be used by all code in the tree, except for code in `src/basic/`,
`src/libsystemd/`, `src/nss-*`, `src/login/pam_systemd.*`, and files under
`src/journal/` that end up in `libjournal-client.a` convenience library.
- may not use any code outside of `src/basic/`, `src/libsystemd/`, `src/shared/`

## PID 1

Code located in `src/core/` implements the main logic of the systemd system (and user)
service manager.

BPF helpers written in C and used by PID 1 can be found under `src/core/bpf/`.

### Implementing Unit Settings

The system and session manager supports a large number of unit settings. These can generally
be configured in three ways:

1. Via textual, INI-style configuration files called *unit* *files*
2. Via D-Bus messages to the manager
3. Via the `systemd-run` and `systemctl set-property` commands

From a user's perspective, the third is a wrapper for the second. To implement a new unit
setting, it is necessary to support all three input methods:

1. *unit* *files* are parsed in `src/core/load-fragment.c`, with many simple and fixed-type
unit settings being parsed by common helpers, with the definition in the generator file
`src/core/load-fragment-gperf.gperf.in`
2. D-Bus messages are defined and parsed in `src/core/dbus-*.c`
3. `systemd-run` and `systemctl set-property` do client-side parsing and translating into
D-Bus messages in `src/shared/bus-unit-util.c`

So that they are exercised by the fuzzing CI, new unit settings should also be listed in the
text files under `test/fuzz/fuzz-unit-file/`.

## UDEV

Sources for the udev daemon and command-line tool (single binary) can be found under
`src/udev/`.

## Unit Tests

Source files found under `src/test/` implement unit-level testing, mostly for
modules found in `src/basic/` and `src/shared/`, but not exclusively. Each test
file is compiled in a standalone binary that can be run to exercise the
corresponding module. While most of the tests can be ran by any user, some
require privileges, and will attempt to clearly log about what they need
(mostly in the form of effective capabilities). These tests are self-contained,
and generally safe to run on the host without side effects.

Ideally, every module in `src/basic/` and `src/shared/` should have a
corresponding unit test under `src/test/`, exercising every helper function.

# Integration Tests

Sources in `test/` implement system-level testing for executables, libraries and
daemons that are shipped by the project. They require privileges to run, and
are not safe to execute directly on a host. By default they will build an image
and run the test under it via `QEMU` or `systemd-nspawn`.

Most of those tests should be able to run via `systemd-nspawn`, which is orders of
magnitude faster than `QEMU`, but some tests require privileged operations like
using `dm-crypt` or `loopdev`. They are clearly marked if that is the case.

See `test/README.testsuite` for more specific details.

# HWDB

Rules built in the static `HWDB` database shipped by the project can be found
under `hwdb.d/`. Some of these files are updated automatically, some are filled
by contributors.

# Documentation

## systemd.io

Markdown files found under `docs/` are automatically published on the
[systemd.io](https://systemd.io) website using Github Pages. A minimal unit test
to ensure the formatting doesn't have errors is included in the
`meson test -C build/ github-pages` run as part of the CI.

## MAN pages

Manpages for binaries and libraries, and the DBUS interfaces, can be found under
`man/` and should ideally be kept in sync with changes to the corresponding
binaries and libraries.

## Translations

Translations files for binaries and daemons, provided by volunteers, can be found
under `po/` in the usual format. They are kept up to date by contributors and by
automated tools.

# System Configuration files and presets

Presets (or templates from which they are generated) for various daemons and tools
can be found under various directories such as `factory/`, `modprobe.d/`, `network/`,
`presets/`, `rules.d/`, `shell-completion/`, `sysctl.d/`, `sysusers.d/`, `tmpfiles.d/`.

# Utilities for Developers

`tools/`, `coccinelle/`, `.github/`, `.semaphore/`, `.lgtm/`, `.mkosi/` host various
utilities and scripts that are used by maintainers and developers. They are not
shipped or installed.
