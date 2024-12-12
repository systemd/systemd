---
title: systemd Repository Architecture
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# The systemd Repository Architecture

## Code Map

This document provides a high-level overview of the various components of the systemd repository.

## Source Code

Directories in `src/` provide the implementation of all daemons, libraries and command-line tools shipped by the project.
There are many, and more are constantly added, so we will not enumerate them all here — the directory names are self-explanatory.

### Shared Code

The code that is shared between components is split into a few directories, each with a different purpose:

- `src/basic/` and `src/fundamental/` — those directories contain code primitives that are used by all other code.
  `src/fundamental/` is stricter, because it used for EFI and user-space code, while `src/basic/` is only used for user-space code.
  The code in `src/fundamental/` cannot depend on any other code in the tree, and `src/basic/` can depend only on itself and `src/fundamental/`.
  For user-space, a static library is built from this code and linked statically in various places.

- `src/libsystemd/` implements the `libsystemd.so` shared library (also available as static `libsystemd.a`).
  This code may use anything in `src/basic/` or `src/fundamental/`.

- `src/shared/` provides various utilities and code shared between other components that is exposed as the `libsystemd-shared-<nnn>.so` shared library.

The other subdirectories implement individual components.
They may depend only on `src/fundamental/` + `src/basic/`, or also on `src/libsystemd/`, or also on `src/shared/`.

You might wonder what kind of code belongs where.
In general, the rule is that code should be linked as few times as possible, ideally only once.
Thus code that is used by "higher-level" components (e.g. our binaries which are linked to `libsystemd-shared-<nnn>.so`),
would go to a subdirectory specific to that component if it is only used there.
If the code is to be shared between components, it'd go to `src/shared/`.
Shared code that is used by multiple components that do not link to `libsystemd-shared-<nnn>.so` may live either in `src/libsystemd/`, `src/basic/`, or `src/fundamental/`.
Any code that is used only for EFI goes under `src/boot/efi/`, and `src/fundamental/` if is shared with non-EFI compoenents.

To summarize:

`src/fundamental/`
- may be used by all code in the tree
- may not use any code outside of `src/fundamental/`

`src/basic/`
- may be used by all code in the tree
- may not use any code outside of `src/fundamental/` and `src/basic/`

`src/libsystemd/`
- may be used by all code in the tree that links to `libsystem.so`
- may not use any code outside of `src/fundamental/`, `src/basic/`, and `src/libsystemd/`

`src/shared/`
- may be used by all code in the tree, except for code in `src/basic/`, `src/libsystemd/`, `src/nss-*`, `src/login/pam_systemd.*`,
  and files under `src/journal/` that end up in `libjournal-client.a` convenience library.
- may not use any code outside of `src/fundamental/`, `src/basic/`, `src/libsystemd/`, `src/shared/`

### PID 1

Code located in `src/core/` implements the main logic of the systemd system (and user) service manager.

BPF helpers written in C and used by PID 1 can be found under `src/core/bpf/`.

#### Implementing Unit Settings

The system and session manager supports a large number of unit settings.
These can generally be configured in three ways:

1. Via textual, INI-style configuration files called *unit* *files*
2. Via D-Bus messages to the manager
3. Via the `systemd-run` and `systemctl set-property` commands

From a user's perspective, the third is a wrapper for the second.
To implement a new unit setting, it is necessary to support all three input methods:

1. *unit* *files* are parsed in `src/core/load-fragment.c`, with many simple and fixed-type unit settings being parsed by common helpers, with the definition in the generator file `src/core/load-fragment-gperf.gperf.in`
2. D-Bus messages are defined and parsed in `src/core/dbus-*.c`
3. `systemd-run` and `systemctl set-property` do client-side parsing and translation into D-Bus messages in `src/shared/bus-unit-util.c`

So that they are exercised by the fuzzing CI, new unit settings should also be listed in the text files under `test/fuzz/fuzz-unit-file/`.

### systemd-udev

Sources for the udev daemon and command-line tool (single binary) can be found under `src/udev/`.

### Unit Tests

Source files found under `src/test/` implement unit-level testing, mostly for modules found in `src/basic/` and `src/shared/`, but not exclusively.
Each test file is compiled in a standalone binary that can be run to exercise the corresponding module.
While most of the tests can be run by any user, some require privileges, and will attempt to clearly log about what they need (mostly in the form of effective capabilities).
These tests are self-contained, and generally safe to run on the host without side effects.

Ideally, every module in `src/basic/` and `src/shared/` should have a corresponding unit test under `src/test/`, exercising every helper function.

### Fuzzing

Fuzzers are a type of unit tests that execute code on an externally-supplied input sample.
Fuzzers are called `fuzz-*`.
Fuzzers for `src/basic/` and `src/shared` live under `src/fuzz/`, and those for other parts of the codebase should be located next to the code they test.

Files under `test/fuzz/` contain input data for fuzzers, one subdirectory for each fuzzer.
Some of the files are "seed corpora", i.e. files that contain lists of settings and input values intended to generate initial coverage, and other files are samples saved by the fuzzing engines when they find an issue.

When adding new input samples under `test/fuzz/*/`, please use some short-but-meaningful names.
Names of meson tests include the input file name and output looks awkward if they are too long.

Fuzzers are invoked primarily in three ways:
firstly, each fuzzer is compiled as a normal executable and executed for each of the input samples under `test/fuzz/` as part of the test suite.
Secondly, fuzzers may be instrumented with sanitizers and invoked as part of the test suite (if `-Dfuzz-tests=true` is configured).
Thirdly, fuzzers are executed through fuzzing engines that tryto find new "interesting" inputs through coverage feedback and massive parallelization; see the links for oss-fuzz in [Code quality](/CODE_QUALITY).
For testing and debugging, fuzzers can be executed as any other program, including under `valgrind` or `gdb`.

## Integration Tests

Sources in `test/TEST-*` implement system-level testing for executables, libraries and daemons that are shipped by the project.

Most of those tests should be able to run via `systemd-nspawn`, which is orders-of-magnitude faster than `qemu`, but some tests require privileged operations like using `dm-crypt` or `loopdev`.
They are clearly marked if that is the case.

See [`test/README.md`](https://github.com/systemd/systemd/blob/main/test/README.md) for more specific details.

## hwdb

Rules built in the static hardware database shipped by the project can be found under `hwdb.d/`.
Some of these files are updated automatically, some are filled by contributors.

## Documentation

### systemd.io

Markdown files found under `docs/` are automatically published on the [systemd.io](https://systemd.io) website using Github Pages.
A minimal unit test to ensure the formatting doesn't have errors is included in the `meson test -C build/ github-pages` run as part of the CI.

### Man pages

Manpages for binaries and libraries, and the DBUS interfaces, can be found under `man/` and should ideally be kept in sync with changes to the corresponding binaries and libraries.

### Translations

Translations files for binaries and daemons, provided by volunteers, can be found under `po/` in the usual format.
They are kept up to date by contributors and by automated tools.

## System Configuration files and presets

Presets (or templates from which they are generated) for various daemons and tools can be found under various directories such as
`factory/`, `modprobe.d/`, `network/`, `presets/`, `rules.d/`, `shell-completion/`, `sysctl.d/`, `sysusers.d/`, `tmpfiles.d/`.

## Utilities for Developers

`tools/`, `coccinelle/`, `.github/`, `.semaphore/`, `.mkosi/` host various utilities and scripts that are used by maintainers and developers.
They are not shipped or installed.

# Service Manager Overview

The Service Manager takes configuration in the form of unit files, credentials, kernel command line options and D-Bus commands, and based on those manages the system and spawns other processes.
It runs in system mode as PID1, and in user mode with one instance per user session.

When starting a unit requires forking a new process, configuration for the new process will be serialized and passed over to the new process, created via a posix_spawn() call.
This is done in order to avoid excessive processing after a fork() but before an exec(), which is against glibc's best practices and can also result in a copy-on-write trap.
The new process will start as the `systemd-executor` binary, which will deserialize the configuration and apply all the options (sandboxing, namespacing, cgroup, etc.) before exec'ing the configured executable.

```
 ┌──────┐posix_spawn() ┌───────────┐execve() ┌────────┐
 │ PID1 ├─────────────►│sd-executor├────────►│program │
 └──────┘  (memfd)     └───────────┘         └────────┘
```
