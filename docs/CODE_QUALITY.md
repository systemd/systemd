---
title: Code Quality Tools
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Code Quality Tools

The systemd project has a number of code quality tools set up in the source
tree and on the github infrastructure. Here's an incomprehensive list of the
available functionality:

1. Use `meson test -C build` to run the unit tests. Some tests are skipped if
   no privileges are available, hence consider also running them with `sudo
   meson test -C build`. A couple of unit tests are considered "unsafe" (as
   they change system state); to run those too, build with `meson setup
   -Dtests=unsafe`. Finally, some unit tests are considered to be very slow,
   build them too with `meson setup -Dslow-tests=true`. (Note that there are a
   couple of manual tests in addition to these unit tests.) (Also note: you can
   change these flags for an already set up build tree, too, with "meson
   configure -C build -D…".)

2. Use `./test/run-integration-tests.sh` to run the full integration test
   suite. This will build OS images with a number of integration tests and run
   them using `systemd-nspawn` and `qemu`. Requires root.

3. Use `./coccinelle/run-coccinelle.sh` to run all
   [Coccinelle](http://coccinelle.lip6.fr/) semantic patch scripts we ship. The
   output will show false positives, hence take it with a pinch of salt.

4. Use `./tools/find-double-newline.sh recdiff` to find double newlines. Use
   `./tools/find-double-newline.sh recpatch` to fix them. Take this with a grain
   of salt, in particular as we generally leave foreign header files we include in
   our tree unmodified, if possible.

5. Similar use `./tools/find-tabs.sh recdiff` to find TABs, and
   `./tools/find-tabs.sh recpatch` to fix them. (Again, grain of salt, foreign
   headers should usually be left unmodified.)

6. Use `ninja -C build check-api-docs` to compare the list of exported symbols
   of `libsystemd.so` and `libudev.so` with the list of man pages. Symbols
   lacking documentation are highlighted.

7. Use `ninja -C build update-hwdb` and `ninja -C build update-hwdb-autosuspend`
   to automatically download and import the PCI, USB, and OUI databases and the
   autosuspend quirks into the hwdb.

8. Use `ninja -C build update-man-rules` to update the meson rules for building
   man pages automatically from the docbook XML files included in `man/`.

9. There are multiple CI systems in use that run on every github pull request
   submission or update.

10. [Coverity](https://scan.coverity.com/) is analyzing systemd `main` branch
    in regular intervals. The reports are available
    [online](https://scan.coverity.com/projects/systemd).

11. [OSS-Fuzz](https://github.com/google/oss-fuzz) is continuously fuzzing the
    codebase. Reports are available
    [online](https://oss-fuzz.com/testcases?project=systemd&open=yes).
    It also builds
    [coverage reports](https://oss-fuzz.com/coverage-report/job/libfuzzer_asan_systemd/latest)
    daily.

12. Our tree includes `.editorconfig`, `.dir-locals.el` and `.vimrc` files, to
    ensure that editors follow the right indentiation styles automatically.

13. When building systemd from a git checkout the build scripts will
    automatically enable a git commit hook that ensures whitespace cleanliness.

14. [CodeQL](https://codeql.github.com/) analyzes each PR and every commit
    pushed to `main`. The list of active alerts can be found
    [here](https://github.com/systemd/systemd/security/code-scanning).

15. Each PR is automatically tested with [Address Sanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
    and [Undefined Behavior Sanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
    See [Testing systemd using sanitizers](/TESTING_WITH_SANITIZERS)
    for more information.

16. Fossies provides [source code misspelling reports](https://fossies.org/features.html#codespell).
    The systemd report can be found [here](https://fossies.org/linux/misc/systemd/codespell.html).

Access to Coverity and oss-fuzz reports is limited. Please reach out to the
maintainers if you need access.
