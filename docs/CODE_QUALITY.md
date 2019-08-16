---
title: Code Quality Tools
---

# Code Quality Tools

The systemd project has a number of code quality tools set up in the source
tree and on the github infrastructure. Here's an incomprehensive list of the
available functionality:

1. Use `ninja -C build test` to run the unit tests. Some tests are skipped if
   no privileges are available, hence consider also running them with `sudo
   ninja -C build test`. A couple of unit tests are considered "unsafe" (as
   they change system state); to run those too, build with `meson
   -Dtests=unsafe`. Finally, some unit tests are considered to be very slow,
   build them too with `meson -Dslow-tests=true`. (Note that there are a couple
   of manual tests in addition to these unit tests.)

2. Use `./test/run-integration-tests.sh` to run the full integration test
   suite. This will build OS images with a number of integration tests and run
   them in nspawn and qemu. Requires root.

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

6. Use `ninja -C build check-api-docs` to compare the list of exported
   symbols of `libsystemd.so` and `libudev.so` with the list of man pages. Symbols
   lacking documentation are highlighted.

7. Use `ninja -C build hwdb-update` to automatically download and import the
   PCI, USB and OUI databases into hwdb.

8. Use `ninja -C build man/update-man-rules` to update the meson rules for
   building man pages automatically from the docbook XML files included in
   `man/`.

9. There are multiple CI systems in use that run on every github PR submission.

10. [Coverity](https://scan.coverity.com/) is analyzing systemd master in
    regular intervals. The reports are available
    [online](https://scan.coverity.com/projects/systemd).

11. [oss-fuzz](https://oss-fuzz.com/) is continuously fuzzing the
    codebase. Reports are available
    [online](https://oss-fuzz.com/v2/testcases?project=systemd).

12. Our tree includes `.editorconfig`, `.dir-locals.el` and `.vimrc` files, to
    ensure that editors follow the right indentiation styles automatically.

13. When building systemd from a git checkout the build scripts will
    automatically enable a git commit hook that ensures whitespace cleanliness.

14. [LGTM](https://lgtm.com/) analyzes every commit pushed to master. The list
    of active alerts can be found
    [here](https://lgtm.com/projects/g/systemd/systemd/alerts/?mode=list).

15. Each PR is automatically tested with [Address Sanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
    and [Undefined Behavior Sanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
    See [Testing systemd using sanitizers](https://systemd.io/TESTING_WITH_SANITIZERS)
    for more information.

Access to Coverity and oss-fuzz reports is limited. Please reach out to the
maintainers if you need access.
