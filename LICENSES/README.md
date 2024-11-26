# systemd Project Licensing

## Main License

The systemd project uses single-line references to Unique License Identifiers as
defined by the Linux Foundation's SPDX project (https://spdx.org/). The line in
each individual source file identifies the license applicable to that file.

The current set of valid, predefined SPDX identifiers can be found on the SPDX
License List at https://spdx.org/licenses/.

The 'LICENSES/' directory contains all the licenses used by the sources included in
the systemd project source tree.

Unless otherwise noted, the systemd project sources are licensed under the terms
and conditions of
**LGPL-2.1-or-later** (**GNU Lesser General Public License v2.1 or later**).

Unless otherwise noted, compiled programs and all shared or static libraries
include sources under **LGPL-2.1-or-later** along with more permissive
licenses, and are effectively licensed **LGPL-2.1-or-later**.
systemd-udevd and other udev helper programs also include sources under
**GPL-2.0-or-later**, and are effectively licensed **GPL-2.0-or-later**.

New sources that cannot be distributed under LGPL-2.1-or-later will no longer
be accepted for inclusion in the systemd project to maintain license uniformity.

## Other Licenses

The following exceptions apply:

 * some sources under src/udev/ are licensed under **GPL-2.0-or-later**,
   so all udev programs (`systemd-udevd`, `udevadm`, and the udev builtins
   and test programs) are also distributed under **GPL-2.0-or-later**.
 * the header files contained in src/basic/linux/ and src/shared/linux/ are copied
   verbatim from the Linux kernel source tree and are licensed under **GPL-2.0 WITH
   Linux-syscall-note** and are used within the scope of the Linux-syscall-note
   exception provisions
 * the following sources are licensed under the **LGPL-2.0-or-later** license:
   - src/basic/utf8.c
   - src/shared/initreq.h
 * the src/shared/linux/bpf_insn.h header is copied from the Linux kernel
   source tree and is licensed under either **BSD-2-Clause** or **GPL-2.0-only**,
   and thus is included in the systemd build under the BSD-2-Clause license.
 * The src/basic/linux/wireguard.h header is copied from the Linux kernel
   source tree and is licensed under either **MIT** or **GPL-2.0 WITH Linux-syscall-note**,
   and thus is included in the systemd build under the MIT license.
 * the following sources are licensed under the **MIT** license (in case of our
   scripts, to facilitate copying and reuse of those helpers to other projects):
   - hwdb.d/parse_hwdb.py
   - src/basic/linux/batman_adv.h
   - src/basic/sparse-endian.h
   - tools/catalog-report.py
 * the following sources are licensed under the **CC0-1.0** license:
   - src/basic/siphash24.c
   - src/basic/siphash24.h
 * the following sources are licensed under the **MIT-0** license:
   - all examples under man/
   - src/systemctl/systemd-sysv-install.SKELETON
   - config files and examples under /network
 * the following sources are under **Public Domain** (LicenseRef-murmurhash2-public-domain):
   - src/basic/MurmurHash2.c
   - src/basic/MurmurHash2.h
 * the following sources are under **Public Domain** (LicenseRef-lookup3-public-domain):
   - src/libsystemd/sd-journal/lookup3.c
   - src/libsystemd/sd-journal/lookup3.h
 * the tools/chromiumos/gen_autosuspend_rules.py script is licensed under the
   **BSD-3-Clause** license.
 * the following sources are under **Public Domain** (LicenseRef-alg-sha1-public-domain):
   - src/fundamental/sha1-fundamental.c
   - src/fundamental/sha1-fundamental.h
 * the following files are licensed under **BSD-3-Clause** license:
   - src/boot/efi/chid.c
   - src/boot/efi/chid.h
 * Heebo fonts under docs/fonts/ are licensed under the **SIL Open Font License 1.1**,
 * any files under test/ without an explicit license we assume non-copyrightable
   (eg: computer-generated fuzzer data)

## OpenSSL Notes

Note that building the systemd project with OpenSSL does not affect the libsystemd.so
shared library, which is not linked with the OpenSSL library.
