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
and conditions of the **GNU Lesser General Public License v2.1 or later**.

New sources that cannot be distributed under LGPL-2.1-or-later will no longer
be accepted for inclusion in the systemd project to maintain license uniformity.

## Other Licenses

The following exceptions apply:

 * some udev sources under src/udev/ are licensed under **GPL-2.0-or-later**, so the
   udev binaries as a whole are also distributed under **GPL-2.0-or-later**.
 * the header files contained in src/basic/linux/ and src/shared/linux/ are copied
   verbatim from the Linux kernel source tree and are licensed under **GPL-2.0 WITH
   Linux-syscall-note** and are used within the scope of the Linux-syscall-note
   exception provisions
 * the src/shared/initreq.h header is licensed under original license,
   **LGPL-2.0-or-later**.
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
   - src/systemctl/systemd-sysv-install.SKELETON
   - tools/check-includes.pl
   - all examples under man/
 * the following sources are under **Public Domain** (LicenseRef-murmurhash2-public-domain):
   - src/basic/MurmurHash2.c
   - src/basic/MurmurHash2.h
 * the following sources are under **Public Domain** (LicenseRef-lookup3-public-domain):
   - src/libsystemd/sd-journal/lookup3.c
   - src/libsystemd/sd-journal/lookup3.h
 * the tools/chromiumos/gen_autosuspend_rules.py script is licensed under the
   **BSD-3-Clause** license.
 * Heebo fonts under docs/fonts/ are licensed under the **SIL Open Font License 1.1**,
 * any files under test/ without an explicit license we assume non-copyrightable
   (eg: computer-generated fuzzer data)

## OpenSSL Notes

Note that building the systemd project with OpenSSL does not affect the libsystemd.so
shared library, which is not linked with the OpenSSL library.
