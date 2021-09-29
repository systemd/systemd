# systemd Project Licensing

## Main License

The systemd project uses a single-line reference to Unique License Identifiers
in source files as defined by the Linux Foundation's SPDX project (https://spdx.org/).

The current set of valid, predefined SPDX identifiers can be found on the SPDX
License List at https://spdx.org/licenses/.

The 'LICENSES/' directory contains all the licenses used by the sources included in
the systemd project source tree.

Unless otherwise noted, the systemd project sources are licensed under the terms
and conditions of the **GNU Lesser General Public License v2.1 or later**.

## Other Licenses

The following exceptions apply:

 * the following udev sources are licensed under **GPL-2.0-or-later**:
   - src/udev/ata_id/*
   - src/udev/cdrom_id/*
   - src/udev/dmi_memory_id/*
   - src/udev/mtd_probe/*
   - src/udev/scsi_id/*
   - src/udev/udevadm*
   - src/udev/udev-builtin-blkid.c
   - src/udev/udev-builtin.h
   - src/udev/udev-builtin-input_id.c
   - src/udev/udev-builtin-kmod.c
   - src/udev/udev-builtin-path_id.c
   - src/udev/udev-builtin-uaccess.c
   - src/udev/udev-builtin-usb_id.c
   - src/udev/udev-ctrl.h
   - src/udev/udevd.c
   - src/udev/udevd.h
   - src/udev/udev-event.c
   - src/udev/udev-event.h
   - src/udev/udev-node.c
   - src/udev/udev-node.h
   - src/udev/udev-rules.c
   - src/udev/udev-rules.h
   - src/udev/udev-watch.c
   - src/udev/udev-watch.h
   - src/udev/v4l_id/*
 * the header files contained in src/basic/linux/ and src/shared/linux/ are copied
   verbatim from the Linux kernel source tree and are licensed under **GPL-2.0 WITH
   Linux-syscall-note** and are used within the scope of the Linux-syscall-note
   exception, and thus their license does not affect the rest of the source
   code/binaries
 * the src/shared/initreq.h header is licensed under original license,
   **LGPL-2.0-or-later**.
 * the src/shared/linux/bpf_insn.h header is copied from the Linux kernel
   source tree and is licensed under either **BSD-2-Clause** or **GPL-2.0-only**,
   and thus is included in the systemd build under the BSD-2-Clause license.
 * The src/basic/linux/wireguard.h header is copied from the Linux kernel
   source tree and is licensed under either **MIT** or **GPL-2.0 WITH Linux-syscall-note**,
   and thus is included in the systemd build under the MIT license.
 * the following sources are licensed under the **MIT** license:
   - hwdb.d/parse_hwdb.py
   - man/glib-event-glue.c
   - src/basic/linux/batman_adv.h
   - src/basic/sparse-endian.h
   - tools/catalog-report.py
 * the following sources are licensed under the **CC0-1.0** license:
   - src/basic/siphash24.c
   - src/basic/siphash24.h
   - src/systemctl/systemd-sysv-install.SKELETON
   - tools/check-includes.pl
 * the following sources are under **Public Domain** (LicenseRef-murmurhash2-public-domain):
   - src/basic/MurmurHash2.c
   - src/basic/MurmurHash2.h
 * the following sources are under **Public Domain** (LicenseRef-lookup3-public-domain):
   - src/libsystemd/sd-journal/lookup3.c
   - src/libsystemd/sd-journal/lookup3.h

## OpenSSL Notes

Note that when building the systemd project with OpenSSL 3.0, the resulting
binaries that link with libssl/libcrypto have to effectively be distributed
under LGPL-3.0-or-later to be compatible with OpenSSL's Apache2 license.

New sources that cannot be distributed under LGPL-2.1-or-later will no longer
be accepted for inclusion in the systemd project to maintain this compatibility.
