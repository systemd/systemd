---
title: Porting to New Architectures
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Porting systemd to New Architectures

Here's a brief checklist of things to implement when porting systemd to a new
architecture.

1. Patch
   [src/basic/architecture.h](https://github.com/systemd/systemd/blob/main/src/basic/architecture.h)
   and
   [src/basic/architecture.c](https://github.com/systemd/systemd/blob/main/src/basic/architecture.c)
   to make your architecture known to systemd. Besides an `ARCHITECTURE_XYZ`
   enumeration entry you need to provide an implementation of
   `native_architecture()` and `uname_architecture()`.

2. Patch
   [src/shared/gpt.h](https://github.com/systemd/systemd/blob/main/src/shared/gpt.h)
   and
   [src/shared/gpt.c](https://github.com/systemd/systemd/blob/main/src/shared/gpt.c)
   and define a new set of GPT partition type UUIDs for the root file system,
   `/usr/` file system, and the matching Verity and Verity signature
   partitions. Use `systemd-id128 new -p` to generate new suitable UUIDs you
   can use for this. Make sure to register your new types in the various
   functions in `gpt.c`. Also make sure to update the tables in
   `docs/DISCOVERABLE_PARTITIONS.md` and `man/systemd-gpt-auto-generator.xml`
   accordingly.

3. If your architecture supports UEFI, make sure to update the `efi_arch`
   variable logic in `meson.build` to be set to the right architecture string
   as defined by the UEFI specification. (This ensures that `systemd-boot` will
   be built as the appropriately named `BOOT<arch>.EFI` binary.) Also, if your
   architecture uses a special boot protocol for the Linux kernel make sure to
   implement it in `src/boot/efi/linux*.c`, so that the `systemd-stub` EFI stub
   can work.

4. Make sure to register the right system call numbers for your architecture in
   `src/basic/missing_syscall_def.h`. systemd uses various system calls the
   Linux kernel provides that are currently not wrapped by glibc (or are only
   in very new glibc), and we need to know the right numbers for them. It might
   also be necessary to tweak `src/basic/raw-clone.h`.

5. Make sure the code in `src/shared/seccomp-util.c` properly understands the
   local architecture and its system call quirks.

6. If your architecture uses a `/lib64/` library directory, then make sure that
   the `BaseFilesystem` table in `src/shared/base-filesystem.c` has an entry
   for it so that it can be set up automatically if missing. This is useful to
   support booting into OS trees that have an empty root directory with only
   `/usr/` mounted in.

7. If your architecture supports VM virtualization and provides CPU opcodes
   similar to x86' CPUID consider adding native support for detecting VMs this
   way to `src/basic/virt.c`.
