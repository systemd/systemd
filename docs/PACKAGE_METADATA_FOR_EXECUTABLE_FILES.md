---
title: Package Metadata for Executable Files
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Package Metadata for Executable Files

*Intended audience: hackers working on userspace subsystems that
create or manipulate ELF or PE/COFF binaries
or parse core files.*

## Motivation

ELF binaries get stamped with a unique, build-time generated hex string identifier called `build-id`,
[which gets embedded as an ELF note called `.note.gnu.build-id`](https://fedoraproject.org/wiki/Releases/FeatureBuildId).
In most cases, this allows a stripped binary to be associated with its debugging information.
It is used, for example, to dynamically fetch DWARF symbols from a debuginfo server, or
to query the local package manager and find out the package metadata or, again, the DWARF
symbols or program sources.

However, this usage of the `build-id` requires either local metadata, usually set up by
the package manager, or access to a remote server over the network. Both of those might
be unavailable or forbidden.

Thus it becomes desirable to add additional metadata to a binary at build time, so that
`systemd-coredump` and other services analyzing core files are able to extract said
metadata simply from the core file itself, without external dependencies.

This metadata is stored as a section in the executable file,
so that it will be loaded into memory along with the text and data of the binary,
and will be preserved in a core dump.
This metadata can also be easily read from the file on disk,
so it can be used to identify provenience of files,
independently of any package management system,
even if the file is renamed or copied.

## Implementation

This document will attempt to define a common metadata format specification, so that
multiple implementers might use it when building packages, or core file analyzers, and
so on.

Implementers working on parsing the metadata should not assume a specific list of names,
but parse anything that is included in the JSON object.

Implementers working on build tools should strive to use the same names, for consistency.
The most common will be listed here.
When corresponding to the content of os-release, the values should match, again for consistency.

If available, the metadata should also include the debuginfod server URL that can provide
the original executable, debuginfo and sources, to further facilitate debugging.

### ELF header section

The metadata will be embedded in a single, 4 byte-aligned, allocated, NUL-padded,
read-only ELF header section, in a name-value JSON object format.
The JSON string is terminated with a NUL
and subsequently padded with NULs to a multiple of four bytes.

The `note type` must be set during creation and checked when reading.

Section: `.note.package`<br/>
`note type`: `0xcafe1a7e`<br/>
Owner: `FDO` (FreeDesktop.org)<br/>
Value: a single JSON object encoded as a NUL-terminated UTF-8 string

### PE/COFF section

The metadata will be embedded in a single, allocated, NUL-padded,
read-only COFF data section,
in a name-value JSON object format.
The JSON string is terminated with a NUL
and subsequently padded with NULs if appropriate.
The `IMAGE_SCN_CNT_INITIALIZED_DATA` section flag shall be set.
The alignment and padding shall be chosen as appropriate for the use of the PE/COFF file.

Section: `.pkgnote`<br/>
Value: a single JSON object encoded as a NUL-terminated UTF-8 string

### JSON payload

```json
{
     "type":"rpm",          # this provides a namespace for the package+package-version fields
     "os":"fedora",
     "osVersion":"33",
     "name":"coreutils",
     "version":"4711.0815.fc13",
     "architecture":"arm32",
     "osCpe": "cpe:/o:fedoraproject:fedora:33",          # A CPE name for the operating system, `CPE_NAME` from os-release is a good default
     "debugInfoUrl": "https://debuginfod.fedoraproject.org/"
}
```

The format is a single JSON object,
encoded as a NUL-terminated `UTF-8` string.
Each name in the object shall be unique as per recommendations of
[RFC8259](https://datatracker.ietf.org/doc/html/rfc8259#section-4).
Strings shall not contain any control characters or use `\uXXX` escaping.

When it comes to JSON numbers, this specification assumes that JSON parsers
processing this information are capable of reproducing the full signed 53bit
integer range (i.e. -2⁵³+1…+2⁵³-1) as well as the full 64-bit IEEE floating
point number range losslessly (with the exception of NaN/-inf/+inf, since JSON
cannot encode that), as per recommendations of
[RFC8259](https://datatracker.ietf.org/doc/html/rfc8259#page-8). Fields in
these JSON objects are thus permitted to encode numeric values from these
ranges as JSON numbers, and should not use numeric values not covered by these
types and ranges.

If available, the metadata should also include the debuginfod server URL that can provide
the original executable, debuginfo and sources, to further facilitate debugging.

Reference implementations of [packaging tools for .deb and .rpm](https://github.com/systemd/package-notes)
are available, and provide macros/helpers to include the note in binaries built
by the package build system.
They make use of the new `--package-metadata=` flag that is available in the
`bfd`, `gold`, `mold`, and `lld` linkers
(versions 2.39, 2.39, 1.3.0, and 15.0 respectively).
This linker flag takes the JSON payload as parameter.

## Well-known keys

The metadata format is intentionally left open, so that vendors can add their own information.
A set of well-known keys is defined here, and hopefully shared among all vendors.

| Key name     | Key description                                                          | Example value                         |
|--------------|--------------------------------------------------------------------------|---------------------------------------|
| type         | The packaging type                                                       | rpm                                   |
| os           | The OS name, typically corresponding to ID in os-release                 | fedora                                |
| osVersion    | The OS version, typically corresponding to VERSION_ID in os-release      | 33                                    |
| name         | The source package name                                                  | coreutils                             |
| version      | The source package version                                               | 4711.0815.fc13                        |
| architecture | The binary package architecture                                          | arm32                                 |
| osCpe        | A CPE name for the OS, typically corresponding to CPE_NAME in os-release | cpe:/o:fedoraproject:fedora:33        |
| debugInfoUrl | The debuginfod server url, if available                                  | https://debuginfod.fedoraproject.org/ |

### Displaying package notes

The raw ELF section can be extracted using `objdump`:
```console
$ objdump -j .note.package -s /usr/bin/ls

/usr/bin/ls:     file format elf64-x86-64

Contents of section .note.package:
 03cc 04000000 7c000000 7e1afeca 46444f00  ....|...~...FDO.
 03dc 7b227479 7065223a 2272706d 222c226e  {"type":"rpm","n
 03ec 616d6522 3a22636f 72657574 696c7322  ame":"coreutils"
 03fc 2c227665 7273696f 6e223a22 392e342d  ,"version":"9.4-
 040c 372e6663 3430222c 22617263 68697465  7.fc40","archite
 041c 63747572 65223a22 7838365f 3634222c  cture":"x86_64",
 042c 226f7343 7065223a 22637065 3a2f6f3a  "osCpe":"cpe:/o:
 043c 6665646f 72617072 6f6a6563 743a6665  fedoraproject:fe
 044c 646f7261 3a343022 7d000000           dora:40"}...
```

It is more convenient to use a higher level tool:
```console
$ readelf --notes /usr/bin/ls
...
Displaying notes found in: .note.gnu.build-id
  Owner                Data size 	Description
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 40e5a1570a9d97fc48f5c61cfb7690fec0f872b2

Displaying notes found in: .note.ABI-tag
  Owner                Data size 	Description
  GNU                  0x00000010	NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 3.2.0

Displaying notes found in: .note.package
  Owner                Data size 	Description
  FDO                  0x0000007c	FDO_PACKAGING_METADATA
    Packaging Metadata: {"type":"rpm","name":"coreutils","version":"9.4-7.fc40","architecture":"x86_64","osCpe":"cpe:/o:fedoraproject:fedora:40"}
...

$ systemd-analyze inspect-elf /usr/bin/ls
           path: /usr/bin/ls
        elfType: executable
elfArchitecture: AMD x86-64

           type: rpm
           name: coreutils
        version: 9.4-7.fc40
   architecture: x86_64
          osCpe: cpe:/o:fedoraproject:fedora:40
        buildId: 40e5a1570a9d97fc48f5c61cfb7690fec0f872b2
```

If the binary crashes, `systemd-coredump` will display the combined information
from the crashing binary and any shared libraries it links to:

```console
$  coredumpctl info
           PID: 3987823 (ls)
        Signal: 11 (SEGV)
  Command Line: ls --color=tty -lR /
    Executable: /usr/bin/ls
...
       Storage: /var/lib/systemd/coredump/core.ls.1000.88dea1b9831c420dbb398f9d2ad9b41e.3987823.1726230641000000.zst (present)
  Size on Disk: 194.4K
       Package: coreutils/9.4-7.fc40
      build-id: 40e5a1570a9d97fc48f5c61cfb7690fec0f872b2
       Message: Process 3987823 (ls) of user 1000 dumped core.

                Module /usr/bin/ls from rpm coreutils-9.4-7.fc40.x86_64
                Module libz.so.1 from rpm zlib-ng-2.1.7-1.fc40.x86_64
                Module libcrypto.so.3 from rpm openssl-3.2.2-3.fc40.x86_64
                Module libmount.so.1 from rpm util-linux-2.40.1-1.fc40.x86_64
                Module libcrypt.so.2 from rpm libxcrypt-4.4.36-5.fc40.x86_64
                Module libblkid.so.1 from rpm util-linux-2.40.1-1.fc40.x86_64
                Module libnss_sss.so.2 from rpm sssd-2.9.5-1.fc40.x86_64
                Module libpcre2-8.so.0 from rpm pcre2-10.44-1.fc40.x86_64
                Module libcap.so.2 from rpm libcap-2.69-8.fc40.x86_64
                Module libselinux.so.1 from rpm libselinux-3.6-4.fc40.x86_64
                Stack trace of thread 3987823:
                #0  0x00007f19331c3f7e lgetxattr (libc.so.6 + 0x116f7e)
                #1  0x00007f19332be4c0 lgetfilecon_raw (libselinux.so.1 + 0x134c0)
                #2  0x00007f19332c3bd9 lgetfilecon (libselinux.so.1 + 0x18bd9)
                #3  0x000056038273ad55 gobble_file.constprop.0 (/usr/bin/ls + 0x17d55)
                #4  0x0000560382733c55 print_dir (/usr/bin/ls + 0x10c55)
                #5  0x0000560382727c35 main (/usr/bin/ls + 0x4c35)
                #6  0x00007f19330d7088 __libc_start_call_main (libc.so.6 + 0x2a088)
                #7  0x00007f19330d714b __libc_start_main@@GLIBC_2.34 (libc.so.6 + 0x2a14b)
                #8  0x0000560382728f15 _start (/usr/bin/ls + 0x5f15)
                ELF object binary architecture: AMD x86-64
```

(This is just a simulation. `ls` is not prone to crashing with a segmentation violation.)
