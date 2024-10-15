---
title: Dlopen Metadata for ELF Files
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# `dlopen()` Metadata for ELF Files

*Intended audience: hackers working on packaging ELF files that use dlopen to load libraries.*

## Motivation

Using `dlopen()` to load optional dependencies brings several advantages: programs can gracefully downgrade
a feature when a library is not available, and the shared library is only loaded into the process (and its
ELF constructors are run) only when the requested feature is actually used. But it also has some drawbacks,
and the main one is that it is harder to track a program's dependencies, since unlike build-time dynamic
linking there will not be a mention in the ELF metadata. This specification aims to solve this problem by
providing a standardized specification for a custom ELF note that can be used to list `dlopen()`
dependencies.

## Implementation

This document will attempt to define a common metadata format specification, so that multiple implementers
might use it when coding upstream software, and packagers might use it when building packages and setting
dependencies.

The metadata will be embedded in a series of new, 4-byte-aligned, allocated, 0-padded, read-only ELF header
sections, in a JSON array containing name-value objects, either one ELF note per dependency or as a single
note listing multiple dependencies in the top-level array. Implementers working on parsing ELF files should
not assume a specific list of names, but parse anything that is included in the section, and should look for
the note using the `note type`. Implementers working on build tools should strive to use the same names, for
consistency. The most common will be listed here.

* Section header

```
SECTION: `.note.dlopen`
note type: `0x407c0c0a`
Owner: `FDO` (FreeDesktop.org)
Value: an array of JSON objects encoded as a zero-terminated UTF-8 string
```

* JSON payload

```json
[
    {
        "soname":      ["libfoo.so.1"],
        "feature":     "foo",
        "description": "Enables the foo feature",
        "priority":    "recommended"
    }
]
```

The format is a single JSON array containing objects, encoded as a zero-terminated `UTF-8` string. Each key
in each object shall be unique as per recommendations of [RFC8259](https://datatracker.ietf.org/doc/html/rfc8259#section-4).
Strings shall not contain any control characters or use `\uXXX` escaping.

Reference implementations of [packaging tools for `.deb` and `.rpm`](https://github.com/systemd/package-notes)
are available, and provide macros/helpers to parse the note when building packages and adding dependencies.

## Well-known keys

The metadata format is intentionally extensible, so that upstreams and later revisions of this spec can add
their own information. The 'soname' array is required, with at least one element, everything else is
optional. If alternative soname versions for the same library are supported at the same time, an array can
be used, listing the most preferred first, and parsers are expected to select only the first one that is
available on the system, as it is a mechanism to specify alternatives. If the `priority` field is used, it
must follow the specification and use one of the values specified in the table. If it is not specified, a
parser should assume 'recommended' if a priority is needed. If the `feature` field is used, it will identify
an individual feature, and multiple entries using the same `feature` denote functionality that requires all
of the libraries they specify in order to be enabled.

| Key name    | Key type                   | Mandatory | Key description                                                          | Example value                    |
|-------------|----------------------------|-----------|--------------------------------------------------------------------------|----------------------------------|
| soname      | array of strings           | yes       | The library names loaded by `dlopen()`                                   | [ "libfoo.so.1", "libfoo.so.0" ] |
| feature     | string                     | no        | A keyword identifying the feature that the library contributes to enable | "foo"                            |
| description | string                     | no        | A human-readable text string describing the feature                      | "Enables the foo feature"        |
| priority    | string                     | no        | The priority of the feature, one of: required, recommended, suggested    | "recommended"                    |

### Priority definition

| Priority    | Semantics                                                                                                                            |
|-------------|--------------------------------------------------------------------------------------------------------------------------------------|
| required    | Core functionality needs the dependency, the binary will not work if it cannot be found                                              |
| recommended | Important functionality needs the dependency, the binary will work but in most cases the dependency should be provided               |
| suggested   | Secondary functionality needs the dependency, the binary will work and the dependency is only needed for full-featured installations |

### Displaying `dlopen()` notes

The raw ELF section can be extracted using `objdump`:
```console
$ objdump -j .note.dlopen -s /usr/lib64/systemd/libsystemd-shared-257.so

/usr/lib64/systemd/libsystemd-shared-257.so:     file format elf64-x86-64

Contents of section .note.dlopen:
 0334 04000000 8e000000 0a0c7c40 46444f00  ..........|@FDO.
 0344 5b7b2266 65617475 7265223a 22627066  [{"feature":"bpf
 0354 222c2264 65736372 69707469 6f6e223a  ","description":
 0364 22537570 706f7274 20666972 6577616c  "Support firewal
 0374 6c696e67 20616e64 2073616e 64626f78  ling and sandbox
 0384 696e6720 77697468 20425046 222c2270  ing with BPF","p
 0394 72696f72 69747922 3a227375 67676573  riority":"sugges
 03a4 74656422 2c22736f 6e616d65 223a5b22  ted","soname":["
 03b4 6c696262 70662e73 6f2e3122 2c226c69  libbpf.so.1","li
 03c4 62627066 2e736f2e 30225d7d 5d000000  bbpf.so.0"]}]...
 03d4 04000000 9e000000 0a0c7c40 46444f00  ..........|@FDO.
...
```

It is more convenient to use a higher level tool:
```console
$ dlopen-notes /usr/lib64/systemd/libsystemd-shared-257.so
# /usr/lib64/systemd/libsystemd-shared-257.so
[
  {
    "feature": "archive",
    "description": "Support for decompressing archive files",
    "priority": "suggested",
    "soname": [
      "libarchive.so.13"
    ]
  },
  {
    "feature": "bpf",
    "description": "Support firewalling and sandboxing with BPF",
    "priority": "suggested",
    "soname": [
      "libbpf.so.1",
      "libbpf.so.0"
    ]
  },
...
```

`dlopen-notes` can display the notes grouped in a few different ways.
One option is to filter the libraries by "feature". This answers the
question "what libraries are needed to provide specified features":

```console
$ dlopen-notes.py -f archive,bpf /usr/lib64/systemd/libsystemd-shared-257.so
# grouped by feature
{
  "bpf": {
    "description": "Support firewalling and sandboxing with BPF",
    "sonames": {
      "libbpf.so.1": "suggested",
      "libbpf.so.0": "suggested"
    }
  },
  "archive": {
    "description": "Support for decompressing archive files",
    "sonames": {
      "libarchive.so.13": "suggested"
    }
  }
}

The format that is used when building `deb` packages:
```console
$ dlopen-notes -s /usr/lib64/systemd/libsystemd-shared-257.so
libarchive.so.13 suggested
libbpf.so.0 suggested
libbpf.so.1 suggested
...
```

The format that can be useful when building `rpm` packages:
```console
$ dlopen-notes --rpm-requires archive --rpm-recommends bpf  /usr/lib64/systemd/libsystemd-shared-257.so
Requires: libarchive.so.13()(64bit)
Recommends: libbpf.so.1()(64bit)
```
