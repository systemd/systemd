---
title: Home Directories
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Home Directories

[`systemd-homed.service(8)`](https://www.freedesktop.org/software/systemd/man/systemd-homed.service.html)
manages home directories of regular ("human") users. Each directory it manages
encapsulates both the data store and the user record of the user, so that it
comprehensively describes the user account, and is thus naturally portable
between systems without any further, external metadata. This document describes
the format used by these home directories, in the context of the storage
mechanism used.

## General Structure

Inside of the home directory a file `~/.identity` contains the JSON formatted
user record of the user. It follows the format defined in
[`JSON User Records`](USER_RECORD.md). It is recommended to bring the
record into 'normalized' form (i.e. all objects should contain their fields
sorted alphabetically by their key) before storing it there, though this is not
required nor enforced. Since the user record is cryptographically signed, the
user cannot make modifications to the file on their own (at least not without
corrupting it, or knowing the private key used for signing the record). Note
that user records are stored here without their `binding`, `status` and
`secret` sections, i.e. only with the sections included in the signature plus
the signature section itself.

## Storage Mechanism: Plain Directory/`btrfs` Subvolume

If the plain directory or `btrfs` subvolume storage mechanism of
`systemd-homed` is used (i.e. `--storage=directory` or `--storage=subvolume` on
the
[`homectl(1)`](https://www.freedesktop.org/software/systemd/man/homectl.html)
command line) the home directory requires no special setup besides including
the user record in the `~/.identity` file.

It is recommended to name home directories managed this way by
`systemd-homed.service` by the user name, suffixed with `.homedir` (example:
`lennart.homedir` for a user `lennart`) but this is not enforced. When the user
is logged in, the directory is generally mounted to `/home/$USER` (in our
example: `/home/lennart`), thus dropping the suffix while the home directory is
active. `systemd-homed` will automatically discover home directories named this
way in `/home/*.homedir` and synthesize NSS user records for them as they show
up.

## Storage Mechanism: `fscrypt` Directories

This storage mechanism is mostly identical to the plain directory storage
mechanism, except that the home directory is encrypted using `fscrypt`. (Use
`--storage=fscrypt` on the `homectl` command line.) Key management is
implemented via extended attributes on the directory itself: for each password
an extended attribute `trusted.fscrypt_slot0`, `trusted.fscrypt_slot1`,
`trusted.fscrypt_slot2`, … is maintained. Its value contains a colon-separated
pair of Base64 encoded data fields. The first field contains a salt value, the
second field the encrypted volume key. The latter is encrypted using AES256 in
counter mode, using a key derived from the password via PBKDF2-HMAC-SHA512,
together with the salt value. The construction is similar to what LUKS does for
`dm-crypt` encrypted volumes. Note that extended attributes are not encrypted
by `fscrypt` and hence are suitable for carrying the key slots. Moreover, by
using extended attributes, the slots are directly attached to the directory and
an independent sidecar key database is not required.

## Storage Mechanism: `cifs` Home Directories

In this storage mechanism, the home directory is mounted from a CIFS server and
service at login, configured inside the user record. (Use `--storage=cifs` on
the `homectl` command line.) The local password of the user is used to log into
the CIFS service. The directory share needs to contain the user record in
`~/.identity` as well. Note that this means that the user record needs to be
registered locally before it can be mounted for the first time, since CIFS
domain and server information needs to be known *before* the mount. Note that
for all other storage mechanisms it is entirely sufficient if the directories
or storage artifacts are placed at the right locations — all information to
activate them can be derived automatically from their mere availability.

## Storage Mechanism: `luks` Home Directories

This is the most advanced and most secure storage mechanism and consists of a
Linux file system inside a LUKS2 volume inside a loopback file (or on removable
media). (Use `--storage=luks` on the `homectl` command line.)  Specifically:

* The image contains a GPT partition table. For now it should only contain a
  single partition, and that partition must have the type UUID
  `773f91ef-66d4-49b5-bd83-d683bf40ad16`. Its partition label must be the
  user name.

* This partition must contain a LUKS2 volume, whose label must be the user
  name. The LUKS2 volume must contain a LUKS2 token field of type
  `systemd-homed`. The JSON data of this token must have a `record` field,
  containing a string with base64-encoded data. This data is the JSON user
  record, in the same serialization as in `~/.identity`, though encrypted. The
  JSON data of this token must also have an `iv` field, which contains a
  base64-encoded binary initialization vector for the encryption. The
  encryption used is the same as the LUKS2 volume itself uses, unlocked by the
  same volume key, but based on its own IV.

* Inside of this LUKS2 volume must be a Linux file system, one of `ext4`,
  `btrfs` and `xfs`. The file system label must be the user name.

* This file system should contain a single directory named after the user. This
  directory will become the home directory of the user when activated. It
  contains a second copy of the user record in the `~/.identity` file, like in
  the other storage mechanisms.

The image file should reside in a directory `/home/` on the system,
named after the user, suffixed with `.home`. When activated, the container home
directory is mounted to the same path, though with the `.home` suffix dropped —
unless a different mount point is defined in the user record. (e.g.: the
loopback file `/home/waldo.home` is mounted to `/home/waldo` while activated.)
When the image is stored on removable media (such as a USB stick), the image
file can be directly `dd`'ed onto it; the format is unchanged. The GPT envelope
should ensure the image is properly recognizable as a home directory both when
used in a loopback file and on a removable USB stick. (Note that when mounting
a home directory from an USB stick, it too defaults to a directory in `/home/`,
named after the username, with no further suffix.)

Rationale for the GPT partition table envelope: this way the image is nicely
discoverable and recognizable already by partition managers as a home
directory. Moreover, when copied onto a USB stick the GPT envelope makes sure
the stick is properly recognizable as a portable home directory
medium. (Moreover, it allows embedding additional partitions later on, for
example on a multi-purpose USB stick that contains both a home
directory and a generic storage volume.)

Rationale for including the encrypted user record in the LUKS2 header:
Linux kernel file system implementations are generally not robust towards
maliciously formatted file systems; there's a good chance that file system
images can be used as attack vectors, exploiting the kernel. Thus it is
necessary to validate the home directory image *before* mounting it and
establishing a minimal level of trust. Since the user record data is
cryptographically signed and user records not signed with a recognized private
key are not accepted, a minimal level of trust between the system and the home
directory image is established.

Rationale for storing the home directory one level below to root directory of
the contained file system: this way special directories such as `lost+found/`
do not show up in the user's home directory.

## Algorithm

Regardless of the storage mechanism used, an activated home directory
necessarily involves a mount point to be established. In case of the
directory-based storage mechanisms (`directory`, `subvolume` and `fscrypt`)
this is a bind mount. In case of `cifs` this is a CIFS network mount, and in
case of the LUKS2 backend a regular block device mount of the file system
contained in the LUKS2 image. By requiring a mount for all cases (even for
those that already are a directory), a clear logic is defined to distinguish
active and inactive home directories, so that the directories become
inaccessible under their regular path the instant they are
deactivated. Moreover, the `nosuid`, `nodev` and `noexec` flags configured in
the user record are applied when the bind mount is established.

During activation, the user records retained on the host, the user record
stored in the LUKS2 header (in case of the LUKS2 storage mechanism) and the
user record stored inside the home directory in `~/.identity` are
compared. Activation is only permitted if they match the same user and are
signed by a recognized key. When the three instances differ in `lastChangeUSec`
field, the newest record wins, and is propagated to the other two locations.

During activation, the file system checker (`fsck`) appropriate for the
selected file system is automatically invoked, ensuring the file system is in a
healthy state before it is mounted.

If the UID assigned to a user does not match the owner of the home directory in
the file system, the home directory is automatically and recursively `chown()`ed
to the correct UID.

Depending on the `luksDiscard` setting of the user record, either the backing
loopback file is `fallocate()`ed during activation, or the mounted file system
is `FITRIM`ed after mounting, to ensure the setting is correctly enforced.

When deactivating a home directory, the file system or block device is trimmed
or extended as configured in the `luksOfflineDiscard` setting of the user
record.
