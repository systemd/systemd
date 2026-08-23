---
title: User Record Blob Directories
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# User Record Blob Directories

The blob directories are for storing binary or unstructured data that would
otherwise be stored in [JSON User Records](/USER_RECORD). For instance,
this includes image files such as the user's avatar picture. This data,
like most of the user record, will be made publicly available to the
system.

The JSON User Record specifies the location of the blob directory via the
`blobDirectory` field. If the field is unset, then there is no blob directory
and thus no blob files to look for.  Note that `blobDirectory` can exist in the
`regular`, `perMachine`, and `status` sections. The blob directory is completely
owned and managed by the service that owns the rest of the user record (as
specified in the `service` field).

For consistency, blob directories have certain restrictions placed on them
that may be enforced by their owning service. Services implementing blob
directories are free to ignore these restrictions, but software that wishes
to store some of its data in blob directories must adhere to the following:

* The directory only contains regular files; no sub-directories or any special
  files are permitted.

* Filenames inside of the directory are restricted to
  [URI Unreserved Characters](https://www.rfc-editor.org/rfc/rfc3986#section-2.3)
  (alphanumeric, `-`, `.`, `_`, and `~`), and must not start with a dot.

* The total size of the directory should not exceed 64M.

* File ownership and permissions will not be preserved. The service may reset
  the mode of the files to 0644, and ownership to whatever it wishes.

* Timestamps, xattrs, ACLs, or any other metadata on the files will not be preserved.

Services are required to ensure that the directory and its contents are
world-readable. Aside from this requirement, services are free to provide
the directory and its contents in whatever manner they like, including but
not limited to synthesizing the directory at runtime using external data
or keeping around multiple copies. Thus, only the service that owns the
directory is permitted to write to this directory in any way: for all
other software the directory is strictly read-only.

Services may choose to provide some way to change user records. Services
that provide this functionality should support changing the blob directory also.
Care must be taken to avoid exposing sensitive data to malicious clients. This
includes but is not limited to disallowing symlinks and using file descriptors
(excluding O_PATH!) to ensure that the client actually has permission to access
the data it wants the service to publish.

Services that make use of the `signature` section in the records they manage
should enforce `blobManifest`. This ensures that the contents of the blob directory
are part of the cryptographically signed data.

## Known Files

Various files in the blob directories have known semantic meanings.
The following files are currently defined:

`avatar` → An image file that should be used as the user's avatar picture.
The exact file type and resolution of this image are left unspecified,
and requirements will depend on the capabilities of the components that will
display it. However, we suggest the use of commonly-supported picture formats
(i.e. PNG or JPEG) and a resolution of 512 x 512. This image should not have any
transparency. If missing, of an incompatible file type, or otherwise unusable,
then the user does not have a profile picture and a default will be used instead.

`login-background` → An image file that will be used as the user's background on the
login screen (i.e. in GDM). The exact file type and resolution are left unspecified
and are ultimately up to the components that will render this background image. This
image should not have any transparency. If missing, of an incompatible file type, or
otherwise unusable, a fallback background of some kind will be used.

## Extending These Directories

Like JSON User Records, the blob directories are intended to be extendable for
various applications. In general, subsystems are free to introduce their own
files, as long as:

* The requirements listed above are all met.

* Care is taken to avoid namespace clashes. Please prefix your file names with
  a short identifier of your project to avoid ambiguities and incompatibilities.

* This specification is supposed to be a living specification. If you need
  additional files, please consider defining them upstream for inclusion in
  this specification. If they are reasonably universally useful, it would be
  best to list them here.

## Examples

The simplest way to define a user record is via the drop-in directories (as documented
in [nss-systemd(8)](https://www.freedesktop.org/software/systemd/man/latest/nss-systemd.html)
and [systemd-userdb.service(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-userdbd.service.html)).
Such records can have blob directories by simply referring to some persistent
place from the record, possibly next to the record itself. For instance,
`/etc/userdb/grobie.user` may contain:

```json
{
        "userName": "grobie",
        "disposition": "regular",
        "homeDirectory": "/home/grobie",
        "blobDirectory": "/etc/userdb/grobie.blob/",
}
```

In this case, `/etc/userdb/grobie.blob/` will be the blob directory for the
user `grobie`.

A more complicated case is a home directory managed by `systemd-homed.service`.
When it manages a home directory, it maintains and synchronizes two separate
blob directories: one belonging to the system in `/var/cache/systemd/home`,
and another belonging to the home directory in `~/.identity-blob`. The system
blob directory ensures that the blob data is available while the home directory
is encrypted or otherwise unavailable, and the home blob directory ensures that
the user account remains portable between systems. To implement this behavior,
`systemd-homed.service` always sets `blobDirectory` to the system blob directory
in the `binding` section of the user record (i.e. this is _not_ persisted to
`~/.identity`). If some client tries to update the user record with a new blob
directory, `systemd-homed.service` will copy the updated blob directory into both
the system and home blob locations.
