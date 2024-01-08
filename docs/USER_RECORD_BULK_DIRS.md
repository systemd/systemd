---
title: User Record Bulk Directories
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2024 GNOME Foundation Inc.
#     Original Author: Adrian Vovk
---

# User Record Bulk Directories

The bulk directories are for storing binary or unstructured data that would
otherwise be stored in [JSON User Records](USER_RECORD.md). For instance,
this includes image files such as the user's avatar picture.

The JSON User Record specifies the location of the bulk directory via the
`bulkDirectory` field. If the field is unset, then there is no bulk directory
and thus no bulk files to look for. The bulk directory is completely
owned and managed by the service that owns the rest of the user record (as
specified in the `service` field).

For consistency, bulk directories have certain restrictions placed on them
that may be enforced by their owning service. Services implementing bulk
directories are free to ignore these restrictions, but software that wishes
to store some of its data in bulk directories must adhere to the following:

* The directory only contains regular files; no sub-directories or any special
  files are permitted.

* Filenames inside of the directory are restricted to printable ASCII.

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
that provide this functionality should support changing the bulk directory.
We recommend that this is done by detecting when the client changes the value
of `bulkDirectory` and responding to this in whichever way is most appropriate
for the service. If implemented in this way, the service should not assume that
the new value for `bulkDirectory` is persistent and should persist the new bulk
directory on its own. This allows a client to update the contents of the bulk
directory by creating a temporary directory, preparing the appropriate contents,
asking the service to change the user record (with the new `bulkDirectory` set to
the temporary directory's path), and finally deleting the temporary directory.

## Known Files

Various files in the bulk directories have known semantic meanings.
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
and are ultimately up to the components that will render this background image.
We suggest that the image is blurred to protect the user's privacy and to improve
readability of GUI components rendered over top of it. This image should not have any
transparency. If missing, of an incompatible file type, or otherwise unusable, a fallback
background of some kind will be used.

## Extending These Directories

Like JSON User Records, the bulk directories are intended to be extendable for
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
and [systemd-userdb.service(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-userdbd.service.html#)).
Such records can have bulk directories by simply referring to some persistent
place from the record, possibly next to the record itself. For instance,
`/etc/userdb/grobie.user` may contain:

```json
{
        "userName": "grobie",
        "disposition": "regular",
        "homeDirectory": "/home/grobie",
        "bulkDirectory": "/etc/userdb/grobie.bulk/",
}
```

In this case, `/etc/userdb/grobie.bulk/` will be the bulk directory for the
user `grobie`.

A more complicated case is a home directory managed by `systemd-homed.service`.
When it manages a home directory, it maintains and synchronizes two separate
bulk directories: one belonging to the system in `/var/cache/systemd/home`,
and another belonging to the home directory in `~/.identity/bulk`. The system
bulk directory ensures that the bulk data is available while the home directory
is encrypted or otherwise unavailable, and the home bulk directory ensures that
the user account remains portable between systems. To implement this behavior,
`systemd-homed.service` always sets `bulkDirectory` to the system bulk directory
in the `binding` section of the user record (i.e. this is _not_ persisted to
`~/.identity/record.json`). If some client tries to update the user record
and sets `bulkDirectory` to something new, `systemd-homed.service` will copy
the updated bulk directory into both the system and home bulk locations.
