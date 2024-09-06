---
title: systemd-homed and JSON User/Group Record Support in Desktop Environments
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# `systemd-homed` and JSON User/Group Record Support in Desktop Environments

Starting with version 245, systemd supports a new subsystem
[`systemd-homed.service`](https://www.freedesktop.org/software/systemd/man/systemd-homed.service.html)
for managing regular ("human") users and their home directories.
Along with it a new concept `userdb` got merged that brings rich, extensible JSON user/group
records, extending the classic UNIX/glibc NSS `struct passwd`/`struct group` structures.
Both additions are added in a fully backwards compatible way, accessible through `getpwnam()`/`getgrnam()`/… (i.e. libc NSS) and PAM as
usual, meaning that for basic support no changes in the upper layers of the
stack (in particular desktop environments, such as GNOME or KDE) have to be made.
However, for better support a number of changes to desktop environments are recommended.
A few areas where that applies are discussed below.

Before reading on, please read up on the basic concepts, specifically:

* [Home Directories](/HOME_DIRECTORY)
* [JSON User Records](/USER_RECORD)
* [JSON Group Records](/GROUP_RECORD)
* [User/Group Record Lookup API via Varlink](/USER_GROUP_API)

## Support for Suspending Home Directory Access during System Suspend

One key feature of `systemd-homed` managed encrypted home directories is the
ability that access to them can be suspended automatically during system sleep,
removing any cryptographic key material from memory while doing so.
This is important in a world where most laptop users seldom shut down their computers
but most of the time just suspend them instead.
Previously, the encryption keys for the home directories remained in memory during system suspend, so that
sufficiently equipped attackers could read them from there and gain full access to the device.
By removing the key material from memory before suspend, and re-requesting it on resume this attack vector can be closed down effectively.

Supporting this mechanism requires support in the desktop environment, since
the encryption keys (i.e. the user's login password) need to be reacquired on
system resume, from a lock screen or similar.
This lock screen must run in system context, and cannot run in the user's own context, since otherwise it
might end up accessing the home directory of the user even though access to it
is temporarily suspended and thus will hang if attempted.

It is suggested that desktop environments that implement lock screens run them
from system context, for example by switching back to the display manager, and
only revert back to the session after re-authentication via this system lock
screen (re-authentication in this case refers to passing the user's login
credentials to the usual PAM authentication hooks).
Or in other words, when going into system suspend it is recommended that GNOME Shell switches back to
the GNOME Display Manager login screen which now should double as screen lock,
and only switches back to the shell's UI after the user re-authenticated there.

Note that this change in behavior is a good idea in any case, and does not
create any dependencies on `systemd-homed` or systemd-specific APIs.
It's simply a change of behavior regarding use of existing APIs, not a suggested hook-up to any new APIs.

A display manager which supports this kind of out-of-context screen lock
operation needs to inform systemd-homed about this so that systemd-homed knows
that it is safe to suspend the user's home directory on suspend.
This is done via the `suspend=` argument to the
[`pam_systemd_home`](https://www.freedesktop.org/software/systemd/man/pam_systemd_home.html)
PAM module.
A display manager should hence change its PAM stack configurationto set this parameter to on.
`systemd-homed` will not suspend home directories if there's at least one active session of the user that does not support
suspending, as communicated via this parameter.

## User Management UIs

The rich user/group records `userdb` and `systemd-homed` support carry various
fields of relevance to UIs that manage the local user database or parts thereof.
In particular, most of the metadata `accounts-daemon` (also see below)
supports is directly available in these JSON records.
Hence it makes sense for any user management UI to expose them directly.

`systemd-homed` exposes APIs to add, remove and make changes to local users via
D-Bus, with full [polkit](https://www.freedesktop.org/software/polkit/docs/latest/) hook-up.
On the command line this is exposed via the `homectl` command. A graphical UI that exposes similar functionality would be
very useful, exposing the various new account settings, and in particular
providing a stream-lined UI for enrolling new-style authentication tokens such
as PKCS#11/YubiKey-style devices.
(Ideally, if the user plugs in an uninitialized YubiKey during operation it might be nice if the Desktop would
automatically ask if a key pair shall be written to it and the local account be
bound to it, `systemd-homed` provides enough YubiKey/PKCS#11 support to make
this a reality today; except that it will not take care of token
initialization).

A strong point of `systemd-homed` is per-user resource management.
In particular disk space assignments are something that most likely should be
exposed in a user management UI. Various metadata fields are supplied allowing
exposure of disk space assignment "slider" UI.
Note however that the file system back-ends of `systemd-homed.service` have different feature sets.
Specifically, only btrfs has online file system shrinking support, ext4 only offline file
system shrinking support, and xfs no shrinking support at all (all three file
systems support online file system growing however).
This means if the LUKS back-end is used, disk space assignment cannot be instant for logged in users, unless btrfs is used.

Note that only `systemd-homed` provides an API for modifying/creating/deleting users.
The generic `userdb` subsystem (which might have other back-ends, besides
`systemd-homed`, for example LDAP or Windows) exclusively provides a read-only interface.
(This is unlikely to change, as the other back-ends might have very
different concepts of adding or modifying users, i.e. might not even have any local concept for that at all).
This means any user management UI that intends to change (and not just view) user accounts should talk directly to
`systemd-homed` to make use of its features; there's no abstraction available
to support other back-ends under the same API.

Unfortunately there's currently no documentation for the `systemd-homed` D-Bus API.
Consider using the `homectl` sources as guidelines for implementing a user management UI.
The JSON user/records are well documented however, see above,
and the D-Bus API provides limited introspection.

## Relationship to `accounts-daemon`

For a long time `accounts-daemon` has been included in Linux distributions
providing richer user accounts.
The functionality of this daemon overlaps in many areas with the functionality of `systemd-homed` or `userdb`, but there are
systematic differences, which means that `systemd-homed` cannot replace
`accounts-daemon` fully.
Most importantly: `accounts-daemon` provides "side-car" metadata for *any* type of user account, while `systemd-homed` only
provides additional metadata for the users it defines itself.
In other words: `accounts-daemon` will augment foreign accounts; `systemd-homed` cannot be used
to augment users defined elsewhere, for example in LDAP or as classic `/etc/passwd` records.

This probably means that for the time being, a user management UI (or other UI)
that wants to support rich user records with compatibility with the status quo
ante should probably talk to both `systemd-homed` and `accounts-daemon` at the
same time, and ignore `accounts-daemon`'s records if `systemd-homed` defines them.
While I (Lennart) personally believe in the long run `systemd-homed` is
the way to go for rich user records, any UI that wants to manage and support
rich records for classic records has to support `accounts-daemon` in parallel
for the time being.

In the short term, it might make sense to also expose the `userdb` provided
records via `accounts-daemon`, so that clients of the latter can consume them
without changes. However, I think in the long run `accounts-daemon` should
probably be removed from the general stack, hence this sounds like a temporary
solution only.

In case you wonder, there's no automatic mechanism for converting existing
users registered in `/etc/passwd` or LDAP to users managed by `systemd-homed`.
There's documentation for doing this manually though, see
[Converting Existing Users to systemd-homed managed Users](/CONVERTING_TO_HOMED).

## Future Additions

JSON user/group records are extensible, hence we can easily add any additional fields desktop environments require.
For example, pattern-based authentication is likely very useful on touch-based devices,
and the user records should hence learn them natively.
Fields for other authentication mechanisms, such as fingerprint authentication should be provided as well, eventually.

It is planned to extend the `userdb` Varlink API to support look-ups by partial
user name and real name (GECOS) data, so that log-in screens can optionally
implement simple complete-as-you-type login screens.

It is planned to extend the `systemd-homed` D-Bus API to instantly inform clients
about hardware associated with a specific user being plugged in, to which login
screens can listen in order to initiate authentication.
Specifically, any YubiKey-like security token plugged in that is associated with a local user
record should initiate authentication for that user, making typing in of the
username unnecessary.
