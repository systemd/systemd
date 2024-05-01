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

## Support for Secure Locking

One key feature of `systemd-homed` managed encrypted home directories is the ability to
suspend access to them by removing the relevant encryption keys from memory.
This is done automatically during system sleep, but could also be triggered manually by the
desktop environment.
This is important in a world where most laptop users seldom shut down their computers and just
close the lid instead.
Previously, the encryption keys for the user's files remained in memory during system suspend,
so sufficiently equipped attackers could extract them (via a cold-boot attack, or similar) and
gain full access to the device.
By removing key material from memory before suspend, and re-requesting it on resume, this attack
vector can be mitigated effectively.

This functionality in `systemd-homed`, and similar functionality in any other
service that manages user home directories, is exposed to desktop environments
via the secure lock mechanism in `systemd-logind`.

Supporting this mechanism requires support in the desktop environment, since
the encryption keys (i.e. the user's login password) need to be reacquired on
system resume, from a lock screen or similar.
This lock screen must run in the system context, and cannot run in the user's
own context, because the user's context is frozen during an active secure lock.

The easiest way to support this mechanism is to run all lock screens from
the system context (i.e. by switching back to the display manager).
For example, whenvever locking the screen GNOME Shell could switch back to
GDM (which would now double as a lock screen).
For basic or custom desktop environments that don't wish to integrate with secure
locking any further, this is the minimum that needs to be done and does not create
any new dependencies on `systemd-homed` or other systemd-specific APIs.

Desktop environments could also choose to implement a hybrid solution, with two
lock screens: a normal one that runs in the user's context, and a special secure
one that runs in the system context.
When reacting to a normal (non-secure) lock, the desktop environment can present
the normal lock screen.
When a secure lock is activated, the desktop environment can switch to the secure
lock screen.
This hybrid solution allows desktop environments more flexibility with the content
they can present on the lock screen: normal locks can leverage the fact that user
data remains accessible, but secure locks remain secure.
For example: GNOME Shell can continue showing the user's notifications and media
controls on the normal lock screen, which cannot be done from GDM.
Display managers that wish to implement this hybrid solution should listen for the
`PrepareForSecureLock()` signal on the
[`org.freedesktop.login1.User` interface](https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html)
and display the secure lock screen in response.

Any display manager that supports the secure lock mechanism needs to inform `systemd-logind`,
so that `systemd-logind` knows that it is safe to activate a secure lock for this user.
This is done by setting the `$SYSTEMD_CAN_SECURE_LOCK` environment variable, or alternatively
by passing the `can-secure-lock=` argument to the
[`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
PAM module.
`systemd-logind` will only activate a secure lock for a user if all of that user's
sessions report that they are compatible with secure locking via the aforementioned means.

`systemd-logind` will automatically activate secure locks for supported users when
the system sleeps.
There are some situations where this behavior is unwanted.
For example, a desktop environment running on a mobile phone device will want to
continue reciving and showing the user's notifications even after the device is put
to sleep. Desktop environments can opt out of this behavior by calling `Inhibit()`
on the aformentioned DBus interface with `what` specified as
`SD_LOGIND_USER_INHIBIT_SUSPEND_SECURE_LOCK` and `delay` set to false, then holding
the returned FD.

`systemd-logind` will automatically activate secure locks for supported users when
all of the user's sessions have become inactive.
This will happen, for instance, if the user switches back to their display manager and
logs into a different account.
Desktop environments can opt out of this behavior simiarly; by calling `Inhibit()`
with `SD_LOGIND_USER_INHIBIT_INACTIVE_SECURE_LOCK`.

Desktop environments can manually activate a secure lock by calling `SecureLock()` on
the same interface.
This should be done in response to explicit user request (similar to the "lockdown" mode feature
found in Android).
Note that any client calling `SecureLock()` from within the session will be frozen before the
call returns.

Applications running in the session may want to be notified about an imminent secure lock.
This is possible via `Inhibit()` and `PrepareForSecureLock()` on the same interface.
Subscribe to `PrepareForSecureLock()`, then call `Inhibit()` with `what` set to
`SD_LOGIND_USER_INHIBIT_SECURE_LOCK` and `delay` set to true.
When the signal is emitted, applications should wipe their own sensitive data from memory
(e.g. login session tokens, open documents, encryption keys, etc.) to strengthen the security
of the secure lock. Applications should also close open FDs, if possible, to give the kernel
a better chance at wiping the files' contents out of memory. Applications should also temporarily
stop listening for signals emitted from system DBus services; since the applciation will be frozen
it won't be able to process the incoming events, and the broker may conclude that the application
is unresponsive and disconnect it from the bus. Once the application has cleaned up its resources,
it can drop the inhibitor FD to signal that it's ready to be locked. Applications are notified that
they're free to re-acquire their inhibitor FDs via the `SecureUnlocked()` signal.

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
