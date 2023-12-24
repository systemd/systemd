---
title: JSON User Records
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# JSON User Records

systemd optionally processes user records that go beyond the classic UNIX (or
glibc NSS) `struct passwd`. Various components of systemd are able to provide
and consume records in a more extensible format of a dictionary of key/value
pairs, encoded as JSON. Specifically:

1. [`systemd-homed.service`](https://www.freedesktop.org/software/systemd/man/systemd-homed.service.html)
   manages `human` user home directories and embeds these JSON records
   directly in the home directory images
   (see [Home Directories](HOME_DIRECTORY.md) for details).

2. [`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
   processes these JSON records for users that log in, and applies various
   settings to the activated session, including environment variables, nice
   levels and more.

3. [`systemd-logind.service`](https://www.freedesktop.org/software/systemd/man/systemd-logind.service.html)
   processes these JSON records of users that log in, and applies various
   resource management settings to the per-user slice units it manages. This
   allows setting global limits on resource consumption by a specific user.

4. [`nss-systemd`](https://www.freedesktop.org/software/systemd/man/nss-systemd.html)
   is a glibc NSS module that synthesizes classic NSS records from these JSON
   records, providing full backwards compatibility with the classic UNIX APIs
   both for look-up and enumeration.

5. The service manager (PID 1) exposes dynamic users (i.e. users synthesized as
   effect of `DynamicUser=` in service unit files) as these advanced JSON
   records, making them discoverable to the rest of the system.

6. [`systemd-userdbd.service`](https://www.freedesktop.org/software/systemd/man/systemd-userdbd.service.html)
   is a small service that can translate UNIX/glibc NSS records to these JSON
   user records. It also provides a unified [Varlink](https://varlink.org/) API
   for querying and enumerating records of this type, optionally acquiring them
   from various other services.

JSON user records may contain various fields that are not available in `struct
passwd`, and are extensible for other applications. For example, the record may
contain information about:

1. Additional security credentials (PKCS#11 security token information,
   biometrical authentication information, SSH public key information)

2. Additional user metadata, such as a picture, email address, location string,
   preferred language or timezone

3. Resource Management settings (such as CPU/IO weights, memory and tasks
   limits, classic UNIX resource limits or nice levels)

4. Runtime parameters such as environment variables or the `nodev`, `noexec`,
   `nosuid` flags to use for the home directory

5. Information about where to mount the home directory from

And various other things. The record is intended to be extensible, for example
the following extensions are envisioned:

1. Windows network credential information

2. Information about default IMAP, SMTP servers to use for this user

3. Parental control information to enforce on this user

4. Default parameters for backup applications and similar

Similar to JSON User Records there are also
[JSON Group Records](GROUP_RECORD.md) that encapsulate UNIX groups.

JSON User Records may be transferred or written to disk in various protocols
and formats. To inquire about such records defined on the local system use the
[User/Group Lookup API via Varlink](USER_GROUP_API.md). User/group records may
also be dropped in number of drop-in directories as files. See
[`nss-systemd(8)`](https://www.freedesktop.org/software/systemd/man/nss-systemd.html)
for details.

## Why JSON?

JSON is nicely extensible and widely used. In particular it's easy to
synthesize and process with numerous programming languages. It's particularly
popular in the web communities, which hopefully should make it easy to link
user credential data from the web and from local systems more closely together.

Please note that this specification assumes that JSON numbers may cover the full
integer range of -2^63 … 2^64-1 without loss of precision (i.e. INT64_MIN …
UINT64_MAX). Please read, write and process user records as defined by this
specification only with JSON implementations that provide this number range.

## General Structure

The JSON user records generated and processed by systemd follow a general
structure, consisting of seven distinct "sections". Specifically:

1. Various fields are placed at the top-level of user record (the `regular`
   section). These are generally fields that shall apply unconditionally to the
   user in all contexts, are portable and not security sensitive.

2. A number of fields are located in the `privileged` section (a sub-object of
   the user record). Fields contained in this object are security sensitive,
   i.e. contain information that the user and the administrator should be able
   to see, but other users should not. In many ways this matches the data
   stored in `/etc/shadow` in classic Linux user accounts, i.e. includes
   password hashes and more. Algorithmically, when a user record is passed to
   an untrusted client, by monopolizing such sensitive records in a single
   object field we can easily remove it from view.

3. A number of fields are located in objects inside the `perMachine` section
   (an array field of the user record). Primarily these are resource
   management-related fields, as those tend to make sense on a specific system
   only, e.g. limiting a user's memory use to 1G only makes sense on a specific
   system that has more than 1G of memory. Each object inside the `perMachine`
   array comes with a `matchMachineId` or `matchHostname` field which indicate
   which systems to apply the listed settings to. Note that many fields
   accepted in the `perMachine` section can also be set at the top level (the
   `regular` section), where they define the fallback if no matching object in
   `perMachine` is found.

4. Various fields are located in the `binding` section (a sub-sub-object of the
   user record; an intermediary object is inserted which is keyed by the
   machine ID of the host). Fields included in this section "bind" the object
   to a specific system. They generally include non-portable information about
   paths or UID assignments, that are true on a specific system, but not
   necessarily on others, and which are managed automatically by some user
   record manager (such as `systemd-homed`). Data in this section is considered
   part of the user record only in the local context, and is generally not
   ported to other systems. Due to that it is not included in the reduced user
   record the cryptographic signature defined in the `signature` section is
   calculated on. In `systemd-homed` this section is also removed when the
   user's record is stored in the `~/.identity` file in the home directory, so
   that every system with access to the home directory can manage these
   `binding` fields individually. Typically, the binding section is persisted
   to the local disk.

5. Various fields are located in the `status` section (a sub-sub-object of the
   user record, also with an intermediary object between that is keyed by the
   machine ID, similar to the way the `binding` section is organized). This
   section is augmented during runtime only, and never persisted to disk. The
   idea is that this section contains information about current runtime
   resource usage (for example: currently used disk space of the user), that
   changes dynamically but is otherwise immediately associated with the user
   record and for many purposes should be considered to be part of the user
   record.

6. The `signature` section contains one or more cryptographic signatures of a
   reduced version of the user record. This is used to ensure that only user
   records defined by a specific source are accepted on a system, by validating
   the signature against the set of locally accepted signature public keys. The
   signature is calculated from the JSON user record with all sections removed,
   except for `regular`, `privileged`, `perMachine`. Specifically, `binding`,
   `status`, `signature` itself and `secret` are removed first and thus not
   covered by the signature. This section is optional, and is only used when
   cryptographic validation of user records is required (as it is by
   `systemd-homed.service` for example).

7. The `secret` section contains secret user credentials, such as password or
   PIN information. This data is never persisted, and never returned when user
   records are inquired by a client, privileged or not. This data should only
   be included in a user record very briefly, for example when certain very
   specific operations are executed. For example, in tools such as
   `systemd-homed` this section may be included in user records, when creating
   a new home directory, as passwords and similar credentials need to be
   provided to encrypt the home directory with.

Here's a tabular overview of the sections and their properties:

| Section    | Included in Signature | Persistent | Security Sensitive | Contains Host-Specific Data |
|------------|-----------------------|------------|--------------------|-----------------------------|
| regular    | yes                   | yes        | no                 | no                          |
| privileged | yes                   | yes        | yes                | no                          |
| perMachine | yes                   | yes        | no                 | yes                         |
| binding    | no                    | yes        | no                 | yes                         |
| status     | no                    | no         | no                 | yes                         |
| signature  | no                    | yes        | no                 | no                          |
| secret     | no                    | no         | yes                | no                          |

Note that services providing user records to the local system are free to
manage only a subset of these sections and never include the others in
them. For example, a service that has no concept of signed records (for example
because the records it manages are inherently trusted anyway) does not have to
bother with the `signature` section. A service that only defines records in a
strictly local context and without signatures doesn't have to deal with the
`perMachine` or `binding` sections and can include its data exclusively in the
regular section. A service that uses a separate, private channel for
authenticating users (or that doesn't have a concept of authentication at all)
does not need to be concerned with the `secret` section of user records, as
the fields included therein are only useful when executing authentication
operations natively against JSON user records.

The `systemd-homed` manager uses all seven sections for various
purposes. Inside the home directories (and if the LUKS2 backend is used, also
in the LUKS2 header) a user record containing the `regular`, `privileged`,
`perMachine` and `signature` sections is stored. `systemd-homed` also stores a
version of the record on the host, with the same four sections and augmented
with an additional, fifth `binding` section. When a local client enquires about
a user record managed by `systemd-homed` the service will add in some
additional information about the user and home directory in the `status`
section — this version is only transferred via IPC and never written to
disk. Finally the `secret` section is used during authentication operations via
IPC to transfer the user record along with its authentication tokens in one go.

## Fields in the `regular` section

As mentioned, the `regular` section's fields are placed at the top level
object. The following fields are currently defined:

`userName` → The UNIX user name for this record. Takes a string with a valid
UNIX user name. This field is the only mandatory field, all others are
optional. Corresponds with the `pw_name` field of `struct passwd` and the
`sp_namp` field of `struct spwd` (i.e. the shadow user record stored in
`/etc/shadow`). See [User/Group Name Syntax](USER_NAMES.md) for
the (relaxed) rules the various systemd components enforce on user/group names.

`realm` → The "realm" a user is defined in. This concept allows distinguishing
users with the same name that originate in different organizations or
installations. This should take a string in DNS domain syntax, but doesn't have
to refer to an actual DNS domain (though it is recommended to use one for
this). The idea is that the user `lpoetter` in the `redhat.com` realm might be
distinct from the same user in the `poettering.hq` realm. User records for the
same user name that have different realm fields are considered referring to
different users. When updating a user record it is required that any new
version has to match in both `userName` and `realm` field. This field is
optional, when unset the user should not be considered part of any realm. A
user record with a realm set is never compatible (for the purpose of updates,
see above) with a user record without one set, even if the `userName` field matches.

`realName` → The real name of the user, a string. This should contain the
user's real ("human") name, and corresponds loosely to the GECOS field of
classic UNIX user records. When converting a `struct passwd` to a JSON user
record this field is initialized from GECOS (i.e. the `pw_gecos` field), and
vice versa when converting back. That said, unlike GECOS this field is supposed
to contain only the real name and no other information. This field must not
contain control characters (such as `\n`) or colons (`:`), since those are used
as record separators in classic `/etc/passwd` files and similar formats.

`emailAddress` → The email address of the user, formatted as
string. [`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
initializes the `$EMAIL` environment variable from this value for all login
sessions.

`iconName` → The name of an icon picked by the user, for example for the
purpose of an avatar. This must be a string, and should follow the semantics
defined in the [Icon Naming
Specification](https://standards.freedesktop.org/icon-naming-spec/icon-naming-spec-latest.html).

`location` → A free-form location string describing the location of the user,
if that is applicable. It's probably wise to use a location string processable
by geo-location subsystems, but this is not enforced nor required. Example:
`Berlin, Germany` or `Basement, Room 3a`.

`disposition` → A string, one of `intrinsic`, `system`, `dynamic`, `regular`,
`container`, `reserved`. If specified clarifies the disposition of the user,
i.e. the context it is defined in. For regular, "human" users this should be
`regular`, for system users (i.e. users that system services run under, and
similar) this should be `system`. The `intrinsic` disposition should be used
only for the two users that have special meaning to the OS kernel itself,
i.e. the `root` and `nobody` users. The `container` string should be used for
users that are used by an OS container, and hence will show up in `ps` listings
and such, but are only defined in container context. Finally `reserved` should
be used for any users outside of these use-cases. Note that this property is
entirely optional and applications are assumed to be able to derive the
disposition of a user automatically from a record even in absence of this
field, based on other fields, for example the numeric UID. By setting this
field explicitly applications can override this default determination.

`lastChangeUSec` → An unsigned 64-bit integer value, referring to a timestamp in µs
since the epoch 1970, indicating when the user record (specifically, any of the
`regular`, `privileged`, `perMachine` sections) was last changed. This field is
used when comparing two records of the same user to identify the newer one, and
is used for example for automatic updating of user records, where appropriate.

`lastPasswordChangeUSec` → Similar, also an unsigned 64-bit integer value,
indicating the point in time the password (or any authentication token) of the
user was last changed. This corresponds to the `sp_lstchg` field of `struct
spwd`, i.e. the matching field in the user shadow database `/etc/shadow`,
though provides finer resolution.

`shell` → A string, referring to the shell binary to use for terminal logins of
this user. This corresponds with the `pw_shell` field of `struct passwd`, and
should contain an absolute file system path. For system users not suitable for
terminal log-in this field should not be set.

`umask` → The `umask` to set for the user's login sessions. Takes an
integer. Note that usually on UNIX the umask is noted in octal, but JSON's
integers are generally written in decimal, hence in this context we denote it
umask in decimal too. The specified value should be in the valid range for
umasks, i.e. 0000…0777 (in octal as typical in UNIX), or 0…511 (in decimal, how
it actually appears in the JSON record). This `umask` is automatically set by
[`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
for all login sessions of the user.

`environment` → An array of strings, each containing an environment variable
and its value to set for the user's login session, in a format compatible with
[`putenv()`](https://man7.org/linux/man-pages/man3/putenv.3.html). Any
environment variable listed here is automatically set by
[`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
for all login sessions of the user.

`timeZone` → A string indicating a preferred timezone to use for the user. When
logging in
[`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
will automatically initialize the `$TZ` environment variable from this
string. The string should be a `tzdata` compatible location string, for
example: `Europe/Berlin`.

`preferredLanguage` → A string indicating the preferred language/locale for the
user. When logging in
[`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
will automatically initialize the `$LANG` environment variable from this
string. The string hence should be in a format compatible with this environment
variable, for example: `de_DE.UTF8`.

`niceLevel` → An integer value in the range -20…19. When logging in
[`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
will automatically initialize the login process' nice level to this value with,
which is then inherited by all the user's processes, see
[`setpriority()`](https://man7.org/linux/man-pages/man2/setpriority.2.html) for
more information.

`resourceLimits` → An object, where each key refers to a Linux resource limit
(such as `RLIMIT_NOFILE` and similar). Their values should be an object with
two keys `cur` and `max` for the soft and hard resource limit. When logging in
[`pam_systemd`](https://www.freedesktop.org/software/systemd/man/pam_systemd.html)
will automatically initialize the login process' resource limits to these
values, which is then inherited by all the user's processes, see
[`setrlimit()`](https://man7.org/linux/man-pages/man2/setrlimit.2.html) for more
information.

`locked` → A boolean value. If true, the user account is locked, the user may
not log in. If this field is missing it should be assumed to be false,
i.e. logins are permitted. This field corresponds to the `sp_expire` field of
`struct spwd` (i.e. the `/etc/shadow` data for a user) being set to zero or
one.

`notBeforeUSec` → An unsigned 64-bit integer value, indicating a time in µs since
the UNIX epoch (1970) before which the record should be considered invalid for
the purpose of logging in.

`notAfterUSec` → Similar, but indicates the point in time *after* which logins
shall not be permitted anymore. This corresponds to the `sp_expire` field of
`struct spwd`, when it is set to a value larger than one, but provides finer
granularity.

`storage` → A string, one of `classic`, `luks`, `directory`, `subvolume`,
`fscrypt`, `cifs`. Indicates the storage mechanism for the user's home
directory. If `classic` the home directory is a plain directory as in classic
UNIX. When `directory`, the home directory is a regular directory, but the
`~/.identity` file in it contains the user's user record, so that the directory
is self-contained. Similar, `subvolume` is a `btrfs` subvolume that also
contains a `~/.identity` user record; `fscrypt` is an `fscrypt`-encrypted
directory, also containing the `~/.identity` user record; `luks` is a per-user
LUKS volume that is mounted as home directory, and `cifs` a home directory
mounted from a Windows File Share. The five latter types are primarily used by
`systemd-homed` when managing home directories, but may be used if other
managers are used too. If this is not set, `classic` is the implied default.

`diskSize` → An unsigned 64-bit integer, indicating the intended home directory
disk space in bytes to assign to the user. Depending on the selected storage
type this might be implemented differently: for `luks` this is the intended size
of the file system and LUKS volume, while for the others this likely translates
to classic file system quota settings.

`diskSizeRelative` → Similar to `diskSize` but takes a relative value, but
specifies a fraction of the available disk space on the selected storage medium
to assign to the user. This unsigned integer value is normalized to 2^32 =
100%.

`skeletonDirectory` → Takes a string with the absolute path to the skeleton
directory to populate a new home directory from. This is only used when a home
directory is first created, and defaults to `/etc/skel` if not defined.

`accessMode` → Takes an unsigned integer in the range 0…511 indicating the UNIX
access mask for the home directory when it is first created.

`tasksMax` → Takes an unsigned 64-bit integer indicating the maximum number of
tasks the user may start in parallel during system runtime. This counts
all tasks (i.e. threads, where each process is at least one thread) the user starts or that are
forked from these processes even if the user identity is changed (for example
by setuid binaries/`su`/`sudo` and similar).
[`systemd-logind.service`](https://www.freedesktop.org/software/systemd/man/systemd-logind.service.html)
enforces this by setting the `TasksMax` slice property for the user's slice
`user-$UID.slice`.

`memoryHigh`/`memoryMax` → These take unsigned 64-bit integers indicating upper
memory limits for all processes of the user (plus all processes forked off them
that might have changed user identity), in bytes. Enforced by
[`systemd-logind.service`](https://www.freedesktop.org/software/systemd/man/systemd-logind.service.html),
similar to `tasksMax`.

`cpuWeight`/`ioWeight` → These take unsigned integers in the range 1…10000
(defaults to 100) and configure the CPU and IO scheduling weights for the
user's processes as a whole. Also enforced by
[`systemd-logind.service`](https://www.freedesktop.org/software/systemd/man/systemd-logind.service.html),
similar to `tasksMax`, `memoryHigh` and `memoryMax`.

`mountNoDevices`/`mountNoSuid`/`mountNoExecute` → Three booleans that control
the `nodev`, `nosuid`, `noexec` mount flags of the user's home
directories. Note that these booleans are only honored if the home directory
is managed by a subsystem such as `systemd-homed.service` that automatically
mounts home directories on login.

`cifsDomain` → A string indicating the Windows File Sharing domain (CIFS) to
use. This is generally useful, but particularly when `cifs` is used as storage
mechanism for the user's home directory, see above.

`cifsUserName` → A string indicating the Windows File Sharing user name (CIFS)
to associate this user record with. This is generally useful, but particularly
useful when `cifs` is used as storage mechanism for the user's home directory,
see above.

`cifsService` → A string indicating the Windows File Share service (CIFS) to
mount as home directory of the user on login. Should be in format
`//<host>/<service>/<directory/…>`. The directory part is optional. If missing
the top-level directory of the CIFS share is used.

`cifsExtraMountOptions` → A string with additional mount options to pass to
`mount.cifs` when mounting the home directory CIFS share.

`imagePath` → A string with an absolute file system path to the file, directory
or block device to use for storage backing the home directory. If the `luks`
storage is used, this refers to the loopback file or block device node to store
the LUKS volume on. For `fscrypt`, `directory`, `subvolume` this refers to the
directory to bind mount as home directory on login. Not defined for `classic`
or `cifs`.

`homeDirectory` → A string with an absolute file system path to the home
directory. This is where the image indicated in `imagePath` is mounted to on
login and thus indicates the application facing home directory while the home
directory is active, and is what the user's `$HOME` environment variable is set
to during log-in. It corresponds to the `pw_dir` field of `struct passwd`.

`uid` → An unsigned integer in the range 0…4294967295: the numeric UNIX user ID (UID) to
use for the user.  This corresponds to the `pw_uid` field of `struct passwd`.

`gid` → An unsigned integer in the range 0…4294967295: the numeric UNIX group
ID (GID) to use for the user. This corresponds to the `pw_gid` field of
`struct passwd`.

`memberOf` → An array of strings, each indicating a UNIX group this user shall
be a member of. The listed strings must be valid group names, but it is not
required that all groups listed exist in all contexts: any entry for which no
group exists should be silently ignored.

`fileSystemType` → A string, one of `ext4`, `xfs`, `btrfs` (possibly others) to
use as file system for the user's home directory. This is primarily relevant
when the storage mechanism used is `luks` as a file system to use inside the
LUKS container must be selected.

`partitionUuid` → A string containing a lower-case, text-formatted UUID, referencing
the GPT partition UUID the home directory is located in. This is primarily
relevant when the storage mechanism used is `luks`.

`luksUuid` → A string containing a lower-case, text-formatted UUID, referencing
the LUKS volume UUID the home directory is located in. This is primarily
relevant when the storage mechanism used is `luks`.

`fileSystemUuid` → A string containing a lower-case, text-formatted UUID,
referencing the file system UUID the home directory is located in. This is
primarily relevant when the storage mechanism used is `luks`.

`luksDiscard` → A boolean. If true and `luks` storage is used, controls whether
the loopback block devices, LUKS and the file system on top shall be used in
`discard` mode, i.e. erased sectors should always be returned to the underlying
storage. If false and `luks` storage is used turns this behavior off. In
addition, depending on this setting an `FITRIM` or `fallocate()` operation is
executed to make sure the image matches the selected option.

`luksOfflineDiscard` → A boolean. Similar to `luksDiscard`, it controls whether
to trim/allocate the file system/backing file when deactivating the home
directory.

`luksExtraMountOptions` → A string with additional mount options to append to
the default mount options for the file system in the LUKS volume.

`luksCipher` → A string, indicating the cipher to use for the LUKS storage mechanism.

`luksCipherMode` → A string, selecting the cipher mode to use for the LUKS storage mechanism.

`luksVolumeKeySize` → An unsigned integer, indicating the volume key length in
bytes to use for the LUKS storage mechanism.

`luksPbkdfHashAlgorithm` → A string, selecting the hash algorithm to use for
the PBKDF operation for the LUKS storage mechanism.

`luksPbkdfType` → A string, indicating the PBKDF type to use for the LUKS storage mechanism.

`luksPbkdfForceIterations` → An unsigned 64-bit integer, indicating the intended
number of iterations for the PBKDF operation, when LUKS storage is used.

`luksPbkdfTimeCostUSec` → An unsigned 64-bit integer, indicating the intended
time cost for the PBKDF operation, when the LUKS storage mechanism is used, in
µs. Ignored when `luksPbkdfForceIterations` is set.

`luksPbkdfMemoryCost` → An unsigned 64-bit integer, indicating the intended
memory cost for the PBKDF operation, when LUKS storage is used, in bytes.

`luksPbkdfParallelThreads` → An unsigned 64-bit integer, indicating the intended
required parallel threads for the PBKDF operation, when LUKS storage is used.

`luksSectorSize` → An unsigned 64-bit integer, indicating the sector size to
use for the LUKS storage mechanism, in bytes. Must be a power of two between
512 and 4096.

`autoResizeMode` → A string, one of `off`, `grow`, `shrink-and-grow`. Unless
set to `off`, controls whether the home area shall be grown automatically to
the size configured in `diskSize` automatically at login time. If set to
`shrink-and-grown` the home area is also shrunk to the minimal size possible
(as dictated by used disk space and file system constraints) on logout.

`rebalanceWeight` → An unsigned integer, `null` or a boolean. Configures the
free disk space rebalancing weight for the home area. The integer must be in
the range 1…10000 to configure an explicit weight. If unset, or set to `null`
or `true` the default weight of 100 is implied. If set to 0 or `false`
rebalancing is turned off for this home area.

`service` → A string declaring the service that defines or manages this user
record. It is recommended to use reverse domain name notation for this. For
example, if `systemd-homed` manages a user a string of `io.systemd.Home` is
used for this.

`rateLimitIntervalUSec` → An unsigned 64-bit integer that configures the
authentication rate limiting enforced on the user account. This specifies a
timer interval (in µs) within which to count authentication attempts. When the
counter goes above the value configured n `rateLimitIntervalBurst` log-ins are
temporarily refused until the interval passes.

`rateLimitIntervalBurst` → An unsigned 64-bit integer, closely related to
`rateLimitIntervalUSec`, that puts a limit on authentication attempts within
the configured time interval.

`enforcePasswordPolicy` → A boolean. Configures whether to enforce the system's
password policy when creating the home directory for the user or changing the
user's password. By default the policy is enforced, but if this field is false
it is bypassed.

`autoLogin` → A boolean. If true the user record is marked as suitable for
auto-login. Systems are supposed to automatically log in a user marked this way
during boot, if there's exactly one user on it defined this way.

`stopDelayUSec` → An unsigned 64-bit integer, indicating the time in µs the
per-user service manager is kept around after the user fully logged out.  This
value is honored by
[`systemd-logind.service`](https://www.freedesktop.org/software/systemd/man/systemd-logind.service.html). If
set to zero the per-user service manager is immediately terminated when the
user logs out, and longer values optimize high-frequency log-ins as the
necessary work to set up and tear down a log-in is reduced if the service
manager stays running.

`killProcesses` → A boolean. If true all processes of the user are
automatically killed when the user logs out. This is enforced by
[`systemd-logind.service`](https://www.freedesktop.org/software/systemd/man/systemd-logind.service.html). If
false any processes left around when the user logs out are left running.

`freezeSession` → A boolean. If true the user's session is frozen whenever the home
directory is locked (i.e. whenever the contents of the user's home directory are made
inaccessible until the user re-authenticates). If false the user's session will not be
frozen whenever the home directory is locked, but the kernel may still freeze any task
that tries to access files in the user's home directory. This can lead to edge-cases that
may lead to data loss (for example: the display server starts killing apps frozen by the
kernel because it sees them as unresponsive). Thus, we recommend that this setting is
left unset or is set to true.

`passwordChangeMinUSec`/`passwordChangeMaxUSec` → An unsigned 64-bit integer,
encoding how much time has to pass at least/at most between password changes of
the user. This corresponds with the `sp_min` and `sp_max` fields of `struct
spwd` (i.e. the `/etc/shadow` entries of the user), but offers finer
granularity.

`passwordChangeWarnUSec` → An unsigned 64-bit integer, encoding how much time to
warn the user before their password expires, in µs. This corresponds with the
`sp_warn` field of `struct spwd`.

`passwordChangeInactiveUSec` → An unsigned 64-bit integer, encoding how much
time has to pass after the password expired that the account is
deactivated. This corresponds with the `sp_inact` field of `struct spwd`.

`passwordChangeNow` → A boolean. If true the user has to change their password
on next login. This corresponds with the `sp_lstchg` field of `struct spwd`
being set to zero.

`pkcs11TokenUri` → An array of strings, each with an RFC 7512 compliant PKCS#11
URI referring to security token (or smart card) of some form, that shall be
associated with the user and may be used for authentication. The URI is used to
search for an X.509 certificate and associated private key that may be used to
decrypt an encrypted secret key that is used to unlock the user's account (see
below). It's undefined how precise the URI is: during log-in it is tested
against all plugged in security tokens and if there's exactly one matching
private key found with it it is used.

`fido2HmacCredential` → An array of strings, each with a Base64-encoded FIDO2
credential ID that shall be used for authentication with FIDO2 devices that
implement the `hmac-secret` extension. The salt to pass to the FIDO2 device is
found in `fido2HmacSalt`.

`recoveryKeyType` → An array of strings, each indicating the type of one
recovery key. The only supported recovery key type at the moment is `modhex64`,
for details see the description of `recoveryKey` below. An account may have any
number of recovery keys defined, and the array should have one entry for each.

`privileged` → An object, which contains the fields of the `privileged` section
of the user record, see below.

`perMachine` → An array of objects, which contain the `perMachine` section of
the user record, and thus fields to apply on specific systems only, see below.

`binding` → An object, keyed by machine IDs formatted as strings, pointing
to objects that contain the `binding` section of the user record,
i.e. additional fields that bind the user record to a specific machine, see
below.

`status` → An object, keyed by machine IDs formatted as strings, pointing to
objects that contain the `status` section of the user record, i.e. additional
runtime fields that expose the current status of the user record on a specific
system, see below.

`signature` → An array of objects, which contain cryptographic signatures of
the user record, i.e. the fields of the `signature` section of the user record,
see below.

`secret` → An object, which contains the fields of the `secret` section of the
user record, see below.

## Fields in the `privileged` section

As mentioned, the `privileged` section is encoded in a sub-object of the user
record top-level object, in the `privileged` field. Any data included in this
object shall only be visible to the administrator and the user themselves, and
be suppressed implicitly when other users get access to a user record. It thus
takes the role of the `/etc/shadow` records for each user, which has similarly
restrictive access semantics. The following fields are currently defined:

`passwordHint` → A user-selected password hint in free-form text. This should
be a string like "What's the name of your first pet?", but is entirely for the
user to choose.

`hashedPassword` → An array of strings, each containing a hashed UNIX password
string, in the format
[`crypt(3)`](https://man7.org/linux/man-pages/man3/crypt.3.html) generates. This
corresponds with `sp_pwdp` field of `struct spwd` (and in a way the `pw_passwd`
field of `struct passwd`).

`sshAuthorizedKeys` → An array of strings, each listing an SSH public key that
is authorized to access the account. The strings should follow the same format
as the lines in the traditional `~/.ssh/authorized_keys` file.

`pkcs11EncryptedKey` → An array of objects. Each element of the array should be
an object consisting of three string fields: `uri` shall contain a PKCS#11
security token URI, `data` shall contain a Base64-encoded encrypted key and
`hashedPassword` shall contain a UNIX password hash to test the key
against. Authenticating with a security token against this account shall work
as follows: the encrypted secret key is converted from its Base64
representation into binary, then decrypted with the PKCS#11 `C_Decrypt()`
function of the PKCS#11 module referenced by the specified URI, using the
private key found on the same token. The resulting decrypted key is then
Base64-encoded and tested against the specified UNIX hashed password. The
Base64-encoded decrypted key may also be used to unlock further resources
during log-in, for example the LUKS or `fscrypt` storage backend. It is
generally recommended that for each entry in `pkcs11EncryptedKey` there's also
a matching one in `pkcs11TokenUri` and vice versa, with the same URI, appearing
in the same order, but this should not be required by applications processing
user records.

`fido2HmacSalt` → An array of objects, implementing authentication support with
FIDO2 devices that implement the `hmac-secret` extension. Each element of the
array should be an object consisting of three string fields: `credential`,
`salt`, `hashedPassword`, and three boolean fields: `up`, `uv` and
`clientPin`. The first two string fields shall contain Base64-encoded binary
data: the FIDO2 credential ID and the salt value to pass to the FIDO2
device. During authentication this salt along with the credential ID is sent to
the FIDO2 token, which will HMAC hash the salt with its internal secret key and
return the result. This resulting binary key should then be Base64-encoded and
used as string password for the further layers of the stack. The
`hashedPassword` field of the `fido2HmacSalt` field shall be a UNIX password
hash to test this derived secret key against for authentication. The `up`, `uv`
and `clientPin` booleans map to the FIDO2 concepts of the same name and encode
whether the `uv`/`up` options are enabled during the authentication, and
whether a PIN shall be required. It is generally recommended that for each
entry in `fido2HmacSalt` there's also a matching one in `fido2HmacCredential`,
and vice versa, with the same credential ID, appearing in the same order, but
this should not be required by applications processing user records.

`recoveryKey`→ An array of objects, each defining a recovery key. The object
has two mandatory fields: `type` indicates the type of recovery key. The only
currently permitted value is the string `modhex64`. The `hashedPassword` field
contains a UNIX password hash of the normalized recovery key. Recovery keys are
in most ways similar to regular passwords, except that they are generated by
the computer, not chosen by the user, and are longer. Currently, the only
supported recovery key format is `modhex64`, which consists of 64
[modhex](https://developers.yubico.com/yubico-c/Manuals/modhex.1.html)
characters (i.e. 256bit of information), in groups of 8 chars separated by
dashes,
e.g. `lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui`. Recovery
keys should be accepted wherever regular passwords are. The `recoveryKey` field
should always be accompanied by a `recoveryKeyType` field (see above), and each
entry in either should map 1:1 to an entry in the other, in the same order and
matching the type. When accepting a recovery key it should be brought
automatically into normalized form, i.e. the dashes inserted when missing, and
converted into lowercase before tested against the UNIX password hash, so that
recovery keys are effectively case-insensitive.

## Fields in the `perMachine` section

As mentioned, the `perMachine` section contains settings that shall apply to
specific systems only. This is primarily interesting for resource management
properties as they tend to require a per-system focus, however they may be used
for other purposes too.

The `perMachine` field in the top-level object is an array of objects. When
processing the user record first the various fields on the top-level object
should be parsed. Then, the `perMachine` array should be iterated in order, and
the various settings within each contained object should be applied that match
either the indicated machine ID or host name, overriding any corresponding
settings previously parsed from the top-level object. There may be multiple
array entries that match a specific system, in which case all settings should
be applied. If the same option is set in the top-level object as in a
per-machine object then the per-machine setting wins and entirely undoes the
setting in the top-level object (i.e. no merging of properties that are arrays
is done). If the same option is set in multiple per-machine objects the one
specified later in the array wins (and here too no merging of individual fields
is done, the later field always wins in full). To summarize, the order of
application is (last one wins):

1. Settings in the top-level object
2. Settings in the first matching `perMachine` array entry
3. Settings in the second matching `perMachine` array entry
4. …
5. Settings in the last matching `perMachine` array entry

The following fields are defined in this section:

`matchMachineId` → An array of strings that are formatted 128-bit IDs in
hex. If any of the specified IDs match the system's local machine ID
(i.e. matches `/etc/machine-id`) the fields in this object are honored. (As a
special case, if only a single machine ID is listed this field may be a single
string rather than an array of strings.)

`matchHostname` → An array of strings that are valid hostnames. If any of the
specified hostnames match the system's local hostname, the fields in this
object are honored. If both `matchHostname` and `matchMachineId` are used
within the same array entry, the object is honored when either match succeeds,
i.e. the two match types are combined in OR, not in AND. (As a special case, if
only a single machine ID is listed this field may be a single string rather
than an array of strings.)

These two are the only two fields specific to this section. All other fields
that may be used in this section are identical to the equally named ones in the
`regular` section (i.e. at the top-level object). Specifically, these are:

`iconName`, `location`, `shell`, `umask`, `environment`, `timeZone`,
`preferredLanguage`, `niceLevel`, `resourceLimits`, `locked`, `notBeforeUSec`,
`notAfterUSec`, `storage`, `diskSize`, `diskSizeRelative`, `skeletonDirectory`,
`accessMode`, `tasksMax`, `memoryHigh`, `memoryMax`, `cpuWeight`, `ioWeight`,
`mountNoDevices`, `mountNoSuid`, `mountNoExecute`, `cifsDomain`,
`cifsUserName`, `cifsService`, `cifsExtraMountOptions`, `imagePath`, `uid`,
`gid`, `memberOf`, `fileSystemType`, `partitionUuid`, `luksUuid`,
`fileSystemUuid`, `luksDiscard`, `luksOfflineDiscard`, `luksCipher`,
`luksCipherMode`, `luksVolumeKeySize`, `luksPbkdfHashAlgorithm`,
`luksPbkdfType`, `luksPbkdfForceIterations`, `luksPbkdfTimeCostUSec`, `luksPbkdfMemoryCost`,
`luksPbkdfParallelThreads`, `luksSectorSize`, `autoResizeMode`, `rebalanceWeight`,
`rateLimitIntervalUSec`, `rateLimitBurst`, `enforcePasswordPolicy`,
`autoLogin`, `stopDelayUSec`, `killProcesses`, `freezeSession`, `passwordChangeMinUSec`,
`passwordChangeMaxUSec`, `passwordChangeWarnUSec`,
`passwordChangeInactiveUSec`, `passwordChangeNow`, `pkcs11TokenUri`,
`fido2HmacCredential`.

## Fields in the `binding` section

As mentioned, the `binding` section contains additional fields about the user
record, that bind it to the local system. These fields are generally used by a
local user manager (such as `systemd-homed.service`) to add in fields that make
sense in a local context but not necessarily in a global one. For example, a
user record that contains no `uid` field in the regular section is likely
extended with one in the `binding` section to assign a local UID if no global
UID is defined.

All fields in the `binding` section only make sense in a local context and are
suppressed when the user record is ported between systems. The `binding` section
is generally persisted on the system but not in the home directories themselves
and the home directory is supposed to be fully portable and thus not contain
the information that `binding` is supposed to contain that binds the portable
record to a specific system.

The `binding` sub-object on the top-level user record object is keyed by the
machine ID the binding is intended for, which point to an object with the
fields of the bindings. These fields generally match fields that may also be
defined in the `regular` and `perMachine` sections, however override
both. Usually, the `binding` value should not contain settings different from
those set via `regular` or `perMachine`, however this might happen if some
settings are not supported locally (think: `fscrypt` is recorded as intended
storage mechanism in the `regular` section, but the local kernel does not
support `fscrypt`, hence `directory` was chosen as implicit fallback), or have
been changed in the `regular` section through updates (e.g. a home directory
was created with `luks` as storage mechanism but later the user record was
updated to prefer `subvolume`, which however doesn't change the actual storage
used already which is pinned in the `binding` section).

The following fields are defined in the `binding` section. They all have an
identical format and override their equally named counterparts in the `regular`
and `perMachine` sections:

`imagePath`, `homeDirectory`, `partitionUuid`, `luksUuid`, `fileSystemUuid`,
`uid`, `gid`, `storage`, `fileSystemType`, `luksCipher`, `luksCipherMode`,
`luksVolumeKeySize`.

## Fields in the `status` section

As mentioned, the `status` section contains additional fields about the user
record that are exclusively acquired during runtime, and that expose runtime
metrics of the user and similar metadata that shall not be persisted but are
only acquired "on-the-fly" when requested.

This section is arranged similarly to the `binding` section: the `status`
sub-object of the top-level user record object is keyed by the machine ID,
which points to the object with the fields defined here. The following fields
are defined:

`diskUsage` → An unsigned 64-bit integer. The currently used disk space of the
home directory in bytes. This value might be determined in different ways,
depending on the selected storage mechanism. For LUKS storage this is the file
size of the loopback file or block device size. For the
directory/subvolume/fscrypt storage this is the current disk space used as
reported by the file system quota subsystem.

`diskFree` → An unsigned 64-bit integer, denoting the number of "free" bytes in
the disk space allotment, i.e. usually the difference between the disk size as
reported by `diskSize` and the used already as reported in `diskFree`, but
possibly skewed by metadata sizes, disk compression and similar.

`diskSize` → An unsigned 64-bit integer, denoting the disk space currently
allotted to the user, in bytes. Depending on the storage mechanism this can mean
different things (see above). In contrast to the top-level field of the same
(or the one in the `perMachine` section), this field reports the current size
allotted to the user, not the intended one. The values may differ when user
records are updated without the home directory being re-sized.

`diskCeiling`/`diskFloor` → Unsigned 64-bit integers indicating upper and lower
bounds when changing the `diskSize` value, in bytes. These values are typically
derived from the underlying data storage, and indicate in which range the home
directory may be re-sized in, i.e. in which sensible range the `diskSize` value
should be kept.

`state` → A string indicating the current state of the home directory. The
precise set of values exposed here are up to the service managing the home
directory to define (i.e. are up to the service identified with the `service`
field below). However, it is recommended to stick to a basic vocabulary here:
`inactive` for a home directory currently not mounted, `absent` for a home
directory that cannot be mounted currently because it does not exist on the
local system, `active` for a home directory that is currently mounted and
accessible.

`service` → A string identifying the service that manages this user record. For
example `systemd-homed.service` sets this to `io.systemd.Home` to all user
records it manages. This is particularly relevant to define clearly the context
in which `state` lives, see above. Note that this field also exists on the
top-level object (i.e. in the `regular` section), which it overrides. The
`regular` field should be used if conceptually the user record can only be
managed by the specified service, and this `status` field if it can
conceptually be managed by different managers, but currently is managed by the
specified one.

`signedLocally` → A boolean. If true indicates that the user record is signed
by a public key for which the private key is available locally. This means that
the user record may be modified locally as it can be re-signed with the private
key. If false indicates that the user record is signed by a public key
recognized by the local manager but whose private key is not available
locally. This means the user record cannot be modified locally as it couldn't
be signed afterwards.

`goodAuthenticationCounter` → An unsigned 64-bit integer. This counter is
increased by one on every successful authentication attempt, i.e. an
authentication attempt where a security token of some form was presented and it
was correct.

`badAuthenticationCounter` → An unsigned 64-bit integer. This counter is
increased by one on every unsuccessfully authentication attempt, i.e. an
authentication attempt where a security token of some form was presented and it
was incorrect.

`lastGoodAuthenticationUSec` → An unsigned 64-bit integer, indicating the time
of the last successful authentication attempt in µs since the UNIX epoch (1970).

`lastBadAuthenticationUSec` → Similar, but the timestamp of the last
unsuccessfully authentication attempt.

`rateLimitBeginUSec` → An unsigned 64-bit integer: the µs timestamp since the
UNIX epoch (1970) where the most recent rate limiting interval has been
started, as configured with `rateLimitIntervalUSec`.

`rateLimitCount` → An unsigned 64-bit integer, counting the authentication
attempts in the current rate limiting interval, see above. If this counter
grows beyond the value configured in `rateLimitBurst` authentication attempts
are temporarily refused.

`removable` → A boolean value. If true the manager of this user record
determined the home directory being on removable media. If false it was
determined the home directory is in internal built-in media. (This is used by
`systemd-logind.service` to automatically pick the right default value for
`stopDelayUSec` if the field is not explicitly specified: for home directories
on removable media the delay is selected very low to minimize the chance the
home directory remains in unclean state if the storage device is removed from
the system by the user).

`accessMode` → The access mode currently in effect for the home directory
itself.

`fileSystemType` → The file system type backing the home directory: a short
string, such as "btrfs", "ext4", "xfs".

## Fields in the `signature` section

As mentioned, the `signature` section of the user record may contain one or
more cryptographic signatures of the user record. Like all others, this section
is optional, and only used when cryptographic validation of user records shall
be used. Specifically, all user records managed by `systemd-homed.service` will
carry such signatures and the service refuses managing user records that come
without signature or with signatures not recognized by any locally defined
public key.

The `signature` field in the top-level user record object is an array of
objects. Each object encapsulates one signature and has two fields: `data` and
`key` (both are strings). The `data` field contains the actual signature,
encoded in Base64, the `key` field contains a copy of the public key whose
private key was used to make the signature, in PEM format. Currently only
signatures with Ed25519 keys are defined.

Before signing the user record should be brought into "normalized" form,
i.e. the keys in all objects should be sorted alphabetically. All redundant
white-space and newlines should be removed and the JSON text then signed.

The signatures only cover the `regular`, `perMachine` and `privileged` sections
of the user records, all other sections (include `signature` itself), are
removed before the signature is calculated.

Rationale for signing and threat model: while a multi-user operating system
like Linux strives for being sufficiently secure even after a user acquired a
local login session reality tells us this is not the case. Hence it is
essential to restrict carefully which users may gain access to a system and
which ones shall not. A minimal level of trust must be established between
system, user record and the user themselves before a log-in request may be
permitted. In particular if the home directory is provided in its own LUKS2
encapsulated file system it is essential this trust is established before the
user logs in (and hence the file system mounted), since file system
implementations on Linux are well known to be relatively vulnerable to rogue
disk images. User records and home directories in many context are expected to
be something shareable between multiple systems, and the transfer between them
might not happen via exclusively trusted channels. Hence it's essential that
the user record is not manipulated between uses. Finally, resource management
(which may be done by the various fields of the user record) is security
sensitive, since it should forcefully lock the user into the assigned resource
usage and not allow them to use more. The requirement of being able to trust
the user record data combined with the potential transfer over untrusted
channels suggest a cryptographic signature mechanism where only user records
signed by a recognized key are permitted to log in locally.

Note that other mechanisms for establishing sufficient trust exist too, and are
perfectly valid as well. For example, systems like LDAP/ActiveDirectory
generally insist on user record transfer from trusted servers via encrypted TLS
channels only. Or traditional UNIX users created locally in `/etc/passwd` never
exist outside of the local trusted system, hence transfer and trust in the
source are not an issue. The major benefit of operating with signed user
records is that they are self-sufficiently trusted, not relying on a secure
channel for transfer, and thus being compatible with a more distributed model
of home directory transfer, including on USB sticks and such.

## Fields in the `secret` section

As mentioned, the `secret` section of the user record should never be persisted
nor transferred across machines. It is only defined in short-lived operations,
for example when a user record is first created or registered, as the secret
key data needs to be available to derive encryption keys from and similar.

The `secret` field of the top-level user record contains the following fields:

`password` → an array of strings, each containing a plain text password.

`tokenPin` → an array of strings, each containing a plain text PIN, suitable
for unlocking security tokens that require that. (The field `pkcs11Pin` should
be considered a compatibility alias for this field, and merged with `tokenPin`
in case both are set.)

`pkcs11ProtectedAuthenticationPathPermitted` → a boolean. If set to true allows
the receiver to use the PKCS#11 "protected authentication path" (i.e. a
physical button/touch element on the security token) for authenticating the
user. If false or unset, authentication this way shall not be attempted.

`fido2UserPresencePermitted` → a boolean. If set to true allows the receiver to
use the FIDO2 "user presence" flag. This is similar to the concept of
`pkcs11ProtectedAuthenticationPathPermitted`, but exposes the FIDO2 "up"
concept behind it. If false or unset authentication this way shall not be
attempted.

`fido2UserVerificationPermitted` → a boolean. If set to true allows the
receiver to use the FIDO2 "user verification" flag. This is similar to the
concept of `pkcs11ProtectedAuthenticationPathPermitted`, but exposes the FIDO2
"uv" concept behind it. If false or unset authentication this way shall not be
attempted.

## Mapping to `struct passwd` and `struct spwd`

When mapping classic UNIX user records (i.e. `struct passwd` and `struct spwd`)
to JSON user records the following mappings should be applied:

| Structure       | Field       | Section      | Field                        | Condition                  |
|-----------------|-------------|--------------|------------------------------|----------------------------|
| `struct passwd` | `pw_name`   | `regular`    | `userName`                   |                            |
| `struct passwd` | `pw_passwd` | `privileged` | `password`                   | (See notes below)          |
| `struct passwd` | `pw_uid`    | `regular`    | `uid`                        |                            |
| `struct passwd` | `pw_gid`    | `regular`    | `gid`                        |                            |
| `struct passwd` | `pw_gecos`  | `regular`    | `realName`                   |                            |
| `struct passwd` | `pw_dir`    | `regular`    | `homeDirectory`              |                            |
| `struct passwd` | `pw_shell`  | `regular`    | `shell`                      |                            |
| `struct spwd`   | `sp_namp`   | `regular`    | `userName`                   |                            |
| `struct spwd`   | `sp_pwdp`   | `privileged` | `password`                   | (See notes below)          |
| `struct spwd`   | `sp_lstchg` | `regular`    | `lastPasswordChangeUSec`     | (if `sp_lstchg` > 0)       |
| `struct spwd`   | `sp_lstchg` | `regular`    | `passwordChangeNow`          | (if `sp_lstchg` == 0)      |
| `struct spwd`   | `sp_min`    | `regular`    | `passwordChangeMinUSec`      |                            |
| `struct spwd`   | `sp_max`    | `regular`    | `passwordChangeMaxUSec`      |                            |
| `struct spwd`   | `sp_warn`   | `regular`    | `passwordChangeWarnUSec`     |                            |
| `struct spwd`   | `sp_inact`  | `regular`    | `passwordChangeInactiveUSec` |                            |
| `struct spwd`   | `sp_expire` | `regular`    | `locked`                     | (if `sp_expire` in [0, 1]) |
| `struct spwd`   | `sp_expire` | `regular`    | `notAfterUSec`               | (if `sp_expire` > 1)       |

At this time almost all Linux machines employ shadow passwords, thus the
`pw_passwd` field in `struct passwd` is set to `"x"`, and the actual password
is stored in the shadow entry `struct spwd`'s field `sp_pwdp`.

## Extending These Records

User records following this specifications are supposed to be extendable for
various applications. In general, subsystems are free to introduce their own
keys, as long as:

* Care should be taken to place the keys in the right section, i.e. the most
  appropriate for the data field.

* Care should be taken to avoid namespace clashes. Please prefix your fields
  with a short identifier of your project to avoid ambiguities and
  incompatibilities.

* This specification is supposed to be a living specification. If you need
  additional fields, please consider submitting them upstream for inclusion in
  this specification. If they are reasonably universally useful, it would be
  best to list them here.

## Examples

The shortest valid user record looks like this:

```json
{
        "userName" : "u"
}
```

A reasonable user record for a system user might look like this:

```json
{
        "userName" : "httpd",
        "uid" : 473,
        "gid" : 473,
        "disposition" : "system",
        "locked" : true
}
```

A fully featured user record associated with a home directory managed by
`systemd-homed.service` might look like this:

```json
{
        "autoLogin" : true,
        "binding" : {
                "15e19cf24e004b949ddaac60c74aa165" : {
                        "fileSystemType" : "ext4",
                        "fileSystemUuid" : "758e88c8-5851-4a2a-b88f-e7474279c111",
                        "gid" : 60232,
                        "homeDirectory" : "/home/grobie",
                        "imagePath" : "/home/grobie.home",
                        "luksCipher" : "aes",
                        "luksCipherMode" : "xts-plain64",
                        "luksUuid" : "e63581ba-79fb-4226-b9de-1888393f7573",
                        "luksVolumeKeySize" : 32,
                        "partitionUuid" : "41f9ce04-c827-4b74-a981-c669f93eb4dc",
                        "storage" : "luks",
                        "uid" : 60232
                }
        },
        "disposition" : "regular",
        "enforcePasswordPolicy" : false,
        "lastChangeUSec" : 1565950024279735,
        "memberOf" : [
                "wheel"
        ],
        "privileged" : {
                "hashedPassword" : [
                        "$6$WHBKvAFFT9jKPA4k$OPY4D4TczKN/jOnJzy54DDuOOagCcvxxybrwMbe1SVdm.Bbr.zOmBdATp.QrwZmvqyr8/SafbbQu.QZ2rRvDs/"
                ]
        },
        "signature" : [
                {
                        "data" : "LU/HeVrPZSzi3MJ0PVHwD5m/xf51XDYCrSpbDRNBdtF4fDVhrN0t2I2OqH/1yXiBidXlV0ptMuQVq8KVICdEDw==",
                        "key" : "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA/QT6kQWOAMhDJf56jBmszEQQpJHqDsGDMZOdiptBgRk=\n-----END PUBLIC KEY-----\n"
                }
        ],
        "userName" : "grobie",
        "status" : {
                "15e19cf24e004b949ddaac60c74aa165" : {
                        "goodAuthenticationCounter" : 16,
                        "lastGoodAuthenticationUSec" : 1566309343044322,
                        "rateLimitBeginUSec" : 1566309342340723,
                        "rateLimitCount" : 1,
                        "state" : "inactive",
                        "service" : "io.systemd.Home",
                        "diskSize" : 161118667776,
                        "diskCeiling" : 190371729408,
                        "diskFloor" : 5242880,
                        "signedLocally" : true
                }
        }
}
```

When `systemd-homed.service` manages a home directory it will also include a
version of the user record in the home directory itself in the `~/.identity`
file. This version lacks the `binding` and `status` sections which are used for
local management of the user, but are not intended to be portable between
systems. It would hence look like this:

```json
{
        "autoLogin" : true,
        "disposition" : "regular",
        "enforcePasswordPolicy" : false,
        "lastChangeUSec" : 1565950024279735,
        "memberOf" : [
                "wheel"
        ],
        "privileged" : {
                "hashedPassword" : [
                        "$6$WHBKvAFFT9jKPA4k$OPY4D4TczKN/jOnJzy54DDuOOagCcvxxybrwMbe1SVdm.Bbr.zOmBdATp.QrwZmvqyr8/SafbbQu.QZ2rRvDs/"
                ]
        },
        "signature" : [
                {
                        "data" : "LU/HeVrPZSzi3MJ0PVHwD5m/xf51XDYCrSpbDRNBdtF4fDVhrN0t2I2OqH/1yXiBidXlV0ptMuQVq8KVICdEDw==",
                        "key" : "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA/QT6kQWOAMhDJf56jBmszEQQpJHqDsGDMZOdiptBgRk=\n-----END PUBLIC KEY-----\n"
                }
        ],
        "userName" : "grobie",
}
```
