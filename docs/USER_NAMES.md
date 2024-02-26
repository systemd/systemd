---
title: User/Group Name Syntax
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# User/Group Name Syntax

The precise set of allowed user and group names on Linux systems is weakly defined.
Depending on the distribution a different set of requirements and
restrictions on the syntax of user/group names are enforced — on some
distributions the accepted syntax is even configurable by the administrator.
In the interest of interoperability systemd enforces different rules when
processing users/group defined by other subsystems and when defining users/groups
itself, following the principle of "Be conservative in what you send, be liberal in what you accept".
Also in the interest of interoperability systemd will enforce the same rules everywhere and not make them configurable or distribution dependent.
The precise rules are described below.

Generally, the same rules apply for user as for group names.

## Other Systems

* On POSIX the set of
  [valid user names](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_437)
  is defined as
  [lower and upper case ASCII letters, digits, period, underscore, and hyphen](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_282),
  with the restriction that hyphen is not allowed as first character of the user name.
  Interestingly no size limit is declared, i.e. in neither
  direction, meaning that strictly speaking, according to POSIX, both the empty
  string is a valid user name as well as a string of gigabytes in length.

* Debian/Ubuntu based systems enforce the regular expression `^[a-z][-a-z0-9]*$`, i.e.
  only lower case ASCII letters, digits and hyphens.
  As first character only lowercase ASCII letters are allowed.
  This regular expression is configurable by the administrator at runtime though.
  This rule enforces a minimum length of one character but no maximum length.

* Upstream shadow-utils enforces the regular expression
  `^[a-z_][a-z0-9_-]*[$]$`, i.e.is similar to the Debian/Ubuntu rule,
  but allows underscores and hyphens, but the latter not as first character.
  Also, an optional trailing dollar character is permitted.

* Fedora/Red Hat based systems enforce the regular expression of
  `^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_.$-]?$`, i.e. a size limit of
  32 characters, with upper and lower case letters, digits, underscores, hyphens and periods.
  No hyphen as first character though, and the last character may be a dollar character.
  On top of that, `.` and `..` are not allowed as user/group names.

* sssd is known to generate user names with embedded `@` and white-space
  characters, as well as non-ASCII (i.e. UTF-8) user/group names.

* winbindd is known to generate user/group names with embedded `\` and
  white-space characters, as well as non-ASCII (i.e. UTF-8) user/group names.

Other operating systems enforce different rules; in this documentation we'll
focus on Linux systems only however, hence those are out of scope.
That said, software like Samba is frequently deployed on Linux for providing compatibility
with Windows systems; on such systems it might be wise to stick to user/group
names also valid according to Windows rules.

## Rules systemd enforces

Distilled from the above, below are the rules systemd enforces on user/group names.
An additional, common rule between both modes listed below is that empty strings are not valid user/group names.

Philosophically, the strict mode described below enforces an allow list of
what's allowed and prohibits everything else, while the relaxed mode described
below implements a deny list of what's not allowed and permits everything else.

### Strict mode

Strict user/group name syntax is enforced whenever a systemd component is used
to register a user or group in the system, for example a system user/group
using
[`systemd-sysusers.service`](https://www.freedesktop.org/software/systemd/man/systemd-sysusers.html)
or a regular user with
[`systemd-homed.service`](https://www.freedesktop.org/software/systemd/man/systemd-homed.html).

In strict mode, only uppercase and lowercase characters are allowed, as well as
digits, underscores and hyphens.
The first character may not be a digit or hyphen. A size limit is enforced: the minimum of `sysconf(_SC_LOGIN_NAME_MAX)`
(typically 256 on Linux; rationale: this is how POSIX suggests to detect the
limit), `UT_NAMESIZE-1` (typically 31 on Linux; rationale: names longer than
this cannot correctly appear in `utmp`/`wtmp` and create ambiguity with login
accounting) and `NAME_MAX` (255 on Linux; rationale: user names typically
appear in directory names, i.e. the home directory), thus MIN(256, 31, 255) = 31.

Note that these rules are both more strict and more relaxed than all of the
rules enforced by other systems listed above.
A user/group name conforming to systemd's strict rules will not necessarily pass a test by the rules enforced
by these other subsystems.

Written as regular expression the above is: `^[a-zA-Z_][a-zA-Z0-9_-]{0,30}$`

### Relaxed mode

Relaxed user/group name syntax is enforced whenever a systemd component accepts
and makes use of user/group names registered by other (non-systemd)
components of the system, for example in
[`systemd-logind.service`](https://www.freedesktop.org/software/systemd/man/systemd-logind.html).

Relaxed syntax is also enforced by the `User=` setting in service unit files,
i.e. for system services used for running services.
Since these users may be registered by a variety of tools relaxed mode is used, but since the primary
purpose of these users is to run a system service and thus a job for systemd a
warning is shown if the specified user name does not qualify by the strict
rules above.

* No embedded NUL bytes (rationale: handling in C must be possible and
  straightforward)

* No names consisting fully of digits (rationale: avoid confusion with numeric
  UID/GID specifications)

* Similar, no names consisting of an initial hyphen and otherwise entirely made
  up of digits (rationale: avoid confusion with negative, numeric UID/GID
  specifications, e.g. `-1`)

* No strings that do not qualify as valid UTF-8 (rationale: we want to be able
  to embed these strings in JSON, with permits only valid UTF-8 in its strings;
  user names using other character sets, such as JIS/Shift-JIS will cause
  validation errors)

* No control characters (i.e. characters in ASCII range 1…31; rationale: they
  tend to have special meaning when output on a terminal in other contexts,
  moreover the newline character — as a specific control character — is used as
  record separator in `/etc/passwd`, and hence it's crucial to avoid
  ambiguities here)

* No colon characters (rationale: it is used as field separator in `/etc/passwd`)

* The two strings `.` and `..` are not permitted, as these have special meaning
  in file system paths, and user names are frequently included in file system
  paths, in particular for the purpose of home directories.

* Similar, no slashes, as these have special meaning in file system paths

* No leading or trailing white-space is permitted; and hence no user/group names
  consisting of white-space only either (rationale: this typically indicates
  parsing errors, and creates confusion since not visible on screen)

Note that these relaxed rules are implied by the strict rules above, i.e. all
user/group names accepted by the strict rules are also accepted by the relaxed
rules, but not vice versa.

Note that this relaxed mode does not refuse a couple of very questionable syntaxes.
For example, it permits a leading or embedded period.
A leading period is problematic because the matching home directory would typically be hidden
from the user's/administrator's view.
An embedded period is problematic since it creates ambiguity in traditional `chown` syntax (which is still accepted
today) that uses it to separate user and group names in the command's
parameter: without consulting the user/group databases it is not possible to
determine if a `chown` invocation would change just the owning user or both the owning user and group.
It also allows embedding `@` (which is confusing to MTAs).

## Common Core

Combining all rules listed above, user/group names that shall be considered
valid in all systemd contexts and on all Linux systems should match the
following regular expression (at least according to our understanding):

`^[a-z][a-z0-9-]{0,30}$`
