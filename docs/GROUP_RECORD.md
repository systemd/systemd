---
title: JSON Group Records
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# JSON Group Records

Long story short: JSON Group Records are to `struct group` what
[JSON User Records](USER_RECORD.md) are to `struct passwd`.

Conceptually, much of what applies to JSON user records also applies to JSON
group records. They also consist of seven sections, with similar properties and
they carry some identical (or at least very similar) fields.

## Fields in the `regular` section

`groupName` → A string with the UNIX group name. Matches the `gr_name` field of
UNIX/glibc NSS `struct group`, or the shadow structure `struct sgrp`'s
`sg_namp` field.

`realm` → The "realm" the group belongs to, conceptually identical to the same
field of user records. A string in DNS domain name syntax.

`description` → A descriptive string for the group. This is similar to the
`realName` field of user records, and accepts arbitrary strings, as long as
they follow the same GECOS syntax requirements as `realName`.

`disposition` → The disposition of the group, conceptually identical to the
same field of user records. A string.

`service` → A string, an identifier for the service managing this group record
(this field is typically in reverse domain name syntax.)

`lastChangeUSec` → An unsigned 64bit integer, a timestamp (in µs since the UNIX
epoch 1970) of the last time the group record has been modified. (Covers only
the `regular`, `perMachine` and `privileged` sections).

`gid` → An unsigned integer in the range 0…4294967295: the numeric UNIX group
ID (GID) to use for the group. This corresponds to the `gr_gid` field of
`struct group`.

`members` → An array of strings, listing user names that are members of this
group. Note that JSON user records also contain a `memberOf` field, or in other
words a group membership can either be denoted in the JSON user record or in
the JSON group record, or in both. The list of memberships should be determined
as the combination of both lists (plus optionally others). If a user is listed
as member of a group and doesn't exist it should be ignored. This field
corresponds to the `gr_mem` field of `struct group` and the `sg_mem` field of
`struct sgrp`.

`administrators` → Similarly, an array of strings, listing user names that
shall be considered "administrators" of this group. This field corresponds to
the `sg_adm` field of `struct sgrp`.

`privileged`/`perMachine`/`binding`/`status`/`signature`/`secret` → The
objects/arrays for the other six group record sections. These are organized the
same way as for the JSON user records, and have the same semantics.

## Fields in the `privileged` section

The following fields are defined:

`hashedPassword` → An array of strings with UNIX hashed passwords; see the
matching field for user records for details. This field corresponds to the
`sg_passwd` field of `struct sgrp` (and `gr_passwd` of `struct group` in a
way).

## Fields in the `perMachine` section

`matchMachineId`/`matchHostname` → Strings, match expressions similar as for
user records, see the user record documentation for details.

The following fields are defined for the `perMachine` section and are defined
equivalent to the fields of the same name in the `regular` section, and
override those:

`gid`, `members`, `administrators`

## Fields in the `binding` section

The following fields are defined for the `binding` section, and are equivalent
to the fields of the same name in the `regular` and `perMachine` sections:

`gid`

## Fields in the `status` section

The following fields are defined in the `status` section, and are mostly
equivalent to the fields of the same name in the `regular` section, though with
slightly different conceptual semantics, see the same fields in the user record
documentation:

`service`

## Fields in the `signature` section

The fields in this section are defined identically to those in the matching
section in the user record.

## Fields in the `secret` section

Currently no fields are defined in this section for group records.

## Mapping to `struct group` and `struct sgrp`

When mapping classic UNIX group records (i.e. `struct group` and `struct sgrp`)
to JSON group records the following mappings should be applied:

| Structure      | Field       | Section      | Field            | Condition                  |
|----------------|-------------|--------------|------------------|----------------------------|
| `struct group` | `gr_name`   | `regular`    | `groupName`      |                            |
| `struct group` | `gr_passwd` | `privileged` | `password`       | (See notes below)          |
| `struct group` | `gr_gid`    | `regular`    | `gid`            |                            |
| `struct group` | `gr_mem`    | `regular`    | `members`        |                            |
| `struct sgrp`  | `sg_namp`   | `regular`    | `groupName`      |                            |
| `struct sgrp`  | `sg_passwd` | `privileged` | `password`       | (See notes below)          |
| `struct sgrp`  | `sg_adm`    | `regular`    | `administrators` |                            |
| `struct sgrp`  | `sg_mem`    | `regular`    | `members`        |                            |

At this time almost all Linux machines employ shadow passwords, thus the
`gr_passwd` field in `struct group` is set to `"x"`, and the actual password
is stored in the shadow entry `struct sgrp`'s field `sg_passwd`.

## Extending These Records

The same logic and recommendations apply as for JSON user records.

## Examples

A reasonable group record for a system group might look like this:

```json
{
	"groupName" : "systemd-resolve",
	"gid" : 193,
	"status" : {
		"6b18704270e94aa896b003b4340978f1" : {
			"service" : "io.systemd.NameServiceSwitch"
		}
	}
}
```

And here's a more complete one for a regular group:

```json
{
	"groupName" : "grobie",
	"binding" : {
		"6b18704270e94aa896b003b4340978f1" : {
			"gid" : 60232
		}
	},
	"disposition" : "regular",
	"status" : {
		"6b18704270e94aa896b003b4340978f1" : {
			"service" : "io.systemd.Home"
		}
	}
}
```
