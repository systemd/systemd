---
title: User/Group Record Lookup API via Varlink
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# User/Group Record Lookup API via Varlink

JSON User/Group Records (as described in the [JSON User Records](USER_RECORD.md)
and [JSON Group Records](GROUP_RECORD.md) documents) that are defined on the
local system may be queried with a [Varlink](https://varlink.org/) API. This
API takes both the role of what
[`getpwnam(3)`](https://man7.org/linux/man-pages/man3/getpwnam.3.html) and
related calls are for `struct passwd`, as well as the interfaces modules
implementing the [glibc Name Service Switch
(NSS)](https://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html)
expose. Or in other words, it both allows applications to efficiently query
user/group records from local services, and allows local subsystems to provide
user/group records efficiently to local applications.

The concepts described here define an IPC interface. Alternatively, user/group
records may be dropped in number of drop-in directories as files where they are
picked up in addition to the users/groups defined by this IPC logic. See
[`nss-systemd(8)`](https://www.freedesktop.org/software/systemd/man/nss-systemd.html)
for details.

This simple API only exposes only three method calls, and requires only a small
subset of the Varlink functionality.

## Why Varlink?

The API described in this document is based on a simple subset of the
mechanisms described by [Varlink](https://varlink.org/). The choice of
preferring Varlink over D-Bus and other IPCs in this context was made for three
reasons:

1. User/Group record resolution should work during early boot and late shutdown
   without special handling. This is very hard to do with D-Bus, as the broker
   service for D-Bus generally runs as regular system daemon and is hence only
   available at the latest boot stage.

2. The JSON user/group records are native JSON data, hence picking an IPC
   system that natively operates with JSON data is natural and clean.

3. IPC systems such as D-Bus do not provide flow control and are thus unusable
   for streaming data. They are useful to pass around short control messages,
   but as soon as potentially many and large objects shall be transferred,
   D-Bus is not suitable, as any such streaming of messages would be considered
   flooding in D-Bus' logic, and thus possibly result in termination of
   communication. Since the APIs defined in this document need to support
   enumerating potentially large numbers of users and groups, D-Bus is simply
   not an appropriate option.

## Concepts

Each subsystem that needs to define users and groups on the local system is
supposed to implement this API, and offer its interfaces on a Varlink
`AF_UNIX`/`SOCK_STREAM` file system socket bound into the
`/run/systemd/userdb/` directory. When a client wants to look up a user or
group record, it contacts all sockets bound in this directory in parallel, and
enqueues the same query to each. The first positive reply is then returned to
the application, or if all fail the last seen error is returned
instead. (Alternatively a special Varlink service is available,
`io.systemd.Multiplexer` which acts as frontend and will do the parallel
queries on behalf of the client, drastically simplifying client
development. This service is not available during earliest boot and final
shutdown phases.)

Unlike with glibc NSS there's no order or programmatic expression language
defined in which queries are issued to the various services. Instead, all
queries are always enqueued in parallel to all defined services, in order to
make look-ups efficient, and the simple rule of "first successful lookup wins"
is unconditionally followed for user and group look-ups (though not for
membership lookups, see below).

This simple scheme only works safely as long as every service providing
user/group records carefully makes sure not to answer with conflicting
records. This API does not define any mechanisms for dealing with user/group
name/ID collisions during look-up nor during record registration. It assumes
the various subsystems that want to offer user and group records to the rest of
the system have made sufficiently sure in advance that their definitions do not
collide with those of other services. Clients are not expected to merge
multiple definitions for the same user or group, and will also not be able to
detect conflicts and suppress such conflicting records.

It is recommended to name the sockets in the directory in reverse domain name
notation, but this is neither required nor enforced.

## Well-Known Services

Any subsystem that wants to provide user/group records can do so, simply by
binding a socket in the aforementioned directory. By default two
services are listening there, that have special relevance:

1. `io.systemd.NameServiceSwitch` → This service makes the classic UNIX/glibc
   NSS user/group records available as JSON User/Group records. Any such
   records are automatically converted as needed, and possibly augmented with
   information from the shadow databases.

2. `io.systemd.Multiplexer` → This service multiplexes client queries to all
   other running services. It's supposed to simplify client development: in
   order to look up or enumerate user/group records it's sufficient to talk to
   one service instead of all of them in parallel. Note that it is not available
   during earliest boot and final shutdown phases, hence for programs running
   in that context it is preferable to implement the parallel lookup
   themselves.

Both these services are implemented by the same daemon
`systemd-userdbd.service`.

Note that these services currently implement a subset of Varlink only. For
example, introspection is not available, and the resolver logic is not used.

## Other Services

The `systemd` project provides three other services implementing this
interface. Specifically:

1. `io.systemd.DynamicUser` → This service is implemented by the service
   manager itself, and provides records for the users and groups synthesized
   via `DynamicUser=` in unit files.

2. `io.systemd.Home` → This service is implemented by `systemd-homed.service`
   and provides records for the users and groups defined by the home
   directories it manages.

3. `io.systemd.Machine` → This service is implemented by
   `systemd-machined.service` and provides records for the users and groups used
   by local containers that use user namespacing.

Other projects are invited to implement these services too. For example it
would make sense for LDAP/ActiveDirectory projects to implement these
interfaces, which would provide them a way to do per-user resource management
enforced by systemd and defined directly in LDAP directories.

## Compatibility with NSS

Two-way compatibility with classic UNIX/glibc NSS user/group records is
provided. When using the Varlink API, lookups into databases provided only via
NSS (and not natively via Varlink) are handled by the
`io.systemd.NameServiceSwitch` service (see above). When using the NSS API
(i.e. `getpwnam()` and friends) the `nss-systemd` module will automatically
synthesize NSS records for users/groups natively defined via a Varlink
API. Special care is taken to avoid recursion between these two compatibility
mechanisms.

Subsystems that shall provide user/group records to the system may choose
between offering them via an NSS module or via a this Varlink API, either way
all records are accessible via both APIs, due to the bidirectional
forwarding. It is also possible to provide the same records via both APIs
directly, but in that case the compatibility logic must be turned off. There
are mechanisms in place for this, please contact the systemd project for
details, as these are currently not documented.

## Caching of User Records

This API defines no concepts for caching records. If caching is desired it
should be implemented in the subsystems that provide the user records, not in
the clients consuming them.

## Method Calls

```
interface io.systemd.UserDatabase

method GetUserRecord(
        uid : ?int,
        userName : ?string,
        service : string
) -> (
        record : object,
        incomplete : bool
)

method GetGroupRecord(
        gid : ?int,
        groupName : ?string,
        service : string
) -> (
        record : object,
        incomplete : bool
)

method GetMemberships(
        userName : ?string,
        groupName : ?string,
        service : string
) -> (
        userName : string,
        groupName : string
)

error NoRecordFound()
error BadService()
error ServiceNotAvailable()
error ConflictingRecordFound()
error EnumerationNotSupported()
```

The `GetUserRecord` method looks up or enumerates a user record. If the `uid`
parameter is set it specifies the numeric UNIX UID to search for. If the
`userName` parameter is set it specifies the name of the user to search
for. Typically, only one of the two parameters are set, depending whether a
look-up by UID or by name is desired. However, clients may also specify both
parameters, in which case a record matching both will be returned, and if only
one exists that matches one of the two parameters but not the other an error of
`ConflictingRecordFound` is returned. If neither of the two parameters are set
the whole user database is enumerated. In this case the method call needs to be
made with `more` set, so that multiple method call replies may be generated as
effect, each carrying one user record.

The `service` parameter is mandatory and should be set to the service name
being talked to (i.e. to the same name as the `AF_UNIX` socket path, with the
`/run/systemd/userdb/` prefix removed). This is useful to allow implementation
of multiple services on the same socket (which is used by
`systemd-userdbd.service`).

The method call returns one or more user records, depending which type of query is
used (see above). The record is returned in the `record` field. The
`incomplete` field indicates whether the record is complete. Services providing
user record lookup should only pass the `privileged` section of user records to
clients that either match the user the record is about or to sufficiently
privileged clients, for all others the section must be removed so that no
sensitive data is leaked this way. The `incomplete` parameter should indicate
whether the record has been modified like this or not (i.e. it is `true` if a
`privileged` section existed in the user record and was removed, and `false` if
no `privileged` section existed or one existed but hasn't been removed).

If no user record matching the specified UID or name is known the error
`NoRecordFound` is returned (this is also returned if neither UID nor name are
specified, and hence enumeration requested but the subsystem currently has no
users defined).

If a method call with an incorrectly set `service` field is received
(i.e. either not set at all, or not to the service's own name) a `BadService`
error is generated. Finally, `ServiceNotAvailable` should be returned when the
backing subsystem is not operational for some reason and hence no information
about existence or non-existence of a record can be returned nor any user
record at all. (The `service` field is defined in order to allow implementation
of daemons that provide multiple distinct user/group services over the same
`AF_UNIX` socket: in order to correctly determine which service a client wants
to talk to, the client needs to provide the name in each request.)

The `GetGroupRecord` method call works analogously but for groups.

The `GetMemberships` method call may be used to inquire about group
memberships. The `userName` and `groupName` arguments take what the name
suggests. If one of the two is specified all matching memberships are returned,
if neither is specified all known memberships of any user and any group are
returned. The return value is a pair of user name and group name, where the
user is a member of the group. If both arguments are specified the specified
membership will be tested for, but no others, and the pair is returned if it is
defined. Unless both arguments are specified the method call needs to be made
with `more` set, so that multiple replies can be returned (since typically
there are multiple members per group and also multiple groups a user is
member of). As with `GetUserRecord` and `GetGroupRecord` the `service`
parameter needs to contain the name of the service being talked to, in order to
allow implementation of multiple services within the same IPC socket. In case no
matching membership is known `NoRecordFound` is returned. The other two errors
are also generated in the same cases as for `GetUserRecord` and
`GetGroupRecord`.

Unlike with `GetUserRecord` and `GetGroupRecord` the lists of memberships
returned by services are always combined. Thus unlike the other two calls a
membership lookup query has to wait for the last simultaneous query to complete
before the complete list is acquired.

Note that only the `GetMemberships` call is authoritative about memberships of
users in groups. i.e. it should not be considered sufficient to check the
`memberOf` field of user records and the `members` field of group records to
acquire the full list of memberships. The full list can only be determined by
`GetMemberships`, and as mentioned requires merging of these lists of all local
services. Result of this is that it can be one service that defines a user A,
and another service that defines a group B, and a third service that declares
that A is a member of B.

Looking up explicit users/groups by their name or UID/GID, or querying
user/group memberships must be supported by all services implementing these
interfaces. However, supporting enumeration (i.e. user/group lookups that may
result in more than one reply, because neither UID/GID nor name is specified)
is optional. Services which are asked for enumeration may return the
`EnumerationNotSupported` error in this case.

And that's really all there is to it.
