---
title: Running Services After the Network Is Up
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Network configuration synchronization points

systemd provides three target units related to network configuration:

## Network pre-configuration: `network-pre.target`

`network-pre.target` is used to order services before any network interfaces
start to be configured. Its primary purpose is for usage with firewall services
that want to establish a firewall *before* any network interface is up.

`network-pre.target` is a passive unit: it cannot be started directly and it is
not pulled in by the the network management service, but instead a service that
wants to run before it must pull it in. Network management services hence
should set `After=network-pre.target`, but not `Wants=network-pre.target` or
`Requires=network-pre.target`. Services that want to be run before the network
is configured should use `Before=network-pre.target` and
`Wants=network-pre.target`. This way, unless there's actually a service that
needs to be ordered before the network is up, this target is not pulled in,
avoiding an unnecessary synchronization point.

## Network management services: `network.target`

`network.target` indicates that the network management stack has been started.
Ordering after it it has little meaning during start-up: whether any network
interfaces are already configured when it is reached is not defined.

Its primary purpose is for ordering things properly at shutdown: since the
shutdown ordering of units in systemd is the reverse of the startup ordering,
any unit that has `After=network.target` can be sure that it is *stopped*
before the network is shut down when the system is going down. This allows
services to cleanly terminate connections before going down, instead of losing
ongoing connections leaving the other side in an undefined state.

Note that `network.target` is a passive unit: you cannot start it directly and
it is not pulled in by any services that want to make use of the network.
Instead, it is pulled in by the network management services
themselves. Services using the network should hence simply place an
`After=network.target` stanza in their unit files, without
`Wants=network.target` or `Requires=network.target`.

## Network connectivity has been estabilished: `network-online.target`

`network-online.target` is a target that actively waits until the network is
"up", where the definition of "up" is defined by the network management
software. Usually it indicates a configured, routable IP address of some
kind. Its primary purpose is to actively delay activation of services until the
network has been set up.

It is an active target, meaning that it may be pulled in by the services
requiring the network to be up, but is not pulled in by the network management
service itself. By default all remote mounts defined in `/etc/fstab` make use
of this service, in order to make sure the network is up before attempts to
connect to a network share are made. Note that normally, if no service requires
it and if no remote mount point is configured, this target is not pulled into
the boot, thus avoiding any delays during boot should the network not be
available. It is strongly recommended not to make use of this target too
liberally: for example network server software should generally not pull this
in (since server software generally is happy to accept local connections even
before any routable network interface is up). Its primary purpose is network
client software that cannot operate without network.

For more details about those targets, see the
[systemd.special(7)](http://www.freedesktop.org/software/systemd/man/systemd.special.html)
man page.

## Compatibility with SysV init

LSB defines a `$network` dependency for legacy init scripts. Whenever systemd
encounters a `$network` dependency in LSB headers of init scripts it will
translate this to `Wants=` and `After=` dependencies on
`network-online.target`, staying relatively close to traditional LSB behaviour.

# Discussion

The meaning of `$network` is defined [only very
unprecisely](http://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/facilname.html)
and people tend to have different ideas what it is supposed to mean. Here are a
couple of ideas people came up with so far:

* The network management software is up.
* All "configured" network interfaces are up and an IP address has been assigned to each.
* All discovered local hardware interfaces that have a link beat have an IP address assigned, independently whether there is actually any explicit local configuration for them.
* The network has been set up precisely to the level that a DNS server is reachable.
* Same, but some specific site-specific server is reachable.
* Same, but "the Internet" is reachable.
* All "configured" ethernet devices are up, but all "configured" PPP links which are supposed to also start at boot don't have to be yet.
* A certain "profile" is enabled and some condition of the above holds. If another "profile" is enabled a different condition would have to be checked.
* Based on the location of the system a different set of configuration should be up or checked for.
* At least one global IPv4 address is configured.
* At least one global IPv6 address is configured.
* At least one global IPv4 or IPv6 address is configured.
* And so on and so on.

All these are valid approaches to the question "When is the network up?", but
none of them would be useful to be good as generic default.

Modern networking tends to be highly dynamic: machines are moved between
networks, network configuration changes, hardware is added and removed, virtual
networks are set up, reconfigured, and shut down again. Network connectivity is
not unconditionally and continuously available, and a machine is connected to
different networks at different times. This is particularly true for mobile
hardware such as handsets, tablets, and laptops, but also for embedded and
servers. Software that is written under the assumption that network
connectivity is available continuously and never changes is hence not
up-to-date with reality. Well-written software should be able to handle dynamic
configuration changes. It should react to changing network configuration and
make the best of it. If it cannot reach a server it must retry. If network
configuration connectivity is lost it must not fail catastrophically. Reacting
to local network configuration changes in daemon code is not particularly
hard. In fact many well-known network-facing services running on Linux have
been doing this for decades. A service written like this is robust, can be
started at any time, and will always do the best of the circumstances it is
running in.

`$network` / `network-online.target` is a mechanism that is required only to
deal with software that assumes continuous network is available (i.e. of the
simple not-well-written kind). Which facet of it it requires is undefined. An
IMAP server might just require a certain IP to be assigned so that it can
listen on it. OTOH a network file system client might need DNS up, and the
service to contact up, as well. What precisely is required is not obvious and
can be different things depending on local configuration.

A robust system boots up independently of external services. More specifically,
if a network DHCP server does not react, this should not slow down boot on most
setups, but only for those where network connectivity is strictly needed (for
example, because the host actually boots from the network).

# FAQ

## How do I make sure that my service starts after the network is *really* online?

That depends on your setup and the services you plan to run after it (see
above). If you need to delay you service after network connectivity has been
established, include

```ini
After=network-online.target
Wants=network-online.target
```

in the `.service` file.

This will delay boot until the network management software says the network is "up".
For details, see the next question.

## What does "up" actually mean?

The services that are ordered before `network-online.target` define it's
meaning. *Usually* means that all configured network devices are up and have an
IP address assigned, but details may vary. In particular, configuration may
affect which interfaces are taken into account.

`network-online.target` will time out after 90s. Enabling this might
considerably delay your boot even if the timeout is not reached.

The right "wait" service must be enabled:
`NetworkManager-wait-online.service` if `NetworkManager` is used to configure
the network, `systemd-networkd-wait-online.service` if `systemd-networkd` is
used, etc. `systemd-networkd.service` has
`Also=systemd-networkd-wait-online.service` in its `[Install]` section, so when
`systemd-networkd.service` is enabled, `systemd-networkd-wait-online.service`
will be enabled too, which means that `network-online.target` will include
`systemd-networkd-wait-online.service` when and only when
`systemd-networkd.service` is enabled.  `NetworkManager-wait-online.service` is
set up similarly. This means that the "wait" services do not need to be enabled
explicitly. They will be enabled automatically when the "main" service is
enabled, though they will not be *used* unless something else pulls in
`network-online.target`.

To verify that the right service is enabled (usually only one should be):
```console
$ systemctl is-enabled NetworkManager-wait-online.service systemd-networkd-wait-online.service
disabled
enabled
```

## Should `network-online.target` be used?

Please note that `network-online.target` means that the network connectivity
*has been* reached, not that it is currently available. By the very nature and
design of the network, connectivity may briefly or permanently disappear, so
for reasonable user experience, services need to handle temporary lack of
connectivity.

If you are a developer, instead of wondering what to do about `network.target`,
please just fix your program to be friendly to dynamically changing network
configuration. That way you will make your users happy because things just
start to work, and you will get fewer bug reports. You also make the boot
faster by not delaying services until network connectivity has been
established. This is particularly important for folks with slow address
assignment replies from a DHCP server.

Here are a couple of possible approaches:

1. Watch rtnetlink and react to network configuration changes as they
   happen. This is usually the nicest solution, but not always the easiest.
2. If you write a server: listen on `[::]`, `[::1]`, `0.0.0.0`, and `127.0.0.1`
   only. These pseudo-addresses are unconditionally available. If you always
   bind to these addresses you will have code that doesn't have to react to
   network changes, as all you listen on is catch-all and private addresses.
3. If you write a server: if you want to listen on other, explicitly configured
   addresses, consider using the `IP_FREEBIND` sockopt functionality of the
   Linux kernel. This allows your code to bind to an address even if it is not
   actually (yet or ever) configured locally. This also makes your code robust
   towards network configuration changes. This is provided as `FreeBind=`
   for systemd services, see
   [systemd.socket(5)](http://www.freedesktop.org/software/systemd/man/systemd.socket.html).

An exception to the above recommendations is services which require network
connectivity, but do not delay system startup. An example may be a service
which downloads package updates into a cache (to be used at some point in the
future by the package management software). Such a service may even start
during boot, and pull in and be ordered after `network-online.target`, but as
long as it is not ordered before any unit that is part of the default target,
it does not delay boot. It is usually easier to write such a service in a
"simplistic" way, where it doesn't try to wait for the network connectivity to
be (re-)established, but is instead started when the network has connectivity,
and if the network goes away, it fails and relies on the system manager to
restart it if appropriate.

## Modyfing the meaning of `network-online.target`

As described above, the meaning of this target is defined first by which
implementing services are enabled (`NetworkManager-wait-online.service`,
`systemd-networkd-wait-online.service`, …), and second by the configuration
specific to those services.

For example, `systemd-networkd-wait-online.service` will wait until all
interfaces that are present and managed by
[systemd-networkd.service(8)](http://www.freedesktop.org/software/systemd/man/systemd-networkd.service.html).
are fully configured or failed and at least one link is online; see
[systemd-networkd-wait-online.service(8)](http://www.freedesktop.org/software/systemd/man/systemd-networkd-wait-online.service.html)
for details. Those conditions are affected by the presence of configuration
that matches various links, but also by settings like
`Unmanaged=`, `RequiredForOnline=`, `RequiredFamilyForOnline=`; see
[systemd.network(5)](http://www.freedesktop.org/software/systemd/man/systemd.socket.html).

It is also possible to plug in additional checks for network state. For
example, to delay `network-online.target` until some a specific host is
reachable (the name can be resolved over DNS and the appropriate route has been
established), the following simple service could be used:

```ini
[Unit]
DefaultDependencies=no
After=nss-lookup.target
Before=network-online.target

[Service]
ExecStart=sh -c 'while ! ping -c 1 example.com; do sleep 1; done'

[Install]
WantedBy=network-online.target
```
