---
title: Writing Network Configuration Managers
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Writing Network Configuration Managers

_Or: How to hook up your favourite network configuration manager's DNS logic with `systemd-resolved`_

_(This is a longer explanation how to use some parts of `systemd-resolved` bus API. If you are just looking for an API reference, consult the [bus API documentation](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html) instead.)_

Since systemd 229 `systemd-resolved` offers a powerful bus API that may be used by network configuration managers (e.g. NetworkManager, connman, …, but also lower level DHCP, VPN or PPP daemons managing specific interfaces) to pass DNS server and DNSSEC configuration directly to `systemd-resolved`.
Note that `systemd-resolved` also reads the DNS configuration data in `/etc/resolv.conf`, for compatibility. However, by passing the DNS configuration directly to `systemd-resolved` via the bus a couple of benefits are available:

1. `systemd-resolved` maintains DNS configuration per-interface, instead of simply system-wide,
   and is capable of sending DNS requests to servers on multiple different network interfaces simultaneously, returning the first positive response
   (or if all fail, the last negative one).
   This allows effective "merging" of DNS views on different interfaces, which makes private DNS zones on multi-homed hosts a lot nicer to use.
   For example, if you are connected to a LAN and a VPN, and both have private DNS zones, then you will be able to resolve both, as long as they don't clash in names.
   By using the bus API to configure DNS settings, the per-interface configuration is opened up.
2. Per-link configuration of DNSSEC is available. This is particularly interesting for network configuration managers that implement captive portal detection:
   as long as a verified connection to the Internet is not found DNSSEC should be turned off
   (as some captive portal systems alter the DNS in order to redirect clients to their internal pages).
3. Per-link configuration of LLMNR and MulticastDNS is available.
4. In contrast to changes to `/etc/resolv.conf` all changes made via the bus take effect immediately for all future lookups.
5. Statistical data about executed DNS transactions is available, as well as information about whether DNSSEC is supported on the chosen DNS server.

Note that `systemd-networkd` is already hooked up with `systemd-resolved`, exposing this functionality in full.

## Suggested Mode of Operation

Whenever a network configuration manager sets up an interface for operation, it should pass the DNS configuration information for the interface to `systemd-resolved`.
It's recommended to do that after the Linux network interface index ("ifindex") has been allocated, but before the interface has been upped (i.e. `IFF_UP` turned on).
That way, `systemd-resolved` will be able to use the configuration the moment the network interface is available.
(Note that `systemd-resolved` watches the kernel interfaces come and go, and will make use of them as soon as they are suitable to be used, which among other factors requires `IFF_UP` to be set).
That said it is OK to change DNS configuration dynamically any time: simply pass the new data to resolved, and it is happy to use it.

In order to pass the DNS configuration information to resolved, use the following methods of the `org.freedesktop.resolve1.Manager` interface of the `/org/freedesktop/resolve1` object, on the `org.freedesktop.resolve1` service:

1. To set the DNS server IP addresses for a network interface, use `SetLinkDNS()`
2. To set DNS search and routing domains for a network interface, use `SetLinkDomains()`
3. To configure the DNSSEC mode for a network interface, use `SetLinkDNSSEC()`
4. To configure DNSSEC Negative Trust Anchors (NTAs, i.e. domains for which not to do DNSSEC validation), use `SetLinkDNSSECNegativeTrustAnchors()`
5. To configure the LLMNR and MulticastDNS mode, use `SetLinkLLMNR()` and `SetLinkMulticastDNS()`

For details about these calls see the [full resolved bus API documentation](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html).

The calls should be pretty obvious to use: they simply take an interface index and the parameters to set.
IP addresses are encoded as an address family specifier (an integer, that takes the usual `AF_INET` and `AF_INET6` constants), followed by a 4 or 16 byte array with the address in network byte order.

`systemd-resolved` distinguishes between "search" and "routing" domains.
Routing domains are used to route DNS requests of specific domains to particular interfaces.
i.e. requests for a hostname `foo.bar.com` will be routed to any interface that has `bar.com` as routing domain.
The same routing domain may be defined on multiple interfaces, in which case the request is routed to all of them in parallel.
Resolver requests for hostnames that do not end in any defined routing domain of any interface will be routed to all suitable interfaces.
Search domains work like routing domain, but are also used to qualify single-label domain names.
They hence are identical to the traditional search domain logic on UNIX.
The `SetLinkDomains()` call may used to define both search and routing domains.

The most basic support of `systemd-resolved` in a network configuration manager would be to simply invoke `SetLinkDNS()` and `SetLinkDomains()` for the specific interface index with the data traditionally written to `/etc/resolv.conf`.
More advanced integration could mean the network configuration manager also makes the DNSSEC mode, the DNSSEC NTAs and the LLMNR/MulticastDNS modes available for configuration.

It is strongly recommended for network configuration managers that implement captive portal detection to turn off DNSSEC validation during the detection phase, so that captive portals that modify DNS do not result in all DNSSEC look-ups to fail.

If a network configuration manager wants to reset specific settings to the defaults (such as the DNSSEC, LLMNR or MulticastDNS mode), it may simply call the function with an empty argument.
To reset all per-link changes it made it may call `RevertLink()`.

To read back the various settings made, use `GetLink()` to get a `org.freedesktop.resolve1.Link` object for a specific network interface.
It exposes the current settings in its bus properties.
See the [full bus API documentation](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html) for details on this.

In order to translate a network interface name to an interface index, use the usual glibc `if_nametoindex()` call.

If the network configuration UI shall expose information about whether the selected DNS server supports DNSSEC, check the `DNSSECSupported` on the link object.

Note that it is fully OK if multiple different daemons push DNS configuration data into `systemd-resolved` as long as they do this only for the network interfaces they own and manage.

## Handling of `/etc/resolv.conf`

`systemd-resolved` receives DNS configuration from a number of sources, via the bus, as well as directly from `systemd-networkd` or user configuration.
It uses this data to write a file that is compatible with the traditional Linux `/etc/resolv.conf` file.
This file is stored in `/run/systemd/resolve/resolv.conf`. It is recommended to symlink `/etc/resolv.conf` to this file, in order to provide compatibility with programs reading the file directly and not going via the NSS and thus `systemd-resolved`.

For network configuration managers it is recommended to rely on this resolved-provided mechanism to update `resolv.conf`.
Specifically, the network configuration manager should stop modifying `/etc/resolv.conf` directly if it notices it being a symlink to `/run/systemd/resolve/resolv.conf`.

If a system configuration manager desires to be compatible both with systems that use `systemd-resolved` and those which do not, it is recommended to first push any discovered DNS configuration into `systemd-resolved`, and deal gracefully with `systemd-resolved` not being available on the bus.
If `/etc/resolv.conf` is a not a symlink to `/run/systemd/resolve/resolv.conf` the manager may then proceed and also update `/etc/resolv.conf`.
With this mode of operation optimal compatibility is provided, as `systemd-resolved` is used for `/etc/resolv.conf` management when this is configured, but transparent compatibility with non-`systemd-resolved` systems is maintained.
Note that `systemd-resolved` is part of systemd, and hence likely to be pretty universally available on Linux systems soon.

By allowing `systemd-resolved` to manage `/etc/resolv.conf` ownership issues regarding different programs overwriting each other's DNS configuration are effectively removed.
