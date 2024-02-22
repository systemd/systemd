---
title: systemd-resolved and VPNs
category: Networking
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# `systemd-resolved.service` and VPNs

`systemd-resolved.service` supports routing lookups for specific domains to specific
interfaces. This is useful for hooking up VPN software with systemd-resolved
and making sure the exact right lookups end up on the VPN and on the other
interfaces.

For a verbose explanation of `systemd-resolved.service`'s domain routing logic,
see its [man
page](https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html). This
document is supposed to provide examples to use the concepts for the specific
purpose of managing VPN DNS configuration.

Let's first define two distinct VPN use-cases:

1. *Corporate* VPNs, i.e. VPNs that open access to a specific set of additional
   hosts. Only specific domains should be resolved via the VPN's DNS servers,
   and everything that is not related to the company's domain names should go
   to regular, non-VPN DNS instead.

2. *Privacy* VPNs, i.e. VPNs that should be used for basically all DNS traffic,
   once they are up. If this type of VPN is used, any regular, non-VPN DNS
   servers should not get any traffic anymore.

Then, let's briefly introduce three DNS routing concepts that software managing
a network interface may configure.

1. Search domains: these are traditional DNS configuration parameters and are
   used to suffix non-qualified domain names (i.e. single-label ones), to turn
   them into fully qualified domain names. Traditionally (before
   `systemd-resolved.service`), search domain names are attached to a system's
   IP configuration as a whole, in `systemd-resolved.service` they are
   associated to individual interfaces instead, since they are typically
   acquired through some network associated concept, such as a DHCP, IPv6RA or
   PPP lease. Most importantly though: in `systemd-resolved.service` they are
   not just used to suffix single-label domain names, but also for routing
   domain name lookups: if a network interface has a search domain `foo.com`
   configured on it, then any lookups for names ending in `.foo.com` (or for
   `foo.com` itself) are preferably routed to the DNS servers configured on the
   same network interface.

2. Routing domains: these are very similar to search domains, but are purely
   about DNS domain name lookup routing — they are not used for qualifying
   single-label domain names. When it comes to routing, assigning a routing
   domain to a network interface is identical to assigning a search domain to
   it.

   Why the need to have both concepts, i.e. search *and* routing domains?
   Mostly because in many cases the qualifying of single-label names is not
   desirable (as it has security implications), but needs to be supported for
   specific use-cases. Routing domains are a concept `systemd-resolved.service`
   introduced, while search domains are traditionally available and are part of
   DHCP/IPv6RA/PPP leases and thus universally supported. In many cases routing
   domains are probably the more appropriate concept, but not easily available,
   since they are not part of DHCP/IPv6RA/PPP.

   Routing domains for `systemd-resolved.service` are usually presented along
   with search domains in mostly the same way, but prefixed with `~` to
   differentiate them. i.e. `~foo.com` is a configured routing domain, while
   `foo.com` would be a configured search domain.

   One routing domain is particularly interesting: `~.` — the catch-all routing
   domain. (The *dot* domain `.` is how DNS denotes the "root" domain, i.e. the
   parent domain of all domains, but itself.) When used on an interface any DNS
   traffic is preferably routed to its DNS servers. (A search domain – i.e. `.`
   instead of `~.` — would have the same effect, but given that it's mostly
   pointless to suffix an unqualified domain with `.`, we generally declare it
   as a routing domain, not a search domain).

   Routing domains also have particular relevance when it comes to the reverse
   lookup DNS domains `.in-addr.arpa` and `.ip6.arpa`. An interface that has
   these (or sub-domains thereof) defined as routing domains, will be preferably
   used for doing reverse IP to domain name lookups. e.g. declaring
   `~168.192.in-addr.arpa` on an interface means that all lookups to find the
   domain names for IPv4 addresses 192.168.x.y are preferably routed to it.

3. The `default-route` boolean. This is a simple boolean value that may be set
   on an interface. If true (the default), any DNS lookups for which no
   matching routing or search domains are defined are routed to interfaces
   marked like this. If false then the DNS servers on this interface are not
   considered for routing lookups to except for the ones listed in the
   search/routing domain list. An interface that has no search/routing domain
   associated and also has this boolean off is not considered for *any*
   lookups.

One more thing to mention: in `systemd-resolved.service` if lookups match the
search/routing domains of multiple interfaces at once, then they are sent to
all of them in parallel, and the first positive reply used. If all lookups fail
the last negative reply is used. This means the DNS zones on the relevant
interfaces are "merged": domains existing on one but not the other will "just
work" and vice versa.

And one more note: the domain routing logic implemented is a tiny bit more
complex that what described above: if there two interfaces have search domains
that are suffix of each other, and a name is looked up that matches both, the
interface with the longer match will win and get the lookup routed to is DNS
servers. Only if the match has the same length, then both will be used in
parallel. Example: one interface has `~foo.example.com` as routing domain, and
another one `example.com` has search domain. A lookup for
`waldo.foo.example.com` is the exclusively routed to the first interface's DNS
server, since it matches by three suffix labels instead of just two. The fact
that the matching length is taken into consideration for the routing decision
is particularly relevant if you have one interface with the `~.` routing domain
and another one with `~corp.company.example` — both suffixes match a lookup for
`foo.corp.company.example`, but the latter interface wins, since the match is
for four labels, while the other is for zero labels.

## Putting it Together

Let's discuss how the three DNS routing concepts above are best used for a
reasonably complex scenario consisting of:

1. One VPN interface of the *corporate* kind, maybe called `company0`. It makes
   available a bunch of servers, all in the domain `corp.company.example`.

2. One VPN interface of the *privacy* kind, maybe called `privacy0`. When it is
   up all DNS traffic shall preferably routed to its DNS servers.

3. One regular WiFi interface, maybe called `wifi0`. It has a regular DNS
   server on it.

Here's how to best configure this for `systemd-resolved.service`:

1. `company0` should get a routing domain `~corp.company.example`
   configured. (A search domain `corp.company.example` would work too, if
   qualifying of single-label names is desired or the VPN lease information
   does not provide for the concept of routing domains, but does support search
   domains.) This interface should also set `default-route` to false, to ensure
   that really only the DNS lookups for the company's servers are routed there
   and nothing else. Finally, it might make sense to also configure a routing
   domain `~2.0.192.in-addr.arpa` on the interface, ensuring that all IPv4
   addresses from the 192.0.2.x range are preferably resolved via the DNS
   server on this interface (assuming that that's the IPv4 address range the
   company uses internally).

2. `privacy0` should get a routing domain `~.` configured. The setting of
   `default-route` for this interface is then irrelevant. This means: once the
   interface is up, all DNS traffic is preferably routed there.

3. `wifi0` should not get any special settings, except possibly whatever the
   local WiFi router considers suitable as search domain, for example
   `fritz.box`. The default `true` setting for `default-route` is good too.

With this configuration if only `wifi0` is up, all DNS traffic goes to its DNS
server, since there are no other interfaces with better matching DNS
configuration. If `privacy0` is then upped, all DNS traffic will exclusively go
to this interface now — with the exception of names below the `fritz.box`
domain, which will continue to go directly to `wifi0`, as the search domain
there says so. Now, if `company0` is also upped, it will receive DNS traffic
for the company's internal domain and internal IP subnet range, but nothing
else.  If `privacy0` is then downed again, `wifi0` will get the regular DNS
traffic again, and `company0` will still get the company's internal domain and
IP subnet traffic and nothing else. Everything hence works as intended.

## How to Implement this in Your VPN Software

Most likely you want to expose a boolean in some way that declares whether a
specific VPN is of the *corporate* or the *privacy* kind:

1. If managing a *corporate* VPN, you configure any search domains the user or
   the VPN contact point provided. And you set `default-route` to false. If you
   have IP subnet information for the VPN, it might make sense to insert
   `~….in-addr.arpa` and `~….ip6.arpa` reverse lookup routing domains for it.

2. If managing a *privacy* VPN, you include `~.` in the routing domains, the
   value for `default-route` is actually irrelevant, but I'd set it to true. No
   need to configure any reverse lookup routing domains for it.

(If you also manage regular WiFi/Ethernet devices, just configure them as
traditional, i.e. with any search domains as acquired, do not set `~.` though,
and do not disable `default-route`.)

## The APIs

Now we determined how we want to configure things, but how do you actually get
the configuration to `systemd-resolved.service`? There are three relevant
interfaces:

1. Ideally, you use D-Bus and talk to [`systemd-resolved.service`'s D-Bus
   API](https://www.freedesktop.org/software/systemd/man/org.freedesktop.resolve1.html)
   directly. Use `SetLinkDomains()` to set the per-interface search and routing
   domains on the interfaces you manage, and `SetLinkDefaultRoute()` to manage
   the `default-route` boolean, all on the `org.freedesktop.resolve1.Manager`
   interface of the `/org/freedesktop/resolve1` object.

2. If that's not in the cards, you may shell out to
   [`resolvectl`](https://www.freedesktop.org/software/systemd/man/resolvectl.html),
   which is a thin wrapper around the D-Bus interface mentioned above. Use
   `resolvectl domain <iface> …` to set the search/routing domains and
   `resolvectl default-route <iface> …` to set the `default-route` boolean.

   Example use from a shell callout of your VPN software for a *corporate* VPN:

        resolvectl domain corporate0 '~corp-company.example' '~2.0.192.in-addr.arpa'
        resolvectl default-route corporate0 false
        resolvectl dns corporate0 192.0.2.1

   Example use from a shell callout of your VPN software for a *privacy* VPN:

        resolvectl domain privacy0 '~.'
        resolvectl default-route privacy0 true
        resolvectl dns privacy0 8.8.8.8

3. If you don't want to use any `systemd-resolved` commands, you may use the
   `resolvconf` wrapper we provide. `resolvectl` is actually a multi-call
   binary and may be symlinked to `resolvconf`, and when invoked like that
   behaves in a way that is largely compatible with FreeBSD's and
   Ubuntu's/Debian's
   [`resolvconf(8)`](https://manpages.ubuntu.com/manpages/trusty/man8/resolvconf.8.html)
   tool. When the `-x` switch is specified, the `~.` routing domain is
   automatically appended to the domain list configured, as appropriate for a
   *privacy* VPN. Note that the `resolvconf` interface only covers *privacy*
   VPNs and regular network interfaces (such as WiFi or Ethernet) well. The
   *corporate* kind of VPN is not well covered, since the interface cannot
   propagate the `default-route` boolean, nor can be used to configure the
   `~….in-addr.arpa` or `~.ip6.arpa` routing domains.

## Ordering

When configuring per-interface DNS configuration settings it is wise to
configure everything *before* actually upping the interface. Once the interface
is up `systemd-resolved.service` might start using it, and hence it's important
to have everything configured properly (this is particularly relevant when
LLMNR or MulticastDNS is enabled, since that works without any explicitly
configured DNS configuration). It is also wise to configure search/routing
domains and the `default-route` boolean *before* configuring the DNS servers,
as the former without the latter has no effect, but the latter without the
former will result in DNS traffic possibly being generated, in a non-desirable
way given that the routing information is not set yet.

## Downgrading Search Domains to Routing Domains

Many VPN implementations provide a way how VPN servers can inform VPN clients
about search domains to use. In some cases it might make sense to install those
as routing domains instead of search domains. Unqualified domain names usually
imply a context of locality: the same unqualified name typically is expected to
resolve to one system in one local network, and to another one in a different
network.  Search domains thus generally come with security implications: they
might cause that unqualified domains are resolved in a different (possibly
remote) context, contradicting user expectations. Thus it might be wise to
downgrade *search domains* provided by VPN servers to *routing domains*, so
that local unqualified name resolution remains untouched and strictly maintains
its local focus — in particular in the aforementioned less trusted *corporate*
VPN scenario.

To illustrate this further, here's an example for an attack scenario using
search domains: a user assumes the printer system they daily contact under the
unqualified name "printer" is the network printer in their basement (with the
fully qualified domain name "printer.home"). Sometimes the user joins the
corporate VPN of their employer, which comes with a search domain
"foocorp.example", so that the user's confidential documents (maybe a job
application to a competing company) might end up being printed on
"printer.foocorp.example" instead of "printer.home". If the local VPN software
had downgraded the VPN's search domain to a routing domain "~foocorp.example",
this mismapping would not have happened.

When connecting to untrusted WiFi networks it might be wise to go one step
further even: suppress installation of search/routing domains by the network
entirely, to ensure that the local DNS information is only used for name
resolution of qualified names and only when no better DNS configuration is
available.
