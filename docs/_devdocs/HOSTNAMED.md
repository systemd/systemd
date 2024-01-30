---
title: On hostnamed
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

**This page has been obsoleted and replaced:** [ https://www.freedesktop.org/software/systemd/man/org.freedesktop.hostname1.html](https://www.freedesktop.org/software/systemd/man/org.freedesktop.hostname1.html).

# hostnamed

systemd 25 and newer include systemd-hostnamed. This is a tiny daemon that can be used to control the host name and related machine meta data from user programs. It currently offers access to five variables:

- The current host name (Example: dhcp-192-168-47-11)
- The static (configured) host name (Example: lennarts-computer)
- The pretty host name (Example: Lennart's Computer)
- A suitable icon name for the local host (Example: computer-laptop)
- A chassis type (Example: "tablet")

See [systemd-hostnamed.service(8)](http://www.freedesktop.org/software/systemd/man/systemd-hostnamed.service.html) for more information.

The daemon is accessible via D-Bus:

```
$ gdbus introspect --system --dest org.freedesktop.hostname1 --object-path /org/freedesktop/hostname1
node /org/freedesktop/hostname1 {
  interface org.freedesktop.hostname1 {
    methods:
      SetHostname(in  s name,
                  in  b user_interaction);
      SetStaticHostname(in  s name,
                        in  b user_interaction);
      SetPrettyHostname(in  s name,
                        in  b user_interaction);
      SetIconName(in  s name,
                  in  b user_interaction);
      SetChassis(in  s name,
                 in  b user_interaction);
    signals:
    properties:
      readonly s Hostname = 'dhcp-192-168-47-11';
      readonly s StaticHostname = 'lennarts-computer';
      readonly s PrettyHostname = 'Lennart's Computer';
      readonly s IconName = 'computer-laptop';
      readonly s Chassis = 'laptop';
  };
  interface org.freedesktop.DBus.Properties {
  };
  interface org.freedesktop.DBus.Introspectable {
  };
  interface org.freedesktop.DBus.Peer {
  };
};
```

Whenever the hostname or other meta data is changed via the daemon PropertyChanged signals are sent out to which clients can subscribe. Changing a hostname using this interface is authenticated via PolicyKit.

A couple of notes on the semantics:

The **static (configured) host name** is the one configured in /etc/hostname or a similar file. It is chosen by the local user. It is not always in sync with the current host name as returned by the gethostname() system call. If no host name is configured this property will be the empty string. Setting this property to the empty string will remove /etc/hostname. This hostname should be an internet-style hostname, 7bit ASCII, no special chars/spaces, lower case.

The **transient (dynamic) host name** is the one configured via the kernel's sethostbyname(). It can be different from the static hostname in case DHCP or mDNS have been configured to change the name based on network information. This property is never empty. If no host name is set this will default to "localhost". Setting this property to the empty string will reset the dynamic hostname to the static host name. If no static host name is configured the dynamic host name will be reset to "localhost". This hostname should be an internet-style hostname, 7bit ASCII, no special chars/spaces, lower case.

The **pretty host name** is a free-form UTF8 host name for presentation to the user. UIs should ensure that the pretty hostname and the static hostname stay in sync. I.e. when the former is "Lennart's Computer" the latter should be "lennarts-computer". If no pretty host name is set this setting will be the empty string. Applications should then find a suitable fallback, such as the dynamic hostname.

The **icon name** is a name following the XDG icon naming spec. If not set information such as the chassis type (see below) are used to find a suitable fallback icon name (i.e. "computer-laptop" vs. "computer-desktop" is picked based on the chassis information). If no such data is available returns the empty string. In that case an application should fall back to a replacement icon, for example "computer". If this property is set to the empty string this automatic fallback name selection is enabled again.

The **chassis type** should be one of the following that are currently defined: "desktop", "laptop", "server", "tablet", "handset", as well as the special chassis types "vm" and "container" for virtualized systems that lack an immediate physical chassis. Note that in most cases the chassis type will be determined automatically from DMI/SMBIOS/ACPI firmware information. Writing to this setting is hence useful only to override misdetected chassis types, or configure a chassis type if none could be auto-detected. Set this property to the empty string to reenable the automatic detection of the chassis type from firmware information.

A client which wants to change the local host name for DHCP/mDNS should invoke SetHostname("newname", false) as soon as the name is available and afterwards reset it via SetHostname("").

Note that hostnamed starts only on request and terminates after a short idle period. This effectively means that [?](//secure.freedesktop.org/write/www/ikiwiki.cgi?do=create&from=Software%2Fsystemd%2Fhostnamed&page=PropertyChanged)PropertyChanged messages are not sent out for changes made directly on the files (as in: administrator edits the files with vi). This is actually intended behavior: manual configuration changes should require manual reloading of them.

The transient (dynamic) hostname directly maps to the kernel hostname. This hostname should be assumed to be highly dynamic, and hence should be watched directly, without involving [?](//secure.freedesktop.org/write/www/ikiwiki.cgi?do=create&from=Software%2Fsystemd%2Fhostnamed&page=PropertyChanged)PropertyChanged messages from hostnamed. For that, open /proc/sys/kernel/hostname and poll() for SIGHUP which is triggered by the kernel every time the hostname changes. Again: this is special for the transient (dynamic) hostname, and does not apply to the configured (fixed) hostname.

Applications may bypass the daemon to read the hostname data if notifications of host name changes are not necessary. Use gethostname(), /etc/hostname (possibly with per-distribution fallbacks), and /etc/machine-data for that. For more information on these files and syscalls see the respective man pages.

The user_interaction boolean parameters can be used to control whether PolicyKit should interactively ask the user for authentication credentials if it needs to.

The PolicyKit action for SetHostname() is _org.freedesktop.hostname1.set-hostname_. For SetStaticHostname() and SetPrettyHostname() it is _org.freedesktop.hostname1.set-static-hostname_. For SetIconName() and SetChassis() it is _org.freedesktop.hostname1.set-machine-info_.

This is inspired by, but not the same as David Zeuthen's xdg-hostname: [http://people.freedesktop.org/~david/xdg-hostname/](http://people.freedesktop.org/~david/xdg-hostname/)

Also see David's original Fedora feature page about this: [http://fedoraproject.org/wiki/Features/BetterHostname](http://fedoraproject.org/wiki/Features/BetterHostname)

The sources for hostnamed are available in git for review: [http://cgit.freedesktop.org/systemd/systemd/tree/src/hostname/hostnamed.c](http://cgit.freedesktop.org/systemd/systemd/tree/src/hostname/hostnamed.c)

Here are three examples how the pretty hostname and the icon name should be used:

- When registering DNS-SD services: use the pretty host name in the service name, and pass the icon name in the TXT data, if there is an icon name. Browsing clients can then show the server icon on each service. Especially useful for WebDAV stuff. Similar for UPnP media sharing.
- Set the bluetooth name to the pretty host name.
- When your file browser has a "Computer" icon, replace the name with the pretty hostname if set, and the icon with the icon name, if it is set.

To properly handle name lookups with changing local hostnames without having to edit /etc/hosts for them we recommend using hostnamed in combination with nss-myhostname: [http://0pointer.de/lennart/projects/nss-myhostname/](http://0pointer.de/lennart/projects/nss-myhostname/)

Here are some recommendations to follow when generating a static (internet) hostname from a pretty name:

- Generate a single DNS label only, not an FQDN. That means no dots allowed. Strip them, or replace them by "-".
- It's probably safer not to use any non-ASCII chars, even if DNS allows this in some way these days. In fact, restrict your charset to a-zA-Z0-9, -. Strip other chars, or try to replace them in some smart way with chars from this set, for example "ä" → "ae" and suchlike, and use "-" as replacement for all kinds of punctuation chars or spaces.
- Try to avoid creating repeated "-", as well as "-" as the first or last char.
- Limit the hostname to 63 chars, which is the length of a DNS label
- If after stripping special chars the empty string is the result, you can pass this as-is to hostnamed in which case it will automatically make "localhost" out of this.
- It probably is a good idea to replace uppercase by lowercase chars

Note that while hostnamed applies some checks to the hostname you pass they are much looser than the recommendations above. For example, hostnamed will also accept "\_" in the hostname, but I'd recommend not using this to avoid clashes with DNS-SD service types. Also hostnamed allows you longer hostnames, but because of the DNS label limitations I'd recommend not making use of this.

Here are a couple of example conversions:

- "Lennart's PC" → lennarts-pc
- "Müllers Computer" → muellers-computer
- "Voran!" → voran
- "Es war einmal ein Männlein" → "es-war-einmal-ein-maennlein"
- "Jawoll. Ist doch wahr!" → "jawoll-ist-doch-wahr"
- "レナート" → "localhost"
- "...zack!!! zack!..." → "zack-zack"

Oh, and of course, an already valid internet hostname label you enter and pass through this conversion should stay unmodified, so that users have direct control of it, if they want -- by simply ignoring the fact that the pretty hostname is pretty and just edit it as if it was the normal internet name.

---

This D-Bus interface follows [the usual interface versioning guidelines](http://0pointer.de/blog/projects/versioning-dbus.html).
