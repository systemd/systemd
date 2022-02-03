---
title: Porting systemd To New Distributions
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Porting systemd To New Distributions

## HOWTO

You need to make the follow changes to adapt systemd to your
distribution:

1. Find the right configure parameters for:

   * `-Drootprefix=`
   * `-Dsysvinit-path=`
   * `-Dsysvrcnd-path=`
   * `-Drc-local=`
   * `-Dloadkeys-path=`
   * `-Dsetfont-path=`
   * `-Dtty-gid=`
   * `-Dntp-servers=`
   * `-Ddns-servers=`
   * `-Dsupport-url=`

2. Try it out.

   Play around (as an ordinary user) with
   `/usr/lib/systemd/systemd --test --system` for a test run
   of systemd without booting. This will read the unit files and
   print the initial transaction it would execute during boot-up.
   This will also inform you about ordering loops and suchlike.

## Compilation options

The default configuration does not enable any optimization or hardening
options. This is suitable for development and testing, but not for end-user
installations.

For deployment, optimization (`-O2` or `-O3` compiler options), link time
optimization (`-Db_lto=true` meson option), and hardening (e.g.
`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, `-fstack-clash-protection`,
`-fcf-protection`, `-pie` compiler options, and `-z relro`, `-z now`,
`--as-needed` linker options) are recommended. The most appropriate set of
options depends on the architecture and distribution specifics so no default is
provided.

## NTP Pool

By default, systemd-timesyncd uses the Google Public NTP servers
`time[1-4].google.com`, if no other NTP configuration is available.
They serve time that uses a
[leap second smear](https://developers.google.com/time/smear)
and can be up to .5s off from servers that use stepped leap seconds.

If you prefer to use leap second steps, please register your own
vendor pool at ntp.org and make it the built-in default by
passing `-Dntp-servers=` to meson. Registering vendor
pools is [free](http://www.pool.ntp.org/en/vendors.html).

Use `-Dntp-servers=` to direct systemd-timesyncd to different fallback
NTP servers.

## DNS Servers

By default, systemd-resolved uses Cloudflare and Google Public DNS servers
`1.1.1.1`, `8.8.8.8`, `1.0.0.1`, `8.8.4.4`, `2606:4700:4700::1111`, `2001:4860:4860::8888`, `2606:4700:4700::1001`, `2001:4860:4860::8844`
as fallback, if no other DNS configuration is available.

Use `-Ddns-servers=` to direct systemd-resolved to different fallback
DNS servers.

## PAM

The default PAM config shipped by systemd is really bare bones.
It does not include many modules your distro might want to enable
to provide a more seamless experience. For example, limits set in
`/etc/security/limits.conf` will not be read unless you load `pam_limits`.
Make sure you add modules your distro expects from user services.

Pass `-Dpamconfdir=no` to meson to avoid installing this file and
instead install your own.

## Contributing Upstream

We generally do no longer accept distribution-specific patches to
systemd upstream. If you have to make changes to systemd's source code
to make it work on your distribution, unless your code is generic
enough to be generally useful, we are unlikely to merge it. Please
always consider adopting the upstream defaults. If that is not
possible, please maintain the relevant patches downstream.

Thank you for understanding.
