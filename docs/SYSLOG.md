---
title: Writing syslog Daemons Which Cooperate Nicely With systemd
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Writing syslog Daemons Which Cooperate Nicely With systemd

Here are a few notes on things to keep in mind when you work on a classic BSD syslog daemon for Linux, to ensure that your syslog daemon works nicely together with systemd.
If your syslog implementation does not follow these rules, then it will not be compatible with systemd v38 and newer.

A few notes in advance: systemd centralizes all log streams in the Journal daemon.
Messages coming in via /dev/log, via the native protocol, via STDOUT/STDERR of all services and via the kernel are received in the journal daemon.

The journal daemon then stores them to disk or in RAM (depending on the configuration of the Storage= option in journald.conf), and optionally forwards them to the console, the kernel log buffer, or to a classic BSD syslog daemon -- and that's where you come in.

Note that it is now the journal that listens on /dev/log, no longer the BSD syslog daemon directly.
If your logging daemon wants to get access to all logging data then it should listen on /run/systemd/journal/syslog instead via the syslog.socket unit file that is shipped along with systemd.
On a systemd system it is no longer OK to listen on /dev/log directly, and your daemon may not bind to the /run/systemd/journal/syslog socket on its own.
If you do that then you will lose logging from STDOUT/STDERR of services (as well as other stuff).

Your BSD compatible logging service should alias `syslog.service` to itself (i.e. symlink) when it is _enabled_.
That way [syslog.socket](http://cgit.freedesktop.org/systemd/systemd/plain/units/syslog.socket) will activate your service when things are logged.
Of course, only one implementation of BSD syslog can own that symlink, and hence only one implementation can be enabled at a time, but that's intended as there can only be one process listening on that socket.
(see below for details how to manage this symlink.)

Note that this means that syslog.socket as shipped with systemd is _shared_ among all implementations, and the implementation that is in control is configured with where syslog.service points to.

Note that journald tries hard to forward to your BSD syslog daemon as much as it can.
That means you will get more than you traditionally got on /dev/log, such as stuff all daemons log on STDOUT/STDERR and the messages that are logged natively to systemd. Also, we will send stuff like the original SCM_CREDENTIALS along if possible.

(BTW, journald is smart enough not to forward the kernel messages it gets to you, you should read that on your own, directly from /proc/kmsg, as you always did.
It's also smart enough never to forward kernel messages back to the kernel, but that probably shouldn't concern you too much...)

And here are the recommendations:

- First of all, make sure your syslog daemon installs a native service unit file (SysV scripts are not sufficient!) and is socket activatable. Newer systemd versions (v35+) do not support non-socket-activated syslog daemons anymore and we do no longer recommend people to order their units after syslog.target.
That means that unless your syslog implementation is socket activatable many services will not be able to log to your syslog implementation and early boot messages are lost entirely to your implementation.
Note that your service should install only one unit file, and nothing else. Do not install socket unit files.

- Make sure that in your unit file you set StandardOutput=null in the [Service] block.
This makes sure that regardless what the global default for StandardOutput= is the output of your syslog implementation goes to /dev/null.
This matters since the default StandardOutput= value for all units can be set to syslog and this should not create a feedback loop with your implementation where the messages your syslog implementation writes out are fed back to it.
In other words: you need to explicitly opt out of the default standard output redirection we do for other services.
(Also note that you do not need to set StandardError= explicitly, since that inherits the setting of StandardOutput= by default)

- /proc/kmsg is your property, flush it to disk as soon as you start up.

- Name your service unit after your daemon (e.g. rsyslog.service or syslog-ng.service) and make sure to include Alias=syslog.service in your [Install] section in the unit file.
This is ensures that the symlink syslog.service is created if your service is enabled and that it points to your service.
Also add WantedBy=multi-user.target so that your service gets started at boot, and add Requires=syslog.socket in [Unit] so that you pull in the socket unit.

Here are a few other recommendations, that are not directly related to systemd:

- Make sure to read the priority prefixes of the kmsg log messages the same way like from normal userspace syslog messages.
When systemd writes to kmsg it will prefix all messages with valid priorities which include standard syslog facility values. OTOH for kernel messages the facility is always 0.
If you need to know whether a message originated in the kernel rely on the facility value, not just on the fact that you read the message from /proc/kmsg! A number of userspace applications write messages to kmsg (systemd, udev, dracut, others), and they'll nowadays all set correct facility values.

- When you read a message from the socket use SCM_CREDENTIALS to get information about the client generating it, and possibly patch the message with this data in order to make it impossible for clients to fake identities.

The unit file you install for your service should look something like this:

```
[Unit]
Description=System Logging Service
Requires=syslog.socket

[Service]
ExecStart=/usr/sbin/syslog-ng -n
StandardOutput=null

[Install]
Alias=syslog.service
WantedBy=multi-user.target
```

And remember: don't ship any socket unit for /dev/log or /run/systemd/journal/syslog (or even make your daemon bind directly to these sockets)! That's already shipped along with systemd for you.
