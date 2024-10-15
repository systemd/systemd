---
title: Frequently Asked Questions
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Frequently Asked Questions

Also check out the [Tips & Tricks](/TIPS_AND_TRICKS)!

**Q: How do I change the current runlevel?**

A: In systemd runlevels are exposed via "target units". You can change them like this:

```sh
# systemctl isolate runlevel5.target
```

Note however, that the concept of runlevels is a bit out of date, and it is usually nicer to use modern names for this. e.g.:

```sh
# systemctl isolate graphical.target
```

This will only change the current runlevel, and has no effect on the next boot.

**Q: How do I change the default runlevel to boot into?**

A: The symlink /etc/systemd/system/default.target controls where we boot into by default. Link it to the target unit of your choice. For example, like this:

```sh
# ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target
```

or

```sh
# ln -sf /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target
```

**Q: How do I figure out the current runlevel?**

A: Note that there might be more than one target active at the same time. So the question regarding _the_ runlevel might not always make sense. Here's how you would figure out all targets that are currently active:

```sh
$ systemctl list-units --type=target
```

If you are just interested in a single number, you can use the venerable _runlevel_ command, but again, its output might be misleading.

**Q: I want to change a service file, but rpm keeps overwriting it in /usr/lib/systemd/system all the time, how should I handle this?**

A: The recommended way is to copy the service file from /usr/lib/systemd/system to /etc/systemd/system and edit it there. The latter directory takes precedence over the former, and rpm will never overwrite it. If you want to use the distributed service file again you can simply delete (or rename) the service file in /etc/systemd/system again.

**Q: My service foo.service as distributed by my operating system vendor is only started when (a connection comes in or some hardware is plugged in). I want to have it started always on boot, too. What should I do?**

A: Simply place a symlink from that service file in the multi-user.target.wants/ directory (which is where you should symlink everything you want to run in the old runlevel 3, i.e. the normal boot-up without graphical UI. It is pulled in by graphical.target too, so will be started for graphical boot-ups, too):

```sh
# ln -sf /usr/lib/systemd/system/foobar.service /etc/systemd/system/multi-user.target.wants/foobar.service
# systemctl daemon-reload
```

**Q: I want to enable another getty, how would I do that?**

A: Simply instantiate a new getty service for the port of your choice (internally, this places another symlink for instantiating another serial getty in the getty.target.wants/ directory).
```sh
# systemctl enable serial-getty@ttyS2.service
# systemctl start serial-getty@ttyS2.service
```

Note that gettys on the virtual console are started on demand. You can control how many you get via the NAutoVTs= setting in [logind.conf(7)](http://www.freedesktop.org/software/systemd/man/systemd-logind.service).
Also see [this blog story](http://0pointer.de/blog/projects/serial-console.html).

**Q: How to I figure out which service a process belongs to?**

A: You may either use ps for that:

```sh
$ alias psc='ps xawf -eo pid,user,cgroup,args'
$ psc
...
```

Or you can even check /proc/$PID/cgroup directly. Also see [this blog story](http://0pointer.de/blog/projects/systemd-for-admins-2.html).

**Q: Why don't you use inotify to reload the unit files automatically on change?**

A: Unfortunately that would be a racy operation. For an explanation why and how we tried to improve the situation, see [the bugzilla report about this](https://bugzilla.redhat.com/show_bug.cgi?id=615527).

**Q: I have a native systemd service file and a SysV init script installed which share the same basename, e.g. /usr/lib/systemd/system/foobar.service vs. /etc/init.d/foobar -- which one wins?**

A: If both files are available the native unit file always takes precedence and the SysV init script is ignored, regardless whether either is enabled or disabled. Note that a SysV service that is enabled but overridden by a native service does not have the effect that the native service would be enabled, too. Enabling of native and SysV services is completely independent. Or in other words: you cannot enable a native service by enabling a SysV service by the same name, and if a SysV service is enabled but the respective native service is not, this will not have the effect that the SysV script is executed.

**Q: How can I use journalctl to display full (= not truncated) messages even if less is not used?**

A: Use:

```sh
# journalctl --full
```


**Q: Whenever my service tries to acquire RT scheduling for one of its threads this is refused with EPERM even though my service is running with full privileges. This works fine on my non-systemd system!**

A: By default, systemd places all systemd daemons in their own cgroup in the "cpu" hierarchy. Unfortunately, due to a kernel limitation, this has the effect of disallowing RT entirely for the service. See [My Service Can't Get Realtime!](/MY_SERVICE_CANT_GET_REALTIME) for a longer discussion and what to do about this.

**Q: My service is ordered after `network.target` but at boot it is still called before the network is up. What's going on?**

A: That's a long story, and that's why we have a wiki page of its own about this: [Running Services After the Network is up](/NETWORK_ONLINE)

**Q: My systemd system always comes up with `/tmp` as a tiny `tmpfs`. How do I get rid of this?**

A: That's also a long story, please have a look on [API File Systems](/API_FILE_SYSTEMS)
