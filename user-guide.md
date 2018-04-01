OpenRC Users Guide
==================

# Purpose and description

OpenRC is an init system for Unixoid operating systems. It takes care of 
startup and shutdown of the whole system, including services.

It evolved out of the Gentoo "Baselayout" package which was a custom pure-shell 
startup solution. (This was both hard to maintain and debug, and not very 
performant)

Most of the core parts are written in C99 for performance and flexibility 
reasons, while everything else is posix sh.
The License is 2-clause BSD

Current size is about 10k LoC C, and about 4k LoC shell.

OpenRC is known to work on Linux, many BSDs (FreeBSD, OpenBSD, DragonFlyBSD at 
least) and HURD.

Services are stateful (i.e. `start`; `start` will lead to "it's already started")

# Startup

Usually PID1 (aka. `init`) calls the OpenRC binary (`/sbin/openrc` by default).
(The default setup assumes sysvinit for this)

openrc scans the runlevels (default: `/etc/runlevels`) and builds a dependency
graph, then starts the needed service scripts, either serialized (default) or in 
parallel.

When all the service scripts are started openrc terminates. There is no
persistent daemon. (Integration with tools like monit, runit or s6 can be done)

# Shutdown

On change to runlevel 0/6 or running `reboot`, `halt` etc., openrc stops all
services that are started and runs the services in the `shutdown` runlevel.

# Modifying Service Scripts

Any service can, at any time, be started/stopped/restarted by executing 
`rc-service someservice start`, `rc-service someservice stop`, etc.
Another, less preferred method, is to run the service script directly,
e.g. `/etc/init.d/service start`, `/etc/init.d/service stop`, etc.

OpenRC will take care of dependencies, e.g starting apache will start network 
first, and stopping network will stop apache first.

There is a special command `zap` that makes OpenRC 'forget' that a service is
started; this is mostly useful to reset a crashed service to stopped state 
without invoking the (possibly broken) stop function of the service script.

Calling `openrc` without any arguments will try to reset all services so
that the current runlevel is satisfied; if you manually started apache it will be 
stopped, and if squid died but is in the current runlevel it'll be restarted.

# Runlevels

OpenRC has a concept of runlevels, similar to what sysvinit historically 
offered. A runlevel is basically a collection of services that needs to be 
started. Instead of random numbers they are named, and users can create their 
own if needed. This allows, for example, to have a default runlevel with 
"everything" enabled, and a "powersaving" runlevel where some services are 
disabled.

The `rc-status` helper will print all currently active runlevels and the state
of services in them:

```
# rc-status
 * Caching service dependencies ... [ ok ]
Runlevel: default
 modules                     [  started  ]
 lvm                         [  started  ]
```

All runlevels are represented as folders in `/etc/runlevels/` with symlinks to 
the actual service scripts.

Calling openrc with an argument (`openrc default`) will switch to that
runlevel; this will start and stop services as needed.

Managing runlevels is usually done through the `rc-update` helper, but could of 
course be done by hand if desired.
e.g. `rc-update add nginx default` - add nginx to the default runlevel
Note: This will not auto-start nginx! You'd still have to trigger `rc` or run 
the service script by hand.

FIXME: Document stacked runlevels

The default startup uses the runlevels `boot`, `sysinit` and `default`, in that 
order. Shutdown uses the `shutdown` runlevel.

# The Magic of `conf.d`

Most service scripts need default values. It would be fragile to
explicitly source some arbitrary files. By convention `openrc-run` will source
the matching file in `/etc/conf.d/` for any script in `/etc/init.d/`

This allows you to set random startup-related things easily. Example:

```
conf.d/foo:
START_OPTS="--extraparameter sausage"

init.d/foo:
start() {
	/usr/sbin/foo-daemon ${STARTOPTS}
}
```

The big advantage of this split is that most of the time editing of the service 
script can be avoided.

# Start-Stop-Daemon

OpenRC has its own modified version of s-s-d, which is historically related and 
mostly syntax-compatible to Debian's s-s-d, but has been rewritten from scratch.

It helps with starting daemons, backgrounding, creating PID files and many 
other convenience functions related to managing daemons.

# `/etc/rc.conf`

This file manages the default configuration for OpenRC, and it has examples of 
per-service-script variables.

Among these are `rc_parallel` (for parallelized startup), `rc_log` (logs all boot 
messages to a file), and a few others.

# ulimit and CGroups

Setting `ulimit` and `nice` values per service can be done through the
`rc_ulimit` variable.

Under Linux, OpenRC can use cgroups for process management as well. Once
the kernel is configured appropriately, the `rc_cgroup_mode` setting in
/etc/rc.conf should be used to control whether cgroups version one,,
two, or both are used. The default is to use both if they are available.

By changing certain settings in the service's `conf.d` file limits can be
enforced per service. These settings are documented in detail in the
default /etc/rc.conf under `LINUX CGROUPS RESOURCE MANAGEMENT`.

# Dealing with Orphaned Processes

It is possible to get into a state where there are orphaned processes
running which were part of a service. For example, if you are monitoring
a service with supervise-daemon and supervise-daemon dies for an unknown
reason. The way to deal with this will be different for each system.

On Linux systems with cgroups enabled, the cgroup_cleanup command is
added to all services. You can run it manually, when the service is
stopped, by using:

```
# rc-service someservice cgroup_cleanup
```

The `rc_cgroup_cleanup` setting can be changed to yes to make this
happen automatically when the service is stopped.


# Caching

For performance reasons OpenRC keeps a cache of pre-parsed service metadata
(e.g. `depend`). The default location for this is `/${RC_SVCDIR}/cache`.

The cache uses `mtime` to check for file staleness. Should any service script
change it'll re-source the relevant files and update the cache

# Convenience functions

OpenRC has wrappers for many common output tasks in libeinfo.
This allows to print colour-coded status notices and other things.
To make the output consistent the bundled service scripts all use ebegin/eend to 
print nice messages.
