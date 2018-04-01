OpenRC Service Script Writing Guide
===================================

This document is aimed at developers or packagers who
write OpenRC service scripts, either for their own projects, or for
the packages they maintain. It contains advice, suggestions, tips,
tricks, hints, and counsel; cautions, warnings, heads-ups,
admonitions, proscriptions, enjoinders, and reprimands.

It is intended to prevent common mistakes that are found "in the wild"
by pointing out those mistakes and suggesting alternatives.  Each
good/bad thing that you should/not do has a section devoted to it. We
don't consider anything exotic, and assume that you will use
start-stop-daemon to manage a fairly typical long-running UNIX
process.

# Syntax of Service Scripts

Service scripts are shell scripts. OpenRC aims at using only the standardized 
POSIX sh subset for portability reasons. The default interpreter (build-time 
toggle) is `/bin/sh`, so using for example mksh is not a problem.

OpenRC has been tested with busybox sh, ash, dash, bash, mksh, zsh and possibly 
others. Using busybox sh has been difficult as it replaces commands with 
builtins that don't offer the expected features.

The interpreter for service scripts is `#!/sbin/openrc-run`.
Not using this interpreter will break the use of dependencies and is not 
supported. (iow: if you insist on using `#!/bin/sh` you're on your own)

A `depend` function declares the dependencies of this service script.
All scripts must have start/stop/status functions, but defaults are provided and should be used unless you have a very strong reason not to use them.

Extra functions can be added easily:

```
extra_commands="checkconfig"
checkconfig() {
	doSomething
}
```

This exports the checkconfig function so that `/etc/init.d/someservice 
checkconfig` will be available, and it "just" runs this function.

While commands defined in `extra_commands` are always available, commands
defined in `extra_started_commands` will only work when the service is started
and those defined in `extra_stopped_commands` will only work when the service is
stopped. This can be used for implementing graceful reload and similar
behaviour.

Adding a restart function will not work, this is a design decision within 
OpenRC. Since there may be dependencies involved (e.g. network -> apache) a 
restart function is in general not going to work. 
restart is internally mapped to `stop()` + `start()` (plus handling dependencies).
If a service needs to behave differently when it is being restarted vs
started or stopped, it should test the `$RC_CMD` variable, for example:

```
[ "$RC_CMD" = restart ] && do_something
```

# The Depend Function

This function declares the dependencies for a service script. This
determines the order the service scripts start.

```
depend() {
	need net
	use dns logger netmount
	want coolservice
}
```

`need` declares a hard dependency - net always needs to be started before this 
	service does

`use` is a soft dependency - if dns, logger or netmount is in this runlevel 
	start it before, but we don't care if it's not in this runlevel.
	`want` is between need and use - try to start coolservice if it is
	installed on the system, regardless of whether it is in the
	runlevel, but we don't care if it starts.

`before` declares that we need to be started before another service

`after` declares that we need to be started after another service, without 
	creating a dependency (so on calling stop the two are independent)

`provide` allows multiple implementations to provide one service type, e.g.:
	`provide cron` is set in all cron-daemons, so any one of them started 
	satisfies a cron dependency

`keyword` allows platform-specific overrides, e.g. `keyword -lxc` makes this 
	service script a noop in lxc containers. Useful for things like keymaps, 
	module loading etc. that are either platform-specific or not available 
	in containers/virtualization/...

FIXME: Anything missing in this list?

# The Default Functions

All service scripts are assumed to have the following functions:

```
start()
stop()
status()
```

There are default implementations in `lib/rc/sh/openrc-run.sh` - this allows very 
compact service scripts. These functions can be overridden per service script as 
needed.

The default functions assume the following variables to be set in the service 
script:

```
command=
command_args=
pidfile=
```

Thus the 'smallest' service scripts can be half a dozen lines long

## Don't write your own start/stop functions

OpenRC is capable of stopping and starting most daemons based on the
information that you give it. For a well-behaved daemon that
backgrounds itself and writes its own PID file by default, the
following OpenRC variables are likely all that you'll need:

  * command
  * command_args
  * pidfile

Given those three pieces of information, OpenRC will be able to start
and stop the daemon on its own. The following is taken from an
[OpenNTPD](http://www.openntpd.org/) service script:

```sh
command="/usr/sbin/ntpd"

# The special RC_SVCNAME variable contains the name of this service.
pidfile="/run/${RC_SVCNAME}.pid"
command_args="-p ${pidfile}"
```

If the daemon runs in the foreground by default but has options to
background itself and to create a pidfile, then you'll also need

  * command_args_background

That variable should contain the flags needed to background your
daemon, and to make it write a PID file. Take for example the
following snippet of an
[NRPE](https://github.com/NagiosEnterprises/nrpe) service script:

```sh
command="/usr/bin/nrpe"
command_args="--config=/etc/nagios/nrpe.cfg"
command_args_background="--daemon"
pidfile="/run/${RC_SVCNAME}.pid"
```

Since NRPE runs as *root* by default, it needs no special permissions
to write to `/run/nrpe.pid`. OpenRC takes care of starting and
stopping the daemon with the appropriate arguments, even passing the
`--daemon` flag during startup to force NRPE into the background (NRPE
knows how to write its own PID file).

But what if the daemon isn't so well behaved? What if it doesn't know
how to background itself or create a pidfile? If it can do neither,
then use,

  * command_background=true

which will additionally pass `--make-pidfile` to start-stop-daemon,
causing it to create the `$pidfile` for you (rather than the daemon
itself being responsible for creating the PID file).

If your daemon doesn't know how to change its own user or group, then
you can tell start-stop-daemon to launch it as an unprivileged user
with

  * command_user="user:group"

Finally, if your daemon always forks into the background but fails to
create a PID file, then your only option is to use

  * procname

With `procname`, OpenRC will try to find the running daemon by
matching the name of its process. That's not so reliable, but daemons
shouldn't background themselves without creating a PID file in the
first place. The next example is part of the [CA NetConsole
Daemon](https://oss.oracle.com/projects/cancd/) service script:

```sh
command="/usr/sbin/cancd"
command_args="-p ${CANCD_PORT}
              -l ${CANCD_LOG_DIR}
              -o ${CANCD_LOG_FORMAT}"
command_user="cancd"

# cancd daemonizes itself, but doesn't write a PID file and doesn't
# have an option to run in the foreground. So, the best we can do
# is try to match the process name when stopping it.
procname="cancd"
```

To recap, in order of preference:

  1. If the daemon backgrounds itself and creates its own PID file, use
     `pidfile`.
  2. If the daemon does not background itself (or has an option to run
     in the foreground) and does not create a PID file, then use
     `command_background=true` and `pidfile`.
  3. If the daemon backgrounds itself and does not create a PID file,
     use `procname` instead of `pidfile`. But, if your daemon has the
     option to run in the foreground, then you should do that instead
     (that would be the case in the previous item).
  4. The last case, where the daemon does not background itself but
     does create a PID file, doesn't make much sense. If there's a way
     to disable the daemon's PID file (or, to write it straight into the
     garbage), then do that, and use `command_background=true`.

## Reloading your daemon's configuration

Many daemons will reload their configuration files in response to a
signal. Suppose your daemon will reload its configuration in response
to a `SIGHUP`. It's possible to add a new "reload" command to your
service script that performs this action. First, tell the service
script about the new command.

```sh
extra_started_commands="reload"
```

We use `extra_started_commands` as opposed to `extra_commands` because
the "reload" action is only valid while the daemon is running (that
is, started). Now, start-stop-daemon can be used to send the signal to
the appropriate process (assuming you've defined the `pidfile`
variable elsewhere):

```sh
reload() {
  ebegin "Reloading ${RC_SVCNAME}"
  start-stop-daemon --signal HUP --pidfile "${pidfile}"
  eend $?
}
```

## Don't restart/reload with a broken config

Often, users will start a daemon, make some configuration change, and
then attempt to restart the daemon. If the recent configuration change
contains a mistake, the result will be that the daemon is stopped but
then cannot be started again (due to the configuration error). It's
possible to prevent that situation with a function that checks for
configuration errors, and a combination of the `start_pre` and
`stop_pre` hooks.

```sh
checkconfig() {
  # However you want to check this...
}

start_pre() {
  # If this isn't a restart, make sure that the user's config isn't
  # busted before we try to start the daemon (this will produce
  # better error messages than if we just try to start it blindly).
  #
  # If, on the other hand, this *is* a restart, then the stop_pre
  # action will have ensured that the config is usable and we don't
  # need to do that again.
  if [ "${RC_CMD}" != "restart" ] ; then
    checkconfig || return $?
  fi
}

stop_pre() {
  # If this is a restart, check to make sure the user's config
  # isn't busted before we stop the running daemon.
  if [ "${RC_CMD}" = "restart" ] ; then
      checkconfig || return $?
  fi
}
```

To prevent a *reload* with a broken config, keep it simple:

```sh
reload() {
  checkconfig || return $?
  ebegin "Reloading ${RC_SVCNAME}"
  start-stop-daemon --signal HUP --pidfile "${pidfile}"
  eend $?
}
```

## PID files should be writable only by root

PID files must be writable only by *root*, which means additionally
that they must live in a *root*-owned directory. This directory is
normally /run under Linux and /var/run under other operating systems.

Some daemons run as an unprivileged user account, and create their PID
files (as the unprivileged user) in a path like
`/var/run/foo/foo.pid`. That can usually be exploited by the unprivileged
user to kill *root* processes, since when a service is stopped, *root*
usually sends a SIGTERM to the contents of the PID file (which are
controlled by the unprivileged user). The main warning sign for that
problem is using `checkpath` to set ownership on the directory
containing the PID file. For example,

```sh
# BAD BAD BAD BAD BAD BAD BAD BAD
start_pre() {
  # Ensure that the pidfile directory is writable by the foo user/group.
  checkpath --directory --mode 0700 --owner foo:foo "/var/run/foo"
}
# BAD BAD BAD BAD BAD BAD BAD BAD
```

If the *foo* user owns `/var/run/foo`, then he can put whatever he wants
in the `/var/run/foo/foo.pid` file. Even if *root* owns the PID file, the
*foo* user can delete it and replace it with his own. To avoid
security concerns, the PID file must be created as *root* and live in
a *root*-owned directory. If your daemon is responsible for forking
and writing its own PID file but the PID file is still owned by the
unprivileged runtime user, then you may have an upstream issue.

Once the PID file is being created as *root* (before dropping
privileges), it can be written directly to a *root*-owned
directory.  For example, the *foo* daemon might write
`/var/run/foo.pid`. No calls to checkpath are needed. Note: there is
nothing technically wrong with using a directory structure like
`/var/run/foo/foo.pid`, so long as *root* owns the PID file and the
directory containing it.

Ideally (see "Upstream your service scripts"), your service script
will be integrated upstream and the build system will determine the
appropriate directory for the pid file. For example,

```sh
pidfile="@piddir@/${RC_SVCNAME}.pid"
```

A decent example of this is the [Nagios core service
script](https://github.com/NagiosEnterprises/nagioscore/blob/master/openrc-init.in),
where the full path to the PID file is specified at build-time.

## Don't let the user control the PID file location

It's usually a mistake to let the end user control the PID file
location through a conf.d variable, for a few reasons:

  1. When the PID file path is controlled by the user, you need to
     ensure that its parent directory exists and is writable. This
     adds unnecessary code to the service script.

  2. If the PID file path changes while the service is running, then
     you'll find yourself unable to stop the service.

  3. The directory that should contain the PID file is best determined
     by the upstream build system (see "Upstream your service scripts").
     On Linux, the preferred location these days is `/run`. Other systems
     still use `/var/run`, though, and a `./configure` script is the
     best place to decide which one you want.

  4. Nobody cares where the PID file is located, anyway.

Since OpenRC service names must be unique, a value of

```sh
pidfile="/var/run/${RC_SVCNAME}.pid"
```

guarantees that your PID file has a unique name.

## Upstream your service scripts (for packagers)

The ideal place for an OpenRC service script is **upstream**. Much like
systemd services, a well-crafted OpenRC service script should be
distribution-agnostic, and the best place for it is upstream. Why? For
two reasons. First, having it upstream means that there's a single
authoritative source for improvements. Second, a few paths in every
service script are dependent upon flags passed to the build system. For
example,

```sh
command=/usr/bin/foo
```

in an autotools-based build system should really be

```sh
command=@bindir@/foo
```

so that the user's value of `--bindir` is respected. If you keep the
service script in your own distribution's repository, then you have to
keep the command path and package synchronized yourself, and that's no
fun.

## Be wary of "need net" dependencies

There are two things you need to know about "need net" dependencies:

  1. They are not satisfied by the loopback interface, so "need net"
     requires some *other* interface to be up.

  2. Depending on the value of `rc_depend_strict` in `rc.conf`, the
     "need net" will be satisfied when either *any* non-loopback
     interface is up, or when *all* non-loopback interfaces are up.

The first item means that "need net" is wrong for daemons that are
happy with `0.0.0.0`, and the second point means that "need net" is
wrong for daemons that need a particular (for example, the WAN)
interface. We'll consider the two most common users of "need net";
network clients who access some network resource, and network servers
who provide them.

### Network clients

Network clients typically want the WAN interface to be up. That may
tempt you to depend on the WAN interface; but first, you should ask
yourself a question: does anything bad happen if the WAN interface is
not available? In other words, if the administrator wants to disable
the WAN, should the service be stopped? Usually the answer to that
question is "no," and in that case, you should forego the "net"
dependency entirely.

Suppose, for example, that your service retrieves virus signature
updates from the internet. In order to do its job correctly, it needs
a (working) internet connection. However, the service itself does not
require the WAN interface to be up: if it is, great; otherwise, the
worst that will happen is that a "server unavailable" warning will be
logged. The signature update service will not crash, and—perhaps more
importantly—you don't want it to terminate if the administrator turns
off the WAN interface for a second.

### Network servers

Network servers are generally easier to handle than their client
counterparts. Most server daemons listen on `0.0.0.0` (all addresses)
by default, and are therefore satisfied to have the loopback interface
present and operational. OpenRC ships with the loopback service in the
*boot* runlevel, and therefore most server daemons require no further
network dependencies.

The exceptions to this rule are those daemons who produce negative
side-effects when the WAN is unavailable. For example, the Nagios
server daemon will generate "the sky is falling" alerts for as long as
your monitored hosts are unreachable. So in that case, you should
require some other interface (often the WAN) to be up. A "need"
dependency would be appropriate, because you want Nagios to be
stopped before the network is taken down.

If your daemon can optionally be configured to listen on a particular
interface, then please see the "Depending on a particular interface"
section.

### Depending on a particular interface

If you need to depend on one particular interface, usually it's not
easy to determine programmatically what that interface is. For
example, if your *sshd* daemon listens on `192.168.1.100` (rather than
`0.0.0.0`), then you have two problems:

  1. Parsing `sshd_config` to figure that out; and

  2. Determining which network service name corresponds to the
     interface for `192.168.1.100`.

It's generally a bad idea to parse config files in your service
scripts, but the second problem is the harder one. Instead, the most
robust (i.e. the laziest) approach is to make the user specify the
dependency when he makes a change to sshd_config. Include something
like the following in the service configuration file,

```sh
# Specify the network service that corresponds to the "bind" setting
# in your configuration file. For example, if you bind to 127.0.0.1,
# this should be set to "loopback" which provides the loopback interface.
rc_need="loopback"
```

This is a sensible default for daemons that are happy with `0.0.0.0`,
but lets the user specify something else, like `rc_need="net.wan"` if
he needs it. The burden is on the user to determine the appropriate
service whenever he changes the daemon's configuration file.
