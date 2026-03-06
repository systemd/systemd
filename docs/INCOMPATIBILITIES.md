---
title: Compatibility with SysV
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Compatibility with SysV

Since systemd v260, support for SysV functionality has been removed.
The documentation below is preserved for historical reference only.

A few interfaces are optionally kept for backward compatibility.
When systemd is compiled with the `-Dcompat-sysv-interfaces=true` setting,
legacy interfaces are provided,
e.g. the `runlevelX.target` aliases,
and lock directories under `/var` and `/run`.
This option may be extended to cover other deprecated interfaces in the future.


## Pre v260 state

systemd provides a fair degree of compatibility with the behavior exposed by the SysV init system as implemented by many distributions.
Compatibility is provided both for the user experience and the SysV scripting APIs.
However, there are some areas where compatibility is limited due to technical reasons or design decisions of systemd and the distributions.
All of the following applies to SysV init scripts handled by systemd, however a number of them matter only on specific distributions.
Many of the incompatibilities are specific to distribution-specific extensions of LSB/SysV init.

* If your distribution removes SysV init scripts in favor of systemd unit files typing "/etc/init.d/foobar start" to start a service will not work, since the script will not be available. Use the more correct "/sbin/service foobar start" instead, and your command will be forwarded to systemd. Note that invoking the init script directly has always been suboptimal since too much of the caller's execution context (environment block, umask, resource limits, audit trails, ...) ended up being inherited by the service, and invocation via "/sbin/service" used to clean this up at least partially. Invocation via /sbin/service works on both SysV and systemd systems. Also, LSB only standardizes invocation via "/sbin/service" anyway. (Note that some distributions ship both systemd unit files and SysV scripts for the services. For these invoking the init scripts will work as expected and the request be forwarded to systemd in any case.)
* LSB header dependency information matters. The SysV implementations on many distributions did not use the dependency information encoded in LSB init script headers, or used them only in very limited ways. Due to that they are often incorrect or incomplete. systemd however fully interprets these headers and follows them closely at runtime (and not at installation time like some implementations).
* Timeouts apply to all init script operations in systemd. While on SysV systems a hanging init script could freeze the system on systemd all init script operations are subject to a timeout of 5min.
* Services are executed in completely clean execution contexts, no context of the invoking user session is inherited. Not even $HOME or similar are set. Init scripts depending on these will not work correctly.
* Services cannot read from stdin, as this will be connected to /dev/null. That means interactive init scripts are not supported (i.e. Debian's X-Interactive in the LSB header is not supported either.) Thankfully most distributions do not support interaction in init scripts anyway. If you need interaction to ask disk or SSL passphrases please consider using the minimal password querying framework systemd supports. ([details](/PASSWORD_AGENTS), [manual page](https://www.freedesktop.org/software/systemd/man/latest/systemd-ask-password.html))
* Additional verbs for init scripts are not supported. If your init script traditionally supported additional verbs for your init script simply move them to an auxiliary script.
* Additional parameters to the standard verbs (i.e. to "start", "stop" and "status") are not supported. This was an extension of SysV that never was standardized officially, and is not supported in systemd.
* Overriding the "restart" verb is not supported. This verb is always implemented by systemd itself, and consists of a "stop" followed by a "start".
* systemd only stops running services. On traditional SysV a K link installed for shutdown was executed when going down regardless whether the service was started before or not. systemd is more strict here and does not stop service that weren't started in the first place.
* Note that neither S nor K links for runlevels 0 and 6 have any effect. Running services will be terminated anyway when shutting down, and no new SysV services are started at shut down.
* If systemd doesn't know which PID is the main PID of a service, it will not be able to track its runtime, and hence a service exiting on its own will not make systemd consider it stopped. Use the Red Hat "pidfile:" syntax in the SysV script header comment block to let systemd know which PID file (and hence PID) belongs to your service. Note that systemd cannot know if a SysV service is one of the kind where the runtime is defined by a specific process or whether it is one where there is none, hence the requirement of explicit configuration of a PID file in order to make systemd track the process lifetime. (Note that the Red Hat "pidfile:" stanza may only appear once in init scripts.)
* Runlevels are supported in a limited fashion only. SysV runlevels are mapped to systemd target units, however not all systemd target units map back to SysV runlevels. This is due to the fact that systemd targets are a lot more flexible and expressive than SysV runlevels. That means that checks for the current runlevel (with /sbin/runlevel or so) may well return "N" (i.e. unknown runlevel) during normal operation. Scripts that rely on explicit runlevel checks are incompatible with many setups. Avoid runlevel checks like these.
* Tools like /sbin/chkconfig might return misleading information when used to list enablement status of services. First of all, the tool will only see SysV services, not native units. Secondly, it will only show runlevel-related information (which does not fully map to systemd targets). Finally, the information shown might be overridden by a native unit file.
* By default runlevels 2,3,4 are all aliases for "multi-user.target". If a service is enabled in one of these runlevels, they'll be enabled in all of these. This is only a default however, and users can easily override the mappings, and split them up into individual runlevels if they want. However, we recommend moving on from runlevels and using the much more expressive target units of systemd.
* Early boot runlevels as they are used by some distributions are no longer supported. i.e. "fake", distribution-specific runlevels such as "S" or "b" cannot be used with systemd.
* On SysV systems changes to init scripts or any other files that define the boot process (such as /etc/fstab) usually had an immediate effect on everything started later. This is different on systemd-based systems where init script information and other boot-time configuration files are only reread when "systemctl daemon-reload" is issued. (Note that some commands, notably "systemctl enable"/"systemctl disable" do this implicitly however.) This is by design, and a safety feature, since it ensures that half-completed changes are not read at the wrong time.
* Multiple entries for the same mount path in /etc/fstab are not supported. In systemd there's only a single unit definition for each mount path read at any time. Also the listing order of mounts in /etc/fstab has no effect, mounts are executed in parallel and dependencies between them generated automatically depending on path prefixes and source paths.
* systemd's handling of the existing "nofail" mount option in /etc/fstab is stricter than it used to be on some sysvinit distributions: mount points that fail and are not listed as "nofail" will cause the boot to be stopped, for security reasons, as we should not permit unprivileged code to run without everything listed — and not expressly exempted through "nofail" — being around. Hence, please mark all mounts where booting shall proceed regardless whether they succeeded or not with "nofail"
* Some SysV systems support an "rc.local" script that is supposed to be called "last" during boot. In systemd, the script is supported, but the semantics are less strict, as there is simply no concept of "last service", as the boot process is event- and request-based, parallelized and compositive. In general, it's a good idea to write proper unit files with properly defined dependencies, and avoid making use of rc.local.
* systemd assumes that the UID boundary between system and regular users is a choice the distribution makes, and not the administrator. Hence it expects this setting as compile-time option to be picked by the distribution. It will _not_ check /etc/login.defs during runtime.
