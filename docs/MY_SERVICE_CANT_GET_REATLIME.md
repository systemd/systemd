---
title: My Service Can't Get Realtime!
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# My Service Can't Get Realtime!

_So, you have a service that requires real-time scheduling.
When you run this service on your systemd system it is unable to acquire real-time scheduling,
even though it is full root and has all possible privileges.
And now you are wondering what is going on and what you can do about it?_

## What is Going on?

By default systemd places all system services into their own control groups in the "cpu" hierarchy.
This has the benefit that the CPU usage of services with many worker threads or processes
(think: Apache with all its gazillion CGIs and stuff)
gets roughly the same amount of CPU as a service with very few worker threads (think: MySQL).
Instead of evening out CPU _per process_ this will cause CPU to be evened out _per service_.

Now, the "cpu" cgroup controller of the Linux kernel has one major shortcoming:
if a cgroup is created it needs an explicit, absolute RT time budget assigned,
or otherwise RT is not available to any process in the group, and an attempt to acquire it will fail with EPERM.
systemd will not assign any RT time budgets to the "cpu" cgroups it creates,
simply because there is no feasible way to do that,
since the budget needs to be specified in absolute time units and comes from a fixed pool.
Or in other words: we'd love to assign a budget, but there are no sane values we could use.
Thus, in its default configuration RT scheduling is simply not available for any system services.

## Working Around the Issue

Of course, that's quite a limitation, so here's how you work around this:

* One option is to simply globally turn off that systemd creates a "cpu" cgroup for each of the system services.
For that, edit `/etc/systemd/system.conf` and set `DefaultControllers=` to the empty string, then reboot.
(An alternative is to disable the "cpu" controller in your kernel, entirely.
systemd will not attempt to make use of controllers that aren't available in the kernel.)
* Another option is to turn this off for the specific service only.
For that, edit your service file, and add `ControlGroup=cpu:/` to its `[Service]` section.
This overrides the default logic for this one service only,
and places all its processes back in the root cgroup of the "cpu" hierarchy, which has the full RT budget assigned.
* A third option is to simply assign your service a realtime budget.
For that use `ControlGroupAttribute=cpu.rt_runtime_us 500000` in its `[Service]` or suchlike.
See [the kernel documentation](http://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt) for details.
The latter two options are not available for System V services.
A possible solution is to write a small wrapper service file that simply calls the SysV script's start verb in `ExecStart=` and the stop verb in `ExecStop=`.
(It also needs to set `RemainAfterExit=1` and `Type=forking`!)

Note that this all only applies to services.
By default, user applications run in the root cgroup of the "cpu" hierarchy, which avoids these problems for normal user applications.

In the long run we hope that the kernel is fixed to not require an RT budget to be assigned for any cgroup created before a process can acquire RT (i.e. a process' RT budget should be derived from the nearest ancestor cgroup which has a budget assigned, rather than unconditionally its own uninitialized budget.)
Ideally, we'd also like to create a per-user cgroup by default, so that users with many processes get roughly the same amount of CPU as users with very few.
