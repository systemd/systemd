---
title: Control Group APIs and Delegation
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Control Group APIs and Delegation

*Intended audience: hackers working on userspace subsystems that require direct
cgroup access, such as container managers and similar.*

So you are wondering about resource management with systemd, you know Linux
control groups (cgroups) a bit and are trying to integrate your software with
what systemd has to offer there. Here's a bit of documentation about the
concepts and interfaces involved with this.

What's described here has been part of systemd and documented since v205
times. However, it has been updated and improved substantially, even
though the concepts stayed mostly the same. This is an attempt to provide more
comprehensive up-to-date information about all this, particular in light of the
poor implementations of the components interfacing with systemd of current
container managers.

Before you read on, please make sure you read the low-level kernel
documentation about the
[unified cgroup hierarchy](https://docs.kernel.org/admin-guide/cgroup-v2.html).
This document then adds in the higher-level view from systemd.

This document augments the existing documentation we already have:

* [The New Control Group Interfaces](/CONTROL_GROUP_INTERFACE)
* [Writing VM and Container Managers](/WRITING_VM_AND_CONTAINER_MANAGERS)

These wiki documents are not as up to date as they should be, currently, but
the basic concepts still fully apply. You should read them too, if you do something
with cgroups and systemd, in particular as they shine more light on the various
D-Bus APIs provided. (That said, sooner or later we should probably fold that
wiki documentation into this very document, too.)

## Two Key Design Rules

Much of the philosophy behind these concepts is based on a couple of basic
design ideas of cgroup v2. Specifically two cgroup v2 rules are the most relevant:

1. The **no-processes-in-inner-nodes** rule: this means that it's not permitted
to have processes directly attached to a cgroup that also has child cgroups and
vice versa. A cgroup is either an inner node or a leaf node of the tree, and if
it's an inner node it may not contain processes directly, and if it's a leaf
node then it may not have child cgroups. (Note that there are some minor
exceptions to this rule, though. E.g. the root cgroup is special and allows
both processes and children — which is used in particular to maintain kernel
threads.)

2. The **single-writer** rule: this means that each cgroup only has a single
writer, i.e. a single process managing it. It's OK if different cgroups have
different processes managing them. However, only a single process should own a
specific cgroup, and when it does that ownership is exclusive, and nothing else
should manipulate it at the same time. This rule ensures that various pieces of
software don't step on each other's toes constantly.

These two rules have various effects. For example, one corollary of this is: if
your container manager creates and manages cgroups in the system's root cgroup
you violate rule #2, as the root cgroup is managed by systemd and hence off
limits to everybody else.

Note that rule #1 is generally enforced by the kernel if cgroup v2 is used: as
soon as you add a process to a cgroup it is ensured the rule is not
violated. On cgroup v1 this rule didn't exist, and hence isn't enforced, even
though it's a good thing to follow it then too. Rule #2 is not enforced on
either cgroup v1 nor cgroup v2 (this is UNIX after all, in the general case
root can do anything, modulo SELinux and friends), but if you ignore it you'll
be in constant pain as various pieces of software will fight over cgroup
ownership.

Note that cgroup v1 is semantically broken in many ways, and in many cases doesn't
actually do what people think it does. cgroup v2 is where things are going, and
new kernel features in this area are only added to cgroup v2, and not cgroup v1
anymore. For example, cgroup v2 provides proper cgroup-empty notifications, has
support for all kinds of per-cgroup BPF magic, supports secure delegation of
cgroup trees to less privileged processes and so on, which all are not
available on cgroup v1.

## Hierarchy and Controller Support

systemd supports what's called **unified** hierarchy, which is a simply mode
that exposes a pure cgroup v2 logic. In this mode `/sys/fs/cgroup/` is the only
mounted cgroup API file system and all available controllers are exclusively
exposed through it.

systemd supports a number of controllers (but not all). Specifically, supported
are: `cpu`, `io`, `memory`, `pids`. It is our intention to natively support all
cgroup v2 controllers as they are added to the kernel.

The following hierarchies were deprecated in v256, and eventually got removed
in v258:

* **Legacy** — this is the traditional cgroup v1 mode. In this mode the
various controllers each get their own cgroup file system mounted to
`/sys/fs/cgroup/<controller>/`. On top of that systemd manages its own cgroup
hierarchy for managing purposes as `/sys/fs/cgroup/systemd/`.

* **Hybrid** — this is a hybrid between the unified and legacy mode. It's set
up mostly like legacy, except that there's also an additional hierarchy
`/sys/fs/cgroup/unified/` that contains the cgroup v2 hierarchy. (Note that in
this mode the unified hierarchy won't have controllers attached, the
controllers are all mounted as separate hierarchies as in legacy mode,
i.e. `/sys/fs/cgroup/unified/` is purely and exclusively about core cgroup v2
functionality and not about resource management.) In this mode compatibility
with cgroup v1 is retained while some cgroup v2 features are available
too. This mode is a stopgap. Don't bother with this too much unless you have
too much free time.

## systemd's Unit Types

The low-level kernel cgroups feature is exposed in systemd in three different
"unit" types. Specifically:

1. 💼 The `.service` unit type. This unit type is for units encapsulating
   processes systemd itself starts. Units of these types have cgroups that are
   the leaves of the cgroup tree the systemd instance manages (though possibly
   they might contain a sub-tree of their own managed by something else, made
   possible by the concept of delegation, see below). Service units are usually
   instantiated based on a unit file on disk that describes the command line to
   invoke and other properties of the service. However, service units may also
   be declared and started programmatically at runtime through a D-Bus API
   (which is called *transient* services).

2. 👓 The `.scope` unit type. This is very similar to `.service`. The main
   difference: the processes the units of this type encapsulate are forked off
   by some unrelated manager process, and that manager asked systemd to expose
   them as a unit. Unlike services, scopes can only be declared and started
   programmatically, i.e. are always transient. That's because they encapsulate
   processes forked off by something else, i.e. existing runtime objects, and
   hence cannot really be defined fully in 'offline' concepts such as unit
   files.

3. 🔪 The `.slice` unit type. Units of this type do not directly contain any
   processes. Units of this type are the inner nodes of part of the cgroup tree
   the systemd instance manages. Much like services, slices can be defined
   either on disk with unit files or programmatically as transient units.

Slices expose the trunk and branches of a tree, and scopes and services are
attached to those branches as leaves. The idea is that scopes and services can
be moved around though, i.e. assigned to a different slice if needed.

The naming of slice units directly maps to the cgroup tree path. This is not
the case for service and scope units however. A slice named `foo-bar-baz.slice`
maps to a cgroup `/foo.slice/foo-bar.slice/foo-bar-baz.slice/`. A service
`quux.service` which is attached to the slice `foo-bar-baz.slice` maps to the
cgroup `/foo.slice/foo-bar.slice/foo-bar-baz.slice/quux.service/`.

By default systemd sets up four slice units:

1. `-.slice` is the root slice. i.e. the parent of everything else. On the host
   system it maps directly to the top-level directory of cgroup v2.

2. `system.slice` is where system services are by default placed, unless
   configured otherwise.

3. `user.slice` is where user sessions are placed. Each user gets a slice of
   its own below that.

4. `machines.slice` is where VMs and containers are supposed to be
   placed. `systemd-nspawn` makes use of this by default, and you're very welcome
   to place your containers and VMs there too if you hack on managers for those.

Users may define any amount of additional slices they like though, the four
above are just the defaults.

## Delegation

Container managers and suchlike often want to control cgroups directly using
the raw kernel APIs. That's entirely fine and supported, as long as proper
*delegation* is followed. Delegation is a concept we inherited from cgroup v2.
It means that some parts of the cgroup tree may be managed by different managers
than others. As long as it is clear which manager manages which part of the tree
each one can do within its sub-graph of the tree whatever it wants.

Only sub-trees can be delegated (though whoever decides to request a sub-tree
can delegate sub-sub-trees further to somebody else if they like). Delegation
takes place at a specific cgroup: in systemd there's a `Delegate=` property you
can set for a service or scope unit. If you do, it's the cut-off point for
systemd's cgroup management: the unit itself is managed by systemd, i.e. all
its attributes are managed exclusively by systemd, however your program may
create/remove sub-cgroups inside it freely, and those then become exclusive
property of your program, systemd won't touch them — all attributes of *those*
sub-cgroups can be manipulated freely and exclusively by your program.

By turning on the `Delegate=` property for a scope or service you get a few
guarantees:

1. systemd won't fiddle with your sub-tree of the cgroup tree anymore. It won't
   change attributes of any cgroups below it, nor will it create or remove any
   cgroups thereunder, nor migrate processes across the boundaries of that
   sub-tree as it deems useful anymore.

2. If your service makes use of the `User=` functionality, then the sub-tree
   will be `chown()`ed to the indicated user so that it can correctly create
   cgroups below it.

3. Any BPF IP filter programs systemd installs will be installed with
   `BPF_F_ALLOW_MULTI` so that your program can install additional ones.

In unit files the `Delegate=` property is superficially exposed as
boolean. However, since v236 it optionally takes a list of controller names
instead. If so, delegation is requested for listed controllers
specifically. Note that this only encodes a request. Depending on various
parameters it might happen that your service actually will get fewer
controllers delegated (for example, because the controller is not available on
the current kernel or was turned off) or more.  If no list is specified
(i.e. the property simply set to `yes`) then all available controllers are
delegated.

Let's stress one thing: delegation is available on scope and service units
only. It's expressly not available on slice units. Why? Because slice units are
our *inner* nodes of the cgroup trees and we freely attach services and scopes
to them. If we'd allow delegation on slice units then this would mean that
both systemd and your own manager would create/delete cgroups below the slice
unit and that conflicts with the single-writer rule.

So, if you want to do your own raw cgroups kernel level access, then allocate a
scope unit, or a service unit (or just use the service unit you already have
for your service code), and turn on delegation for it.

The service manager sets the `user.delegate` extended attribute (readable via
`getxattr(2)` and related calls) to the character `1` on cgroup directories
where delegation is enabled (and removes it on those cgroups where it is
not). This may be used by service programs to determine whether a cgroup tree
was delegated to them. Note that this is only supported on kernels 5.6 and
newer in combination with systemd 251 and newer.

(OK, here's one caveat: if you turn on delegation for a service, and that
service has `ExecStartPost=`, `ExecReload=`, `ExecStop=` or `ExecStopPost=`
set, then these commands will be executed within the `.control/` sub-cgroup of
your service's cgroup. This is necessary because by turning on delegation we
have to assume that the cgroup delegated to your service is now an *inner*
cgroup, which means that it may not directly contain any processes. Hence, if
your service has any of these four settings set, you must be prepared that a
`.control/` subcgroup might appear, managed by the service manager. This also
means that your service code should have moved itself further down the cgroup
tree by the time it notifies the service manager about start-up readiness, so
that the service's main cgroup is definitely an inner node by the time the
service manager might start `ExecStartPost=`. Starting with systemd 254 you may
also use `DelegateSubgroup=` to let the service manager put your initial
service process into a subgroup right away.)

(Also note, if you intend to use "threaded" cgroups — as added in Linux 4.14 —,
then you should do that *two* levels down from the main service cgroup your
turned delegation on for. Why that? You need one level so that systemd can
properly create the `.control` subgroup, as described above. But that one
cannot be threaded, since that would mean `.control` has to be threaded too —
this is a requirement of threaded cgroups: either a cgroup and all its siblings
are threaded or none –, but systemd expects it to be a regular cgroup. Thus you
have to nest a second cgroup beneath it which then can be threaded.)

Finally, if you turn on cgroup delegation with `Delegate=yes`, systemd will make
the requested controllers available to your service or scope, but won't actually
enable them. Currently you have to do that manually by writing to
`cgroup.subtree_control` within your delegated cgroup (e.g. write `+memory` to
enable the memory controller).

## Three Scenarios

Let's say you write a container manager, and you wonder what to do regarding
cgroups for it, as you want your manager to be able to run on systemd systems.

You basically have three options:

1. 😊 The *integration-is-good* option. For this, you register each container
   you have either as a systemd service (i.e. let systemd invoke the executor
   binary for you) or a systemd scope (i.e. your manager executes the binary
   directly, but then tells systemd about it. In this mode the administrator
   can use the usual systemd resource management and reporting commands
   individually on those containers. By turning on `Delegate=` for these scopes
   or services you make it possible to run cgroup-enabled programs in your
   containers, for example a nested systemd instance. This option has two
   sub-options:

   a. You transiently register the service or scope by directly contacting
      systemd via D-Bus. In this case systemd will just manage the unit for you
      and nothing else.

   b. Instead you register the service or scope through `systemd-machined`
      (also via D-Bus). This mini-daemon is basically just a proxy for the same
      operations as in a. The main benefit of this: this way you let the system
      know that what you are registering is a container, and this opens up
      certain additional integration points. For example, `journalctl -M` can
      then be used to directly look into any container's journal logs (should
      the container run systemd inside), or `systemctl -M` can be used to
      directly invoke systemd operations inside the containers. Moreover tools
      like "ps" can then show you to which container a process belongs (`ps -eo
      pid,comm,machine`), and even gnome-system-monitor supports it.

2. 🙁 The *i-like-islands* option. If all you care about is your own cgroup tree,
   and you want to have to do as little as possible with systemd and no
   interest in integration with the rest of the system, then this is a valid
   option. For this all you have to do is turn on `Delegate=` for your main
   manager daemon. Then figure out the cgroup systemd placed your daemon in:
   you can now freely create sub-cgroups beneath it. Don't forget the
   *no-processes-in-inner-nodes* rule however: you have to move your main
   daemon process out of that cgroup (and into a sub-cgroup) before you can
   start further processes in any of your sub-cgroups.

3. 🙁 The *i-like-continents* option. In this option you'd leave your manager
   daemon where it is, and would not turn on delegation on its unit. However,
   as you start your first managed process (a container, for example) you would
   register a new scope unit with systemd, and that scope unit would have
   `Delegate=` turned on, and it would contain the PID of this process; all
   your managed processes subsequently created should also be moved into this
   scope. From systemd's PoV there'd be two units: your manager service and the
   big scope that contains all your managed processes in one.

BTW: if for whatever reason you say "I hate D-Bus, I'll never call any D-Bus
API, kthxbye", then options #1 and #3 are not available, as they generally
involve talking to systemd from your program code, via D-Bus. You still have
option #2 in that case however, as you can simply set `Delegate=` in your
service's unit file and you are done and have your own sub-tree. In fact, #2 is
the one option that allows you to completely ignore systemd's existence: you
can entirely generically follow the single rule that you just use the cgroup
you are started in, and everything below it, whatever that might be. That said,
maybe if you dislike D-Bus and systemd that much, the better approach might be
to work on that, and widen your horizon a bit. You are welcome.

## systemd as Container Payload

systemd can happily run as a container payload's PID 1. Note that systemd
unconditionally needs write access to the cgroup tree however, hence you need
to delegate a sub-tree to it. Note that there's nothing too special you have to
do beyond that: just invoke systemd as PID 1 inside the root of the delegated
cgroup sub-tree, and it will figure out the rest: it will determine the cgroup
it is running in and take possession of it. It won't interfere with any cgroup
outside of the sub-tree it was invoked in. Use of `CLONE_NEWCGROUP` is hence
optional (but of course wise).

Note one particular asymmetry here though: systemd will try to take possession
of the root cgroup you pass to it *in* *full*, i.e. it will not only
create/remove child cgroups below it, it will also attempt to manage the
attributes of it. OTOH as mentioned above, when delegating a cgroup tree to
somebody else it only passes the rights to create/remove sub-cgroups, but will
insist on managing the delegated cgroup tree's top-level attributes. Or in
other words: systemd is *greedy* when accepting delegated cgroup trees and also
*greedy* when delegating them to others: it insists on managing attributes on
the specific cgroup in both cases. A container manager that is itself a payload
of a host systemd which wants to run a systemd as its own container payload
instead hence needs to insert an extra level in the hierarchy in between, so
that the systemd on the host and the one in the container won't fight for the
attributes. That said, you likely should do that anyway, due to the
no-processes-in-inner-cgroups rule, see below.

When systemd runs as container payload it will make use of all hierarchies it
has write access to. For legacy mode you need to make at least
`/sys/fs/cgroup/systemd/` available, all other hierarchies are optional. For
hybrid mode you need to add `/sys/fs/cgroup/unified/`. Finally, for fully
unified you (of course, I guess) need to provide only `/sys/fs/cgroup/` itself.

## Some Dos

1. ⚡ If you go for implementation option 1a or 1b (as in the list above), then
   each of your containers will have its own systemd-managed unit and hence
   cgroup with possibly further sub-cgroups below. Typically the first process
   running in that unit will be some kind of executor program, which will in
   turn fork off the payload processes of the container. In this case don't
   forget that there are two levels of delegation involved: first, systemd
   delegates a group sub-tree to your executor. And then your executor should
   delegate a sub-tree further down to the container payload. Oh, and because
   of the no-process-in-inner-nodes rule, your executor needs to migrate itself
   to a sub-cgroup of the cgroup it got delegated, too. Most likely you hence
   want a two-pronged approach: below the cgroup you got started in, you want
   one cgroup maybe called `supervisor/` where your manager runs in and then
   for each container a sibling cgroup of that maybe called `payload-xyz/`.

2. ⚡ Don't forget that the cgroups you create have to have names that are
   suitable as UNIX file names, and that they live in the same namespace as the
   various kernel attribute files. Hence, when you want to allow the user
   arbitrary naming, you might need to escape some of the names (for example,
   you really don't want to create a cgroup named `tasks`, just because the
   user created a container by that name, because `tasks` after all is a magic
   attribute in cgroup v1, and your `mkdir()` will hence fail with `EEXIST`. In
   systemd we do escaping by prefixing names that might collide with a kernel
   attribute name with an underscore. You might want to do the same, but this
   is really up to you how you do it. Just do it, and be careful.

## Some Don'ts

1. 🚫 Never create your own cgroups below arbitrary cgroups systemd manages, i.e
   cgroups you haven't set `Delegate=` in. Specifically: 🔥 don't create your
   own cgroups below the root cgroup 🔥. That's owned by systemd, and you will
   step on systemd's toes if you ignore that, and systemd will step on
   yours. Get your own delegated sub-tree, you may create as many cgroups there
   as you like. Seriously, if you create cgroups directly in the cgroup root,
   then all you do is ask for trouble.

2. 🚫 Don't attempt to set `Delegate=` in slice units, and in particular not in
   `-.slice`. It's not supported, and will generate an error.

3. 🚫 Never *write* to any of the attributes of a cgroup systemd created for
   you. It's systemd's private property. You are welcome to manipulate the
   attributes of cgroups you created in your own delegated sub-tree, but the
   cgroup tree of systemd itself is out of limits for you. It's fine to *read*
   from any attribute you like however. That's totally OK and welcome.

4. 🚫 When not using `CLONE_NEWCGROUP` when delegating a sub-tree to a
   container payload running systemd, then don't get the idea that you can bind
   mount only a sub-tree of the host's cgroup tree into the container. Part of
   the cgroup API is that `/proc/$PID/cgroup` reports the cgroup path of every
   process, and hence any path below `/sys/fs/cgroup/` needs to match what
   `/proc/$PID/cgroup` of the payload processes reports. What you can do safely
   however, is mount the upper parts of the cgroup tree read-only (or even
   replace the middle bits with an intermediary `tmpfs` — but be careful not to
   break the `statfs()` detection logic discussed above), as long as the path
   to the delegated sub-tree remains accessible as-is.

5. ⚡ Currently, the algorithm for mapping between slice/scope/service unit
   naming and their cgroup paths is not considered public API of systemd, and
   may change in future versions. This means: it's best to avoid implementing a
   local logic of translating cgroup paths to slice/scope/service names in your
   program, or vice versa — it's likely going to break sooner or later. Use the
   appropriate D-Bus API calls for that instead, so that systemd translates
   this for you. (Specifically: each Unit object has a `ControlGroup` property
   to get the cgroup for a unit. The method `GetUnitByControlGroup()` may be
   used to get the unit for a cgroup.)

And that's it for now. If you have further questions, refer to the systemd
mailing list.

— Berlin, 2018-04-20
