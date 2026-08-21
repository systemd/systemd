---
title: Mount Stacks
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Mount Stacks

*Intended audience: hackers working on `src/shared/mstack.c` and its callers.*

For the user-facing description of the on-disk format, see
[systemd.mstack(5)](https://www.freedesktop.org/software/systemd/man/systemd.mstack.html).
This document describes how a stack is turned into a mounted root, and — more importantly — *why*
the steps are in the order they are. Almost every apparent detour in `mstack.c` exists to satisfy a
kernel restriction that only shows up in one specific configuration, so the code reads as arbitrary
unless the restrictions are written down next to it.

## The data model

An `MStack` is an ordered list of `MStackMount` entries plus a little global state. Each entry has a
type, which determines both its role and its sort position:

| Type | Directory | Role |
|---|---|---|
| `MSTACK_ROOT` | `root/` | Bottom-most layer, or the whole root on its own |
| `MSTACK_LAYER` | `layer@*` | Read-only lower layers, stacked in sort-key order |
| `MSTACK_RW` | `rw/` | The writable upper layer; holds `data/` and `work/` |
| `MSTACK_TMPFS` | `tmpfs@*` | A fresh tmpfs mounted at a path on top |
| `MSTACK_BIND` | `bind@*` | Writable bind mount on top |
| `MSTACK_ROBIND` | `robind@*` | Read-only bind mount on top |

The first three take part in an overlayfs; the last three are attached *on top of* the assembled
root afterwards. `mstack_normalize()` sorts entries so this ordering is structural rather than
something each call site has to remember — `root/` sorts below every `layer@`, which is why the
assembly loop can simply walk the array backwards and hand layers to the kernel in the order it
wants them.

Two derived flags drive most branching: `has_overlayfs` (more than one stacked layer, so an overlay
is actually needed) and `has_tmpfs_root` (nothing persistent underneath, so the root is a throwaway
tmpfs).

## The pipeline

Assembly is four calls, deliberately separable so that callers can interleave their own work:

1. **`mstack_load()`** — parse a `.mstack/` directory into an `MStack`. No mounting.
2. **`mstack_open_images()`** — resolve each entry to a source fd, going through mountfsd when
   unprivileged.
3. **`mstack_make_mounts()`** — build the root as a *detached* mount, and hand it back as an fd.
   This is where the overlay is created and where all idmapping happens.
4. **`mstack_bind_mounts()`** — attach that root at its final location, then attach the entries that
   have to go on top of it.

`mstack_apply()` is all four in one, for callers with nothing to interleave.

The split between 3 and 4 is the important one. Everything in step 3 happens while the root is
detached and reachable only through an fd, because that is the only state in which the kernel allows
several of the operations involved. Step 4 is the first moment the tree is visible in a namespace.

### The deferred bind pass

`bind@`/`robind@`/`tmpfs@` entries are attached in a *second* pass, after the caller has mounted the
API VFS (`/proc`, `/sys`, `/dev`, …). If they went up during assembly, `mount_all()` would mount
straight over any entry targeting one of those paths, and the entry would silently vanish. Callers
request this with `MSTACK_DEFER_MOUNT` and then call `mstack_apply_bind_mounts_late()` themselves at
the right moment. (`mstack_apply_bind_mounts()` is the inner helper both phases share, taking an
already-open root fd and a `volatile_only` selector; a new caller wants the `_late()` wrapper.)

Mount points are resolved by `mstack_open_mount_point()`, which tries a strict resolution first and only
follows symlinks if that fails. The strict attempt is what guarantees a symlink-free target lands exactly
where the entry named it; the fallback is there because entries are routinely written against paths an
image redirects with a compatibility symlink. `chaseat()` resolves against the root fd throughout, so a
followed symlink can redirect within the container but never out of it, and the resolved path is logged
because the entry no longer describes where the mount went.

The exception is entries synthesized from `--volatile=` (`from_volatile`). Those only ever target
paths the root itself owns — `/var` — never an API VFS path, and they must go up during assembly so
that the root can be idmapped as one piece. The two sets are disjoint, so neither pass ever attaches
anything twice.

## Where --volatile= fits

`--volatile=` used to be a separate mechanism that mounted its own tmpfs over an already-assembled
root. It is now expressed as extra layers merged into an `MStack`, via `mstack_merge_volatile()`:

| Mode | Merged as |
|---|---|
| `yes` | tmpfs root, with `/usr/` extracted from the original root and re-attached read-only |
| `state` | original root read-only, plus a tmpfs at `/var` |
| `overlay` | original root as lower layer, plus a synthetic writable `rw` layer |

This means there are three ways an `MStack` comes into existence, and all three converge on the same
pipeline:

- `mstack_load()` — a real `.mstack/` directory (`--mstack=`).
- `mstack_new_from_root_fd()` — a plain `--directory=`/`--image=` root wrapped as a single-entry
  stack, so that `--volatile=` has something to merge into. This is the *synthetic* path.
- Either of the above, plus `mstack_merge_volatile()`.

Most of the subtlety in nspawn's integration comes from those two paths having different *identity*
models, which is the next section.

## Ownership: two different questions

There are two uid-shift values in play and conflating them is the single easiest mistake to make
here.

- **`uid_shift`** (argument to `mstack_make_mounts()`) means *"idmap the layers with this shift"*. It
  says nothing about who the payload will run as.
- **`mstack->tmpfs_uid_shift`** means *"the container's own root will actually run as this uid"*. It
  is set only when the caller implements the user namespace itself.

On the synthetic path with `--private-users=pick|fixed`, nspawn creates the userns, so both are set
and equal. On the `--mstack=` path the payload runs as real root — `--mstack=` is restricted to
managed userns or userns off — so `tmpfs_uid_shift` stays `UID_INVALID` even when a caller asks for
the layers to be idmapped.

An idmapped layer presents its on-disk owner 0 as `uid_shift`, i.e. as the container's root. That is
what makes an unshifted base image usable by a shifted container, and it is why the *read-only*
layers are idmapped.

The writable layer is deliberately **not** idmapped, and is chowned instead. See the next section for
why it cannot be idmapped; the consequence is that nothing shifts its ownership on the container's
behalf, so `data/` and `work/` are created and then chowned to `tmpfs_uid_shift`. Keying that chown
off `tmpfs_uid_shift` rather than `uid_shift` matters: where the payload runs as real root it writes
through the layer regardless, and chowning would be modifying ownership inside the caller's
persistent `rw/` directory to no purpose.

## Kernel restrictions that shape the code

Each of these is a case where the obvious ordering does not work. They are listed with the symptom,
because the symptom is usually not an error at the point of the mistake.

- **An assembled overlay cannot be idmapped.** `mount_setattr(MOUNT_ATTR_IDMAP)` on a merged overlay
  returns `EINVAL`. Only the individual layers can be idmapped, before they are merged — so the
  userns is acquired once and applied per layer, and the finished overlay inherits the mapping.

- **An idmapped mount refuses inode creation by a caller outside the mapped range** (`EOVERFLOW`) —
  our own unmapped credentials cannot be represented as a backing-store owner. This is why `data/`
  and `work/` are created on the *pre-clone source*, never through the clone that is about to be
  idmapped.

- **…except overlayfs does not fail the mount for it.** overlayfs creates a private `work/work`
  bookkeeping directory inside the workdir while materializing the superblock. If the workdir is
  idmapped, that creation fails — and the kernel *silently falls back to a read-only mount* rather
  than failing. Nothing notices, and the root is unusable for the container's whole lifetime. This
  is the reason the writable layer is never idmapped.

- **A mount that has had inodes created through it can no longer be idmapped** (`EINVAL`). Combined
  with the previous point, this pins creation and idmapping to opposite sides of the clone.

- **overlayfs insists `upperdir` be the root inode of its mount**, and `upperdir`/`workdir` be
  siblings on the same mount. `data/` and `work/` are subdirectories of the layer, so on a detached
  mount those two demands cannot both be met. Separately, `open_tree(OPEN_TREE_CLONE)` on a
  *subdirectory* of a detached mount is refused outright on some kernels. Attaching the mount
  somewhere, even momentarily, relaxes both — hence `mstack_attach_temporarily()`. Callers in a
  throwaway mount namespace can leave it attached; callers in their own namespace must
  `umount2(MNT_DETACH)` on every path.

  Do not assume a new enough kernel lifts this. Detached-mount support for overlayfs is usually
  dated to 6.14, but measured on 7.1.5: with every layer left detached the overlay fails at
  `FSCONFIG_CMD_CREATE` with EINVAL, for a writable stack and a read-only one alike, and attaching
  the upper alone is enough to make it succeed. Since at least one layer must be attached, and
  attaching needs a namespace to hide it in, the forked child cannot currently be skipped on any
  kernel we have tested. A probe that constructs the same sequence out of scratch tmpfs mounts
  reports that it *should* work, so it is not a reliable guide either — whatever the kernel objects
  to has not been identified.

- **`open_tree(OPEN_TREE_CLONE)` requires `CAP_SYS_ADMIN`.** Unprivileged callers get `EPERM`, which
  is why the unprivileged path goes through mountfsd instead, and why `test-mstack` skips the blocks
  that need real mounts.

- **Incremental `lowerdir+` is only partially back-ported on some kernels.** Every `fsconfig()` call
  succeeds and `FSCONFIG_CMD_CREATE` then fails with `EINVAL`. A retry on the same context returns
  `EBUSY`, so a genuinely fresh superblock is needed — which is why a second `fsopen()` is opened up
  front, before forking, and the layer fds are kept open for the joined-`lowerdir=` fallback.

- **Holding an fd to a mount pins it.** A later non-lazy `umount()` of that path fails with `EBUSY`,
  so `usr_extract_fd` is dropped immediately after the mount is attached.

## Code structure

The restrictions above are the reason this subsystem resists being read top to bottom: the ordering
is dictated by them rather than by the shape of the problem. The structure aims to keep each of them
visible at the point it applies, rather than as a rule you have to already know.

- **Model, no syscalls.** `mstack_load*()`, `mstack_normalize()`, `mstack_find()`,
  `mstack_has_writable_layers()` and friends operate purely on the entry list. Sorting is done once,
  centrally, so no call site re-derives layer order.
- **Source resolution.** `mstack_open_images()` turns entries into fds, and is the only place that
  knows whether we go direct or through mountfsd.
- **Per-layer preparation.** `mstack_overlay_builder_add()` takes one entry from source fd to a mount
  the overlay will accept, and hands it to the superblock in the role its type implies. Its inputs
  and the fds it produces travel in an `MStackOverlayBuilder` rather than as a parameter list. This
  is where the create-before-clone and idmap-before-attach orderings live.
- **Overlay orchestration.** `mstack_make_overlayfs()` keeps only what is genuinely about the
  overlay as a whole: acquiring the userns once, opening both superblocks, and forking the child that
  owns the temporary attachments. `mstack_overlay_assemble()` runs inside it and holds the layer loop
  and the `lowerdir+` → joined `lowerdir=` fallback.
- **Planning before doing.** `mstack_plan()` settles the root's shape, each layer's role and
  ownership treatment, and what needs backing, before anything is mounted — so execution reads
  answers instead of deriving them a second time, and the decisions can be asserted on with no
  privileges at all. `mstack_caps()` probes, once per process, the kernel behaviour that cannot be
  had from a version number.
- **Assembly and attachment.** `mstack_make_mounts()` produces a detached root; `mstack_bind_mounts()`
  and `mstack_apply_bind_mounts_late()` attach it and the entries that sit on top.

Everything the child does is in `mstack_overlay_assemble()`, which returns its errors normally; only
the child's outermost frame converts the result into `report_errno_and_exit()`. That split is what
keeps the assembly independent of being in a process it may throw away.

## Invariants worth checking

- Nothing is created through a mount that is going to be idmapped afterwards.
- The writable layer is never idmapped; its ownership comes from a chown.
- Every temporary attach has a matching detach, unless it is in a throwaway mount namespace.
- `from_volatile` entries go up during assembly; caller entries go up in the deferred pass; no entry
  is in both sets.
- A caller that lets mstack idmap the assembled root does not also remount it idmapped itself.

## Known gaps

- A writable `rw/` layer combined with a managed user namespace does not work: the layer arrives from
  mountfsd as a foreign-owned idmapped mount, so creating `data/` through it fails with `EPERM`
  before assembly gets anywhere. Reproduce with `--mstack=` and `--private-users=managed`.
- The pipe out of the forked `(layerfd)` child carries an errno and nothing else, so every one of its
  failure paths reaches the parent as the same bare error. Each one logs on the child's side first,
  which means `SYSTEMD_LOG_LEVEL=debug` is needed to tell them apart.
