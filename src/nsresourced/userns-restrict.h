/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

struct userns_restrict_bpf;

/* Bringing the policy up is split in two so that callers can seed the maps in between: the programs only
 * start enforcing once userns_restrict_attach() ran, and whatever they find in the maps at that point is
 * what they enforce from their very first invocation. Attaching first and filling the maps afterwards would
 * leave a window in which every namespace looks unmanaged and the policy fails open. Callers that only
 * manipulate the maps of an already running policy (i.e. the workers) stop after the install step. */
int userns_restrict_install(bool pin, struct userns_restrict_bpf **ret);
int userns_restrict_attach(struct userns_restrict_bpf *obj, bool pin);

struct userns_restrict_bpf *userns_restrict_bpf_free(struct userns_restrict_bpf *obj);

int userns_restrict_register_by_fd(struct userns_restrict_bpf *obj, int userns_fd);
int userns_restrict_register_by_inode(struct userns_restrict_bpf *obj, uint64_t userns_inode);

int userns_restrict_reset_by_inode(struct userns_restrict_bpf *obj, uint64_t userns_inode);

int userns_restrict_setgroups_deny_by_fd(struct userns_restrict_bpf *obj, int userns_fd);
int userns_restrict_setgroups_deny_by_inode(struct userns_restrict_bpf *obj, uint64_t userns_inode);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct userns_restrict_bpf*, userns_restrict_bpf_free);
