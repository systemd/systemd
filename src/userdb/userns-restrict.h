/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "macro.h"

#if BPF_FRAMEWORK
#include "bpf/userns_restrict/userns-restrict-skel.h"
#endif

int userns_restrict_install(bool pin, struct userns_restrict_bpf **ret);
struct userns_restrict_bpf *userns_restrict_bpf_free(struct userns_restrict_bpf *obj);

int userns_restrict_put_by_fd(struct userns_restrict_bpf *obj, int userns_fd, bool replace, const int mount_fds[], size_t n_mount_fds);
int userns_restrict_put_by_inode(struct userns_restrict_bpf *obj, uint64_t userns_inode, bool replace, const int mount_fds[], size_t n_mount_fds);

int userns_restrict_reset_by_inode(struct userns_restrict_bpf *obj, uint64_t userns_inode);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct userns_restrict_bpf*, userns_restrict_bpf_free);
