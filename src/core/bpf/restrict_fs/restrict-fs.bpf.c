/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

struct super_block {
        unsigned long int s_magic;
} __attribute__((preserve_access_index));

struct inode {
        struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
        struct inode *f_inode;
} __attribute__((preserve_access_index));

/*
 * max_entries is set from user space with the bpf_map__set_max_entries helper.
 * */
struct {
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __type(key, uint64_t);      /* cgroup ID */
        __type(value, uint32_t);    /* fs magic set */
} cgroup_hash SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(restrict_filesystems, struct file *file, int ret)
{
        unsigned long magic_number;
        uint64_t cgroup_id;
        uint32_t *value, *magic_map, zero = 0, *is_allow;

        /* ret is the return value from the previous BPF program or 0 if it's
         * the first hook */
        if (ret != 0)
                return ret;

        BPF_CORE_READ_INTO(&magic_number, file, f_inode, i_sb, s_magic);

        cgroup_id = bpf_get_current_cgroup_id();

        magic_map = bpf_map_lookup_elem(&cgroup_hash, &cgroup_id);
        if (!magic_map)
                return 0;

        is_allow = bpf_map_lookup_elem(magic_map, &zero);
        if (!is_allow)
                /* Malformed map, it doesn't include whether it's an allow list
                 * or a deny list. Allow. */
                return 0;

        if (*is_allow) {
                /* Allow-list: Allow access only if magic_number present in inner map */
                if (!bpf_map_lookup_elem(magic_map, &magic_number))
                        return -EPERM;
        } else {
                /* Deny-list: Allow access only if magic_number is not present in inner map */
                if (bpf_map_lookup_elem(magic_map, &magic_number))
                        return -EPERM;
        }

        return 0;
}

static const char _license[] SEC("license") = "GPL";
