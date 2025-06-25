/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

/* If offsetof() is implemented via __builtin_offset() then it doesn't work on current compilers, since the
 * built-ins do not understand CO-RE. Let's undefine any such macros here, to force bpf_helpers.h to define
 * its own definitions for this. (In new versions it will do so automatically, but at least in libbpf 1.1.0
 * it does not.) */
#undef offsetof
#undef container_of

#include "vmlinux.h"

#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef bpf_core_cast
/* bpf_rdonly_cast() was introduced in libbpf commit 688879f together with
 * the definition of a bpf_core_cast macro. So use that one to avoid
 * defining a prototype for bpf_rdonly_cast */
void* bpf_rdonly_cast(const void *, __u32) __ksym;
#endif

/* BPF module that implements an allowlist of mounts (identified by mount ID) for user namespaces (identified
 * by their inode number in nsfs) that restricts creation of inodes (which would inherit the callers UID/GID)
 * or changing of ownership (similar).
 *
 * This hooks into the various path-based LSM entrypoints that control inode creation as well as chmod(), and
 * then looks up the calling process' user namespace in a global map of namespaces, which points us to
 * another map that is simply a list of allowed mnt_ids. */

// FIXME: ACL adjustments are currently not blocked. There's no path-based LSM hook available in the kernel
// for setting xattrs or ACLs, hence we cannot easily block them, even though we want that. We can get away
// with ignoring this for now, as ACLs never define ownership, but purely access: i.e. ACLs never allow
// taking possession of an object, but only control access to it. Thus, things like suid access modes should
// not be reachable through it. It still sucks though that a user can persistently add an ACL entry to a file
// with their transient UIDs/GIDs.

/* kernel currently enforces a maximum usernamespace nesting depth of 32, see create_user_ns() in the kernel sources */
#define USER_NAMESPACE_DEPTH_MAX 32U

struct mnt_id_map {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1);        /* placeholder, configured otherwise by nsresourced */
        __type(key, int);
        __type(value, int);
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __uint(max_entries, 1);        /* placeholder, configured otherwise by nsresourced */
        __type(key, unsigned);         /* userns inode */
        __array(values, struct mnt_id_map);
} userns_mnt_id_hash SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 4096);
} userns_ringbuf SEC(".maps");

static inline struct mount *real_mount(struct vfsmount *mnt) {
        return container_of(mnt, struct mount, mnt);
}

static int validate_inode_on_mount(struct inode *inode, struct vfsmount *v) {
        struct user_namespace *mount_userns, *task_userns, *p;
        unsigned task_userns_inode;
        struct task_struct *task;
        void *mnt_id_map;
        struct mount *m;
        int mnt_id;

        /* Get user namespace from vfsmount */
        m = bpf_rdonly_cast(real_mount(v), bpf_core_type_id_kernel(struct mount));
        mount_userns = m->mnt_ns->user_ns;

        /* Get user namespace from task */
        task = (struct task_struct*) bpf_get_current_task_btf();
        task_userns = task->cred->user_ns;

        /* Is the file on a mount that belongs to our own user namespace or a child of it? If so, say
         * yes immediately. */
        p = mount_userns;
        for (unsigned i = 0; i < USER_NAMESPACE_DEPTH_MAX; i++) {
                if (p == task_userns)
                        return 0; /* our task's user namespace (or a child thereof) owns this superblock: allow! */

                p = p->parent;
                if (!p)
                        break;
        }

        /* Hmm, something is fishy if there's more than 32 levels of namespaces involved. Let's better be
         * safe than sorry, and refuse. */
        if (p)
                return -EPERM;

        /* This is a mount foreign to our task's user namespace, let's consult our allow list */
        task_userns_inode = task_userns->ns.inum;

        mnt_id_map = bpf_map_lookup_elem(&userns_mnt_id_hash, &task_userns_inode);
        if (!mnt_id_map) /* No rules installed for this userns? Then say yes, too! */
                return 0;

        mnt_id = m->mnt_id;

        /* Otherwise, say yes if the mount ID is allowlisted */
        if (bpf_map_lookup_elem(mnt_id_map, &mnt_id))
                return 0;

        return -EPERM;
}

static int validate_path(const struct path *path, int ret) {
        struct inode *inode;
        struct vfsmount *v;

        if (ret != 0) /* propagate earlier error */
                return ret;

        inode = path->dentry->d_inode;
        v = path->mnt;

        return validate_inode_on_mount(inode, v);
}

SEC("lsm/path_chown")
int BPF_PROG(userns_restrict_path_chown, struct path *path, void* uid, void *gid, int ret) {
        return validate_path(path, ret);
}

SEC("lsm/path_mkdir")
int BPF_PROG(userns_restrict_path_mkdir, struct path *dir, struct dentry *dentry, umode_t mode, int ret) {
        return validate_path(dir, ret);
}

SEC("lsm/path_mknod")
int BPF_PROG(userns_restrict_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned dev, int ret) {
        return validate_path(dir, ret);
}

SEC("lsm/path_symlink")
int BPF_PROG(userns_restrict_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name, int ret) {
        return validate_path(dir, ret);
}

SEC("lsm/path_link")
int BPF_PROG(userns_restrict_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, int ret) {
        return validate_path(new_dir, ret);
}

SEC("kprobe/free_user_ns")
void BPF_KPROBE(userns_restrict_free_user_ns, struct work_struct *work) {
        struct user_namespace *userns;
        unsigned inode;
        void *mnt_id_map;

        /* Inform userspace that a user namespace just went away. I wish there was a nicer way to hook into
         * user namespaces being deleted than using kprobes, but couldn't find any. */

        userns = bpf_rdonly_cast(container_of(work, struct user_namespace, work),
                                 bpf_core_type_id_kernel(struct user_namespace));

        inode = userns->ns.inum;

        mnt_id_map = bpf_map_lookup_elem(&userns_mnt_id_hash, &inode);
        if (!mnt_id_map) /* No rules installed for this userns? Then send no notification. */
                return;

        bpf_ringbuf_output(&userns_ringbuf, &inode, sizeof(inode), 0);
}

static const char _license[] SEC("license") = "GPL";
