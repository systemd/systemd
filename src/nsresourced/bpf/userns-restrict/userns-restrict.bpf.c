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

#define CONTAINER_UID_MIN ((uid_t) CONTAINER_UID_BASE_MIN)
#define CONTAINER_UID_MAX ((uid_t) CONTAINER_UID_BASE_MAX + 0xFFFFU)

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
 * This hooks into the various path-based LSM entrypoints that control inode creation as well as chown(), and
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
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1);        /* placeholder, configured otherwise by nsresourced */
        __type(key, unsigned);         /* userns inode */
        __type(value, int);            /* dummy value */
} userns_setgroups_deny SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 4096);
} userns_ringbuf SEC(".maps");

static inline struct mount *real_mount(struct vfsmount *mnt) {
        return container_of(mnt, struct mount, mnt);
}

static inline bool uid_is_dynamic(uid_t uid) {
        return DYNAMIC_UID_MIN <= uid && uid <= DYNAMIC_UID_MAX;
}

static inline bool uid_is_container(uid_t uid) {
        return CONTAINER_UID_MIN <= uid && uid <= CONTAINER_UID_MAX;
}

static inline bool uid_is_transient(uid_t uid) {
        return uid_is_dynamic(uid) || uid_is_container(uid);
}

static int userns_owns_mount(struct user_namespace *userns, struct vfsmount *v) {
        struct user_namespace *mount_userns, *p;
        struct mount *m;

        /* Get user namespace from vfsmount */
        m = bpf_rdonly_cast(real_mount(v), bpf_core_type_id_kernel(struct mount));
        mount_userns = m->mnt_ns->user_ns;

        p = mount_userns;
        for (unsigned i = 0; i < USER_NAMESPACE_DEPTH_MAX; i++) {
                if (p == userns)
                        return true;

                p = p->parent;
                if (!p)
                        break;
        }

        /* Hmm, something is fishy if there's more than 32 levels of namespaces involved. Let's better be
         * safe than sorry, and refuse. */
        if (p)
                return -EPERM;

        return false;
}

static int validate_mount(struct vfsmount *v, int ret) {
        struct user_namespace *task_userns;
        unsigned task_userns_inode;
        struct task_struct *task;
        void *mnt_id_map;
        struct mount *m;
        int mnt_id, r;

        if (ret != 0) /* propagate earlier error */
                return ret;

        /* Get user namespace from task */
        task = (struct task_struct*) bpf_get_current_task_btf();
        task_userns = task->cred->user_ns;

        /* fsuid/fsgid are the UID/GID in the initial user namespace, before any idmapped mounts have been
         * applied. There is no way (yet) to figure out what the UID/GID that will be written to disk will be
         * after idmapped mounts are taken into account, hence we have to rely on an allowlist of mounts
         * populated by userspace which tells us if a mount has an appropriate uid mapping in place to
         * translate the transient UID range to something else. For other UIDs/GIDs, there's no need to do
         * these checks as we don't insist on idmapped mounts or such for UIDs/GIDs outside the transient
         * ranges. */
        if (!uid_is_transient(task->cred->fsuid.val) && !uid_is_transient((uid_t) task->cred->fsgid.val))
                return 0;

        r = userns_owns_mount(task_userns, v);
        if (r < 0)
                return r;
        /* Is the file on a mount that belongs to our own user namespace or a child of it? If so, say
         * yes immediately. */
        if (r > 0)
                return 0;

        /* This is a mount foreign to our task's user namespace, let's consult our allow list */
        task_userns_inode = task_userns->ns.inum;

        mnt_id_map = bpf_map_lookup_elem(&userns_mnt_id_hash, &task_userns_inode);
        if (!mnt_id_map) /* No rules installed for this userns? Then say yes, too! */
                return 0;

        m = bpf_rdonly_cast(real_mount(v), bpf_core_type_id_kernel(struct mount));
        mnt_id = m->mnt_id;

        /* Otherwise, say yes if the mount ID is allowlisted */
        if (bpf_map_lookup_elem(mnt_id_map, &mnt_id))
                return 0;

        return -EPERM;
}

SEC("lsm/path_chown")
int BPF_PROG(userns_restrict_path_chown, struct path *path, unsigned long long uid, unsigned long long gid, int ret) {
        struct user_namespace *task_userns;
        unsigned task_userns_inode;
        struct task_struct *task;
        struct vfsmount *v;
        void *mnt_id_map;
        int r;

        if (ret != 0) /* propagate earlier error */
                return ret;

        /* Get user namespace from task */
        task = (struct task_struct*) bpf_get_current_task_btf();
        task_userns = task->cred->user_ns;
        v = path->mnt;

        r = userns_owns_mount(task_userns, v);
        if (r < 0)
                return r;
        /* Is the file on a mount that belongs to our own user namespace or a child of it? If so, say
         * yes immediately. */
        if (r > 0)
                return 0;

        /* This is a mount foreign to our task's user namespace, if the user namespace was provisioned by
         * nsresourced, refuse any UIDs/GIDs in the transient ranges. Note that we can only do this check in
         * the chown() hook because it receives the UID/GID with idmapped mounts already taken into account,
         * unlike the other hooks where we cannot (yet) figure out the UID/GID after idmapped mounts are
         * applied. Hence in the other hooks we have to rely on the mount allowlist to ensure the transient
         * fsuid/fsgid will be translated to something else when written to disk but in the chown() hook we
         * can check the provided UID/GID directly to see if it is transient or not. */

        /* User namespaces that were not provisioned by nsresourced can still write to the transient ranges
         * so that we don't break use cases like systemd-nspawn's --private-users=pick switch. */

        task_userns_inode = task_userns->ns.inum;

        mnt_id_map = bpf_map_lookup_elem(&userns_mnt_id_hash, &task_userns_inode);
        if (!mnt_id_map) /* No rules installed for this userns? Then say yes, too! */
                return 0;

        if (uid_is_transient((uid_t) uid) || uid_is_transient((uid_t) gid))
                return -EPERM;

        return 0;
}

SEC("lsm/path_mkdir")
int BPF_PROG(userns_restrict_path_mkdir, struct path *dir, struct dentry *dentry, umode_t mode, int ret) {
        return validate_mount(dir->mnt, ret);
}

/* The mknod hook covers all file creations, including regular files, in case the reader is looking for a
 * missing hook for open(). */
SEC("lsm/path_mknod")
int BPF_PROG(userns_restrict_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned dev, int ret) {
        return validate_mount(dir->mnt, ret);
}

SEC("lsm/path_symlink")
int BPF_PROG(userns_restrict_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name, int ret) {
        return validate_mount(dir->mnt, ret);
}

SEC("lsm/path_link")
int BPF_PROG(userns_restrict_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, int ret) {
        return validate_mount(new_dir->mnt, ret);
}

SEC("lsm/task_fix_setgroups")
int BPF_PROG(userns_restrict_task_fix_setgroups, struct cred *new_cred, const struct cred *old, int ret) {
        struct user_namespace *p;
        unsigned inode;

        if (ret != 0) /* propagate earlier error */
                return ret;

        /* Walk the task's user namespace and its ancestors to find the first one managed by nsresourced
         * (i.e. present in either the setgroups deny map or the mount ID hash map). This is necessary
         * because a task could otherwise trivially bypass the setgroups() restriction by unsharing the user
         * namespace and mapping the same users and groups. */
        p = new_cred->user_ns;
        for (unsigned i = 0; i < USER_NAMESPACE_DEPTH_MAX; i++) {
                if (!p)
                        break;

                inode = p->ns.inum;

                if (bpf_map_lookup_elem(&userns_setgroups_deny, &inode))
                        return -EPERM;

                if (bpf_map_lookup_elem(&userns_mnt_id_hash, &inode))
                        return 0;

                p = p->parent;
        }

        /* No nsresourced-managed ancestor found, allow. */
        return 0;
}

SEC("kprobe/retire_userns_sysctls")
int BPF_KPROBE(userns_restrict_retire_userns_sysctls, struct user_namespace *userns) {
        unsigned inode;

        /* Inform userspace that a user namespace just went away. I wish there was a nicer way to hook into
         * user namespaces being deleted than using kprobes, but couldn't find any. */
        userns = bpf_rdonly_cast(userns, bpf_core_type_id_kernel(struct user_namespace));
        inode = userns->ns.inum;

        /* Check each map separately to avoid the compiler merging the two lookups into a pointer OR
         * operation, which the BPF verifier rejects. */
        if (bpf_map_lookup_elem(&userns_mnt_id_hash, &inode))
                goto notify;

        if (bpf_map_lookup_elem(&userns_setgroups_deny, &inode))
                goto notify;

        /* No rules installed for this userns? Then send no notification. */
        return 0;

notify:
        bpf_ringbuf_output(&userns_ringbuf, &inode, sizeof(inode), 0);
        return 0;
}

static const char _license[] SEC("license") = "GPL";
