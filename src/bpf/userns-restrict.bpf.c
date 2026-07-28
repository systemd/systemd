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

#include <errno.h>                      /* IWYU pragma: keep */
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

/* BPF module that keeps user namespaces provisioned by nsresourced (identified by their inode number in
 * nsfs) from leaving objects owned by their transient UID/GID range behind on file systems that outlive the
 * namespace. Transient ranges are recycled, so any such object would later be owned by an unrelated client.
 *
 * This hooks into the various path-based LSM entrypoints that control inode creation as well as chown(), and
 * for each asks the only two questions that matter:
 *
 *   a) Does the file system die together with the user namespace? Superblocks record the user namespace they
 *      were mounted in, so this is simply whether sb->s_user_ns sits at or below the provisioned namespace.
 *
 *   b) Will the transient ID actually reach the disk? An idmapped mount may translate it into something
 *      else entirely, in which case nothing recyclable is recorded anywhere.
 *
 * Both are answered from fields the kernel stamps itself and that a client cannot influence: unlike the
 * mount namespace a mount happens to sit in, neither a superblock's user namespace nor a mount's idmapping
 * can be forged with unshare(), and both are preserved when a mount is cloned. */

// FIXME: ACL adjustments are currently not blocked. There's no path-based LSM hook available in the kernel
// for setting xattrs or ACLs, hence we cannot easily block them, even though we want that. We can get away
// with ignoring this for now, as ACLs never define ownership, but purely access: i.e. ACLs never allow
// taking possession of an object, but only control access to it. Thus, things like suid access modes should
// not be reachable through it. It still sucks though that a user can persistently add an ACL entry to a file
// with their transient UIDs/GIDs.

/* create_user_ns() in the kernel sources refuses to nest below a user namespace whose level is above 32,
 * hence the deepest reachable level is 33, i.e. a chain of 34 user namespaces including the initial one. */
#define USER_NAMESPACE_DEPTH_MAX 34U

/* Mirrors UID_GID_MAP_MAX_BASE_EXTENTS/UID_GID_MAP_MAX_EXTENTS, see include/linux/user_namespace.h */
#define UID_GID_MAP_MAX_BASE_EXTENTS 5U
#define UID_GID_MAP_MAX_EXTENTS 340U

/* The kernel's INVALID_UID/INVALID_GID, i.e. what an unmapped translation results in */
#define UID_GID_INVALID ((uid_t) -1)

/* From include/uapi/linux/magic.h, which vmlinux.h does not provide. */
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1);        /* placeholder, configured otherwise by nsresourced */
        __type(key, unsigned);         /* userns inode */
        __type(value, int);            /* dummy value */
} userns_managed SEC(".maps");

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

static inline bool uid_is_dynamic(uid_t uid) {
        return DYNAMIC_UID_MIN <= uid && uid <= DYNAMIC_UID_MAX;
}

static inline bool uid_is_container(uid_t uid) {
        return CONTAINER_UID_MIN <= uid && uid <= CONTAINER_UID_MAX;
}

static inline bool uid_is_transient(uid_t uid) {
        return uid_is_dynamic(uid) || uid_is_container(uid);
}

/* Finds the closest user namespace at or above the passed one that nsresourced provisioned. Walking upwards
 * is what keeps a nested user namespace from shaking off the policy. Returns 1 and stores it in the return
 * argument if found, 0 if the whole chain was walked without a match, and a negative error if the chain is
 * longer than the kernel permits (in which case we refuse rather than fail open, as we cannot rule out a
 * managed ancestor). */
static int find_managed_userns(struct user_namespace *userns, struct user_namespace **ret) {
        struct user_namespace *p = userns;

        /* All callers pass a valid pointer; the guard just satisfies the pointer-deref checker. */
        if (!ret)
                return -EINVAL;

        for (unsigned i = 0; i < USER_NAMESPACE_DEPTH_MAX; i++) {
                unsigned inode;

                inode = p->ns.inum;
                if (bpf_map_lookup_elem(&userns_managed, &inode)) {
                        *ret = p;
                        return true;
                }

                p = p->parent;
                if (!p) /* Walked the whole chain up to the initial namespace without a match. */
                        return false;
        }

        /* Chain longer than the kernel permits: refuse rather than fail open, as we cannot rule out a
         * managed ancestor. */
        return -EPERM;
}

/* Is the second user namespace the first one itself, or nested below it? */
static int userns_is_below(struct user_namespace *ancestor, struct user_namespace *ns) {
        struct user_namespace *p = ns;

        for (unsigned i = 0; i < USER_NAMESPACE_DEPTH_MAX; i++) {
                if (p == ancestor)
                        return true;

                p = p->parent;
                if (!p)
                        break;
        }

        /* Hmm, something is fishy if there's more than 34 levels of namespaces involved. Let's better be
         * safe than sorry, and refuse. */
        if (p)
                return -EPERM;

        return false;
}

/* Resolves a uid_gid_map's extent array for the requested direction. Small maps carry their extents inline,
 * larger ones keep two arrays instead, each sorted by one end (the kernel bisects them, a linear scan
 * arrives at the same answer). Those two pointers share storage with the inline extent array; the verifier
 * resolves the overlap to the latter and then refuses an 8 byte load in the middle of it, so we read the
 * wanted pointer out explicitly. The bpf_core_field_offset() operands have to stay compile time constants,
 * hence the branch per direction. always_inline so each caller keeps the hand-inlined shape the verifier
 * already accepts (a register that is a BTF pointer on one branch and a scalar on the other). Returns NULL
 * for an empty map or on a read failure. */
static inline __attribute__((always_inline))
struct uid_gid_extent *uid_gid_map_extents(struct uid_gid_map *map, bool up) {
        struct uid_gid_extent *array;

        if (map->nr_extents == 0)
                return NULL;

        if (map->nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
                return map->extent;

        if (up) {
                if (bpf_probe_read_kernel(&array, sizeof(array),
                                          (const void*) map + bpf_core_field_offset(struct uid_gid_map, reverse)) != 0)
                        return NULL;
        } else {
                if (bpf_probe_read_kernel(&array, sizeof(array),
                                          (const void*) map + bpf_core_field_offset(struct uid_gid_map, forward)) != 0)
                        return NULL;
        }

        return array;
}

/* Mirrors map_id_range_up()/map_id_range_down() from kernel/user_namespace.c: translates the passed ID
 * through the map, where the up flag selects which end of the extents is searched. Stores UID_GID_INVALID if
 * the ID is not mapped, and returns negative if the map could not be read, which callers must keep apart: an
 * unmapped ID records nothing on disk, whereas a map we failed to read tells us nothing at all. */
static int uid_gid_map_translate(struct uid_gid_map *map, uid_t id, bool up, uid_t *ret) {
        struct uid_gid_extent *array;
        unsigned n;

        /* All callers pass a valid pointer; the guard just satisfies the pointer-deref checker. */
        if (!ret)
                return -EINVAL;

        n = map->nr_extents;
        if (n == 0) { /* Empty map: nothing is mapped, and that is an answer, not a failure. */
                *ret = UID_GID_INVALID;
                return 0;
        }

        array = uid_gid_map_extents(map, up);
        if (!array) /* Non-empty map whose extents we could not resolve. */
                return -EPERM;

        /* Copy each extent out instead of indexing the array in place: a variable index into a kernel
         * pointer is something the verifier refuses. */
        for (unsigned i = 0; i < UID_GID_MAP_MAX_EXTENTS; i++) {
                struct uid_gid_extent e;
                uid_t first;

                if (i >= n)
                        break;

                if (bpf_probe_read_kernel(&e, sizeof(e), array + i) != 0)
                        return -EPERM;

                first = up ? e.lower_first : e.first;
                if (id >= first && id - first < e.count) {
                        *ret = (up ? e.first : e.lower_first) + (id - first);
                        return 0;
                }
        }

        *ret = UID_GID_INVALID;
        return 0;
}

/* Mirrors from_vfsuid()/from_vfsgid() from fs/mnt_idmapping.c: the ID that is actually recorded on disk when
 * the passed ID creates an object on the given mount. The gid flag selects the GID maps over the UID maps.
 * Stores UID_GID_INVALID if the ID does not map, in which case the kernel refuses the operation with
 * EOVERFLOW anyway, see fsuidgid_has_mapping(). Returns negative if a map could not be read. */
static int mount_map_id(struct vfsmount *mnt, struct user_namespace *fs_userns, uid_t id, bool gid, uid_t *ret) {
        struct mnt_idmap *idmap;
        struct uid_gid_map *m;
        int r;

        /* All callers pass a valid pointer; the guard just satisfies the pointer-deref checker. */
        if (!ret)
                return -EINVAL;

        idmap = mnt->mnt_idmap;
        if (!idmap) {
                *ret = id;
                return 0;
        }

        m = gid ? &idmap->gid_map : &idmap->uid_map;

        /* Both nop_mnt_idmap and invalid_mnt_idmap carry empty maps. For the former that is an identity
         * mapping; for the latter the operation fails later on regardless, so treating it as identity only
         * ever makes us stricter. */
        if (m->nr_extents > 0) {
                r = uid_gid_map_translate(m, id, /* up= */ true, &id);
                if (r < 0)
                        return r;
                if (id == UID_GID_INVALID) {
                        *ret = UID_GID_INVALID;
                        return 0;
                }
        }

        /* initial_idmapping(): the initial user namespace is the only one without a parent. */
        if (!fs_userns->parent) {
                *ret = id;
                return 0;
        }

        return uid_gid_map_translate(gid ? &fs_userns->gid_map : &fs_userns->uid_map, id, /* up= */ false, ret);
}

/* Common tail of the inode creation hooks: would the object the calling task is about to create end up
 * owned by a transient ID on a file system that outlives the user namespace that ID was handed to? */
static int validate_mount(struct vfsmount *v, int ret) {
        struct user_namespace *managed, *fs_userns;
        const struct cred *cred;
        struct task_struct *task;
        uid_t uid, gid;
        int r;

        if (ret != 0) /* propagate earlier error */
                return ret;

        /* Get user namespace from task */
        task = (struct task_struct*) bpf_get_current_task_btf();
        cred = task->cred;
        if (!cred)
                return -EPERM;

        /* fsuid/fsgid are the UID/GID in the initial user namespace. Anything outside the transient ranges
         * is never recycled by us, hence there's nothing to protect. */
        if (!uid_is_transient(cred->fsuid.val) && !uid_is_transient((uid_t) cred->fsgid.val))
                return 0;

        r = find_managed_userns(cred->user_ns, &managed);
        if (r < 0)
                return r;
        if (r == 0) /* Not provisioned by nsresourced? Then this is none of our business. */
                return 0;

        fs_userns = v->mnt_sb->s_user_ns;

        /* Does the file system die together with the user namespace? Then nothing it carries can outlive
         * the transient range, and we can allow this. */
        r = userns_is_below(managed, fs_userns);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        /* Refuse if we cannot resolve where the IDs land: an ID we failed to translate is not an ID we know
         * to be harmless. */
        r = mount_map_id(v, fs_userns, cred->fsuid.val, /* gid= */ false, &uid);
        if (r < 0)
                return r;

        r = mount_map_id(v, fs_userns, (uid_t) cred->fsgid.val, /* gid= */ true, &gid);
        if (r < 0)
                return r;

        /* If the mount's idmapping translates our transient IDs into something else, nothing recyclable is
         * recorded on disk, and we are fine. */
        if (!uid_is_transient(uid) && !uid_is_transient(gid))
                return 0;

        return -EPERM;
}

SEC("lsm/path_chown")
int BPF_PROG(userns_restrict_path_chown, struct path *path, unsigned long long uid, unsigned long long gid, int ret) {
        struct user_namespace *managed;
        const struct cred *cred;
        struct task_struct *task;
        int r;

        if (ret != 0) /* propagate earlier error */
                return ret;

        /* Get user namespace from task */
        task = (struct task_struct*) bpf_get_current_task_btf();
        cred = task->cred;
        if (!cred)
                return -EPERM;

        /* User namespaces that were not provisioned by nsresourced can still write to the transient ranges
         * so that we don't break use cases like systemd-nspawn's --private-users=pick switch. */
        r = find_managed_userns(cred->user_ns, &managed);
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        r = userns_is_below(managed, path->mnt->mnt_sb->s_user_ns);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        /* Unlike the creation hooks this one is handed the IDs with the mount's idmapping already applied,
         * i.e. the ones that end up on disk, hence we can look at them directly. See chown_common() in the
         * kernel sources. */
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

/* overlayfs' struct ovl_fs and struct ovl_layer are private to the module and hence absent from vmlinux.h
 * whenever overlayfs is built as a module. We declare the two fields we need as CO-RE "type flavors": libbpf
 * strips the ___local suffix and relocates these against the kernel's real ovl_fs/ovl_layer. This both
 * avoids clashing with a vmlinux.h that does carry them (built-in overlayfs) and, combined with
 * bpf_core_type_exists() below, lets the program still load when overlayfs is entirely unavailable.
 * systemd-nsresourced.service orders itself after modprobe@overlay.service so the module's BTF is present by
 * the time this program is loaded. @mnt is documented in the kernel to be the first member of ovl_layer. */
struct ovl_layer___local {
        struct vfsmount *mnt;
} __attribute__((preserve_access_index));

struct ovl_fs___local {
        struct ovl_layer___local *layers;
} __attribute__((preserve_access_index));

/* True if the inclusive range [a, b] overlaps either transient id range. */
static bool range_hits_transient(uint64_t a, uint64_t b) {
        if (a <= DYNAMIC_UID_MAX && DYNAMIC_UID_MIN <= b)
                return true;
        if (a <= CONTAINER_UID_MAX && CONTAINER_UID_MIN <= b)
                return true;
        return false;
}

/* Returns true if the map (a mount idmap's uid_map or gid_map) never records a transient id on disk, so
 * nothing recyclable can reach the disk through it. Read in the "up" direction (i.e. as a mount idmap) an
 * extent maps input ids [lower_first, lower_first+count) to on-disk ids [first, first+count); we refuse if
 * any extent's on-disk range is transient, no matter which input reaches it. Ids no extent covers are left
 * unmapped, which fails the write with EOVERFLOW, so they are fine too. An empty map is the identity
 * mapping and hence neutralizes nothing. */
static bool idmap_map_neutralizes_transient(struct uid_gid_map *map) {
        struct uid_gid_extent *array;
        unsigned n;

        n = map->nr_extents;

        array = uid_gid_map_extents(map, /* up= */ true);
        /* NULL means an empty map (identity mapping, neutralizes nothing) or a read failure; refuse either. */
        if (!array)
                return false;

        for (unsigned i = 0; i < UID_GID_MAP_MAX_EXTENTS; i++) {
                struct uid_gid_extent e;

                if (i >= n)
                        break;
                if (bpf_probe_read_kernel(&e, sizeof(e), array + i) != 0)
                        return false;

                if (e.count == 0)
                        continue;

                /* The on-disk ids this extent can record are [first, first+count). If any is transient,
                 * some write through this mount is recyclable, so the map does not neutralize. */
                if (range_hits_transient(e.first, (uint64_t) e.first + e.count - 1))
                        return false;
        }

        return true;
}

/* True if the mount's idmapping maps the whole transient UID and GID ranges away, so a transient client
 * writing through it leaves nothing recyclable on disk. A non-idmapped mount maps them through unchanged. */
static bool mount_neutralizes_transient(struct vfsmount *mnt) {
        struct mnt_idmap *idmap;

        idmap = mnt->mnt_idmap;
        if (!idmap)
                return false;

        return idmap_map_neutralizes_transient(&idmap->uid_map) &&
               idmap_map_neutralizes_transient(&idmap->gid_map);
}

/* overlayfs would let a managed user namespace sidestep all of the above: a write to an overlay mount
 * creates the real inode on the upper layer via vfs_create(), which reaches only the inode-based LSM hooks,
 * not the path-based ones we attach to. The single path hook that does fire sees the overlay mount itself,
 * whose superblock belongs to the (managed) mounting namespace and so looks like it dies with it, while the
 * upper may be a persistent file system on which our transient IDs then persist. So we judge the upper
 * here, at mount time, the only point we can see it. We permit the overlay if its upper dies with the
 * managed namespace (e.g. a tmpfs the client set up itself), or if the upper is a persistent file system
 * whose mount idmapping maps the transient ranges away so nothing recyclable reaches its disk (as
 * mountfsd-style idmapped mounts do); everything else, and any overlay owned by a namespace we do not
 * manage, is refused.
 *
 * We key on whether a writable upper exists (layers[0].mnt), which is fixed for the superblock's lifetime,
 * not on the mutable SB_RDONLY flag: an overlay mounted read-only but with an upper can be remounted
 * read-write later without re-entering this hook, so it is judged now. A genuinely read-only overlay has no
 * upper (layers[0].mnt is NULL) and cannot record anything, so it is left alone. Refusing the mount cannot
 * undo the work/index dirs overlayfs already stamped onto the upper during ovl_fill_super(), which runs
 * before this hook; it stops all further writes, but those mount-time dirs remain a residual leak. Reaching
 * it takes an upperdir and a workdir that already exist on the same persistent, non-idmapped file system and
 * that the transient IDs may write to: the client cannot create them itself, since that is what the path
 * hooks deny.
 *
 * We only look at the upper: overlayfs requires the workdir to be under the same mount as the upperdir
 * (ovl_get_workdir()), and stamps work/index using the upper mount's idmapping (ovl_upper_mnt_idmap() ==
 * mnt_idmap(layers[0].mnt)), so the upper's superblock and idmapping already govern the workdir too. */
SEC("lsm/sb_kern_mount")
int BPF_PROG(userns_restrict_sb_kern_mount, struct super_block *sb, int ret) {
        struct ovl_layer___local *layers;
        struct user_namespace *managed, *fs_userns;
        struct ovl_fs___local *ofs;
        struct vfsmount *upper;
        void *upper_addr;
        int r;

        if (ret != 0) /* propagate earlier error */
                return ret;

        if (sb->s_magic != OVERLAYFS_SUPER_MAGIC)
                return 0;

        r = find_managed_userns(sb->s_user_ns, &managed);
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        /* If we cannot read overlayfs' private layout (module not loaded, built without overlayfs at all,
         * or the fields we need went away), we cannot locate the upper, so refuse conservatively. */
        if (!bpf_core_type_exists(struct ovl_fs___local) ||
            !bpf_core_field_exists(struct ovl_fs___local, layers) ||
            !bpf_core_field_exists(struct ovl_layer___local, mnt))
                return -EPERM;

        /* Walk to the upper one field at a time: a failed read comes back as NULL just like a genuinely
         * absent upper does, and only the latter may be allowed. A mounted overlay always has both its
         * private data and its layer array, so NULL there means we failed to read them. */
        ofs = (struct ovl_fs___local*) BPF_CORE_READ(sb, s_fs_info);
        if (!ofs)
                return -EPERM;

        layers = BPF_CORE_READ(ofs, layers);
        if (!layers)
                return -EPERM;

        upper_addr = BPF_CORE_READ(layers, mnt); /* layers[0] is the upper; .mnt is its first member */
        if (!upper_addr) /* no upper: a genuinely read-only overlay, which can record nothing */
                return 0;

        /* BPF_CORE_READ() lowers to bpf_probe_read_kernel(), so its result is a raw address the verifier
         * tracks as a scalar. Re-type it as a BTF pointer, as the retire_userns_sysctls kprobe does with
         * its argument, so we may walk and dereference it directly below. */
        upper = bpf_rdonly_cast(upper_addr, bpf_core_type_id_kernel(struct vfsmount));
        fs_userns = upper->mnt_sb->s_user_ns;

        /* Upper dies together with the managed user namespace? Then nothing it carries can outlive the
         * transient range. */
        r = userns_is_below(managed, fs_userns);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        /* The upper outlives the namespace. It is still safe if it is a persistent file system in the
         * initial user namespace whose mount idmapping maps the transient ranges away. We refuse anything
         * we cannot prove this for, including any non-initial-namespace upper. */
        if (fs_userns->parent)
                return -EPERM;

        if (mount_neutralizes_transient(upper))
                return 0;

        return -EPERM;
}

SEC("lsm/task_fix_setgroups")
int BPF_PROG(userns_restrict_task_fix_setgroups, struct cred *new_cred, const struct cred *old, int ret) {
        struct user_namespace *p;
        unsigned inode;

        if (ret != 0) /* propagate earlier error */
                return ret;

        /* Walk the task's user namespace and its ancestors to find the first one managed by nsresourced
         * (i.e. present in either the setgroups deny map or the managed userns map). This is necessary
         * because a task could otherwise trivially bypass the setgroups() restriction by unsharing the user
         * namespace and mapping the same users and groups. */
        p = new_cred->user_ns;
        for (unsigned i = 0; i < USER_NAMESPACE_DEPTH_MAX; i++) {
                inode = p->ns.inum;

                if (bpf_map_lookup_elem(&userns_setgroups_deny, &inode))
                        return -EPERM;

                if (bpf_map_lookup_elem(&userns_managed, &inode))
                        return 0;

                p = p->parent;
                if (!p) /* Walked the whole chain up to the initial namespace without a match, allow. */
                        return 0;
        }

        /* Chain longer than the kernel permits: refuse rather than fail open, like find_managed_userns(). */
        return -EPERM;
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
        if (bpf_map_lookup_elem(&userns_managed, &inode))
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
