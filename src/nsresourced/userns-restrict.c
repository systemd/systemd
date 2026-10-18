/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#if HAVE_VMLINUX_H
#include "userns-restrict-skel.h"
#endif

#include "bpf-util.h"
#include "log.h"
#include "lsm-util.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "userns-restrict.h"

#define USERNS_MAX (16U*1024U)

/* No dots in any of the path components: bpffs reserves those for its own use and fails every lookup that
 * contains one with EPERM, see bpf_lookup() in the kernel sources. */
#define LINK_PREFIX "/sys/fs/bpf/systemd/userns-restrict-v2"
#define PROGRAM_LINK_PREFIX LINK_PREFIX "/programs"
#define MAP_LINK_PREFIX LINK_PREFIX "/maps"

/* Programs pinned here enforce the mount allowlist policy we used until v261, which is bypassable with a
 * single unshare(). They'd stay attached next to ours, hence get rid of them. */
#define OBSOLETE_LINK_PREFIX "/sys/fs/bpf/systemd/userns-restrict"

#if HAVE_VMLINUX_H
static bool inode_hooks_supported(void) {
        _cleanup_(sym_btf__freep) struct btf *btf = NULL;
        int idmap_id;

        if (!sym_btf__load_vmlinux_btf || !sym_btf__find_by_name_kind ||
            !sym_btf__type_by_id || !sym_btf__free)
                return false;

        btf = sym_btf__load_vmlinux_btf();
        if (bpf_get_error_translated(btf) < 0)
                return false;

        idmap_id = sym_btf__find_by_name_kind(btf, "mnt_idmap", BTF_KIND_STRUCT);
        if (idmap_id <= 0)
                return false;

        FOREACH_STRING(name,
                       "bpf_lsm_inode_create",
                       "bpf_lsm_inode_link",
                       "bpf_lsm_inode_symlink",
                       "bpf_lsm_inode_mkdir",
                       "bpf_lsm_inode_mknod",
                       "bpf_lsm_inode_setattr") {
                const struct btf_type *type;
                int id;

                id = sym_btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
                if (id <= 0)
                        return false;

                type = sym_btf__type_by_id(btf, id);
                if (!type)
                        return false;

                type = sym_btf__type_by_id(btf, type->type);
                if (!type || !btf_is_func_proto(type) || btf_vlen(type) == 0)
                        return false;

                type = sym_btf__type_by_id(btf, btf_params(type)[0].type);
                if (!type || !btf_is_ptr(type))
                        return false;

                /* Kernel 7.4 passes the idmap to the hooks as a const pointer. BTF records the const as a
                 * separate type between the pointer and struct mnt_idmap. Without skipping it, we would
                 * fall back to the path hooks on 7.4. */
                id = type->type;
                for (;;) {
                        type = sym_btf__type_by_id(btf, id);
                        if (!type)
                                return false;
                        if (!btf_is_mod(type))
                                break;
                        id = type->type;
                }

                if (id != idmap_id)
                        return false;
        }

        return true;
}

static bool program_enabled(const char *name, bool inode_hooks) {
        if (streq(name, "userns_restrict_file_ioctl_compat"))
                return bpf_kernel_has_kfunc("bpf_lsm_file_ioctl_compat");

        if (streq(name, "userns_restrict_path_rename"))
                return true;

        if (startswith(name, "userns_restrict_inode_"))
                return inode_hooks;

        if (startswith(name, "userns_restrict_path_") || streq(name, "userns_restrict_sb_kern_mount"))
                return !inode_hooks;

        return true;
}
#endif

struct userns_restrict_bpf *userns_restrict_bpf_free(struct userns_restrict_bpf *obj) {
#if HAVE_VMLINUX_H
        userns_restrict_bpf__destroy(obj); /* this call is fine with NULL */
#endif
        return NULL;

}

int userns_restrict_install(
                bool pin,
                struct userns_restrict_bpf **ret) {

#if HAVE_VMLINUX_H
        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *obj = NULL;
        int r;

        r = lsm_supported("bpf");
        if (r == -ENOPKG)
                /* We propagate this as EOPNOTSUPP! */
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-lsm support not available, as securityfs is not mounted.");
        if (r < 0)
                return log_error_errno(r, "Failed to check if bpf-lsm support is available: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-lsm not supported, can't lock down user namespace.");

        LIBBPF_NOTE(recommended);
        r = dlopen_bpf(LOG_DEBUG);
        if (r < 0)
                return r;

        /* bpf_object__next_map() is not available in libbpf pre-0.7.0, and we want to use it. */
        if (!sym_bpf_object__next_map)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libbpf too old for locking down user namespace.");

        obj = userns_restrict_bpf__open();
        if (!obj)
                return log_error_errno(errno, "Failed to open userns_restrict BPF object: %m");

        bool inode_hooks = inode_hooks_supported();
        log_debug("Using %s hooks to restrict user namespace writes.", inode_hooks ? "inode" : "path");

        for (int i = 0; i < obj->skeleton->prog_cnt; i++) {
                struct bpf_prog_skeleton *ps = obj->skeleton->progs + i;

                r = sym_bpf_program__set_autoload(*ps->prog, program_enabled(ps->name, inode_hooks));
                if (r < 0)
                        return log_error_errno(r, "Failed to select user namespace restriction BPF program: %m");
        }

        if (pin) {
                struct bpf_map *map;

                /* libbpf will only create one level of dirs. Let's create the rest. Failing here means the
                 * pinning below fails too, so complain rather than run into that without a clue. */
                FOREACH_STRING(d, MAP_LINK_PREFIX, PROGRAM_LINK_PREFIX) {
                        r = mkdir_p(d, 0755);
                        if (r < 0)
                                log_warning_errno(r, "Failed to create '%s', ignoring: %m", d);
                }

                for (map = sym_bpf_object__next_map(obj->obj, /* map= */ NULL); map;
                     map = sym_bpf_object__next_map(obj->obj, map)) {
                        _cleanup_free_ char *fn = NULL;

                        fn = path_join(MAP_LINK_PREFIX, sym_bpf_map__name(map));
                        if (!fn)
                                return log_oom();

                        r = sym_bpf_map__set_pin_path(map, fn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set pin path to '%s': %m", fn);
                }
        }

        r = sym_bpf_map__set_max_entries(obj->maps.userns_managed, USERNS_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to size managed userns hash table: %m");

        r = sym_bpf_map__set_max_entries(obj->maps.userns_ringbuf, USERNS_MAX * sizeof(unsigned));
        if (r < 0)
                return log_error_errno(r, "Failed to size userns ring buffer: %m");

        r = sym_bpf_map__set_max_entries(obj->maps.userns_setgroups_deny, USERNS_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to size userns setgroups deny hash table: %m");

        r = userns_restrict_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to load BPF object: %m");

        /* Pin the maps already here: the programs are not attached yet, so nothing enforces anything, but
         * the caller may now seed the maps before userns_restrict_attach() puts the policy in effect. */
        if (pin) {
                r = sym_bpf_object__pin_maps(obj->obj, /* path= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to pin BPF maps: %m");
        }

        if (ret)
                *ret = TAKE_PTR(obj);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "User Namespace Restriction BPF support disabled.");
#endif
}

int userns_restrict_attach(struct userns_restrict_bpf *obj, bool pin) {

#if HAVE_VMLINUX_H
        _cleanup_(rm_rf_physical_and_freep) char *staging = NULL;
        int r;

        assert(obj);

        /* Attach every program before we touch the pins. If a program fails to attach, the caller destroys
         * the object, which detaches the programs attached here. The programs that a previous run pinned
         * then stay attached and keep enforcing the policy. */
        for (int i = 0; i < obj->skeleton->prog_cnt; i++) {
                struct bpf_prog_skeleton *ps = obj->skeleton->progs + i;
                struct bpf_link *link;

                if (sym_bpf_program__fd(*ps->prog) < 0)
                        continue;

                link = sym_bpf_program__attach(*ps->prog);
                r = bpf_get_error_translated(link);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach LSM BPF program %s: %m", ps->name);

                *ps->link = link;
                log_debug("userns-restrict BPF-LSM program %s now attached.", ps->name);
        }

        if (!pin)
                return 0;

        staging = strdup(PROGRAM_LINK_PREFIX "-new");
        if (!staging)
                return log_oom();

        /* A previous run may have exited before removing its staging directory. The active directory
         * still pins the complete policy, so removing the staging directory cannot remove protection. */
        r = rm_rf(staging, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_MISSING_OK);
        if (r < 0)
                return log_error_errno(r, "Failed to remove previous LSM attachment staging directory: %m");

        if (mkdir(staging, 0755) < 0)
                return log_error_errno(errno, "Failed to create LSM attachment staging directory: %m");

        for (int i = 0; i < obj->skeleton->prog_cnt; i++) {
                struct bpf_prog_skeleton *ps = obj->skeleton->progs + i;
                _cleanup_free_ char *fn = NULL;
                const char *e;

                if (sym_bpf_program__fd(*ps->prog) < 0)
                        continue;

                e = startswith(ps->name, "userns_restrict_");
                assert(e);

                fn = path_join(staging, e);
                if (!fn)
                        return log_oom();

                r = sym_bpf_link__pin(*ps->link, fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to pin LSM attachment '%s': %m", fn);
        }

        /* Replacing individual pins could remove protection if a later pin fails and the caller destroys
         * the object. The exchange preserves every old pin until the complete replacement is pinned. */
        if (renameat2(AT_FDCWD, staging, AT_FDCWD, PROGRAM_LINK_PREFIX, RENAME_EXCHANGE) < 0)
                return log_error_errno(errno, "Failed to replace pinned LSM attachments: %m");

        (void) rm_rf(OBSOLETE_LINK_PREFIX, REMOVE_PHYSICAL);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "User Namespace Restriction BPF support disabled.");
#endif
}

int userns_restrict_register_by_inode(
                struct userns_restrict_bpf *obj,
                uint64_t userns_inode) {

#if HAVE_VMLINUX_H
        uint32_t dummy_value = 1;
        int map_fd, r;
        unsigned ino;

        assert(obj);
        assert(userns_inode != 0);

        /* The BPF map only supports 32bit keys, and user namespace inode numbers are 32bit too, even though
         * ino_t is 64bit these days. Should we ever run into a 64bit inode let's refuse early, we can't
         * support this with the current BPF code for now. */
        if (userns_inode > UINT32_MAX)
                return -EINVAL;

        ino = (unsigned) userns_inode;

        map_fd = sym_bpf_map__fd(obj->maps.userns_managed);
        if (map_fd < 0)
                return log_debug_errno(map_fd, "Failed to get managed userns BPF map fd: %m");

        r = sym_bpf_map_update_elem(map_fd, &ino, &dummy_value, BPF_ANY);
        if (r < 0)
                return log_debug_errno(r, "Failed to add userns inode to managed map: %m");

        log_debug("Restricting persistent writes for userns inode %" PRIu64, userns_inode);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "User Namespace Restriction BPF support disabled.");
#endif
}

int userns_restrict_register_by_fd(
                struct userns_restrict_bpf *obj,
                int userns_fd) {

#if HAVE_VMLINUX_H
        struct stat st;
        int r;

        assert(obj);
        assert(userns_fd >= 0);

        r = fd_is_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if file descriptor is user namespace: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADF), "User namespace fd is not actually a user namespace fd.");

        if (fstat(userns_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace: %m");

        return userns_restrict_register_by_inode(obj, st.st_ino);
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "User Namespace Restriction BPF support disabled.");
#endif
}

int userns_restrict_reset_by_inode(struct userns_restrict_bpf *obj, uint64_t userns_inode) {

#if HAVE_VMLINUX_H
        int r, managed_fd, setgroups_deny_fd;
        unsigned u;

        assert(obj);
        assert(userns_inode != 0);

        if (userns_inode > UINT32_MAX) /* inodes larger than 32bit are definitely not included in our map, exit early */
                return 0;

        managed_fd = sym_bpf_map__fd(obj->maps.userns_managed);
        if (managed_fd < 0)
                return log_debug_errno(managed_fd, "Failed to get managed userns BPF map fd: %m");

        u = (uint32_t) userns_inode;

        /* A missing entry is an ordinary state here (the maps come up empty after a schema change, and
         * registration is idempotent), so don't let it cut the setgroups deny cleanup below short. */
        r = sym_bpf_map_delete_elem(managed_fd, &u);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to remove entry for inode %" PRIu64 " from managed map: %m", userns_inode);

        setgroups_deny_fd = sym_bpf_map__fd(obj->maps.userns_setgroups_deny);
        if (setgroups_deny_fd < 0)
                return log_debug_errno(setgroups_deny_fd, "Failed to get setgroups deny BPF map fd: %m");

        r = sym_bpf_map_delete_elem(setgroups_deny_fd, &u);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to remove entry for inode %" PRIu64 " from setgroups deny map: %m", userns_inode);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "User Namespace Restriction BPF support disabled.");
#endif
}

int userns_restrict_setgroups_deny_by_inode(
                struct userns_restrict_bpf *obj,
                uint64_t userns_inode) {

#if HAVE_VMLINUX_H
        int map_fd, r;
        uint32_t dummy = 1;
        unsigned ino;

        assert(obj);
        assert(userns_inode != 0);

        /* The BPF map only supports 32bit keys, and user namespace inode numbers are 32bit too, even though
         * ino_t is 64bit these days. Should we ever run into a 64bit inode let's refuse early. */
        if (userns_inode > UINT32_MAX)
                return -EINVAL;

        ino = (unsigned) userns_inode;

        map_fd = sym_bpf_map__fd(obj->maps.userns_setgroups_deny);
        if (map_fd < 0)
                return log_debug_errno(map_fd, "Failed to get setgroups deny BPF map fd: %m");

        r = sym_bpf_map_update_elem(map_fd, &ino, &dummy, BPF_ANY);
        if (r < 0)
                return log_debug_errno(r, "Failed to add userns inode to setgroups deny map: %m");

        log_debug("Denying setgroups() on userns inode %" PRIu64, userns_inode);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "User Namespace Restriction BPF support disabled.");
#endif
}

int userns_restrict_setgroups_deny_by_fd(
                struct userns_restrict_bpf *obj,
                int userns_fd) {

#if HAVE_VMLINUX_H
        struct stat st;
        int r;

        assert(obj);
        assert(userns_fd >= 0);

        r = fd_is_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if file descriptor is user namespace: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADF), "User namespace fd is not actually a user namespace fd.");

        if (fstat(userns_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace: %m");

        return userns_restrict_setgroups_deny_by_inode(obj, st.st_ino);
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "User Namespace Restriction BPF support disabled.");
#endif
}
