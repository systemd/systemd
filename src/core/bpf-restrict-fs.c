/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bpf-restrict-fs.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "stat-util.h"
#include "strv.h"

#if BPF_FRAMEWORK
/* libbpf, clang and llc compile time dependencies are satisfied */
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf-util.h"
#include "bpf/restrict_fs/restrict-fs-skel.h"

#define CGROUP_HASH_SIZE_MAX 2048

static struct restrict_fs_bpf *restrict_fs_bpf_free(struct restrict_fs_bpf *obj) {
        /* restrict_fs_bpf__destroy handles object == NULL case */
        (void) restrict_fs_bpf__destroy(obj);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct restrict_fs_bpf *, restrict_fs_bpf_free);

static bool bpf_can_link_lsm_program(struct bpf_program *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;

        assert(prog);

        link = sym_bpf_program__attach_lsm(prog);

        /* If bpf_program__attach_lsm fails the resulting value stores libbpf error code instead of memory
         * pointer. That is the case when the helper is called on architectures where BPF trampoline (hence
         * BPF_LSM_MAC attach type) is not supported. */
        return bpf_get_error_translated(link) == 0;
}

static int prepare_restrict_fs_bpf(struct restrict_fs_bpf **ret_obj) {
        _cleanup_(restrict_fs_bpf_freep) struct restrict_fs_bpf *obj = NULL;
        _cleanup_close_ int inner_map_fd = -EBADF;
        int r;

        assert(ret_obj);

        obj = restrict_fs_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-restrict-fs: Failed to open BPF object: %m");

        /* TODO Maybe choose a number based on runtime information? */
        r = sym_bpf_map__set_max_entries(obj->maps.cgroup_hash, CGROUP_HASH_SIZE_MAX);
        assert(r <= 0);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fs: Failed to resize BPF map '%s': %m",
                                       sym_bpf_map__name(obj->maps.cgroup_hash));

        /* Dummy map to satisfy the verifier */
        inner_map_fd = compat_bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(uint32_t), sizeof(uint32_t), 128U, NULL);
        if (inner_map_fd < 0)
                return log_error_errno(errno, "bpf-restrict-fs: Failed to create BPF map: %m");

        r = sym_bpf_map__set_inner_map_fd(obj->maps.cgroup_hash, inner_map_fd);
        assert(r <= 0);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fs: Failed to set inner map fd: %m");

        r = restrict_fs_bpf__load(obj);
        assert(r <= 0);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fs: Failed to load BPF object: %m");

        *ret_obj = TAKE_PTR(obj);

        return 0;
}

bool bpf_restrict_fs_supported(bool initialize) {
        _cleanup_(restrict_fs_bpf_freep) struct restrict_fs_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;
        if (!initialize)
                return false;

        if (!cgroup_bpf_supported())
                return (supported = false);

        r = lsm_supported("bpf");
        if (r == -ENOPKG) {
                log_info_errno(r, "bpf-restrict-fs: securityfs not mounted, BPF LSM support not available.");
                return (supported = false);
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-restrict-fs: Can't determine whether the BPF LSM module is used: %m");
                return (supported = false);
        }
        if (r == 0) {
                log_info("bpf-restrict-fs: BPF LSM hook not enabled in the kernel, BPF LSM not supported.");
                return (supported = false);
        }

        r = prepare_restrict_fs_bpf(&obj);
        if (r < 0)
                return (supported = false);

        if (!bpf_can_link_lsm_program(obj->progs.restrict_filesystems)) {
                log_warning("bpf-restrict-fs: Failed to link program; assuming BPF LSM is not available.");
                return (supported = false);
        }

        return (supported = true);
}

int bpf_restrict_fs_setup(Manager *m) {
        _cleanup_(restrict_fs_bpf_freep) struct restrict_fs_bpf *obj = NULL;
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        int r;

        assert(m);

        r = prepare_restrict_fs_bpf(&obj);
        if (r < 0)
                return r;

        link = sym_bpf_program__attach_lsm(obj->progs.restrict_filesystems);
        r = bpf_get_error_translated(link);
        if (r != 0)
                return log_error_errno(r, "bpf-restrict-fs: Failed to link '%s' LSM BPF program: %m",
                                       sym_bpf_program__name(obj->progs.restrict_filesystems));

        log_info("bpf-restrict-fs: LSM BPF program attached");

        obj->links.restrict_filesystems = TAKE_PTR(link);
        m->restrict_fs = TAKE_PTR(obj);

        return 0;
}

int bpf_restrict_fs_update(const Set *filesystems, uint64_t cgroup_id, int outer_map_fd, bool allow_list) {
        uint32_t dummy_value = 1, zero = 0;
        const char *fs;
        const statfs_f_type_t *magic;
        int r;

        assert(filesystems);
        assert(outer_map_fd >= 0);

        int inner_map_fd = compat_bpf_map_create(
                        BPF_MAP_TYPE_HASH,
                        NULL,
                        sizeof(uint32_t),
                        sizeof(uint32_t),
                        128U, /* Should be enough for all filesystem types */
                        NULL);
        if (inner_map_fd < 0)
                return log_error_errno(errno, "bpf-restrict-fs: Failed to create inner BPF map: %m");

        if (sym_bpf_map_update_elem(outer_map_fd, &cgroup_id, &inner_map_fd, BPF_ANY) != 0)
                return log_error_errno(errno, "bpf-restrict-fs: Error populating BPF map: %m");

        uint32_t allow = allow_list;

        /* Use key 0 to store whether this is an allow list or a deny list */
        if (sym_bpf_map_update_elem(inner_map_fd, &zero, &allow, BPF_ANY) != 0)
                return log_error_errno(errno, "bpf-restrict-fs: Error initializing map: %m");

        SET_FOREACH(fs, filesystems) {
                r = fs_type_from_string(fs, &magic);
                if (r < 0) {
                        log_warning("bpf-restrict-fs: Invalid filesystem name '%s', ignoring.", fs);
                        continue;
                }

                log_debug("bpf-restrict-fs: Restricting filesystem access to '%s'", fs);

                for (int i = 0; i < FILESYSTEM_MAGIC_MAX; i++) {
                        if (magic[i] == 0)
                                break;

                        if (sym_bpf_map_update_elem(inner_map_fd, &magic[i], &dummy_value, BPF_ANY) != 0) {
                                r = log_error_errno(errno, "bpf-restrict-fs: Failed to update BPF map: %m");

                                if (sym_bpf_map_delete_elem(outer_map_fd, &cgroup_id) != 0)
                                        log_debug_errno(errno, "bpf-restrict-fs: Failed to delete cgroup entry from BPF map: %m");

                                return r;
                        }
                }
        }

        return 0;
}

int bpf_restrict_fs_cleanup(Unit *u) {
        CGroupRuntime *crt;

        assert(u);
        assert(u->manager);

        /* If we never successfully detected support, there is nothing to clean up. */
        if (!bpf_restrict_fs_supported(/* initialize = */ false))
                return 0;

        if (!u->manager->restrict_fs)
                return 0;

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        if (crt->cgroup_id == 0)
                return 0;

        int fd = sym_bpf_map__fd(u->manager->restrict_fs->maps.cgroup_hash);
        if (fd < 0)
                return log_unit_error_errno(u, errno, "bpf-restrict-fs: Failed to get BPF map fd: %m");

        if (sym_bpf_map_delete_elem(fd, &crt->cgroup_id) != 0 && errno != ENOENT)
                return log_unit_debug_errno(u, errno, "bpf-restrict-fs: Failed to delete cgroup entry from LSM BPF map: %m");

        return 0;
}

int bpf_restrict_fs_map_fd(Unit *unit) {
        assert(unit);
        assert(unit->manager);

        if (!unit->manager->restrict_fs)
                return -ENOMEDIUM;

        return sym_bpf_map__fd(unit->manager->restrict_fs->maps.cgroup_hash);
}

void bpf_restrict_fs_destroy(struct restrict_fs_bpf *prog) {
        restrict_fs_bpf__destroy(prog);
}
#else /* ! BPF_FRAMEWORK */
bool bpf_restrict_fs_supported(bool initialize) {
        return false;
}

int bpf_restrict_fs_setup(Manager *m) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-restrict-fs: BPF framework is not supported.");
}

int bpf_restrict_fs_update(const Set *filesystems, uint64_t cgroup_id, int outer_map_fd, const bool allow_list) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-restrict-fs: BPF framework is not supported.");
}

int bpf_restrict_fs_cleanup(Unit *u) {
        return 0;
}

int bpf_restrict_fs_map_fd(Unit *unit) {
        return -ENOMEDIUM;
}

void bpf_restrict_fs_destroy(struct restrict_fs_bpf *prog) {
        return;
}
#endif

int bpf_restrict_fs_parse_filesystem(
                const char *name,
                Set **filesystems,
                FilesystemParseFlags flags,
                const char *unit,
                const char *filename,
                unsigned line) {
        int r;

        assert(name);
        assert(filesystems);

        if (name[0] == '@') {
                const FilesystemSet *set;

                set = filesystem_set_find(name);
                if (!set) {
                        log_syntax(unit, flags & FILESYSTEM_PARSE_LOG ? LOG_WARNING : LOG_DEBUG, filename, line, 0,
                                   "bpf-restrict-fs: Unknown filesystem group, ignoring: %s", name);
                        return 0;
                }

                NULSTR_FOREACH(i, set->value) {
                        /* Call ourselves again, for the group to parse. Note that we downgrade logging here
                         * (i.e. take away the FILESYSTEM_PARSE_LOG flag) since any issues in the group table
                         * are our own problem, not a problem in user configuration data and we shouldn't
                         * pretend otherwise by complaining about them. */
                        r = bpf_restrict_fs_parse_filesystem(i, filesystems, flags &~ FILESYSTEM_PARSE_LOG, unit, filename, line);
                        if (r < 0)
                                return r;
                }
        } else {
                /* If we previously wanted to forbid access to a filesystem and now
                 * we want to allow it, then remove it from the list. */
                if (!(flags & FILESYSTEM_PARSE_INVERT) == !!(flags & FILESYSTEM_PARSE_ALLOW_LIST)) {
                        r = set_put_strdup(filesystems, name);
                        if (r == -ENOMEM)
                                return flags & FILESYSTEM_PARSE_LOG ? log_oom() : -ENOMEM;
                        if (r < 0 && r != -EEXIST)  /* When already in set, ignore */
                                return r;
                } else
                        free(set_remove(*filesystems, name));
        }

        return 0;
}
