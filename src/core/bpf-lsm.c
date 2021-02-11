/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include "bpf-lsm.h"

#include <fcntl.h>
#include <linux/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "bpf-object.h"
#include "cgroup-util.h"
#include "filesystems-gperf.h"
#include "log.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "stat-util.h"
#include "fd-util.h"
#include "strv.h"

#if BUILD_BPF
/* libbpf, clang and llc compile time dependencies are satisfied */
#include <bpf/bpf.h>

#include "bpf/restrict_fs/restrict-fs-hexdump.h"

#define LSM_PROG_SECTION_NAME "lsm/file_open"
#define LSM_MAP_BPFFS_PATH "/sys/fs/bpf/systemd/lsm_bpf_map"

static int mac_bpf_use(void) {
        _cleanup_free_ char *lsm_list = NULL;
        static int cached_use = -1;
        int r;

        if (cached_use < 0) {
                cached_use = 0;

                r = read_one_line_file("/sys/kernel/security/lsm", &lsm_list);
                if (r < 0) {
                       if (errno != ENOENT)
                               log_debug_errno(r, "Failed to read /sys/kernel/security/lsm: %m");

                       return 0;
                }

                const char *p = lsm_list;

                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, ",", 0);
                        if (r == 0)
                                break;
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return 0;

                        if (strstr(word, "bpf")) {
                                cached_use = 1;
                                break;
                        }
                }
        }

        return cached_use;
}

int lsm_bpf_supported(void) {
        _cleanup_(bpf_object_freep) struct bpf_object *obj = NULL;
        _cleanup_close_ int inner_map_fd = -1;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0) {
                log_debug_errno(r, "Can't determine whether the unified hierarchy is used: %m");
                return supported = 0;
        }

        if (r == 0) {
                log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                         "Not running with unified cgroup hierarchy, LSM BPF is not supported");
                return supported = 0;
        }

        r = mac_bpf_use();
        if (r < 0) {
                log_debug_errno(r, "Can't determine whether the BPF LSM module is used: %m");
                return supported = 0;
        }

        if (r == 0) {
                log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                         "BPF LSM hook not enabled in the kernel");
                return supported = 0;
        }

        /*
         * Try loading bpf object with inner map to probe whether the BPF_PROG_TYPE_LSM program type and
         * BTF are supported by kernel and if resource limits allow locking enough memory for bpf programs.
         */
        r = bpf_object_new(restrict_fs_hexdump_buffer, sizeof(restrict_fs_hexdump_buffer), &obj);
        if (r < 0) {
                log_error_errno(r, "Failed to create BPF object from hexdump buffer: %m");
                return supported = 0;
        }

        /* Dummy map to satisfy the verifier */
        inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), 128, 0);
        if (inner_map_fd < 0) {
                log_debug_errno(errno, "Failed to create BPF map");
                return supported = 0;
        }

        r = bpf_object_set_inner_map_fd(obj, "cgroup_hash", inner_map_fd);
        if (r < 0) {
                log_debug_errno(r, "Failed to set inner map fd: %m");
                return supported = 0;
        }

        r = bpf_object_load(obj);
        if (r < 0) {
                log_debug_errno(errno, "Failed to load LSM BPF program: %m");
                return supported = 0;
        }

        return supported = 1;
}

int lsm_bpf_setup(void) {
        _cleanup_(bpf_object_freep) struct bpf_object *obj = NULL;
        struct bpf_program *prog = NULL;
        struct bpf_link *link = NULL;
        _cleanup_close_ int inner_map_fd = -1;
        int outer_map_fd;
        int r;

        r = bpf_object_new(restrict_fs_hexdump_buffer, sizeof(restrict_fs_hexdump_buffer), &obj);
        if (r < 0)
                return log_error_errno(r, "Failed to create BPF object from hexdump buffer: %m");

        /* Dummy map to satisfy the verifier */
        inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), 128, 0);
        if (inner_map_fd < 0)
                return log_error_errno(errno, "Failed to create BPF map: %m");

        r = bpf_object_set_inner_map_fd(obj, "cgroup_hash", inner_map_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to set inner map fd: %m");

        r = bpf_object_load(obj);
        if (r < 0)
                return log_error_errno(errno, "Failed to load LSM BPF program: %m");

        /* Close dummy map */
        inner_map_fd = safe_close(inner_map_fd);

        r = bpf_object_find_program_by_title(obj, LSM_PROG_SECTION_NAME, &prog);
        if (r < 0)
                return log_error_errno(r, "Failed to find LSM BPF program '%s': %m", LSM_PROG_SECTION_NAME);

        link = bpf_program__attach_lsm(prog);
        if (!link)
                return log_error_errno(errno, "Failed to attach BPF LSM program: %m");

        log_info("LSM BPF program attached");

        outer_map_fd = bpf_object_get_map_fd(obj, "cgroup_hash");
        if (outer_map_fd < 0)
                return log_error_errno(outer_map_fd, "Failed to get map fd: %m");

        r = mkdir_parents(LSM_MAP_BPFFS_PATH, 0700);
        if (r < 0)
                return log_error_errno(r, "Failed create systemd bpffs directory: %m");

        r = bpf_obj_pin(outer_map_fd, LSM_MAP_BPFFS_PATH);
        if (r < 0)
                return log_error_errno(r, "Failed to pin LSM BPF map in the bpffs: %m");

        return 0;
}

int bpf_restrict_filesystems(const Set *filesystems, const bool allow_list, const char *cgroup_path) {
        _cleanup_close_ int inner_map_fd = -1, outer_map_fd = -1;
        _cleanup_free_ char *path = NULL;
        uint64_t cgroup_id;
        uint32_t dummy_value = 1, zero = 0;
        const char *fs;
        statfs_f_type_t *magic;
        int r;

        assert(filesystems);
        assert(cgroup_path);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, cgroup_path, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to get systemd cgroup path: %m");

        r = cg_path_get_cgroupid(path, &cgroup_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get cgroup ID for path '%s': %m", path);

        inner_map_fd = bpf_create_map(
            BPF_MAP_TYPE_HASH,
            sizeof(uint32_t),
            sizeof(uint32_t),
            128, /* Should be enough for all filesystem types */
            0);
        if (inner_map_fd < 0)
                return log_error_errno(errno, "Failed to create inner LSM map: %m");

        outer_map_fd = bpf_obj_get(LSM_MAP_BPFFS_PATH);
        if (outer_map_fd < 0)
                return log_error_errno(errno, "Error getting pinned LSM BPF map: %m");

        if (bpf_map_update_elem(outer_map_fd, &cgroup_id, &inner_map_fd, BPF_ANY) != 0)
                return log_error_errno(errno, "Error populating LSM BPF map: %m");

        uint32_t allow = allow_list;

        /* Use key 0 to store whether this is an allow list or a deny list */
        if (bpf_map_update_elem(inner_map_fd, &zero, &allow, BPF_ANY) != 0)
                return log_error_errno(errno, "Error initializing BPF map: %m");

        SET_FOREACH(fs, filesystems) {
                int i;

                r = fs_type_from_string(fs, &magic);
                if (r < 0) {
                        log_warning("Invalid filesystem name '%s', ignoring.", fs);
                        continue;
                }

                log_debug("Restricting filesystem access to '%s'", fs);

                for (i=0; i<FILESYSTEM_MAGIC_MAX; i++) {
                        if (magic[i] == 0)
                                break;

                        if (bpf_map_update_elem(inner_map_fd, &magic[i], &dummy_value, BPF_ANY) != 0) {
                                r = log_error_errno(errno, "Failed to update BPF map: %m");

                                if (bpf_map_delete_elem(outer_map_fd, &cgroup_id) != 0)
                                        log_debug_errno(errno, "Failed to delete cgroup entry from LSM BPF map: %m");

                                return r;
                        }
                }
        }

        return 0;
}

int cleanup_lsm_bpf(const char *cgroup_path) {
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *path = NULL;
        uint64_t cgroup_id;
        int r;

        assert(cgroup_path);

        if (!lsm_bpf_supported())
                return 0;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, cgroup_path, NULL, &path);
        if (r < 0)
                return r;

        r = cg_path_get_cgroupid(path, &cgroup_id);
        if (r < 0)
                return r;

        fd = bpf_obj_get(LSM_MAP_BPFFS_PATH);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to get LSM Map object from bpffs: %m");

        if (bpf_map_delete_elem(fd, &cgroup_id) != 0)
                return log_debug_errno(errno, "Failed to delete cgroup entry from LSM BPF map: %m");

        return 0;
}
#else /* ! BUILD_BPF */
int lsm_bpf_supported(void) {
        return 0;
}

int lsm_bpf_setup(void) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to set up LSM BPF: %m");
}

int bpf_restrict_filesystems(const Set *magic_numbers, char *cgroup_path) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to restrict filesystems using LSM BPF: %m");
}

int cleanup_lsm_bpf(const char *cgroup_path) {
        return 0;
}
#endif

int bpf_lsm_parse_filesystem(
                const char *name,
                Set *filesystems,
                FilesystemParseFlags flags,
                const char *unit,
                const char *filename,
                unsigned line) {
        char *fs;
        int r;

        assert(name);
        assert(filesystems);

        if (name[0] == '@') {
                const FilesystemSet *set;
                const char *i;

                set = filesystem_set_find(name);
                if (!set) {
                        log_syntax(unit, flags & FILESYSTEM_PARSE_LOG ? LOG_WARNING : LOG_DEBUG, filename, line, 0,
                                   "Unknown filesystem group, ignoring: %s", name);
                        return 0;
                }

                NULSTR_FOREACH(i, set->value) {
                        /* Call ourselves again, for the group to parse. Note that we downgrade logging here (i.e. take
                         * away the FILESYSTEM_PARSE_LOG flag) since any issues in the group table are our own problem,
                         * not a problem in user configuration data and we shouldn't pretend otherwise by complaining
                         * about them. */
                        r = bpf_lsm_parse_filesystem(i, filesystems, flags &~ FILESYSTEM_PARSE_LOG, unit, filename, line);
                        if (r < 0)
                                return r;
                }
        } else {
                /* If we previously wanted to forbid access to a filesystem and now
                 * we want to allow it, then remove it from the list. */
                if (!(flags & FILESYSTEM_PARSE_INVERT) == !!(flags & FILESYSTEM_PARSE_ALLOW_LIST)) {
                        SET_FOREACH(fs, filesystems) {
                                if (streq(fs, name)) {
                                        /* Already present, ignoring */
                                        return 0;
                                }
                        }

                        r = set_put_strdup(&filesystems, name);
                        if (r < 0)
                                switch (r) {
                                case -ENOMEM:
                                        return flags & FILESYSTEM_PARSE_LOG ? log_oom() : -ENOMEM;
                                case -EEXIST:
                                        /* Alredy in set, ignore */
                                        break;
                                default:
                                        return r;
                                }
                } else {
                        SET_FOREACH(fs, filesystems) {
                                if (streq(fs, name)) {
                                        free(set_remove(filesystems, fs));
                                        break;
                                }
                        }
                }
        }

        return 0;
}
