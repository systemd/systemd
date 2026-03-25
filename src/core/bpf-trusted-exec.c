/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "alloc-util.h"
#include "bpf-trusted-exec.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "parse-util.h"
#include "serialize.h"

const char* const trusted_exec_link_names[_TRUSTED_EXEC_LINK_MAX] = {
        [TRUSTED_EXEC_LINK_BDEV_SETINTEGRITY] = "trusted-exec-bdev-setintegrity-link",
        [TRUSTED_EXEC_LINK_BDEV_FREE]         = "trusted-exec-bdev-free-link",
        [TRUSTED_EXEC_LINK_BPRM_CHECK]        = "trusted-exec-bprm-check-link",
        [TRUSTED_EXEC_LINK_MMAP_FILE]         = "trusted-exec-mmap-file-link",
        [TRUSTED_EXEC_LINK_FILE_MPROTECT]     = "trusted-exec-file-mprotect-link",
        [TRUSTED_EXEC_LINK_PTRACE_GUARD]      = "trusted-exec-ptrace-guard-link",
        [TRUSTED_EXEC_LINK_BPF_MAP_GUARD]     = "trusted-exec-bpf-map-guard-link",
        [TRUSTED_EXEC_LINK_BPF_PROG_GUARD]    = "trusted-exec-bpf-prog-guard-link",
        [TRUSTED_EXEC_LINK_BPF_GUARD]         = "trusted-exec-bpf-guard-link",
};

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/trusted-exec/trusted-exec-skel.h"

/* Verify that trusted_exec_bss matches the skeleton's .bss layout. The sizeof
 * check catches field additions/removals; the offsetof checks catch field
 * reordering. Field order in trusted_exec_bss must match the BPF global
 * declaration order in trusted-exec.bpf.c — this is what bpftool uses for the
 * generated struct. The read-modify-write in trusted_exec_clear_initramfs_trust()
 * depends on this layout. */
typedef typeof(*((struct trusted_exec_bpf *)0)->bss) trusted_exec_bpf_bss_skel_t;
assert_cc(sizeof(struct trusted_exec_bss) == sizeof(trusted_exec_bpf_bss_skel_t));
assert_cc(offsetof(struct trusted_exec_bss, initramfs_s_dev) ==
          offsetof(trusted_exec_bpf_bss_skel_t, initramfs_s_dev));
assert_cc(offsetof(struct trusted_exec_bss, protected_map_id_verity) ==
          offsetof(trusted_exec_bpf_bss_skel_t, protected_map_id_verity));

/* Build the skeleton links array indexed by the link enum. */
#define TRUSTED_EXEC_LINKS(obj) {                                                              \
        [TRUSTED_EXEC_LINK_BDEV_SETINTEGRITY] = (obj)->links.trusted_exec_bdev_setintegrity,   \
        [TRUSTED_EXEC_LINK_BDEV_FREE]         = (obj)->links.trusted_exec_bdev_free,           \
        [TRUSTED_EXEC_LINK_BPRM_CHECK]        = (obj)->links.trusted_exec_bprm_check,         \
        [TRUSTED_EXEC_LINK_MMAP_FILE]         = (obj)->links.trusted_exec_mmap_file,           \
        [TRUSTED_EXEC_LINK_FILE_MPROTECT]     = (obj)->links.trusted_exec_file_mprotect,       \
        [TRUSTED_EXEC_LINK_PTRACE_GUARD]      = (obj)->links.trusted_exec_ptrace_guard,        \
        [TRUSTED_EXEC_LINK_BPF_MAP_GUARD]     = (obj)->links.trusted_exec_bpf_map_guard,       \
        [TRUSTED_EXEC_LINK_BPF_PROG_GUARD]    = (obj)->links.trusted_exec_bpf_prog_guard,      \
        [TRUSTED_EXEC_LINK_BPF_GUARD]         = (obj)->links.trusted_exec_bpf_guard,           \
}

static bool dm_verity_require_signatures(void) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = read_one_line_file("/sys/module/dm_verity/parameters/require_signatures", &val);
        if (r == -ENOENT) {
                log_debug("bpf-trusted-exec: dm-verity module not loaded, require_signatures not available.");
                return false;
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-trusted-exec: Failed to read dm-verity require_signatures: %m");
                return false;
        }

        return parse_boolean(val) > 0;
}

static int get_root_s_dev(uint32_t *ret) {
        struct stat st;

        assert(ret);

        if (stat("/", &st) < 0)
                return log_error_errno(errno, "bpf-trusted-exec: Failed to stat root filesystem: %m");

        *ret = STAT_DEV_TO_KERNEL(st.st_dev);
        return 0;
}

static int prepare_trusted_exec_bpf(struct trusted_exec_bpf **ret) {
        _cleanup_(trusted_exec_bpf_freep) struct trusted_exec_bpf *obj = NULL;
        int r;

        assert(ret);

        obj = trusted_exec_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-trusted-exec: Failed to open BPF object: %m");

        r = trusted_exec_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to load BPF object: %m");

        *ret = TAKE_PTR(obj);
        return 0;
}

static const char* const trusted_exec_link_names[_TRUSTED_EXEC_LINK_MAX] = {
        [TRUSTED_EXEC_LINK_BDEV_SETINTEGRITY] = "trusted-exec-bdev-setintegrity-link",
        [TRUSTED_EXEC_LINK_BDEV_FREE]         = "trusted-exec-bdev-free-link",
        [TRUSTED_EXEC_LINK_BPRM_CHECK]        = "trusted-exec-bprm-check-link",
        [TRUSTED_EXEC_LINK_MMAP_FILE]         = "trusted-exec-mmap-file-link",
        [TRUSTED_EXEC_LINK_FILE_MPROTECT]     = "trusted-exec-file-mprotect-link",
        [TRUSTED_EXEC_LINK_PTRACE_GUARD]      = "trusted-exec-ptrace-guard-link",
        [TRUSTED_EXEC_LINK_BPF_MAP_GUARD]     = "trusted-exec-bpf-map-guard-link",
        [TRUSTED_EXEC_LINK_BPF_PROG_GUARD]    = "trusted-exec-bpf-prog-guard-link",
        [TRUSTED_EXEC_LINK_BPF_GUARD]         = "trusted-exec-bpf-guard-link",
};

static int bpf_get_map_id(int fd, uint32_t *ret_id) {
        struct bpf_map_info info = {};
        uint32_t len = sizeof(info);
        int r;

        assert(fd >= 0);
        assert(ret_id);

        r = sym_bpf_obj_get_info_by_fd(fd, &info, &len);
        if (r < 0)
                return r;

        *ret_id = info.id;
        return 0;
}

static int bpf_get_link_ids(int fd, uint32_t *ret_link_id, uint32_t *ret_prog_id) {
        struct bpf_link_info info = {};
        uint32_t len = sizeof(info);
        int r;

        assert(fd >= 0);

        r = sym_bpf_obj_get_info_by_fd(fd, &info, &len);
        if (r < 0)
                return r;

        if (ret_link_id)
                *ret_link_id = info.id;
        if (ret_prog_id)
                *ret_prog_id = info.prog_id;

        return 0;
}

/* Populate the guard BPF program's globals with the kernel-assigned IDs of all
 * maps, programs, and links in the skeleton. The guard uses these to block
 * non-PID1 processes from obtaining FDs to our BPF objects via the bpf() syscall. */
int bpf_trusted_exec_populate_guard(struct trusted_exec_bpf *obj) {
        int r;

        assert(obj);

        struct bpf_link *links[] = TRUSTED_EXEC_LINKS(obj);
        assert_cc(ELEMENTSOF(links) == _TRUSTED_EXEC_LINK_MAX);

        /* Map IDs */
        r = bpf_get_map_id(sym_bpf_map__fd(obj->maps.verity_devices), &obj->bss->protected_map_id_verity);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to get verity_devices map ID: %m");

        r = bpf_get_map_id(sym_bpf_map__fd(obj->maps.bss), &obj->bss->protected_map_id_bss);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to get .bss map ID: %m");

        /* Link and program IDs (each link knows its associated program) */
        for (size_t i = 0; i < ELEMENTSOF(links); i++) {
                r = bpf_get_link_ids(sym_bpf_link__fd(links[i]),
                                     &obj->bss->protected_link_ids[i],
                                     &obj->bss->protected_prog_ids[i]);
                if (r < 0)
                        return log_error_errno(r, "bpf-trusted-exec: Failed to get link/prog IDs for %s: %m",
                                               trusted_exec_link_names[i]);
        }

        log_info("bpf-trusted-exec: Guard globals populated (verity_map=%u, bss_map=%u)",
                 (unsigned) obj->bss->protected_map_id_verity,
                 (unsigned) obj->bss->protected_map_id_bss);
        return 0;
}

bool bpf_trusted_exec_supported(void) {
        _cleanup_(trusted_exec_bpf_freep) struct trusted_exec_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;
        if (dlopen_bpf_full(LOG_WARNING) < 0)
                return (supported = false);

        r = lsm_supported("bpf");
        if (r == -ENOPKG) {
                log_debug_errno(r, "bpf-trusted-exec: securityfs not mounted, BPF LSM not available.");
                return (supported = false);
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-trusted-exec: Can't determine whether the BPF LSM module is used: %m");
                return (supported = false);
        }
        if (r == 0) {
                log_info("bpf-trusted-exec: BPF LSM hook not enabled in the kernel, not supported.");
                return (supported = false);
        }

        r = prepare_trusted_exec_bpf(&obj);
        if (r < 0)
                return (supported = false);

        if (!bpf_can_link_lsm_program(obj->progs.trusted_exec_bprm_check)) {
                log_warning("bpf-trusted-exec: Failed to link program; assuming BPF LSM is not available.");
                return (supported = false);
        }

        return (supported = true);
}

static bool trusted_exec_have_deserialized_fds(Manager *m) {
        size_t count = 0;

        assert(m);

        /* Check if we have link FDs deserialized from a previous exec */
        for (size_t i = 0; i < ELEMENTSOF(m->trusted_exec_link_fds); i++)
                if (m->trusted_exec_link_fds[i] >= 0)
                        count++;

        if (count > 0 && count < ELEMENTSOF(m->trusted_exec_link_fds))
                log_error("bpf-trusted-exec: Only %zu of %zu link FDs deserialized, enforcement may be incomplete.",
                          count, ELEMENTSOF(m->trusted_exec_link_fds));

        return count > 0;
}

/* Close the initramfs trust window after switch_root by clearing initramfs_s_dev
 * in the BPF .bss map. We must read-modify-write the full .bss to preserve guard
 * globals (protected map/prog/link IDs). */
static int trusted_exec_clear_initramfs_trust(int bss_map_fd) {
        struct trusted_exec_bss bss = {};
        uint32_t key = 0;
        int r;

        r = dlopen_bpf_full(LOG_ERR);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to load libbpf for .bss update: %m");

        r = sym_bpf_map_lookup_elem(bss_map_fd, &key, &bss);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to read .bss map: %m");

        bss.initramfs_s_dev = 0;
        r = sym_bpf_map_update_elem(bss_map_fd, &key, &bss, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to clear initramfs_s_dev via .bss map: %m");

        log_info("bpf-trusted-exec: Cleared initramfs trust window after switch_root.");
        return 0;
}

/* Validate that deserialized FDs actually reference BPF links. A corrupted
 * serialization file could leave FDs pointing at arbitrary kernel objects. */
static void trusted_exec_validate_deserialized_fds(Manager *m) {
        int r;

        assert(m);

        r = dlopen_bpf_full(LOG_WARNING);
        if (r < 0) {
                log_warning_errno(r, "bpf-trusted-exec: Failed to load libbpf for FD validation, skipping.");
                return;
        }

        for (size_t i = 0; i < ELEMENTSOF(m->trusted_exec_link_fds); i++) {
                uint32_t link_id;

                if (m->trusted_exec_link_fds[i] < 0)
                        continue;

                r = bpf_get_link_ids(m->trusted_exec_link_fds[i], &link_id, NULL);
                if (r < 0) {
                        log_warning_errno(r, "bpf-trusted-exec: Deserialized FD for %s is not a valid BPF link, closing.",
                                          trusted_exec_link_names[i]);
                        m->trusted_exec_link_fds[i] = safe_close(m->trusted_exec_link_fds[i]);
                }
        }

        if (m->trusted_exec_bss_map_fd >= 0) {
                uint32_t map_id;

                r = bpf_get_map_id(m->trusted_exec_bss_map_fd, &map_id);
                if (r < 0) {
                        log_warning_errno(r, "bpf-trusted-exec: Deserialized FD for .bss map is not a valid BPF map, closing.");
                        m->trusted_exec_bss_map_fd = safe_close(m->trusted_exec_bss_map_fd);
                }
        }
}

int bpf_trusted_exec_setup(Manager *m) {
        _cleanup_(trusted_exec_bpf_freep) struct trusted_exec_bpf *obj = NULL;
        int r;

        assert(m);

        /* If we already have link FDs from a previous exec, the BPF programs are still attached in the
         * kernel. Just keep holding the FDs — no need to re-create the skeleton. */
        if (trusted_exec_have_deserialized_fds(m)) {
                log_info("bpf-trusted-exec: Recovered link FDs from previous exec, programs still attached.");

                trusted_exec_validate_deserialized_fds(m);

                /* Re-check: validation may have closed all FDs as invalid. If none survived, the old
                 * programs are gone — fall through to fresh setup. */
                if (!trusted_exec_have_deserialized_fds(m)) {
                        log_warning("bpf-trusted-exec: All deserialized link FDs failed validation, attempting fresh setup.");
                } else {
                        if (m->switching_root && m->trusted_exec_bss_map_fd >= 0)
                                (void) trusted_exec_clear_initramfs_trust(m->trusted_exec_bss_map_fd);

                        return 0;
                }
        }

        /* Fresh setup: verify BPF LSM is available */
        if (!bpf_trusted_exec_supported())
                return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                         "bpf-trusted-exec: BPF LSM is not available.");

        /* Require dm-verity signature enforcement */
        if (!dm_verity_require_signatures())
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                       "bpf-trusted-exec: dm-verity require_signatures is not enabled. "
                                       "TrustedExec= requires the kernel to enforce dm-verity signatures. "
                                       "Set dm_verity.require_signatures=1 on the kernel command line.");

        r = prepare_trusted_exec_bpf(&obj);
        if (r < 0)
                return r;

        /* If we haven't switched root yet, we're still on the initramfs. Allow
         * execution from the initramfs filesystem by recording its s_dev. After
         * switch_root, PID1 re-execs and this code runs again with
         * m->switching_root == true — at that point we leave initramfs_s_dev at
         * 0 (its default), closing the initramfs trust window. */
        if (!m->switching_root) {
                uint32_t root_dev;

                r = get_root_s_dev(&root_dev);
                if (r < 0)
                        return r;

                obj->bss->initramfs_s_dev = root_dev;
                log_info("bpf-trusted-exec: Initramfs trusted (s_dev=%u:%u)",
                         root_dev >> 20, root_dev & 0xFFFFF);
        }

        r = trusted_exec_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to attach BPF programs: %m");

        log_info("bpf-trusted-exec: LSM BPF programs attached");

        /* Now that all programs are attached, populate the guard's globals with
         * the kernel-assigned IDs of our maps, programs, and links. From this
         * point on, non-PID1 processes cannot obtain FDs to our BPF objects. */
        r = bpf_trusted_exec_populate_guard(obj);
        if (r < 0)
                return r;

        m->trusted_exec = TAKE_PTR(obj);
        return 0;
}

void bpf_trusted_exec_destroy(struct trusted_exec_bpf *prog) {
        trusted_exec_bpf__destroy(prog);
}

int bpf_trusted_exec_serialize(Manager *m, FILE *f, FDSet *fds) {
        int r;

        assert(m);
        assert(f);
        assert(fds);

        /* If we have a live skeleton, serialize from its link objects */
        if (m->trusted_exec) {
                struct bpf_link *links[] = TRUSTED_EXEC_LINKS(m->trusted_exec);

                for (size_t i = 0; i < ELEMENTSOF(links); i++) {
                        r = bpf_serialize_link(f, fds, trusted_exec_link_names[i], links[i]);
                        if (r < 0 && r != -ENOENT)
                                return r;
                }

                r = serialize_fd(f, fds, "trusted-exec-bss-map", sym_bpf_map__fd(m->trusted_exec->maps.bss));
                if (r < 0)
                        return r;

                return 0;
        }

        /* Otherwise, if we have raw FDs from a previous deserialization, forward those */
        for (size_t i = 0; i < ELEMENTSOF(m->trusted_exec_link_fds); i++) {
                r = serialize_fd(f, fds, trusted_exec_link_names[i], m->trusted_exec_link_fds[i]);
                if (r < 0)
                        return r;
        }

        r = serialize_fd(f, fds, "trusted-exec-bss-map", m->trusted_exec_bss_map_fd);
        if (r < 0)
                return r;

        return 0;
}

#else /* ! BPF_FRAMEWORK */

bool bpf_trusted_exec_supported(void) {
        return false;
}

int bpf_trusted_exec_setup(Manager *m) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-trusted-exec: BPF framework is not supported.");
}

void bpf_trusted_exec_destroy(struct trusted_exec_bpf *prog) {
        return;
}

int bpf_trusted_exec_populate_guard(struct trusted_exec_bpf *obj) {
        return 0;
}

int bpf_trusted_exec_serialize(Manager *m, FILE *f, FDSet *fds) {
        return 0;
}

#endif
