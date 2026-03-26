/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "bpf-restrict-exec.h"
#include "fileio.h"
#include "initrd-util.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "memory-util.h"
#include "parse-util.h"
#include "serialize.h"
#include "string-table.h"

/* DMVERITY_DEVICES_MAX lives in bpf-restrict-exec.h for sharing with tests. */

static const char* const restrict_exec_table[_RESTRICT_EXEC_MAX] = {
        [RESTRICT_EXEC_NO]     = "no",
        [RESTRICT_EXEC_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(restrict_exec, RestrictExec, RESTRICT_EXEC_STRICT);

const char* const restrict_exec_link_names[_RESTRICT_EXEC_LINK_MAX] = {
        [RESTRICT_EXEC_LINK_BDEV_SETINTEGRITY] = "restrict-exec-bdev-setintegrity-link",
        [RESTRICT_EXEC_LINK_BDEV_FREE]         = "restrict-exec-bdev-free-link",
        [RESTRICT_EXEC_LINK_BPRM_CHECK]        = "restrict-exec-bprm-check-link",
        [RESTRICT_EXEC_LINK_MMAP_FILE]         = "restrict-exec-mmap-file-link",
        [RESTRICT_EXEC_LINK_FILE_MPROTECT]     = "restrict-exec-file-mprotect-link",
        [RESTRICT_EXEC_LINK_PTRACE_GUARD]      = "restrict-exec-ptrace-guard-link",
        [RESTRICT_EXEC_LINK_BPF_MAP_GUARD]     = "restrict-exec-bpf-map-guard-link",
        [RESTRICT_EXEC_LINK_BPF_PROG_GUARD]    = "restrict-exec-bpf-prog-guard-link",
        [RESTRICT_EXEC_LINK_BPF_GUARD]         = "restrict-exec-bpf-guard-link",
};

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/restrict-exec/restrict-exec-skel.h"

/* Verify that restrict_exec_bss matches the skeleton's .bss layout. The sizeof
 * check catches field additions/removals; the offsetof checks catch field
 * reordering. Field order in restrict_exec_bss must match the BPF global
 * declaration order in restrict-exec.bpf.c — this is what bpftool uses for the
 * generated struct. The read-modify-write in restrict_exec_clear_initramfs_trust()
 * depends on this layout. */
assert_cc(sizeof(struct restrict_exec_bss) == sizeof_field(struct restrict_exec_bpf, bss[0]));
assert_cc(offsetof(struct restrict_exec_bss, initramfs_s_dev) ==
          offsetof(typeof_field(struct restrict_exec_bpf, bss[0]), initramfs_s_dev));
assert_cc(offsetof(struct restrict_exec_bss, protected_map_id_verity) ==
          offsetof(typeof_field(struct restrict_exec_bpf, bss[0]), protected_map_id_verity));
assert_cc(offsetof(struct restrict_exec_bss, protected_map_id_bss) ==
          offsetof(typeof_field(struct restrict_exec_bpf, bss[0]), protected_map_id_bss));

/* Build the skeleton links array indexed by the link enum. */
#define RESTRICT_EXEC_LINKS(obj) {                                                              \
        [RESTRICT_EXEC_LINK_BDEV_SETINTEGRITY] = (obj)->links.restrict_exec_bdev_setintegrity,   \
        [RESTRICT_EXEC_LINK_BDEV_FREE]         = (obj)->links.restrict_exec_bdev_free,           \
        [RESTRICT_EXEC_LINK_BPRM_CHECK]        = (obj)->links.restrict_exec_bprm_check,         \
        [RESTRICT_EXEC_LINK_MMAP_FILE]         = (obj)->links.restrict_exec_mmap_file,           \
        [RESTRICT_EXEC_LINK_FILE_MPROTECT]     = (obj)->links.restrict_exec_file_mprotect,       \
        [RESTRICT_EXEC_LINK_PTRACE_GUARD]      = (obj)->links.restrict_exec_ptrace_guard,        \
        [RESTRICT_EXEC_LINK_BPF_MAP_GUARD]     = (obj)->links.restrict_exec_bpf_map_guard,       \
        [RESTRICT_EXEC_LINK_BPF_PROG_GUARD]    = (obj)->links.restrict_exec_bpf_prog_guard,      \
        [RESTRICT_EXEC_LINK_BPF_GUARD]         = (obj)->links.restrict_exec_bpf_guard,           \
}

bool dm_verity_require_signatures(void) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = read_one_line_file("/sys/module/dm_verity/parameters/require_signatures", &val);
        if (r == -ENOENT) {
                log_debug("bpf-restrict-exec: dm-verity module not loaded, require_signatures not available.");
                return false;
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-restrict-exec: Failed to read dm-verity require_signatures: %m");
                return false;
        }

        return parse_boolean(val) > 0;
}

static int get_root_s_dev(uint32_t *ret) {
        struct stat st;

        assert(ret);

        /* Stat /usr/ rather than / — executable code lives in /usr/ and we push toward
         * a writable non-executable /. On systems with a separate /usr partition this
         * means / is intentionally not trusted. */
        if (stat("/usr/", &st) < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to stat /usr/ filesystem: %m");

        *ret = STAT_DEV_TO_KERNEL(st.st_dev);
        return 0;
}

static int prepare_restrict_exec_bpf(struct restrict_exec_bpf **ret) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        int r;

        assert(ret);

        obj = restrict_exec_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to open BPF object: %m");

        r = sym_bpf_map__set_max_entries(obj->maps.verity_devices, DMVERITY_DEVICES_MAX);
        if (r < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to size hash table: %m");

        r = restrict_exec_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to load BPF object: %m");

        *ret = TAKE_PTR(obj);
        return 0;
}

bool bpf_restrict_exec_supported(void) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;
        if (dlopen_bpf_full(LOG_WARNING) < 0)
                return (supported = false);

        r = lsm_supported("bpf");
        if (r == -ENOPKG) {
                log_debug_errno(r, "bpf-restrict-exec: securityfs not mounted, BPF LSM not available.");
                return (supported = false);
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-restrict-exec: Can't determine whether the BPF LSM module is used: %m");
                return (supported = false);
        }
        if (r == 0) {
                log_info("bpf-restrict-exec: BPF LSM hook not enabled in the kernel, not supported.");
                return (supported = false);
        }

        r = prepare_restrict_exec_bpf(&obj);
        if (r < 0)
                return (supported = false);

        if (!bpf_can_link_lsm_program(obj->progs.restrict_exec_bprm_check)) {
                log_warning("bpf-restrict-exec: Failed to link program; assuming BPF LSM is not available.");
                return (supported = false);
        }

        return (supported = true);
}

static bool restrict_exec_have_deserialized_fds(Manager *m) {
        size_t count = 0;

        assert(m);

        /* Check if we have link FDs deserialized from a previous exec */
        FOREACH_ELEMENT(fd, m->restrict_exec_link_fds)
                if (*fd >= 0)
                        count++;

        if (count > 0 && count < ELEMENTSOF(m->restrict_exec_link_fds))
                log_error("bpf-restrict-exec: Only %zu of %zu link FDs deserialized, enforcement may be incomplete.",
                          count, ELEMENTSOF(m->restrict_exec_link_fds));

        return count > 0;
}

/* Close the initramfs trust window after switch_root by clearing initramfs_s_dev
 * in the BPF .bss map. The .bss is a BPF_F_MMAPABLE array map — mmap it and do
 * a single aligned 4-byte store instead of a full-value read-modify-write via
 * bpf_map_update_elem, which would needlessly rewrite the guard globals too. */
static int restrict_exec_clear_initramfs_trust(int bss_map_fd) {
        void *p;

        assert(bss_map_fd >= 0);
        assert_cc(offsetof(struct restrict_exec_bss, initramfs_s_dev) == 0);

        p = mmap(NULL, page_size(), PROT_READ | PROT_WRITE, MAP_SHARED, bss_map_fd, 0);
        if (p == MAP_FAILED)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to mmap .bss map: %m");

        /* initramfs_s_dev is at offset 0 in the .bss layout. Single aligned
         * 32-bit store is atomic — BPF programs see either the old or new value,
         * no torn reads possible. Guard globals are untouched. */
        *(uint32_t *) p = 0;

        if (munmap(p, page_size()) < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to munmap .bss map: %m");

        log_info("bpf-restrict-exec: Cleared initramfs trust window after switch_root.");
        return 0;
}

static int bpf_get_map_id(int fd, uint32_t *ret_id) {
        struct bpf_map_info info = {};
        uint32_t len = sizeof(info);
        int r;

        if (fd < 0)
                return -EBADF;

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

        if (fd < 0)
                return -EBADF;

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
int bpf_restrict_exec_populate_guard(struct restrict_exec_bpf *obj) {
        int r;

        assert(obj);

        struct bpf_link *links[] = RESTRICT_EXEC_LINKS(obj);
        assert_cc(ELEMENTSOF(links) == _RESTRICT_EXEC_LINK_MAX);

        /* Map IDs */
        r = bpf_get_map_id(sym_bpf_map__fd(obj->maps.verity_devices), &obj->bss->protected_map_id_verity);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to get verity_devices map ID: %m");

        r = bpf_get_map_id(sym_bpf_map__fd(obj->maps.bss), &obj->bss->protected_map_id_bss);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to get .bss map ID: %m");

        /* Link and program IDs (each link knows its associated program) */
        FOREACH_ELEMENT(link, links) {
                size_t idx = link - links;

                r = bpf_get_link_ids(sym_bpf_link__fd(*link),
                                     &obj->bss->protected_link_ids[idx],
                                     &obj->bss->protected_prog_ids[idx]);
                if (r < 0)
                        return log_error_errno(r, "bpf-restrict-exec: Failed to get link/prog IDs for %s: %m",
                                               restrict_exec_link_names[idx]);
        }

        log_info("bpf-restrict-exec: Guard globals populated (verity_map=%u, bss_map=%u)",
                 (unsigned) obj->bss->protected_map_id_verity,
                 (unsigned) obj->bss->protected_map_id_bss);
        return 0;
}

/* Validate that deserialized FDs actually reference BPF links. A corrupted
 * serialization file could leave FDs pointing at arbitrary kernel objects. */
static int restrict_exec_validate_deserialized_fds(Manager *m) {
        uint32_t id;
        int r;

        assert(m);

        r = dlopen_bpf_full(LOG_WARNING);
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "bpf-restrict-exec: Failed to load libbpf for FD validation, aborting.");

        FOREACH_ELEMENT(fd, m->restrict_exec_link_fds) {
                r = bpf_get_link_ids(*fd, &id, NULL);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "bpf-restrict-exec: Deserialized FD for %s is not a valid BPF link, aborting.",
                                               restrict_exec_link_names[fd - m->restrict_exec_link_fds]);
        }

        if (m->restrict_exec_bss_map_fd >= 0) {
                r = bpf_get_map_id(m->restrict_exec_bss_map_fd, &id);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "bpf-restrict-exec: Deserialized FD for .bss map is not a valid BPF map, aborting.");
        }

        return 0;
}

int bpf_restrict_exec_setup(Manager *m) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(m) || m->restrict_exec <= RESTRICT_EXEC_NO)
                return 0;

        /* If we already have link FDs from a previous exec, the BPF programs are still attached in the
         * kernel. Just keep holding the FDs — no need to re-create the skeleton. */
        if (restrict_exec_have_deserialized_fds(m)) {
                log_info("bpf-restrict-exec: Recovered link FDs from previous exec, programs still attached.");

                r = restrict_exec_validate_deserialized_fds(m);
                if (r < 0)
                        return r;
                if (m->switching_root) {
                        if (m->restrict_exec_bss_map_fd < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADF),
                                                       "bpf-restrict-exec: Cannot clear initramfs trust after switch_root.");
                        r = restrict_exec_clear_initramfs_trust(m->restrict_exec_bss_map_fd);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

        /* Fresh setup: verify BPF LSM is available */
        if (!bpf_restrict_exec_supported())
                return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                         "bpf-restrict-exec: BPF LSM is not available.");

        /* Require dm-verity signature enforcement */
        if (!dm_verity_require_signatures())
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                       "bpf-restrict-exec: dm-verity require_signatures is not enabled. "
                                       "RestrictExec= requires the kernel to enforce dm-verity signatures. "
                                       "Set dm_verity.require_signatures=1 on the kernel command line.");

        r = prepare_restrict_exec_bpf(&obj);
        if (r < 0)
                return r;

        /* If we're still in the initramfs, allow execution from it by recording
         * its s_dev. After switch_root, PID1 re-execs and in_initrd() returns
         * false — initramfs_s_dev stays at 0 (its default), closing the trust
         * window. */
        if (in_initrd()) {
                uint32_t root_dev;

                r = get_root_s_dev(&root_dev);
                if (r < 0)
                        return r;

                obj->bss->initramfs_s_dev = root_dev;
                log_info("bpf-restrict-exec: Initramfs trusted (s_dev=%" PRIu32 ":%" PRIu32 ")",
                         root_dev >> 20, root_dev & 0xFFFFF);
        }

        r = restrict_exec_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to attach BPF programs: %m");

        log_info("bpf-restrict-exec: LSM BPF programs attached");

        /* Now that all programs are attached, populate the guard's globals with
         * the kernel-assigned IDs of our maps, programs, and links. From this
         * point on, non-PID1 processes cannot obtain FDs to our BPF objects. */
        r = bpf_restrict_exec_populate_guard(obj);
        if (r < 0)
                return r;

        /* Extract owned FDs from the skeleton. These keep the kernel BPF objects
         * alive after the skeleton is destroyed. Destroying the skeleton unmaps
         * the .bss page from our address space so no BPF state (guard globals,
         * map IDs, initramfs_s_dev) is reachable via /proc/1/mem. */
        struct bpf_link *links[] = RESTRICT_EXEC_LINKS(obj);
        FOREACH_ELEMENT(link, links) {
                size_t idx = link - links;

                m->restrict_exec_link_fds[idx] = fcntl(sym_bpf_link__fd(*link), F_DUPFD_CLOEXEC, 3);
                if (m->restrict_exec_link_fds[idx] < 0)
                        return log_error_errno(errno, "bpf-restrict-exec: Failed to dup link FD for %s: %m",
                                               restrict_exec_link_names[idx]);
        }

        m->restrict_exec_bss_map_fd = fcntl(sym_bpf_map__fd(obj->maps.bss), F_DUPFD_CLOEXEC, 3);
        if (m->restrict_exec_bss_map_fd < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to dup .bss map FD: %m");

        return 0;
}

int bpf_restrict_exec_close_initramfs_trust(Manager *m) {
        assert(m);

        /* Clear initramfs_s_dev in the BPF .bss map BEFORE switch_root unmounts
         * the initramfs. This eliminates the dev_t recycling window: the anonymous
         * dev_t is still held by the mounted initramfs superblock, so no other
         * filesystem can recycle it yet. Anonymous dev_t recycling is immediate
         * and lowest-first, so a stale initramfs_s_dev is a near-certain trust
         * bypass — fail closed. */
        if (!in_initrd() || m->restrict_exec_bss_map_fd < 0)
                return 0;

        return restrict_exec_clear_initramfs_trust(m->restrict_exec_bss_map_fd);
}

int bpf_restrict_exec_serialize(Manager *m, FILE *f, FDSet *fds) {
        int r;

        assert(m);
        assert(f);
        assert(fds);

        if (!MANAGER_IS_SYSTEM(m) || m->restrict_exec <= RESTRICT_EXEC_NO)
                return 0;

        FOREACH_ELEMENT(fd, m->restrict_exec_link_fds) {
                r = serialize_fd(f, fds, restrict_exec_link_names[fd - m->restrict_exec_link_fds], *fd);
                if (r < 0)
                        return r;
        }

        r = serialize_fd(f, fds, "restrict-exec-bss-map", m->restrict_exec_bss_map_fd);
        if (r < 0)
                return r;

        return 0;
}

#else /* ! BPF_FRAMEWORK */

bool dm_verity_require_signatures(void) {
        return false;
}

bool bpf_restrict_exec_supported(void) {
        return false;
}

int bpf_restrict_exec_setup(Manager *m) {
        if (!MANAGER_IS_SYSTEM(m) || m->restrict_exec <= RESTRICT_EXEC_NO)
                return 0;

        return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                 "bpf-restrict-exec: RestrictExec= requested but BPF framework is not compiled in.");
}

int bpf_restrict_exec_populate_guard(struct restrict_exec_bpf *obj) {
        return 0;
}

int bpf_restrict_exec_close_initramfs_trust(Manager *m) {
        return 0;
}

int bpf_restrict_exec_serialize(Manager *m, FILE *f, FDSet *fds) {
        return 0;
}

#endif
