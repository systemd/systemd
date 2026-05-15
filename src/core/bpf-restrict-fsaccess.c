/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "bpf-restrict-fsaccess.h"
#include "fd-util.h"
#include "fileio.h"
#include "initrd-util.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "memory-util.h"
#include "serialize.h"
#include "string-table.h"

/* DMVERITY_DEVICES_MAX lives in bpf-restrict-fsaccess.h for sharing with tests. */

static const char* const restrict_filesystem_access_table[_RESTRICT_FILESYSTEM_ACCESS_MAX] = {
        [RESTRICT_FILESYSTEM_ACCESS_NO]   = "no",
        [RESTRICT_FILESYSTEM_ACCESS_EXEC] = "exec",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(restrict_filesystem_access, RestrictFileSystemAccess, RESTRICT_FILESYSTEM_ACCESS_EXEC);

const char* const restrict_fsaccess_link_names[_RESTRICT_FILESYSTEM_ACCESS_LINK_MAX] = {
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BDEV_SETINTEGRITY] = "restrict-fsaccess-bdev-setintegrity-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BDEV_FREE]         = "restrict-fsaccess-bdev-free-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPRM_CHECK]        = "restrict-fsaccess-bprm-check-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_MMAP_FILE]         = "restrict-fsaccess-mmap-file-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_FILE_MPROTECT]     = "restrict-fsaccess-file-mprotect-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_PTRACE_GUARD]      = "restrict-fsaccess-ptrace-guard-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_MAP_GUARD]     = "restrict-fsaccess-bpf-map-guard-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_PROG_GUARD]    = "restrict-fsaccess-bpf-prog-guard-link",
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_GUARD]         = "restrict-fsaccess-bpf-guard-link",
};

#if BPF_FRAMEWORK && HAVE_LSM_INTEGRITY_TYPE
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "restrict-fsaccess-skel.h"

static struct restrict_fsaccess_bpf *restrict_fsaccess_bpf_free(struct restrict_fsaccess_bpf *obj) {
        restrict_fsaccess_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct restrict_fsaccess_bpf *, restrict_fsaccess_bpf_free);

/* Verify that restrict_fsaccess_bss matches the skeleton's .bss layout. The sizeof
 * check catches field additions/removals; the offsetof checks catch field
 * reordering. Field order in restrict_fsaccess_bss must match the BPF global
 * declaration order in restrict-fsaccess.bpf.c — this is what bpftool uses for the
 * generated struct. The read-modify-write in restrict_fsaccess_clear_initramfs_trust()
 * depends on this layout. */
assert_cc(sizeof(struct restrict_fsaccess_bss) == sizeof_field(struct restrict_fsaccess_bpf, bss[0]));
assert_cc(offsetof(struct restrict_fsaccess_bss, initramfs_s_dev) ==
          offsetof(typeof_field(struct restrict_fsaccess_bpf, bss[0]), initramfs_s_dev));
assert_cc(offsetof(struct restrict_fsaccess_bss, protected_map_id_verity) ==
          offsetof(typeof_field(struct restrict_fsaccess_bpf, bss[0]), protected_map_id_verity));
assert_cc(offsetof(struct restrict_fsaccess_bss, protected_map_id_bss) ==
          offsetof(typeof_field(struct restrict_fsaccess_bpf, bss[0]), protected_map_id_bss));

/* Build the skeleton links array indexed by the link enum.
 * For BDEV_SETINTEGRITY, use whichever variant was loaded (full or compat).
 * This compat logic can be removed once the kernel baseline includes
 * 1271a40eeafa ("bpf: Allow access to const void pointer arguments"). */
#define RESTRICT_FSACCESS_LINKS(obj) {                                                                      \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BDEV_SETINTEGRITY] = (obj)->links.restrict_fsaccess_bdev_setintegrity ?:        \
                                                 (obj)->links.restrict_fsaccess_bdev_setintegrity_compat,   \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BDEV_FREE]         = (obj)->links.restrict_fsaccess_bdev_free,                  \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPRM_CHECK]        = (obj)->links.restrict_fsaccess_bprm_check,                 \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_MMAP_FILE]         = (obj)->links.restrict_fsaccess_mmap_file,                  \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_FILE_MPROTECT]     = (obj)->links.restrict_fsaccess_file_mprotect,              \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_PTRACE_GUARD]      = (obj)->links.restrict_fsaccess_ptrace_guard,               \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_MAP_GUARD]     = (obj)->links.restrict_fsaccess_bpf_map_guard,              \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_PROG_GUARD]    = (obj)->links.restrict_fsaccess_bpf_prog_guard,             \
        [RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_GUARD]         = (obj)->links.restrict_fsaccess_bpf_guard,                  \
}

bool dm_verity_require_signatures(void) {
        int r;

        r = read_boolean_file("/sys/module/dm_verity/parameters/require_signatures");
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_errno(r, "bpf-restrict-fsaccess: Failed to read dm-verity require_signatures: %m");
                return false;
        }

        return r > 0;
}

static int get_root_s_dev(uint32_t *ret) {
        struct stat st;

        assert(ret);

        /* Stat /usr/ rather than / — executable code lives in /usr/ and we push toward
         * a writable non-executable /. On systems with a separate /usr partition this
         * means / is intentionally not trusted. */
        if (stat("/usr/", &st) < 0)
                return log_error_errno(errno, "bpf-restrict-fsaccess: Failed to stat /usr/ filesystem: %m");

        *ret = STAT_DEV_TO_KERNEL(st.st_dev);
        return 0;
}

int bpf_restrict_fsaccess_prepare(struct restrict_fsaccess_bpf **ret) {
        _cleanup_(restrict_fsaccess_bpf_freep) struct restrict_fsaccess_bpf *obj = NULL;
        int r;

        assert(ret);

        /* Try the preferred version first — it reads the const void *value
         * argument for defense-in-depth. On kernels before v6.16 (missing
         * 1271a40eeafa) the verifier rejects loads from const void * context
         * arguments, so we fall back to the _compat variant that only reads
         * the size argument via raw ctx access. */
        obj = restrict_fsaccess_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-restrict-fsaccess: Failed to open BPF object: %m");

        r = sym_bpf_map__set_max_entries(obj->maps.verity_devices, DMVERITY_DEVICES_MAX);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to size hash table: %m");

        r = sym_bpf_program__set_autoload(obj->progs.restrict_fsaccess_bdev_setintegrity_compat, false);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to disable compat program: %m");

        r = restrict_fsaccess_bpf__load(obj);
        if (r >= 0) {
                log_debug("bpf-restrict-fsaccess: Loaded with full const void * access.");
                *ret = TAKE_PTR(obj);
                return 0;
        }

        log_debug_errno(r, "bpf-restrict-fsaccess: Full version failed to load (%m), trying compat variant.");
        obj = restrict_fsaccess_bpf_free(obj);

        obj = restrict_fsaccess_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-restrict-fsaccess: Failed to reopen BPF object: %m");

        r = sym_bpf_map__set_max_entries(obj->maps.verity_devices, DMVERITY_DEVICES_MAX);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to size hash table: %m");

        r = sym_bpf_program__set_autoload(obj->progs.restrict_fsaccess_bdev_setintegrity, false);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to disable full program: %m");

        r = restrict_fsaccess_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to load BPF object (compat): %m");

        log_debug("bpf-restrict-fsaccess: Loaded with compat bdev_setintegrity.");
        *ret = TAKE_PTR(obj);
        return 0;
}

bool bpf_restrict_fsaccess_supported(void) {
        _cleanup_(restrict_fsaccess_bpf_freep) struct restrict_fsaccess_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;
        if (dlopen_bpf(LOG_WARNING) < 0)
                return (supported = false);

        r = lsm_supported("bpf");
        if (r == -ENOPKG) {
                log_debug_errno(r, "bpf-restrict-fsaccess: securityfs not mounted, BPF LSM not available.");
                return (supported = false);
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-restrict-fsaccess: Can't determine whether the BPF LSM module is used: %m");
                return (supported = false);
        }
        if (r == 0) {
                log_info("bpf-restrict-fsaccess: BPF LSM hook not enabled in the kernel, not supported.");
                return (supported = false);
        }

        r = bpf_restrict_fsaccess_prepare(&obj);
        if (r < 0)
                return (supported = false);

        if (!bpf_can_link_lsm_program(obj->progs.restrict_fsaccess_bprm_check)) {
                log_warning("bpf-restrict-fsaccess: Failed to link program; assuming BPF LSM is not available.");
                return (supported = false);
        }

        return (supported = true);
}

/* Partial deserialization (some FDs but not all) is fatal: continuing
 * would leave enforcement incomplete. */
static int restrict_fsaccess_have_deserialized_fds(Manager *m) {
        size_t count = 0;

        assert(m);

        FOREACH_ELEMENT(fd, m->restrict_fsaccess_link_fds)
                if (*fd >= 0)
                        count++;

        if (count == 0)
                return 0;
        if (count == ELEMENTSOF(m->restrict_fsaccess_link_fds))
                return 1;

        return log_error_errno(SYNTHETIC_ERRNO(EBADFD),
                               "bpf-restrict-fsaccess: Only %zu of %zu link FDs deserialized, refusing to continue with partial enforcement.",
                               count, ELEMENTSOF(m->restrict_fsaccess_link_fds));
}

/* Close the initramfs trust window after switch_root by clearing initramfs_s_dev
 * in the BPF .bss map. The .bss is a BPF_F_MMAPABLE array map — mmap it and do
 * a single aligned 4-byte store instead of a full-value read-modify-write via
 * bpf_map_update_elem, which would needlessly rewrite the guard globals too. */
static int restrict_fsaccess_clear_initramfs_trust(int bss_map_fd) {
        void *p;

        assert(bss_map_fd >= 0);
        assert_cc(offsetof(struct restrict_fsaccess_bss, initramfs_s_dev) == 0);

        p = mmap(NULL, page_size(), PROT_READ | PROT_WRITE, MAP_SHARED, bss_map_fd, 0);
        if (p == MAP_FAILED)
                return log_error_errno(errno, "bpf-restrict-fsaccess: Failed to mmap .bss map: %m");

        /* initramfs_s_dev is at offset 0 in the .bss layout. Single aligned
         * 32-bit store is atomic — BPF programs see either the old or new value,
         * no torn reads possible. Guard globals are untouched. */
        *(uint32_t *) p = 0;

        /* munmap failure here is harmless: the clear above already landed in
         * the kernel, and the mapping is discarded by exec anyway. */
        if (munmap(p, page_size()) < 0)
                log_warning_errno(errno, "bpf-restrict-fsaccess: Failed to munmap .bss map, ignoring: %m");

        log_info("bpf-restrict-fsaccess: Cleared initramfs trust window after switch_root.");
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

/* Populate guard globals with kernel-assigned IDs so the guard hooks block
 * non-PID1 access to our maps/progs/links via the bpf() syscall. */
int bpf_restrict_fsaccess_populate_guard(struct restrict_fsaccess_bpf *obj) {
        int r;

        assert(obj);

        struct bpf_link *links[] = RESTRICT_FSACCESS_LINKS(obj);
        assert_cc(ELEMENTSOF(links) == _RESTRICT_FILESYSTEM_ACCESS_LINK_MAX);

        /* Map IDs */
        r = bpf_get_map_id(sym_bpf_map__fd(obj->maps.verity_devices), &obj->bss->protected_map_id_verity);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to get verity_devices map ID: %m");

        r = bpf_get_map_id(sym_bpf_map__fd(obj->maps.bss), &obj->bss->protected_map_id_bss);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to get .bss map ID: %m");

        /* Link and program IDs (each link knows its associated program) */
        FOREACH_ELEMENT(link, links) {
                size_t idx = link - links;

                /* BDEV_SETINTEGRITY slot resolves via ?: between full and compat
                 * variants; assert at least one was attached. */
                if (!*link)
                        return log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                               "bpf-restrict-fsaccess: %s link missing after attach.",
                                               restrict_fsaccess_link_names[idx]);

                r = bpf_get_link_ids(sym_bpf_link__fd(*link),
                                     &obj->bss->protected_link_ids[idx],
                                     &obj->bss->protected_prog_ids[idx]);
                if (r < 0)
                        return log_error_errno(r, "bpf-restrict-fsaccess: Failed to get link/prog IDs for %s: %m",
                                               restrict_fsaccess_link_names[idx]);
        }

        log_info("bpf-restrict-fsaccess: Guard globals populated (verity_map=%u, bss_map=%u)",
                 (unsigned) obj->bss->protected_map_id_verity,
                 (unsigned) obj->bss->protected_map_id_bss);
        return 0;
}

/* Validate that deserialized FDs actually reference our LSM BPF links. A
 * corrupted serialization file could leave FDs pointing at arbitrary kernel
 * objects; a stale FD could point at a BPF link of an entirely different type
 * (e.g. kprobe-multi). Verify both link type and attach type so a substituted
 * FD that happens to be a BPF link still fails the check. */
static int restrict_fsaccess_validate_deserialized_fds(Manager *m) {
        int r;

        assert(m);

        r = dlopen_bpf(LOG_WARNING);
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "bpf-restrict-fsaccess: Failed to load libbpf for FD validation, aborting.");

        FOREACH_ELEMENT(fd, m->restrict_fsaccess_link_fds) {
                struct bpf_link_info info = {};
                uint32_t len = sizeof(info);
                const char *name = restrict_fsaccess_link_names[fd - m->restrict_fsaccess_link_fds];

                r = sym_bpf_obj_get_info_by_fd(*fd, &info, &len);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "bpf-restrict-fsaccess: Deserialized FD for %s is not a valid BPF object, aborting.",
                                               name);

                if (info.type != BPF_LINK_TYPE_TRACING || info.tracing.attach_type != BPF_LSM_MAC)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "bpf-restrict-fsaccess: Deserialized FD for %s is not an LSM tracing link (type=%u attach=%u), aborting.",
                                               name, info.type, info.tracing.attach_type);
        }

        if (m->restrict_fsaccess_bss_map_fd >= 0) {
                uint32_t id;

                r = bpf_get_map_id(m->restrict_fsaccess_bss_map_fd, &id);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "bpf-restrict-fsaccess: Deserialized FD for .bss map is not a valid BPF map, aborting.");
        }

        return 0;
}

int bpf_restrict_fsaccess_setup(Manager *m) {
        _cleanup_(restrict_fsaccess_bpf_freep) struct restrict_fsaccess_bpf *obj = NULL;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(m) || m->restrict_filesystem_access <= RESTRICT_FILESYSTEM_ACCESS_NO)
                return 0;

        r = restrict_fsaccess_have_deserialized_fds(m);
        if (r < 0)
                return r;
        if (r > 0) {
                log_info("bpf-restrict-fsaccess: Recovered link FDs from previous exec, programs still attached.");

                r = restrict_fsaccess_validate_deserialized_fds(m);
                if (r < 0)
                        return r;
                if (m->switching_root) {
                        if (m->restrict_fsaccess_bss_map_fd < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADF),
                                                       "bpf-restrict-fsaccess: Cannot clear initramfs trust after switch_root.");
                        r = restrict_fsaccess_clear_initramfs_trust(m->restrict_fsaccess_bss_map_fd);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

        /* Fresh setup: verify BPF LSM is available */
        if (!bpf_restrict_fsaccess_supported())
                return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                         "bpf-restrict-fsaccess: BPF LSM is not available.");

        /* Require dm-verity signature enforcement */
        if (!dm_verity_require_signatures())
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                       "bpf-restrict-fsaccess: dm-verity require_signatures is not enabled. "
                                       "RestrictFileSystemAccess= requires the kernel to enforce dm-verity signatures. "
                                       "Set dm_verity.require_signatures=1 on the kernel command line.");

        r = bpf_restrict_fsaccess_prepare(&obj);
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
                log_info("bpf-restrict-fsaccess: Initramfs trusted (s_dev=%" PRIu32 ":%" PRIu32 ")",
                         root_dev >> 20, root_dev & 0xFFFFF);
        }

        r = restrict_fsaccess_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-fsaccess: Failed to attach BPF programs: %m");

        log_info("bpf-restrict-fsaccess: LSM BPF programs attached");

        /* Now that all programs are attached, populate the guard's globals with
         * the kernel-assigned IDs of our maps, programs, and links. From this
         * point on, non-PID1 processes cannot obtain FDs to our BPF objects. */
        r = bpf_restrict_fsaccess_populate_guard(obj);
        if (r < 0)
                return r;

        /* Extract owned FDs from the skeleton. These keep the kernel BPF objects
         * alive after the skeleton is destroyed. Destroying the skeleton unmaps
         * the .bss page from our address space so no BPF state (guard globals,
         * map IDs, initramfs_s_dev) is reachable via /proc/1/mem. */
        struct bpf_link *links[] = RESTRICT_FSACCESS_LINKS(obj);
        FOREACH_ELEMENT(link, links) {
                size_t idx = link - links;

                if (!*link) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                            "bpf-restrict-fsaccess: %s link missing after attach.",
                                            restrict_fsaccess_link_names[idx]);
                        goto fail;
                }

                m->restrict_fsaccess_link_fds[idx] = fcntl(sym_bpf_link__fd(*link), F_DUPFD_CLOEXEC, 3);
                if (m->restrict_fsaccess_link_fds[idx] < 0) {
                        r = log_error_errno(errno, "bpf-restrict-fsaccess: Failed to dup link FD for %s: %m",
                                            restrict_fsaccess_link_names[idx]);
                        goto fail;
                }
        }

        m->restrict_fsaccess_bss_map_fd = fcntl(sym_bpf_map__fd(obj->maps.bss), F_DUPFD_CLOEXEC, 3);
        if (m->restrict_fsaccess_bss_map_fd < 0) {
                r = log_error_errno(errno, "bpf-restrict-fsaccess: Failed to dup .bss map FD: %m");
                goto fail;
        }

        return 0;

fail:
        /* Close partial FDs so we don't leave a half-baked policy attached
         * once the skeleton is destroyed by _cleanup_. */
        FOREACH_ELEMENT(fd, m->restrict_fsaccess_link_fds)
                *fd = safe_close(*fd);
        m->restrict_fsaccess_bss_map_fd = safe_close(m->restrict_fsaccess_bss_map_fd);
        return r;
}

int bpf_restrict_fsaccess_close_initramfs_trust(Manager *m) {
        assert(m);

        /* Clear initramfs_s_dev in the BPF .bss map BEFORE switch_root unmounts
         * the initramfs. This eliminates the dev_t recycling window: the anonymous
         * dev_t is still held by the mounted initramfs superblock, so no other
         * filesystem can recycle it yet. Anonymous dev_t recycling is immediate
         * and lowest-first, so a stale initramfs_s_dev is a near-certain trust
         * bypass — fail closed. */
        if (!in_initrd() || m->restrict_fsaccess_bss_map_fd < 0)
                return 0;

        return restrict_fsaccess_clear_initramfs_trust(m->restrict_fsaccess_bss_map_fd);
}

int bpf_restrict_fsaccess_serialize(Manager *m, FILE *f, FDSet *fds) {
        int r;

        assert(m);
        assert(f);
        assert(fds);

        if (!MANAGER_IS_SYSTEM(m) || m->restrict_filesystem_access <= RESTRICT_FILESYSTEM_ACCESS_NO)
                return 0;

        FOREACH_ELEMENT(fd, m->restrict_fsaccess_link_fds) {
                r = serialize_fd(f, fds, restrict_fsaccess_link_names[fd - m->restrict_fsaccess_link_fds], *fd);
                if (r < 0)
                        return r;
        }

        r = serialize_fd(f, fds, "restrict-fsaccess-bss-map", m->restrict_fsaccess_bss_map_fd);
        if (r < 0)
                return r;

        return 0;
}

#else /* ! BPF_FRAMEWORK || ! HAVE_LSM_INTEGRITY_TYPE */

bool dm_verity_require_signatures(void) {
        return false;
}

bool bpf_restrict_fsaccess_supported(void) {
        return false;
}

int bpf_restrict_fsaccess_setup(Manager *m) {
        if (!MANAGER_IS_SYSTEM(m) || m->restrict_filesystem_access <= RESTRICT_FILESYSTEM_ACCESS_NO)
                return 0;

        return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                 "bpf-restrict-fsaccess: RestrictFileSystemAccess= requested but BPF framework is not compiled in.");
}

int bpf_restrict_fsaccess_prepare(struct restrict_fsaccess_bpf **ret) {
        return -EOPNOTSUPP;
}

int bpf_restrict_fsaccess_populate_guard(struct restrict_fsaccess_bpf *obj) {
        return 0;
}

int bpf_restrict_fsaccess_close_initramfs_trust(Manager *m) {
        return 0;
}

int bpf_restrict_fsaccess_serialize(Manager *m, FILE *f, FDSet *fds) {
        return 0;
}

#endif
