/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Test helper for RestrictFileSystemAccess= BPF enforcement tests.
 *
 * Usage:
 *   test-bpf-restrict-fsaccess attach              — Load, attach, print IDs, then block.
 *                                                Kill the process to detach (synchronous
 *                                                via bpf_link_put_direct on last FD close).
 *   test-bpf-restrict-fsaccess check               — Check BPF LSM + require_signatures preconditions
 *   test-bpf-restrict-fsaccess mmap-exec PATH      — Attempt PROT_READ|PROT_EXEC mmap of PATH
 *   test-bpf-restrict-fsaccess anon-mmap-exec      — Attempt anonymous PROT_READ|PROT_EXEC mmap
 *   test-bpf-restrict-fsaccess mprotect-exec PATH  — mmap PATH PROT_READ, then mprotect to PROT_EXEC
 *
 * When "attach" is used, the BPF LSM program is loaded with initramfs_s_dev
 * set to the current rootfs s_dev, so the calling test script (running from
 * the rootfs) continues to work. The process holds all link FDs and blocks;
 * when killed, close() drops the last reference synchronously.
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bpf-restrict-fsaccess.h"
#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

/* ---- mmap/mprotect probe commands (no BPF dependency) ----
 *
 * These exercise the mmap_file, file_mprotect, and anonymous-mmap LSM hooks.
 * The test script copies a file to tmpfs and passes its path here.
 * Returns 0 if the operation was allowed, negative errno if denied. */

static int do_mmap_exec(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        void *addr;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED)
                return log_info_errno(errno, "PROT_EXEC mmap of %s denied: %m", path);

        (void) munmap(addr, 4096);
        log_info("PROT_EXEC mmap of %s succeeded", path);
        return 0;
}

static int do_anon_mmap_exec(void) {
        void *addr;

        addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED)
                return log_info_errno(errno, "Anonymous PROT_EXEC mmap denied: %m");

        (void) munmap(addr, 4096);
        log_info("Anonymous PROT_EXEC mmap succeeded");
        return 0;
}

static int do_mprotect_exec(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        void *addr;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED)
                return log_error_errno(errno, "PROT_READ mmap of %s failed: %m", path);

        r = mprotect(addr, 4096, PROT_READ | PROT_EXEC);
        if (r < 0)
                r = -errno;

        (void) munmap(addr, 4096);

        if (r < 0)
                return log_info_errno(r, "mprotect PROT_EXEC on %s denied: %m", path);

        log_info("mprotect PROT_EXEC on %s succeeded", path);
        return 0;
}

#if BPF_FRAMEWORK && HAVE_LSM_INTEGRITY_TYPE
#include "bpf-dlopen.h"
#include "restrict-fsaccess-skel.h"

static struct restrict_fsaccess_bpf *restrict_fsaccess_bpf_free(struct restrict_fsaccess_bpf *obj) {
        restrict_fsaccess_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct restrict_fsaccess_bpf *, restrict_fsaccess_bpf_free);

static int do_attach(void) {
        _cleanup_(restrict_fsaccess_bpf_freep) struct restrict_fsaccess_bpf *obj = NULL;
        struct stat st;
        int r;

        r = dlopen_bpf(LOG_ERR);
        if (r < 0)
                return log_error_errno(r, "Failed to dlopen libbpf: %m");

        r = bpf_restrict_fsaccess_prepare(&obj);
        if (r < 0)
                return r;

        /* Set initramfs_s_dev to rootfs s_dev so the test script keeps running */
        if (stat("/", &st) < 0)
                return log_error_errno(errno, "Failed to stat /: %m");

        obj->bss->initramfs_s_dev = STAT_DEV_TO_KERNEL(st.st_dev);
        log_info("Set initramfs_s_dev to %u:%u (kernel dev_t=0x%x)",
                 major(st.st_dev), minor(st.st_dev), obj->bss->initramfs_s_dev);

        r = restrict_fsaccess_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to attach BPF programs: %m");

        /* Populate guard globals so the guard protects our BPF objects */
        r = bpf_restrict_fsaccess_populate_guard(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to populate guard globals: %m");

        printf("VERITY_MAP_ID=%u\n", (unsigned) obj->bss->protected_map_id_verity);
        printf("BSS_MAP_ID=%u\n", (unsigned) obj->bss->protected_map_id_bss);

        /* Print comma-separated prog and link IDs for guard tests */
        printf("PROG_IDS=\"");
        for (size_t i = 0; i < _RESTRICT_FILESYSTEM_ACCESS_LINK_MAX; i++)
                printf("%s%u", i > 0 ? "," : "", (unsigned) obj->bss->protected_prog_ids[i]);
        printf("\"\n");

        printf("LINK_IDS=\"");
        for (size_t i = 0; i < _RESTRICT_FILESYSTEM_ACCESS_LINK_MAX; i++)
                printf("%s%u", i > 0 ? "," : "", (unsigned) obj->bss->protected_link_ids[i]);
        printf("\"\n");

        fflush(stdout);

        /* Block until killed. The _cleanup_ destructor holds all link FDs via
         * the skeleton. When this process is killed, close() on the FDs goes
         * through bpf_link_put_direct() which synchronously detaches the
         * trampoline before the process exits. No bpffs pins needed. */
        log_info("BPF programs attached, waiting for signal to detach...");
        for (;;)
                pause();

        /* unreachable — cleanup happens via signal/exit */
}

static int do_check(void) {
        if (!bpf_restrict_fsaccess_supported()) {
                log_error("BPF LSM is not available");
                return -EOPNOTSUPP;
        }
        log_info("BPF LSM: supported");

        if (!dm_verity_require_signatures()) {
                log_error("dm-verity require_signatures is not enabled");
                return -ENOKEY;
        }
        log_info("dm-verity require_signatures: enabled");

        return 0;
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        if (argc < 2) {
                log_error("Usage: %s attach|check|mmap-exec|anon-mmap-exec|mprotect-exec",
                          program_invocation_short_name);
                return EXIT_FAILURE;
        }

        if (streq(argv[1], "attach"))
                return do_attach() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "check"))
                return do_check() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "mmap-exec") && argc == 3)
                return do_mmap_exec(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "anon-mmap-exec"))
                return do_anon_mmap_exec() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "mprotect-exec") && argc == 3)
                return do_mprotect_exec(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        log_error("Usage: %s attach|check|mmap-exec PATH|anon-mmap-exec|mprotect-exec PATH",
                  program_invocation_short_name);
        return EXIT_FAILURE;
}

#else /* ! BPF_FRAMEWORK || ! HAVE_LSM_INTEGRITY_TYPE */

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        /* mmap/mprotect probes work without BPF */
        if (argc >= 2) {
                if (streq(argv[1], "mmap-exec") && argc == 3)
                        return do_mmap_exec(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
                if (streq(argv[1], "anon-mmap-exec"))
                        return do_anon_mmap_exec() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
                if (streq(argv[1], "mprotect-exec") && argc == 3)
                        return do_mprotect_exec(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        }

        log_info("BPF framework not available, attach/check not supported");
        return 77; /* skip */
}

#endif
