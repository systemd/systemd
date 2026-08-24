/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Test helper for RestrictFileSystemAccess= BPF enforcement tests.
 *
 * Usage:
 *   test-bpf-restrict-fsaccess attach              — Load, attach, print IDs, then block.
 *                                                Kill the process to detach (synchronous
 *                                                via bpf_link_put_direct on last FD close).
 *   test-bpf-restrict-fsaccess check               — Check BPF LSM, require_signatures and
 *                                                proc_mem.force_override preconditions (incl. a
 *                                                /proc/self/mem self-probe)
 *   test-bpf-restrict-fsaccess mmap-exec PATH      — Attempt PROT_READ|PROT_EXEC mmap of PATH
 *   test-bpf-restrict-fsaccess anon-mmap-exec      — Attempt anonymous PROT_READ|PROT_EXEC mmap
 *   test-bpf-restrict-fsaccess mprotect-exec PATH  — mmap PATH PROT_READ, then mprotect to PROT_EXEC
 *   test-bpf-restrict-fsaccess mmap-wx PATH        — PROT_WRITE|PROT_EXEC mmap of PATH (W^X variant A)
 *   test-bpf-restrict-fsaccess mprotect-cow-exec PATH — mmap PROT_WRITE, write, mprotect PROT_EXEC (variant B)
 *   test-bpf-restrict-fsaccess mprotect-wx PATH    — mmap PROT_EXEC, then mprotect +PROT_WRITE (variant C)
 *   test-bpf-restrict-fsaccess procmem-cow PATH    — mmap PROT_EXEC, then rewrite it via /proc/self/mem
 *   test-bpf-restrict-fsaccess poketext            — install ptrace seccomp, verify PTRACE_POKETEXT is denied
 *
 * When "attach" is used, the BPF LSM program is loaded with initramfs_s_dev
 * set to the current rootfs s_dev, so the calling test script (running from
 * the rootfs) continues to work. The process holds all link FDs and blocks;
 * when killed, close() drops the last reference synchronously.
 */

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bpf-link.h"
#include "bpf-restrict-fsaccess.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "log.h"
#include "lsm-util.h"
#include "seccomp-util.h"
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

/* ---- W^X bypass probes (GHSA-q65q-ggpx-fjgp) ----
 *
 * Each tries to get attacker-controlled bytes into an executable page of a
 * trusted file. With the W^X hooks in place they must all be denied; a return
 * of 0 (allowed) means the bypass still works. */

static int do_mmap_wx(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        void *addr;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        /* Variant A: a private writable+executable mapping. */
        addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED)
                return log_info_errno(errno, "W+X mmap of %s denied: %m", path);

        (void) munmap(addr, 4096);
        log_info("W+X mmap of %s succeeded", path);
        return 0;
}

static int do_mprotect_cow_exec(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        void *addr;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        /* Variant B: map writable, modify via copy-on-write, then turn executable. */
        addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED)
                return log_error_errno(errno, "PROT_WRITE mmap of %s failed: %m", path);

        *(volatile uint8_t *) addr = 0x90;   /* trigger copy-on-write */

        r = mprotect(addr, 4096, PROT_READ | PROT_EXEC);
        if (r < 0)
                r = -errno;

        (void) munmap(addr, 4096);

        if (r < 0)
                return log_info_errno(r, "mprotect PROT_EXEC after COW write on %s denied: %m", path);

        log_info("mprotect PROT_EXEC after COW write on %s succeeded", path);
        return 0;
}

static int do_mprotect_wx(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        void *addr;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        /* Variant C: map executable, then add write. */
        addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED)
                return log_info_errno(errno, "PROT_EXEC mmap of %s denied: %m", path);

        r = mprotect(addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
        if (r < 0)
                r = -errno;

        (void) munmap(addr, 4096);

        if (r < 0)
                return log_info_errno(r, "mprotect PROT_WRITE|PROT_EXEC on %s denied: %m", path);

        log_info("mprotect PROT_WRITE|PROT_EXEC on %s succeeded", path);
        return 0;
}

static int do_procmem_cow(const char *path) {
        _cleanup_close_ int fd = -EBADF, mem_fd = -EBADF;
        static const uint8_t byte = 0x90;
        void *addr;
        ssize_t n;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        /* A read-only executable mapping — no W^X violation, so it is allowed. */
        addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED)
                return log_info_errno(errno, "PROT_EXEC mmap of %s denied: %m", path);

        mem_fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
        if (mem_fd < 0) {
                (void) munmap(addr, 4096);
                return log_error_errno(errno, "Failed to open /proc/self/mem: %m");
        }

        /* Rewrite the read-only executable page through /proc/self/mem. Succeeds
         * only under proc_mem.force_override=always (FOLL_FORCE), defeating W^X. */
        n = pwrite(mem_fd, &byte, sizeof(byte), (off_t) (uintptr_t) addr);

        (void) munmap(addr, 4096);

        if (n < 0)
                return log_info_errno(errno, "/proc/self/mem write to exec page of %s denied: %m", path);

        log_info("/proc/self/mem write to exec page of %s succeeded", path);
        return 0;
}

#if HAVE_SECCOMP
/* Self-contained check of the ptrace() memory-write block (seccomp layer). The
 * filter is installed by PID 1 in production, not by "attach", and seccomp is
 * per-process-tree, so this probe installs it itself and then verifies that
 * PTRACE_POKETEXT is refused while attach and read (PTRACE_PEEKTEXT) still work.
 * Returns <0 (denied, like the other bypass probes) when POKETEXT is blocked. */
static int do_poketext_seccomp(void) {
        int status = 0, r, poke_errno = 0;
        long peek, poke = 0;
        pid_t pid;

        r = seccomp_restrict_ptrace();
        if (r < 0)
                return log_error_errno(r, "Failed to install ptrace seccomp filter: %m");

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "fork failed: %m");
        if (pid == 0) {
                /* Child: invite tracing (PTRACE_TRACEME is not blocked), then stop. */
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
                        _exit(EXIT_FAILURE);
                raise(SIGSTOP);
                _exit(EXIT_SUCCESS);
        }

        /* WUNTRACED: if PTRACE_TRACEME failed (e.g. Yama ptrace_scope=3) the child stops untraced, and
         * without the flag we would wait forever. */
        if (waitpid(pid, &status, WUNTRACED) < 0) {
                r = log_error_errno(errno, "waitpid failed: %m");
                goto reap;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE) {
                r = log_error_errno(SYNTHETIC_ERRNO(EPERM), "PTRACE_TRACEME failed in the child, cannot ptrace in this environment.");
                goto reap;
        }
        if (!WIFSTOPPED(status)) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Child did not stop as expected (status=%i).", status);
                goto reap;
        }

        /* PEEKTEXT (read) must still work — attach/inspection stays allowed. */
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, pid, (void *) (uintptr_t) &do_poketext_seccomp, NULL);
        if (peek == -1 && errno == EPERM) {
                r = log_error_errno(SYNTHETIC_ERRNO(EPERM), "ptrace(PTRACE_PEEKTEXT) unexpectedly denied — filter too broad.");
                goto reap;
        }

        /* POKETEXT (write) must be refused by the seccomp filter with EPERM. */
        errno = 0;
        poke = ptrace(PTRACE_POKETEXT, pid, (void *) (uintptr_t) &do_poketext_seccomp, (void *) 0x42);
        poke_errno = errno;
        r = 0;

reap:
        (void) kill(pid, SIGKILL);
        (void) waitpid(pid, &status, 0);
        if (r < 0)
                return r;

        if (poke == -1 && poke_errno == EPERM) {
                log_info("ptrace(PTRACE_POKETEXT) denied by seccomp (EPERM) as expected");
                return -EPERM;
        }

        log_info("ptrace(PTRACE_POKETEXT) succeeded — seccomp NOT enforcing");
        return 0;
}
#endif

#if BPF_FRAMEWORK && HAVE_LSM_INTEGRITY_TYPE
#include "bpf-util.h"
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
        printf("HAVE_REAL_DATA_INODE=%u\n", (unsigned) obj->rodata->have_real_data_inode);

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
        int r;

        r = dlopen_bpf(LOG_WARNING);
        if (r < 0)
                return r;

        r = lsm_supported("bpf");
        if (r <= 0)
                return log_error_errno(r < 0 ? r : EOPNOTSUPP, "BPF LSM is not available: %m");
        log_info("BPF LSM: supported");

        if (!dm_verity_require_signatures())
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "dm-verity require_signatures is not enabled.");
        log_info("dm-verity require_signatures: enabled");

        r = proc_mem_force_override_restricted();
        if (r < 0)
                return log_error_errno(r, "Failed to read the kernel command line: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "proc_mem.force_override is not set to \"never\" on the kernel command line; "
                                       "/proc/<pid>/mem can rewrite executable pages. Add proc_mem.force_override=never.");
        log_info("proc_mem.force_override=never: set");

        r = proc_mem_force_override_probe();
        if (r < 0)
                return log_error_errno(r, "Failed to probe /proc/self/mem: %m");
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "proc_mem.force_override=never is on the kernel command line, but a write through "
                                       "/proc/self/mem still overrides memory protections; the kernel ignores the option.");
        log_info("proc_mem.force_override=never: effective");

        /* Last: linking attaches bprm_check for an instant with an empty trust map, during which every
         * execve() on the system is denied. Keep that window out of the cheap failure paths above. */
        _cleanup_(restrict_fsaccess_bpf_freep) struct restrict_fsaccess_bpf *obj = NULL;
        r = bpf_restrict_fsaccess_prepare(&obj);
        if (r < 0)
                return r;

        if (!bpf_can_link_lsm_program(obj->progs.restrict_fsaccess_bprm_check))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "bpf-restrict-fsaccess: Failed to link program.");

        return 0;
}

#if HAVE_SECCOMP
#define USAGE_POKETEXT "|poketext"
#else
#define USAGE_POKETEXT ""
#endif

static int usage(void) {
        log_error("Usage: %s attach|check|mmap-exec PATH|anon-mmap-exec|mprotect-exec PATH|"
                  "mmap-wx PATH|mprotect-cow-exec PATH|mprotect-wx PATH|procmem-cow PATH" USAGE_POKETEXT,
                  program_invocation_short_name);
        return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        if (argc < 2)
                return usage();

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
        if (streq(argv[1], "mmap-wx") && argc == 3)
                return do_mmap_wx(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "mprotect-cow-exec") && argc == 3)
                return do_mprotect_cow_exec(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "mprotect-wx") && argc == 3)
                return do_mprotect_wx(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "procmem-cow") && argc == 3)
                return do_procmem_cow(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
#if HAVE_SECCOMP
        if (streq(argv[1], "poketext"))
                return do_poketext_seccomp() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
#endif

        return usage();
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
                if (streq(argv[1], "mmap-wx") && argc == 3)
                        return do_mmap_wx(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
                if (streq(argv[1], "mprotect-cow-exec") && argc == 3)
                        return do_mprotect_cow_exec(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
                if (streq(argv[1], "mprotect-wx") && argc == 3)
                        return do_mprotect_wx(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
                if (streq(argv[1], "procmem-cow") && argc == 3)
                        return do_procmem_cow(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
#if HAVE_SECCOMP
                if (streq(argv[1], "poketext"))
                        return do_poketext_seccomp() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
#endif
        }

        log_info("BPF framework not available, attach/check not supported");
        return 77; /* skip */
}

#endif
