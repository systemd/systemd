/* SPDX-License-Identifier: LGPL-2.1+ */

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "build.h"
#include "cgroup-util.h"
#include "def.h"
#include "device-nodes.h"
#include "dirent-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

int saved_argc = 0;
char **saved_argv = NULL;
static int saved_in_initrd = -1;

size_t page_size(void) {
        static thread_local size_t pgsz = 0;
        long r;

        if (_likely_(pgsz > 0))
                return pgsz;

        r = sysconf(_SC_PAGESIZE);
        assert(r > 0);

        pgsz = (size_t) r;
        return pgsz;
}

bool plymouth_running(void) {
        return access("/run/plymouth/pid", F_OK) >= 0;
}

bool display_is_local(const char *display) {
        assert(display);

        return
                display[0] == ':' &&
                display[1] >= '0' &&
                display[1] <= '9';
}

bool kexec_loaded(void) {
       _cleanup_free_ char *s = NULL;

       if (read_one_line_file("/sys/kernel/kexec_loaded", &s) < 0)
               return false;

       return s[0] == '1';
}

int prot_from_flags(int flags) {

        switch (flags & O_ACCMODE) {

        case O_RDONLY:
                return PROT_READ;

        case O_WRONLY:
                return PROT_WRITE;

        case O_RDWR:
                return PROT_READ|PROT_WRITE;

        default:
                return -EINVAL;
        }
}

bool in_initrd(void) {
        struct statfs s;
        int r;

        if (saved_in_initrd >= 0)
                return saved_in_initrd;

        /* We make two checks here:
         *
         * 1. the flag file /etc/initrd-release must exist
         * 2. the root file system must be a memory file system
         *
         * The second check is extra paranoia, since misdetecting an
         * initrd can have bad consequences due the initrd
         * emptying when transititioning to the main systemd.
         */

        r = getenv_bool_secure("SYSTEMD_IN_INITRD");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");

        if (r >= 0)
                saved_in_initrd = r > 0;
        else
                saved_in_initrd = access("/etc/initrd-release", F_OK) >= 0 &&
                                  statfs("/", &s) >= 0 &&
                                  is_temporary_fs(&s);

        return saved_in_initrd;
}

void in_initrd_force(bool value) {
        saved_in_initrd = value;
}

/* hey glibc, APIs with callbacks without a user pointer are so useless */
void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 __compar_d_fn_t compar, void *arg) {
        size_t l, u, idx;
        const void *p;
        int comparison;

        assert(!size_multiply_overflow(nmemb, size));

        l = 0;
        u = nmemb;
        while (l < u) {
                idx = (l + u) / 2;
                p = (const uint8_t*) base + idx * size;
                comparison = compar(key, p, arg);
                if (comparison < 0)
                        u = idx;
                else if (comparison > 0)
                        l = idx + 1;
                else
                        return (void *)p;
        }
        return NULL;
}

int on_ac_power(void) {
        bool found_offline = false, found_online = false;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;

        d = opendir("/sys/class/power_supply");
        if (!d)
                return errno == ENOENT ? true : -errno;

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_close_ int fd = -1, device = -1;
                char contents[6];
                ssize_t n;

                device = openat(dirfd(d), de->d_name, O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (device < 0) {
                        if (IN_SET(errno, ENOENT, ENOTDIR))
                                continue;

                        return -errno;
                }

                fd = openat(device, "type", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                n = read(fd, contents, sizeof(contents));
                if (n < 0)
                        return -errno;

                if (n != 6 || memcmp(contents, "Mains\n", 6))
                        continue;

                safe_close(fd);
                fd = openat(device, "online", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                n = read(fd, contents, sizeof(contents));
                if (n < 0)
                        return -errno;

                if (n != 2 || contents[1] != '\n')
                        return -EIO;

                if (contents[0] == '1') {
                        found_online = true;
                        break;
                } else if (contents[0] == '0')
                        found_offline = true;
                else
                        return -EIO;
        }

        return found_online || !found_offline;
}

int container_get_leader(const char *machine, pid_t *pid) {
        _cleanup_free_ char *s = NULL, *class = NULL;
        const char *p;
        pid_t leader;
        int r;

        assert(machine);
        assert(pid);

        if (streq(machine, ".host")) {
                *pid = 1;
                return 0;
        }

        if (!machine_name_is_valid(machine))
                return -EINVAL;

        p = strjoina("/run/systemd/machines/", machine);
        r = parse_env_file(NULL, p, NEWLINE, "LEADER", &s, "CLASS", &class, NULL);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!s)
                return -EIO;

        if (!streq_ptr(class, "container"))
                return -EIO;

        r = parse_pid(s, &leader);
        if (r < 0)
                return r;
        if (leader <= 1)
                return -EIO;

        *pid = leader;
        return 0;
}

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd) {
        _cleanup_close_ int pidnsfd = -1, mntnsfd = -1, netnsfd = -1, usernsfd = -1;
        int rfd = -1;

        assert(pid >= 0);

        if (mntns_fd) {
                const char *mntns;

                mntns = procfs_file_alloca(pid, "ns/mnt");
                mntnsfd = open(mntns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntnsfd < 0)
                        return -errno;
        }

        if (pidns_fd) {
                const char *pidns;

                pidns = procfs_file_alloca(pid, "ns/pid");
                pidnsfd = open(pidns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (pidnsfd < 0)
                        return -errno;
        }

        if (netns_fd) {
                const char *netns;

                netns = procfs_file_alloca(pid, "ns/net");
                netnsfd = open(netns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netnsfd < 0)
                        return -errno;
        }

        if (userns_fd) {
                const char *userns;

                userns = procfs_file_alloca(pid, "ns/user");
                usernsfd = open(userns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (usernsfd < 0 && errno != ENOENT)
                        return -errno;
        }

        if (root_fd) {
                const char *root;

                root = procfs_file_alloca(pid, "root");
                rfd = open(root, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
                if (rfd < 0)
                        return -errno;
        }

        if (pidns_fd)
                *pidns_fd = pidnsfd;

        if (mntns_fd)
                *mntns_fd = mntnsfd;

        if (netns_fd)
                *netns_fd = netnsfd;

        if (userns_fd)
                *userns_fd = usernsfd;

        if (root_fd)
                *root_fd = rfd;

        pidnsfd = mntnsfd = netnsfd = usernsfd = -1;

        return 0;
}

int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd) {
        if (userns_fd >= 0) {
                /* Can't setns to your own userns, since then you could
                 * escalate from non-root to root in your own namespace, so
                 * check if namespaces equal before attempting to enter. */
                _cleanup_free_ char *userns_fd_path = NULL;
                int r;
                if (asprintf(&userns_fd_path, "/proc/self/fd/%d", userns_fd) < 0)
                        return -ENOMEM;

                r = files_same(userns_fd_path, "/proc/self/ns/user", 0);
                if (r < 0)
                        return r;
                if (r)
                        userns_fd = -1;
        }

        if (pidns_fd >= 0)
                if (setns(pidns_fd, CLONE_NEWPID) < 0)
                        return -errno;

        if (mntns_fd >= 0)
                if (setns(mntns_fd, CLONE_NEWNS) < 0)
                        return -errno;

        if (netns_fd >= 0)
                if (setns(netns_fd, CLONE_NEWNET) < 0)
                        return -errno;

        if (userns_fd >= 0)
                if (setns(userns_fd, CLONE_NEWUSER) < 0)
                        return -errno;

        if (root_fd >= 0) {
                if (fchdir(root_fd) < 0)
                        return -errno;

                if (chroot(".") < 0)
                        return -errno;
        }

        return reset_uid_gid();
}

uint64_t physical_memory(void) {
        _cleanup_free_ char *root = NULL, *value = NULL;
        uint64_t mem, lim;
        size_t ps;
        long sc;
        int r;

        /* We return this as uint64_t in case we are running as 32bit process on a 64bit kernel with huge amounts of
         * memory.
         *
         * In order to support containers nicely that have a configured memory limit we'll take the minimum of the
         * physically reported amount of memory and the limit configured for the root cgroup, if there is any. */

        sc = sysconf(_SC_PHYS_PAGES);
        assert(sc > 0);

        ps = page_size();
        mem = (uint64_t) sc * (uint64_t) ps;

        r = cg_get_root_path(&root);
        if (r < 0) {
                log_debug_errno(r, "Failed to determine root cgroup, ignoring cgroup memory limit: %m");
                return mem;
        }

        r = cg_all_unified();
        if (r < 0) {
                log_debug_errno(r, "Failed to determine root unified mode, ignoring cgroup memory limit: %m");
                return mem;
        }
        if (r > 0) {
                r = cg_get_attribute("memory", root, "memory.max", &value);
                if (r < 0) {
                        log_debug_errno(r, "Failed to read memory.max cgroup attribute, ignoring cgroup memory limit: %m");
                        return mem;
                }

                if (streq(value, "max"))
                        return mem;
        } else {
                r = cg_get_attribute("memory", root, "memory.limit_in_bytes", &value);
                if (r < 0) {
                        log_debug_errno(r, "Failed to read memory.limit_in_bytes cgroup attribute, ignoring cgroup memory limit: %m");
                        return mem;
                }
        }

        r = safe_atou64(value, &lim);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse cgroup memory limit '%s', ignoring: %m", value);
                return mem;
        }
        if (lim == UINT64_MAX)
                return mem;

        /* Make sure the limit is a multiple of our own page size */
        lim /= ps;
        lim *= ps;

        return MIN(mem, lim);
}

uint64_t physical_memory_scale(uint64_t v, uint64_t max) {
        uint64_t p, m, ps, r;

        assert(max > 0);

        /* Returns the physical memory size, multiplied by v divided by max. Returns UINT64_MAX on overflow. On success
         * the result is a multiple of the page size (rounds down). */

        ps = page_size();
        assert(ps > 0);

        p = physical_memory() / ps;
        assert(p > 0);

        m = p * v;
        if (m / p != v)
                return UINT64_MAX;

        m /= max;

        r = m * ps;
        if (r / ps != m)
                return UINT64_MAX;

        return r;
}

uint64_t system_tasks_max(void) {

        uint64_t a = TASKS_MAX, b = TASKS_MAX;
        _cleanup_free_ char *root = NULL;
        int r;

        /* Determine the maximum number of tasks that may run on this system. We check three sources to determine this
         * limit:
         *
         * a) the maximum tasks value the kernel allows on this architecture
         * b) the cgroups pids_max attribute for the system
         * c) the kernel's configured maximum PID value
         *
         * And then pick the smallest of the three */

        r = procfs_tasks_get_limit(&a);
        if (r < 0)
                log_debug_errno(r, "Failed to read maximum number of tasks from /proc, ignoring: %m");

        r = cg_get_root_path(&root);
        if (r < 0)
                log_debug_errno(r, "Failed to determine cgroup root path, ignoring: %m");
        else {
                _cleanup_free_ char *value = NULL;

                r = cg_get_attribute("pids", root, "pids.max", &value);
                if (r < 0)
                        log_debug_errno(r, "Failed to read pids.max attribute of cgroup root, ignoring: %m");
                else if (!streq(value, "max")) {
                        r = safe_atou64(value, &b);
                        if (r < 0)
                                log_debug_errno(r, "Failed to parse pids.max attribute of cgroup root, ignoring: %m");
                }
        }

        return MIN3(TASKS_MAX,
                    a <= 0 ? TASKS_MAX : a,
                    b <= 0 ? TASKS_MAX : b);
}

uint64_t system_tasks_max_scale(uint64_t v, uint64_t max) {
        uint64_t t, m;

        assert(max > 0);

        /* Multiply the system's task value by the fraction v/max. Hence, if max==100 this calculates percentages
         * relative to the system's maximum number of tasks. Returns UINT64_MAX on overflow. */

        t = system_tasks_max();
        assert(t > 0);

        m = t * v;
        if (m / t != v) /* overflow? */
                return UINT64_MAX;

        return m / max;
}

int version(void) {
        puts(PACKAGE_STRING "\n"
             SYSTEMD_FEATURES);
        return 0;
}

/* This is a direct translation of str_verscmp from boot.c */
static bool is_digit(int c) {
        return c >= '0' && c <= '9';
}

static int c_order(int c) {
        if (c == 0 || is_digit(c))
                return 0;

        if ((c >= 'a') && (c <= 'z'))
                return c;

        return c + 0x10000;
}

int str_verscmp(const char *s1, const char *s2) {
        const char *os1, *os2;

        assert(s1);
        assert(s2);

        os1 = s1;
        os2 = s2;

        while (*s1 || *s2) {
                int first;

                while ((*s1 && !is_digit(*s1)) || (*s2 && !is_digit(*s2))) {
                        int order;

                        order = c_order(*s1) - c_order(*s2);
                        if (order != 0)
                                return order;
                        s1++;
                        s2++;
                }

                while (*s1 == '0')
                        s1++;
                while (*s2 == '0')
                        s2++;

                first = 0;
                while (is_digit(*s1) && is_digit(*s2)) {
                        if (first == 0)
                                first = *s1 - *s2;
                        s1++;
                        s2++;
                }

                if (is_digit(*s1))
                        return 1;
                if (is_digit(*s2))
                        return -1;

                if (first != 0)
                        return first;
        }

        return strcmp(os1, os2);
}

/* Turn off core dumps but only if we're running outside of a container. */
void disable_coredumps(void) {
        int r;

        if (detect_container() > 0)
                return;

        r = write_string_file("/proc/sys/kernel/core_pattern", "|/bin/false", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_debug_errno(r, "Failed to turn off coredumps, ignoring: %m");
}
