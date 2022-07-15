/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "alloc-util.h"
#include "architecture.h"
#include "base-filesystem.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "string-util.h"
#include "umask-util.h"
#include "user-util.h"

typedef struct BaseFilesystem {
        const char *dir;      /* directory or symlink to create */
        mode_t mode;
        const char *target;   /* if non-NULL create as symlink to this target */
        const char *exists;   /* conditionalize this entry on existence of this file */
        bool ignore_failure;
} BaseFilesystem;

static const BaseFilesystem table[] = {
        { "bin",      0, "usr/bin\0",                  NULL },
        { "lib",      0, "usr/lib\0",                  NULL },
        { "root",  0750, NULL,                         NULL, true },
        { "sbin",     0, "usr/sbin\0",                 NULL },
        { "usr",   0755, NULL,                         NULL },
        { "var",   0755, NULL,                         NULL },
        { "etc",   0755, NULL,                         NULL },
        { "proc",  0755, NULL,                         NULL, true },
        { "sys",   0755, NULL,                         NULL, true },
        { "dev",   0755, NULL,                         NULL, true },

        /* Various architecture ABIs define the path to the dynamic loader via the /lib64/ subdirectory of
         * the root directory. When booting from an otherwise empty root file system (where only /usr/ has
         * been mounted into) it is thus necessary to create a symlink pointing to the right subdirectory of
         * /usr/ first — otherwise we couldn't invoke any dynamic binary. Let's detect this case here, and
         * create the symlink as needed should it be missing. We prefer doing this consistently with Debian's
         * multiarch logic, but support Fedora-style multilib too.*/
#if defined(__aarch64__)
        /* aarch64 ELF ABI actually says dynamic loader is in /lib/, but Fedora puts it in /lib64/ anyway and
         * just symlinks /lib/ld-linux-aarch64.so.1 to ../lib64/ld-linux-aarch64.so.1. For this to work
         * correctly, /lib64/ must be symlinked to /usr/lib64/. */
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64\0",                "ld-linux-aarch64.so.1" },
#  define KNOW_LIB64_DIRS 1
#elif defined(__alpha__)
#elif defined(__arc__) || defined(__tilegx__)
#elif defined(__arm__)
        /* No /lib64 on arm. The linker is /lib/ld-linux-armhf.so.3. */
#  define KNOW_LIB64_DIRS 1
#elif defined(__i386__) || defined(__x86_64__)
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64\0",                "ld-linux-x86-64.so.2" },
#  define KNOW_LIB64_DIRS 1
#elif defined(__ia64__)
#elif defined(__loongarch64)
#  define KNOW_LIB64_DIRS 1
#  if defined(__loongarch_double_float)
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64\0",                "ld-linux-loongarch-lp64d.so.1" },
#  elif defined(__loongarch_single_float)
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64\0",                "ld-linux-loongarch-lp64f.so.1" },
#  elif defined(__loongarch_soft_float)
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64\0",                "ld-linux-loongarch-lp64s.so.1" },
#  else
#    error "Unknown LoongArch ABI"
#  endif
#elif defined(__m68k__)
        /* No link needed. */
#  define KNOW_LIB64_DIRS 1
#elif defined(_MIPS_SIM)
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#  else
#    error "Unknown MIPS ABI"
#  endif
#elif defined(__powerpc__)
#  if defined(__PPC64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64\0",                "ld64.so.2" },
#    define KNOW_LIB64_DIRS 1
#  elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        /* powerpc64-linux-gnu */
#  else
        /* powerpc-linux-gnu */
#  endif
#elif defined(__riscv)
#  if __riscv_xlen == 32
#  elif __riscv_xlen == 64
        /* Same situation as for aarch64 */
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64\0",                "ld-linux-riscv64-lp64d.so.1" },
#    define KNOW_LIB64_DIRS 1
#  else
#    error "Unknown RISC-V ABI"
#  endif
#elif defined(__s390__)
        /* s390-linux-gnu */
#elif defined(__s390x__)
        { "lib64",    0, "usr/lib/"LIB_ARCH_TUPLE"\0"
                         "usr/lib64",                  "ld-lsb-s390x.so.3" },
#    define KNOW_LIB64_DIRS 1
#elif defined(__sparc__)
#endif
        /* gcc doesn't allow pragma to be used within constructs, hence log about this separately below */
};

#ifndef KNOW_LIB64_DIRS
#  pragma message "Please add an entry above specifying whether your architecture uses /lib64/, /lib32/, or no such links."
#endif

int base_filesystem_create(const char *root, uid_t uid, gid_t gid) {
        _cleanup_close_ int fd = -1;
        int r;

        fd = open(root, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open root file system: %m");

        for (size_t i = 0; i < ELEMENTSOF(table); i++) {
                if (faccessat(fd, table[i].dir, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                        continue;

                if (table[i].target) {
                        const char *target = NULL, *s;

                        /* check if one of the targets exists */
                        NULSTR_FOREACH(s, table[i].target) {
                                if (faccessat(fd, s, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                                        continue;

                                /* check if a specific file exists at the target path */
                                if (table[i].exists) {
                                        _cleanup_free_ char *p = NULL;

                                        p = path_join(s, table[i].exists);
                                        if (!p)
                                                return log_oom();

                                        if (faccessat(fd, p, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                                                continue;
                                }

                                target = s;
                                break;
                        }

                        if (!target)
                                continue;

                        if (symlinkat(target, fd, table[i].dir) < 0) {
                                log_full_errno(IN_SET(errno, EEXIST, EROFS) || table[i].ignore_failure ? LOG_DEBUG : LOG_ERR, errno,
                                               "Failed to create symlink at %s/%s: %m", root, table[i].dir);

                                if (IN_SET(errno, EEXIST, EROFS) || table[i].ignore_failure)
                                        continue;

                                return -errno;
                        }

                        if (uid_is_valid(uid) || gid_is_valid(gid))
                                if (fchownat(fd, table[i].dir, uid, gid, AT_SYMLINK_NOFOLLOW) < 0)
                                        return log_error_errno(errno, "Failed to chown symlink at %s/%s: %m", root, table[i].dir);

                        continue;
                }

                RUN_WITH_UMASK(0000)
                        r = mkdirat(fd, table[i].dir, table[i].mode);
                if (r < 0) {
                        log_full_errno(IN_SET(errno, EEXIST, EROFS) || table[i].ignore_failure ? LOG_DEBUG : LOG_ERR, errno,
                                       "Failed to create directory at %s/%s: %m", root, table[i].dir);

                        if (IN_SET(errno, EEXIST, EROFS) || table[i].ignore_failure)
                                continue;

                        return -errno;
                }

                if (uid_is_valid(uid) || gid_is_valid(gid))
                        if (fchownat(fd, table[i].dir, uid, gid, AT_SYMLINK_NOFOLLOW) < 0)
                                return log_error_errno(errno, "Failed to chown directory at %s/%s: %m", root, table[i].dir);
        }

        return 0;
}
