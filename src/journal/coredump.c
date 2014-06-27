/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <systemd/sd-journal.h>
#include <systemd/sd-login.h>

#include "log.h"
#include "util.h"
#include "strv.h"
#include "macro.h"
#include "mkdir.h"
#include "special.h"
#include "cgroup-util.h"
#include "journald-native.h"
#include "conf-parser.h"
#include "copy.h"
#include "stacktrace.h"
#include "path-util.h"
#include "compress.h"
#include "coredump-vacuum.h"

#ifdef HAVE_ACL
#  include <sys/acl.h>
#  include "acl-util.h"
#endif

#ifdef HAVE_XZ
#  include <lzma.h>
#else
#  define LZMA_PRESET_DEFAULT 0
#endif

/* The maximum size up to which we process coredumps */
#define PROCESS_SIZE_MAX ((off_t) (2LLU*1024LLU*1024LLU*1024LLU))

/* The maximum size up to which we leave the coredump around on
 * disk */
#define EXTERNAL_SIZE_MAX PROCESS_SIZE_MAX

/* The maximum size up to which we store the coredump in the
 * journal */
#define JOURNAL_SIZE_MAX ((size_t) (767LU*1024LU*1024LU))

/* Make sure to not make this larger than the maximum journal entry
 * size. See ENTRY_SIZE_MAX in journald-native.c. */
assert_cc(JOURNAL_SIZE_MAX <= ENTRY_SIZE_MAX);

enum {
        INFO_PID,
        INFO_UID,
        INFO_GID,
        INFO_SIGNAL,
        INFO_TIMESTAMP,
        INFO_COMM,
        INFO_EXE,
        _INFO_LEN
};

typedef enum CoredumpStorage {
        COREDUMP_STORAGE_NONE,
        COREDUMP_STORAGE_EXTERNAL,
        COREDUMP_STORAGE_JOURNAL,
        COREDUMP_STORAGE_BOTH,
        _COREDUMP_STORAGE_MAX,
        _COREDUMP_STORAGE_INVALID = -1
} CoredumpStorage;

static const char* const coredump_storage_table[_COREDUMP_STORAGE_MAX] = {
        [COREDUMP_STORAGE_NONE] = "none",
        [COREDUMP_STORAGE_EXTERNAL] = "external",
        [COREDUMP_STORAGE_JOURNAL] = "journal",
        [COREDUMP_STORAGE_BOTH] = "both",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(coredump_storage, CoredumpStorage);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_coredump_storage, coredump_storage, CoredumpStorage, "Failed to parse storage setting");

static CoredumpStorage arg_storage = COREDUMP_STORAGE_EXTERNAL;
static bool arg_compress = true;
static off_t arg_process_size_max = PROCESS_SIZE_MAX;
static off_t arg_external_size_max = EXTERNAL_SIZE_MAX;
static size_t arg_journal_size_max = JOURNAL_SIZE_MAX;
static off_t arg_keep_free = (off_t) -1;
static off_t arg_max_use = (off_t) -1;

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "Coredump", "Storage",          config_parse_coredump_storage,  0, &arg_storage           },
                { "Coredump", "Compress",         config_parse_bool,              0, &arg_compress          },
                { "Coredump", "ProcessSizeMax",   config_parse_iec_off,           0, &arg_process_size_max  },
                { "Coredump", "ExternalSizeMax",  config_parse_iec_off,           0, &arg_external_size_max },
                { "Coredump", "JournalSizeMax",   config_parse_iec_size,          0, &arg_journal_size_max  },
                { "Coredump", "KeepFree",         config_parse_iec_off,           0, &arg_keep_free         },
                { "Coredump", "MaxUse",           config_parse_iec_off,           0, &arg_max_use           },
                {}
        };

        return config_parse(
                        NULL,
                        "/etc/systemd/coredump.conf",
                        NULL,
                        "Coredump\0",
                        config_item_table_lookup,
                        (void*) items,
                        false,
                        false,
                        NULL);
}

static int fix_acl(int fd, uid_t uid) {

#ifdef HAVE_ACL
        _cleanup_(acl_freep) acl_t acl = NULL;
        acl_entry_t entry;
        acl_permset_t permset;

        assert(fd >= 0);

        if (uid <= SYSTEM_UID_MAX)
                return 0;

        /* Make sure normal users can read (but not write or delete)
         * their own coredumps */

        acl = acl_get_fd(fd);
        if (!acl) {
                log_error("Failed to get ACL: %m");
                return -errno;
        }

        if (acl_create_entry(&acl, &entry) < 0 ||
            acl_set_tag_type(entry, ACL_USER) < 0 ||
            acl_set_qualifier(entry, &uid) < 0) {
                log_error("Failed to patch ACL: %m");
                return -errno;
        }

        if (acl_get_permset(entry, &permset) < 0 ||
            acl_add_perm(permset, ACL_READ) < 0 ||
            calc_acl_mask_if_needed(&acl) < 0) {
                log_warning("Failed to patch ACL: %m");
                return -errno;
        }

        if (acl_set_fd(fd, acl) < 0) {
                log_error("Failed to apply ACL: %m");
                return -errno;
        }
#endif

        return 0;
}

static int fix_xattr(int fd, const char *info[_INFO_LEN]) {

        static const char * const xattrs[_INFO_LEN] = {
                [INFO_PID] = "user.coredump.pid",
                [INFO_UID] = "user.coredump.uid",
                [INFO_GID] = "user.coredump.gid",
                [INFO_SIGNAL] = "user.coredump.signal",
                [INFO_TIMESTAMP] = "user.coredump.timestamp",
                [INFO_COMM] = "user.coredump.comm",
                [INFO_EXE] = "user.coredump.exe",
        };

        int r = 0;
        unsigned i;

        assert(fd >= 0);

        /* Attach some metadata to coredumps via extended
         * attributes. Just because we can. */

        for (i = 0; i < _INFO_LEN; i++) {
                int k;

                if (isempty(info[i]) || !xattrs[i])
                        continue;

                k = fsetxattr(fd, xattrs[i], info[i], strlen(info[i]), XATTR_CREATE);
                if (k < 0 && r == 0)
                        r = -errno;
        }

        return r;
}

#define filename_escape(s) xescape((s), "./ ")

static int fix_permissions(
                int fd,
                const char *filename,
                const char *target,
                const char *info[_INFO_LEN],
                uid_t uid) {

        assert(fd >= 0);
        assert(filename);
        assert(target);
        assert(info);

        /* Ignore errors on these */
        fchmod(fd, 0640);
        fix_acl(fd, uid);
        fix_xattr(fd, info);

        if (fsync(fd) < 0) {
                log_error("Failed to sync coredump %s: %m", filename);
                return -errno;
        }

        if (rename(filename, target) < 0) {
                log_error("Failed to rename coredump %s -> %s: %m", filename, target);
                return -errno;
        }

        return 0;
}

static int maybe_remove_external_coredump(const char *filename, off_t size) {

        /* Returns 1 if might remove, 0 if will not remove, < 0 on error. */

        if (IN_SET(arg_storage, COREDUMP_STORAGE_EXTERNAL, COREDUMP_STORAGE_BOTH) &&
            size <= arg_external_size_max)
                return 0;

        if (!filename)
                return 1;

        if (unlink(filename) < 0 && errno != ENOENT) {
                log_error("Failed to unlink %s: %m", filename);
                return -errno;
        }

        return 1;
}

static int make_filename(const char *info[_INFO_LEN], char **ret) {
        _cleanup_free_ char *c = NULL, *u = NULL, *p = NULL, *t = NULL;
        sd_id128_t boot;
        int r;

        assert(info);

        c = filename_escape(info[INFO_COMM]);
        if (!c)
                return -ENOMEM;

        u = filename_escape(info[INFO_UID]);
        if (!u)
                return -ENOMEM;

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return r;

        p = filename_escape(info[INFO_PID]);
        if (!p)
                return -ENOMEM;

        t = filename_escape(info[INFO_TIMESTAMP]);
        if (!t)
                return -ENOMEM;

        if (asprintf(ret,
                     "/var/lib/systemd/coredump/core.%s.%s." SD_ID128_FORMAT_STR ".%s.%s000000",
                     c,
                     u,
                     SD_ID128_FORMAT_VAL(boot),
                     p,
                     t) < 0)
                return -ENOMEM;

        return 0;
}

static int save_external_coredump(
                const char *info[_INFO_LEN],
                uid_t uid,
                char **ret_filename,
                int *ret_fd,
                off_t *ret_size) {

        _cleanup_free_ char *fn = NULL, *tmp = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;
        int r;

        assert(info);
        assert(ret_filename);
        assert(ret_fd);
        assert(ret_size);

        r = make_filename(info, &fn);
        if (r < 0) {
                log_error("Failed to determine coredump file name: %s", strerror(-r));
                return r;
        }

        tmp = tempfn_random(fn);
        if (!tmp)
                return log_oom();

        mkdir_p_label("/var/lib/systemd/coredump", 0755);

        fd = open(tmp, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0640);
        if (fd < 0) {
                log_error("Failed to create coredump file %s: %m", tmp);
                return -errno;
        }

        r = copy_bytes(STDIN_FILENO, fd, arg_process_size_max);
        if (r == -E2BIG) {
                log_error("Coredump of %s (%s) is larger than configured processing limit, refusing.", info[INFO_PID], info[INFO_COMM]);
                goto fail;
        } else if (IN_SET(r, -EDQUOT, -ENOSPC)) {
                log_error("Not enough disk space for coredump of %s (%s), refusing.", info[INFO_PID], info[INFO_COMM]);
                goto fail;
        } else if (r < 0) {
                log_error("Failed to dump coredump to file: %s", strerror(-r));
                goto fail;
        }

        if (fstat(fd, &st) < 0) {
                log_error("Failed to fstat coredump %s: %m", tmp);
                goto fail;
        }

        if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
                log_error("Failed to seek on %s: %m", tmp);
                goto fail;
        }

#ifdef HAVE_XZ
        /* If we will remove the coredump anyway, do not compress. */
        if (maybe_remove_external_coredump(NULL, st.st_size) == 0
            && arg_compress) {

                _cleanup_free_ char *fn_compressed = NULL, *tmp_compressed = NULL;
                _cleanup_close_ int fd_compressed = -1;

                fn_compressed = strappend(fn, ".xz");
                if (!fn_compressed) {
                        r = log_oom();
                        goto uncompressed;
                }

                tmp_compressed = tempfn_random(fn_compressed);
                if (!tmp_compressed) {
                        r = log_oom();
                        goto uncompressed;
                }

                fd_compressed = open(tmp_compressed, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0640);
                if (fd_compressed < 0) {
                        log_error("Failed to create file %s: %m", tmp_compressed);
                        goto uncompressed;
                }

                r = compress_stream(fd, fd_compressed, LZMA_PRESET_DEFAULT, -1);
                if (r < 0) {
                        log_error("Failed to compress %s: %s", tmp_compressed, strerror(-r));
                        goto fail_compressed;
                }

                r = fix_permissions(fd_compressed, tmp_compressed, fn_compressed, info, uid);
                if (r < 0)
                        goto fail_compressed;

                /* OK, this worked, we can get rid of the uncompressed version now */
                unlink_noerrno(tmp);

                *ret_filename = fn_compressed;    /* compressed */
                *ret_fd = fd;                     /* uncompressed */
                *ret_size = st.st_size;           /* uncompressed */

                fn_compressed = NULL;
                fd = -1;

                return 0;

        fail_compressed:
                unlink_noerrno(tmp_compressed);
        }
#endif

uncompressed:
        r = fix_permissions(fd, tmp, fn, info, uid);
        if (r < 0)
                goto fail;

        *ret_filename = fn;
        *ret_fd = fd;
        *ret_size = st.st_size;

        fn = NULL;
        fd = -1;

        return 0;

fail:
        unlink_noerrno(tmp);
        return r;
}

static int allocate_journal_field(int fd, size_t size, char **ret, size_t *ret_size) {
        _cleanup_free_ char *field = NULL;
        ssize_t n;

        assert(fd >= 0);
        assert(ret);
        assert(ret_size);

        if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
                log_warning("Failed to seek: %m");
                return -errno;
        }

        field = malloc(9 + size);
        if (!field) {
                log_warning("Failed to allocate memory for coredump, coredump will not be stored.");
                return -ENOMEM;
        }

        memcpy(field, "COREDUMP=", 9);

        n = read(fd, field + 9, size);
        if (n < 0) {
                log_error("Failed to read core data: %s", strerror(-n));
                return (int) n;
        }
        if ((size_t) n < size) {
                log_error("Core data too short.");
                return -EIO;
        }

        *ret = field;
        *ret_size = size + 9;

        field = NULL;

        return 0;
}

int main(int argc, char* argv[]) {

        _cleanup_free_ char *core_pid = NULL, *core_uid = NULL, *core_gid = NULL, *core_signal = NULL,
                *core_timestamp = NULL, *core_comm = NULL, *core_exe = NULL, *core_unit = NULL,
                *core_session = NULL, *core_message = NULL, *core_cmdline = NULL, *coredump_data = NULL,
                *core_slice = NULL, *core_cgroup = NULL, *core_owner_uid = NULL,
                *exe = NULL, *comm = NULL, *filename = NULL;
        const char *info[_INFO_LEN];

        _cleanup_close_ int coredump_fd = -1;

        struct iovec iovec[18];
        off_t coredump_size;
        int r, j = 0;
        uid_t uid, owner_uid;
        gid_t gid;
        pid_t pid;
        char *t;

        /* Make sure we never enter a loop */
        prctl(PR_SET_DUMPABLE, 0);

        /* First, log to a safe place, since we don't know what
         * crashed and it might be journald which we'd rather not log
         * to then. */
        log_set_target(LOG_TARGET_KMSG);
        log_open();

        if (argc < INFO_COMM + 1) {
                log_error("Not enough arguments passed from kernel (%d, expected %d).",
                          argc - 1, INFO_COMM + 1 - 1);
                r = -EINVAL;
                goto finish;
        }

        /* Ignore all parse errors */
        parse_config();

        log_debug("Selected storage '%s'.", coredump_storage_to_string(arg_storage));
        log_debug("Selected compression %s.", yes_no(arg_compress));

        r = parse_uid(argv[INFO_UID + 1], &uid);
        if (r < 0) {
                log_error("Failed to parse UID.");
                goto finish;
        }

        r = parse_pid(argv[INFO_PID + 1], &pid);
        if (r < 0) {
                log_error("Failed to parse PID.");
                goto finish;
        }

        r = parse_gid(argv[INFO_GID + 1], &gid);
        if (r < 0) {
                log_error("Failed to parse GID.");
                goto finish;
        }

        if (get_process_comm(pid, &comm) < 0) {
                log_warning("Failed to get COMM, falling back to the commandline.");
                comm = strv_join(argv + INFO_COMM + 1, " ");
        }

        if (get_process_exe(pid, &exe) < 0)
                log_warning("Failed to get EXE.");

        info[INFO_PID] = argv[INFO_PID + 1];
        info[INFO_UID] = argv[INFO_UID + 1];
        info[INFO_GID] = argv[INFO_GID + 1];
        info[INFO_SIGNAL] = argv[INFO_SIGNAL + 1];
        info[INFO_TIMESTAMP] = argv[INFO_TIMESTAMP + 1];
        info[INFO_COMM] = comm;
        info[INFO_EXE] = exe;

        if (cg_pid_get_unit(pid, &t) >= 0) {

                if (streq(t, SPECIAL_JOURNALD_SERVICE)) {

                        /* If we are journald, we cut things short,
                         * don't write to the journal, but still
                         * create a coredump. */

                        if (arg_storage != COREDUMP_STORAGE_NONE)
                                arg_storage = COREDUMP_STORAGE_EXTERNAL;

                        r = save_external_coredump(info, uid, &filename, &coredump_fd, &coredump_size);
                        if (r < 0)
                                goto finish;

                        r = maybe_remove_external_coredump(filename, coredump_size);
                        if (r < 0)
                                goto finish;

                        log_info("Detected coredump of the journal daemon itself, diverted to %s.", filename);
                        goto finish;
                }

                core_unit = strappend("COREDUMP_UNIT=", t);
        } else if (cg_pid_get_user_unit(pid, &t) >= 0)
                core_unit = strappend("COREDUMP_USER_UNIT=", t);

        if (core_unit)
                IOVEC_SET_STRING(iovec[j++], core_unit);

        /* OK, now we know it's not the journal, hence we can make use
         * of it now. */
        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_open();

        core_pid = strappend("COREDUMP_PID=", info[INFO_PID]);
        if (core_pid)
                IOVEC_SET_STRING(iovec[j++], core_pid);

        core_uid = strappend("COREDUMP_UID=", info[INFO_UID]);
        if (core_uid)
                IOVEC_SET_STRING(iovec[j++], core_uid);

        core_gid = strappend("COREDUMP_GID=", info[INFO_GID]);
        if (core_gid)
                IOVEC_SET_STRING(iovec[j++], core_gid);

        core_signal = strappend("COREDUMP_SIGNAL=", info[INFO_SIGNAL]);
        if (core_signal)
                IOVEC_SET_STRING(iovec[j++], core_signal);

        if (sd_pid_get_session(pid, &t) >= 0) {
                core_session = strappend("COREDUMP_SESSION=", t);
                free(t);

                if (core_session)
                        IOVEC_SET_STRING(iovec[j++], core_session);
        }

        if (sd_pid_get_owner_uid(pid, &owner_uid) >= 0) {
                asprintf(&core_owner_uid, "COREDUMP_OWNER_UID=" UID_FMT, owner_uid);

                if (core_owner_uid)
                        IOVEC_SET_STRING(iovec[j++], core_owner_uid);
        }

        if (sd_pid_get_slice(pid, &t) >= 0) {
                core_slice = strappend("COREDUMP_SLICE=", t);
                free(t);

                if (core_slice)
                        IOVEC_SET_STRING(iovec[j++], core_slice);
        }

        if (comm) {
                core_comm = strappend("COREDUMP_COMM=", comm);
                if (core_comm)
                        IOVEC_SET_STRING(iovec[j++], core_comm);
        }

        if (exe) {
                core_exe = strappend("COREDUMP_EXE=", exe);
                if (core_exe)
                        IOVEC_SET_STRING(iovec[j++], core_exe);
        }

        if (get_process_cmdline(pid, 0, false, &t) >= 0) {
                core_cmdline = strappend("COREDUMP_CMDLINE=", t);
                free(t);

                if (core_cmdline)
                        IOVEC_SET_STRING(iovec[j++], core_cmdline);
        }

        if (cg_pid_get_path_shifted(pid, NULL, &t) >= 0) {
                core_cgroup = strappend("COREDUMP_CGROUP=", t);
                free(t);

                if (core_cgroup)
                        IOVEC_SET_STRING(iovec[j++], core_cgroup);
        }

        core_timestamp = strjoin("COREDUMP_TIMESTAMP=", info[INFO_TIMESTAMP], "000000", NULL);
        if (core_timestamp)
                IOVEC_SET_STRING(iovec[j++], core_timestamp);

        IOVEC_SET_STRING(iovec[j++], "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1");
        IOVEC_SET_STRING(iovec[j++], "PRIORITY=2");

        /* Vacuum before we write anything again */
        coredump_vacuum(-1, arg_keep_free, arg_max_use);

        /* Always stream the coredump to disk, if that's possible */
        r = save_external_coredump(info, uid, &filename, &coredump_fd, &coredump_size);
        if (r < 0)
                /* skip whole core dumping part */
                goto log;

        /* If we don't want to keep the coredump on disk, remove it
         * now, as later on we will lack the privileges for
         * it. However, we keep the fd to it, so that we can still
         * process it and log it. */
        r = maybe_remove_external_coredump(filename, coredump_size);
        if (r < 0)
                goto finish;
        if (r == 0) {
                const char *coredump_filename;

                coredump_filename = strappenda("COREDUMP_FILENAME=", filename);
                IOVEC_SET_STRING(iovec[j++], coredump_filename);
        }

        /* Vacuum again, but exclude the coredump we just created */
        coredump_vacuum(coredump_fd, arg_keep_free, arg_max_use);

        /* Now, let's drop privileges to become the user who owns the
         * segfaulted process and allocate the coredump memory under
         * his uid. This also ensures that the credentials journald
         * will see are the ones of the coredumping user, thus making
         * sure the user himself gets access to the core dump. */
        if (setresgid(gid, gid, gid) < 0 ||
            setresuid(uid, uid, uid) < 0) {
                log_error("Failed to drop privileges: %m");
                r = -errno;
                goto finish;
        }

#ifdef HAVE_ELFUTILS
        /* Try to get a strack trace if we can */
        if (coredump_size <= arg_process_size_max) {
                _cleanup_free_ char *stacktrace = NULL;

                r = coredump_make_stack_trace(coredump_fd, exe, &stacktrace);
                if (r >= 0)
                        core_message = strjoin("MESSAGE=Process ", info[INFO_PID], " (", comm, ") of user ", info[INFO_UID], " dumped core.\n\n", stacktrace, NULL);
                else
                        log_warning("Failed to generate stack trace: %s", strerror(-r));
        }

        if (!core_message)
#endif
log:
        core_message = strjoin("MESSAGE=Process ", info[INFO_PID], " (", comm, ") of user ", info[INFO_UID], " dumped core.", NULL);
        if (core_message)
                IOVEC_SET_STRING(iovec[j++], core_message);

        /* Optionally store the entire coredump in the journal */
        if (IN_SET(arg_storage, COREDUMP_STORAGE_JOURNAL, COREDUMP_STORAGE_BOTH) &&
            coredump_size <= (off_t) arg_journal_size_max) {
                size_t sz;

                /* Store the coredump itself in the journal */

                r = allocate_journal_field(coredump_fd, (size_t) coredump_size, &coredump_data, &sz);
                if (r >= 0) {
                        iovec[j].iov_base = coredump_data;
                        iovec[j].iov_len = sz;
                        j++;
                }
        }

        r = sd_journal_sendv(iovec, j);
        if (r < 0)
                log_error("Failed to log coredump: %s", strerror(-r));

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
