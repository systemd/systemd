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
#include "macro.h"
#include "mkdir.h"
#include "special.h"
#include "cgroup-util.h"
#include "journald-native.h"
#include "conf-parser.h"
#include "copy.h"
#include "stacktrace.h"
#include "path-util.h"

#ifdef HAVE_ACL
#include <sys/acl.h>
#include "acl-util.h"
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
        ARG_PID = 1,
        ARG_UID,
        ARG_GID,
        ARG_SIGNAL,
        ARG_TIMESTAMP,
        ARG_COMM,
        _ARG_MAX
};

typedef enum CoredumpStorage {
        COREDUMP_STORAGE_NONE,
        COREDUMP_STORAGE_EXTERNAL,
        COREDUMP_STORAGE_JOURNAL,
        COREDUMP_STORAGE_BOTH,
        _COREDUMP_STORAGE_MAX,
        _COREDUMP_STORAGE_INVALID = -1
} CoredumpStorage;

static CoredumpStorage arg_storage = COREDUMP_STORAGE_EXTERNAL;
static off_t arg_process_size_max = PROCESS_SIZE_MAX;
static off_t arg_external_size_max = EXTERNAL_SIZE_MAX;
static size_t arg_journal_size_max = JOURNAL_SIZE_MAX;

static const char* const coredump_storage_table[_COREDUMP_STORAGE_MAX] = {
        [COREDUMP_STORAGE_NONE] = "none",
        [COREDUMP_STORAGE_EXTERNAL] = "external",
        [COREDUMP_STORAGE_JOURNAL] = "journal",
        [COREDUMP_STORAGE_BOTH] = "both",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(coredump_storage, CoredumpStorage);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_coredump_storage, coredump_storage, CoredumpStorage, "Failed to parse storage setting");

static int parse_config(void) {

        static const ConfigTableItem items[] = {
                { "Coredump", "ProcessSizeMax",  config_parse_iec_off,           0, &arg_process_size_max  },
                { "Coredump", "ExternalSizeMax", config_parse_iec_off,           0, &arg_external_size_max },
                { "Coredump", "JournalSizeMax",  config_parse_iec_size,          0, &arg_journal_size_max  },
                { "Coredump", "Storage",         config_parse_coredump_storage,  0, &arg_storage           },
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

static int fix_xattr(int fd, char *argv[]) {

        static const char * const xattrs[_ARG_MAX] = {
                [ARG_PID] = "user.coredump.pid",
                [ARG_UID] = "user.coredump.uid",
                [ARG_GID] = "user.coredump.gid",
                [ARG_SIGNAL] = "user.coredump.signal",
                [ARG_TIMESTAMP] = "user.coredump.timestamp",
                [ARG_COMM] = "user.coredump.comm",
        };

        int r = 0;
        unsigned i;

        /* Attach some metadate to coredumps via extended
         * attributes. Just because we can. */

        for (i = 0; i < _ARG_MAX; i++) {
                if (isempty(argv[i]))
                        continue;

                if (fsetxattr(fd, xattrs[i], argv[i], strlen(argv[i]), XATTR_CREATE) < 0)
                        r = -errno;
        }

        return r;
}

#define filename_escape(s) xescape((s), "./ ")

static int save_external_coredump(char **argv, uid_t uid, char **ret_filename, int *ret_fd, off_t *ret_size) {
        _cleanup_free_ char *p = NULL, *t = NULL, *c = NULL, *fn = NULL, *tmp = NULL;
        _cleanup_close_ int fd = -1;
        sd_id128_t boot;
        struct stat st;
        int r;

        assert(argv);
        assert(ret_filename);
        assert(ret_fd);
        assert(ret_size);

        c = filename_escape(argv[ARG_COMM]);
        if (!c)
                return log_oom();

        p = filename_escape(argv[ARG_PID]);
        if (!p)
                return log_oom();

        t = filename_escape(argv[ARG_TIMESTAMP]);
        if (!t)
                return log_oom();

        r = sd_id128_get_boot(&boot);
        if (r < 0) {
                log_error("Failed to determine boot ID: %s", strerror(-r));
                return r;
        }

        r = asprintf(&fn,
                     "/var/lib/systemd/coredump/core.%s." SD_ID128_FORMAT_STR ".%s.%s000000",
                     c,
                     SD_ID128_FORMAT_VAL(boot),
                     p,
                     t);
        if (r < 0)
                return log_oom();

        tmp = tempfn_random(fn);
        if (!tmp)
                return log_oom();

        mkdir_p_label("/var/lib/systemd/coredump", 0755);

        fd = open(tmp, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0640);
        if (fd < 0) {
                log_error("Failed to create coredump file: %m");
                return -errno;
        }

        r = copy_bytes(STDIN_FILENO, fd);
        if (r < 0) {
                log_error("Failed to dump coredump to file: %s", strerror(-r));
                goto fail;
        }

        /* Ignore errors on these */
        fchmod(fd, 0640);
        fix_acl(fd, uid);
        fix_xattr(fd, argv);

        if (fsync(fd) < 0) {
                log_error("Failed to sync coredump: %m");
                r = -errno;
                goto fail;
        }

        if (fstat(fd, &st) < 0) {
                log_error("Failed to fstat coredump: %m");
                r = -errno;
                goto fail;
        }

        if (rename(tmp, fn) < 0) {
                log_error("Failed to rename coredump: %m");
                r = -errno;
                goto fail;
        }

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
                log_warning("Failed to allocate memory fore coredump, coredump will not be stored.");
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

static int maybe_remove_external_coredump(const char *filename, off_t size) {

        if (!filename)
                return 0;

        if (IN_SET(arg_storage, COREDUMP_STORAGE_EXTERNAL, COREDUMP_STORAGE_BOTH) &&
            size <= arg_external_size_max)
                return 0;

        if (unlink(filename) < 0) {
                log_error("Failed to unlink %s: %m", filename);
                return -errno;
        }

        return 0;
}

int main(int argc, char* argv[]) {

        _cleanup_free_ char *core_pid = NULL, *core_uid = NULL, *core_gid = NULL, *core_signal = NULL,
                *core_timestamp = NULL, *core_comm = NULL, *core_exe = NULL, *core_unit = NULL,
                *core_session = NULL, *core_message = NULL, *core_cmdline = NULL, *coredump_data = NULL,
                *coredump_filename = NULL, *core_slice = NULL, *core_cgroup = NULL, *core_owner_uid = NULL,
                *exe = NULL;

        _cleanup_close_ int coredump_fd = -1;

        struct iovec iovec[17];
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

        if (argc != _ARG_MAX) {
                log_error("Invalid number of arguments passed from kernel.");
                r = -EINVAL;
                goto finish;
        }

        /* Ignore all parse errors */
        parse_config();
        log_debug("Selected storage '%s'.", coredump_storage_to_string(arg_storage));

        /* Exit early if we cannot write the coredump to disk anyway */
        if (path_is_read_only_fs("/var/lib") != 0) {
                log_error("Coredump directory not mounted or not writable, skipping coredump.");
                r = -EROFS;
                goto finish;
        }

        r = parse_uid(argv[ARG_UID], &uid);
        if (r < 0) {
                log_error("Failed to parse UID.");
                goto finish;
        }

        r = parse_pid(argv[ARG_PID], &pid);
        if (r < 0) {
                log_error("Failed to parse PID.");
                goto finish;
        }

        r = parse_gid(argv[ARG_GID], &gid);
        if (r < 0) {
                log_error("Failed to parse GID.");
                goto finish;
        }

        if (cg_pid_get_unit(pid, &t) >= 0) {

                if (streq(t, SPECIAL_JOURNALD_SERVICE)) {

                        /* If we are journald, we cut things short,
                         * don't write to the journal, but still
                         * create a coredump. */

                        if (arg_storage != COREDUMP_STORAGE_NONE)
                                arg_storage = COREDUMP_STORAGE_EXTERNAL;

                        r = save_external_coredump(argv, uid, &coredump_filename, &coredump_fd, &coredump_size);
                        if (r < 0)
                                goto finish;

                        r = maybe_remove_external_coredump(coredump_filename, coredump_size);
                        if (r < 0)
                                goto finish;

                        log_info("Detected coredump of the journal daemon itself, diverted to %s.", coredump_filename);
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

        core_pid = strappend("COREDUMP_PID=", argv[ARG_PID]);
        if (core_pid)
                IOVEC_SET_STRING(iovec[j++], core_pid);

        core_uid = strappend("COREDUMP_UID=", argv[ARG_UID]);
        if (core_uid)
                IOVEC_SET_STRING(iovec[j++], core_uid);

        core_gid = strappend("COREDUMP_GID=", argv[ARG_GID]);
        if (core_gid)
                IOVEC_SET_STRING(iovec[j++], core_gid);

        core_signal = strappend("COREDUMP_SIGNAL=", argv[ARG_SIGNAL]);
        if (core_signal)
                IOVEC_SET_STRING(iovec[j++], core_signal);

        core_comm = strappend("COREDUMP_COMM=", argv[ARG_COMM]);
        if (core_comm)
                IOVEC_SET_STRING(iovec[j++], core_comm);

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

        if (get_process_exe(pid, &exe) >= 0) {
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

        core_timestamp = strjoin("COREDUMP_TIMESTAMP=", argv[ARG_TIMESTAMP], "000000", NULL);
        if (core_timestamp)
                IOVEC_SET_STRING(iovec[j++], core_timestamp);

        IOVEC_SET_STRING(iovec[j++], "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1");
        IOVEC_SET_STRING(iovec[j++], "PRIORITY=2");

        /* Always stream the coredump to disk, if that's possible */
        r = save_external_coredump(argv, uid, &coredump_filename, &coredump_fd, &coredump_size);
        if (r < 0)
                goto finish;

        /* If we don't want to keep the coredump on disk, remove it
         * now, as later on we will lack the privileges for
         * it. However, we keep the fd to it, so that we can still
         * process it and log it. */
        r = maybe_remove_external_coredump(coredump_filename, coredump_size);
        if (r < 0)
                goto finish;

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
                        core_message = strjoin("MESSAGE=Process ", argv[ARG_PID], " (", argv[ARG_COMM], ") of user ", argv[ARG_UID], " dumped core.\n\n", stacktrace, NULL);
                else
                        log_warning("Failed to generate stack trace: %s", strerror(-r));
        }

        if (!core_message)
#endif
        core_message = strjoin("MESSAGE=Process ", argv[ARG_PID], " (", argv[ARG_COMM], ") of user ", argv[ARG_UID], " dumped core.", NULL);
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
