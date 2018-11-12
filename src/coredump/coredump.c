/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <unistd.h>

#if HAVE_ELFUTILS
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#endif

#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "compress.h"
#include "conf-parser.h"
#include "copy.h"
#include "coredump-vacuum.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "journal-importer.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "stacktrace.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

/* The maximum size up to which we process coredumps */
#define PROCESS_SIZE_MAX ((uint64_t) (2LLU*1024LLU*1024LLU*1024LLU))

/* The maximum size up to which we leave the coredump around on disk */
#define EXTERNAL_SIZE_MAX PROCESS_SIZE_MAX

/* The maximum size up to which we store the coredump in the journal */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define JOURNAL_SIZE_MAX ((size_t) (767LU*1024LU*1024LU))
#else
/* oss-fuzz limits memory usage. */
#define JOURNAL_SIZE_MAX ((size_t) (10LU*1024LU*1024LU))
#endif

/* Make sure to not make this larger than the maximum journal entry
 * size. See DATA_SIZE_MAX in journal-importer.h. */
assert_cc(JOURNAL_SIZE_MAX <= DATA_SIZE_MAX);

enum {
        /* We use this as array indexes for a couple of special fields we use for
         * naming coredump files, and attaching xattrs, and for indexing argv[].

         * Our pattern for man:systectl(1) kernel.core_pattern is such that the
         * kernel passes fields until CONTEXT_RLIMIT as arguments in argv[]. After
         * that it gets complicated: the kernel passes "comm" as one or more fields
         * starting at index CONTEXT_COMM (in other words, full "comm" is under index
         * CONTEXT_COMM when it does not contain spaces, which is the common
         * case). This mapping is not reversible, so we prefer to retrieve "comm"
         * from /proc. We only fall back to argv[CONTEXT_COMM...] when that fails.
         *
         * In the internal context[] array, fields before CONTEXT_COMM are the
         * strings from argv[], so they should not be freed. The strings at indices
         * CONTEXT_COMM and higher are allocated by us and should be freed at the
         * end.
         */
        CONTEXT_PID,
        CONTEXT_UID,
        CONTEXT_GID,
        CONTEXT_SIGNAL,
        CONTEXT_TIMESTAMP,
        CONTEXT_RLIMIT,
        CONTEXT_HOSTNAME,
        CONTEXT_COMM,
        CONTEXT_EXE,
        CONTEXT_UNIT,
        _CONTEXT_MAX
};

typedef enum CoredumpStorage {
        COREDUMP_STORAGE_NONE,
        COREDUMP_STORAGE_EXTERNAL,
        COREDUMP_STORAGE_JOURNAL,
        _COREDUMP_STORAGE_MAX,
        _COREDUMP_STORAGE_INVALID = -1
} CoredumpStorage;

static const char* const coredump_storage_table[_COREDUMP_STORAGE_MAX] = {
        [COREDUMP_STORAGE_NONE] = "none",
        [COREDUMP_STORAGE_EXTERNAL] = "external",
        [COREDUMP_STORAGE_JOURNAL] = "journal",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(coredump_storage, CoredumpStorage);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_coredump_storage, coredump_storage, CoredumpStorage, "Failed to parse storage setting");

static CoredumpStorage arg_storage = COREDUMP_STORAGE_EXTERNAL;
static bool arg_compress = true;
static uint64_t arg_process_size_max = PROCESS_SIZE_MAX;
static uint64_t arg_external_size_max = EXTERNAL_SIZE_MAX;
static uint64_t arg_journal_size_max = JOURNAL_SIZE_MAX;
static uint64_t arg_keep_free = (uint64_t) -1;
static uint64_t arg_max_use = (uint64_t) -1;

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "Coredump", "Storage",          config_parse_coredump_storage,  0, &arg_storage           },
                { "Coredump", "Compress",         config_parse_bool,              0, &arg_compress          },
                { "Coredump", "ProcessSizeMax",   config_parse_iec_uint64,        0, &arg_process_size_max  },
                { "Coredump", "ExternalSizeMax",  config_parse_iec_uint64,        0, &arg_external_size_max },
                { "Coredump", "JournalSizeMax",   config_parse_iec_size,          0, &arg_journal_size_max  },
                { "Coredump", "KeepFree",         config_parse_iec_uint64,        0, &arg_keep_free         },
                { "Coredump", "MaxUse",           config_parse_iec_uint64,        0, &arg_max_use           },
                {}
        };

        return config_parse_many_nulstr(PKGSYSCONFDIR "/coredump.conf",
                                        CONF_PATHS_NULSTR("systemd/coredump.conf.d"),
                                        "Coredump\0",
                                        config_item_table_lookup, items,
                                        CONFIG_PARSE_WARN, NULL);
}

static inline uint64_t storage_size_max(void) {
        if (arg_storage == COREDUMP_STORAGE_EXTERNAL)
                return arg_external_size_max;
        if (arg_storage == COREDUMP_STORAGE_JOURNAL)
                return arg_journal_size_max;
        assert(arg_storage == COREDUMP_STORAGE_NONE);
        return 0;
}

static int fix_acl(int fd, uid_t uid) {

#if HAVE_ACL
        _cleanup_(acl_freep) acl_t acl = NULL;
        acl_entry_t entry;
        acl_permset_t permset;
        int r;

        assert(fd >= 0);

        if (uid_is_system(uid) || uid_is_dynamic(uid) || uid == UID_NOBODY)
                return 0;

        /* Make sure normal users can read (but not write or delete)
         * their own coredumps */

        acl = acl_get_fd(fd);
        if (!acl)
                return log_error_errno(errno, "Failed to get ACL: %m");

        if (acl_create_entry(&acl, &entry) < 0 ||
            acl_set_tag_type(entry, ACL_USER) < 0 ||
            acl_set_qualifier(entry, &uid) < 0)
                return log_error_errno(errno, "Failed to patch ACL: %m");

        if (acl_get_permset(entry, &permset) < 0 ||
            acl_add_perm(permset, ACL_READ) < 0)
                return log_warning_errno(errno, "Failed to patch ACL: %m");

        r = calc_acl_mask_if_needed(&acl);
        if (r < 0)
                return log_warning_errno(r, "Failed to patch ACL: %m");

        if (acl_set_fd(fd, acl) < 0)
                return log_error_errno(errno, "Failed to apply ACL: %m");
#endif

        return 0;
}

static int fix_xattr(int fd, const char *context[_CONTEXT_MAX]) {

        static const char * const xattrs[_CONTEXT_MAX] = {
                [CONTEXT_PID] = "user.coredump.pid",
                [CONTEXT_UID] = "user.coredump.uid",
                [CONTEXT_GID] = "user.coredump.gid",
                [CONTEXT_SIGNAL] = "user.coredump.signal",
                [CONTEXT_TIMESTAMP] = "user.coredump.timestamp",
                [CONTEXT_RLIMIT] = "user.coredump.rlimit",
                [CONTEXT_HOSTNAME] = "user.coredump.hostname",
                [CONTEXT_COMM] = "user.coredump.comm",
                [CONTEXT_EXE] = "user.coredump.exe",
        };

        int r = 0;
        unsigned i;

        assert(fd >= 0);

        /* Attach some metadata to coredumps via extended
         * attributes. Just because we can. */

        for (i = 0; i < _CONTEXT_MAX; i++) {
                int k;

                if (isempty(context[i]) || !xattrs[i])
                        continue;

                k = fsetxattr(fd, xattrs[i], context[i], strlen(context[i]), XATTR_CREATE);
                if (k < 0 && r == 0)
                        r = -errno;
        }

        return r;
}

#define filename_escape(s) xescape((s), "./ ")

static inline const char *coredump_tmpfile_name(const char *s) {
        return s ? s : "(unnamed temporary file)";
}

static int fix_permissions(
                int fd,
                const char *filename,
                const char *target,
                const char *context[_CONTEXT_MAX],
                uid_t uid) {

        int r;

        assert(fd >= 0);
        assert(target);
        assert(context);

        /* Ignore errors on these */
        (void) fchmod(fd, 0640);
        (void) fix_acl(fd, uid);
        (void) fix_xattr(fd, context);

        if (fsync(fd) < 0)
                return log_error_errno(errno, "Failed to sync coredump %s: %m", coredump_tmpfile_name(filename));

        (void) fsync_directory_of_file(fd);

        r = link_tmpfile(fd, filename, target);
        if (r < 0)
                return log_error_errno(r, "Failed to move coredump %s into place: %m", target);

        return 0;
}

static int maybe_remove_external_coredump(const char *filename, uint64_t size) {

        /* Returns 1 if might remove, 0 if will not remove, < 0 on error. */

        if (arg_storage == COREDUMP_STORAGE_EXTERNAL &&
            size <= arg_external_size_max)
                return 0;

        if (!filename)
                return 1;

        if (unlink(filename) < 0 && errno != ENOENT)
                return log_error_errno(errno, "Failed to unlink %s: %m", filename);

        return 1;
}

static int make_filename(const char *context[_CONTEXT_MAX], char **ret) {
        _cleanup_free_ char *c = NULL, *u = NULL, *p = NULL, *t = NULL;
        sd_id128_t boot = {};
        int r;

        assert(context);

        c = filename_escape(context[CONTEXT_COMM]);
        if (!c)
                return -ENOMEM;

        u = filename_escape(context[CONTEXT_UID]);
        if (!u)
                return -ENOMEM;

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return r;

        p = filename_escape(context[CONTEXT_PID]);
        if (!p)
                return -ENOMEM;

        t = filename_escape(context[CONTEXT_TIMESTAMP]);
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
                const char *context[_CONTEXT_MAX],
                int input_fd,
                char **ret_filename,
                int *ret_node_fd,
                int *ret_data_fd,
                uint64_t *ret_size,
                bool *ret_truncated) {

        _cleanup_free_ char *fn = NULL, *tmp = NULL;
        _cleanup_close_ int fd = -1;
        uint64_t rlimit, process_limit, max_size;
        struct stat st;
        uid_t uid;
        int r;

        assert(context);
        assert(ret_filename);
        assert(ret_node_fd);
        assert(ret_data_fd);
        assert(ret_size);

        r = parse_uid(context[CONTEXT_UID], &uid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse UID: %m");

        r = safe_atou64(context[CONTEXT_RLIMIT], &rlimit);
        if (r < 0)
                return log_error_errno(r, "Failed to parse resource limit '%s': %m", context[CONTEXT_RLIMIT]);
        if (rlimit < page_size()) {
                /* Is coredumping disabled? Then don't bother saving/processing the coredump.
                 * Anything below PAGE_SIZE cannot give a readable coredump (the kernel uses
                 * ELF_EXEC_PAGESIZE which is not easily accessible, but is usually the same as PAGE_SIZE. */
                log_info("Resource limits disable core dumping for process %s (%s).",
                         context[CONTEXT_PID], context[CONTEXT_COMM]);
                return -EBADSLT;
        }

        process_limit = MAX(arg_process_size_max, storage_size_max());
        if (process_limit == 0) {
                log_debug("Limits for coredump processing and storage are both 0, not dumping core.");
                return -EBADSLT;
        }

        /* Never store more than the process configured, or than we actually shall keep or process */
        max_size = MIN(rlimit, process_limit);

        r = make_filename(context, &fn);
        if (r < 0)
                return log_error_errno(r, "Failed to determine coredump file name: %m");

        mkdir_p_label("/var/lib/systemd/coredump", 0755);

        fd = open_tmpfile_linkable(fn, O_RDWR|O_CLOEXEC, &tmp);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create temporary file for coredump %s: %m", fn);

        r = copy_bytes(input_fd, fd, max_size, 0);
        if (r < 0) {
                log_error_errno(r, "Cannot store coredump of %s (%s): %m", context[CONTEXT_PID], context[CONTEXT_COMM]);
                goto fail;
        }
        *ret_truncated = r == 1;
        if (*ret_truncated)
                log_struct(LOG_INFO,
                           LOG_MESSAGE("Core file was truncated to %zu bytes.", max_size),
                           "SIZE_LIMIT=%zu", max_size,
                           "MESSAGE_ID=" SD_MESSAGE_TRUNCATED_CORE_STR);

        if (fstat(fd, &st) < 0) {
                log_error_errno(errno, "Failed to fstat core file %s: %m", coredump_tmpfile_name(tmp));
                goto fail;
        }

        if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
                log_error_errno(errno, "Failed to seek on %s: %m", coredump_tmpfile_name(tmp));
                goto fail;
        }

#if HAVE_XZ || HAVE_LZ4
        /* If we will remove the coredump anyway, do not compress. */
        if (arg_compress && !maybe_remove_external_coredump(NULL, st.st_size)) {

                _cleanup_free_ char *fn_compressed = NULL, *tmp_compressed = NULL;
                _cleanup_close_ int fd_compressed = -1;

                fn_compressed = strappend(fn, COMPRESSED_EXT);
                if (!fn_compressed) {
                        log_oom();
                        goto uncompressed;
                }

                fd_compressed = open_tmpfile_linkable(fn_compressed, O_RDWR|O_CLOEXEC, &tmp_compressed);
                if (fd_compressed < 0) {
                        log_error_errno(fd_compressed, "Failed to create temporary file for coredump %s: %m", fn_compressed);
                        goto uncompressed;
                }

                r = compress_stream(fd, fd_compressed, -1);
                if (r < 0) {
                        log_error_errno(r, "Failed to compress %s: %m", coredump_tmpfile_name(tmp_compressed));
                        goto fail_compressed;
                }

                r = fix_permissions(fd_compressed, tmp_compressed, fn_compressed, context, uid);
                if (r < 0)
                        goto fail_compressed;

                /* OK, this worked, we can get rid of the uncompressed version now */
                if (tmp)
                        unlink_noerrno(tmp);

                *ret_filename = TAKE_PTR(fn_compressed);     /* compressed */
                *ret_node_fd = TAKE_FD(fd_compressed);      /* compressed */
                *ret_data_fd = TAKE_FD(fd);                 /* uncompressed */
                *ret_size = (uint64_t) st.st_size; /* uncompressed */

                return 0;

        fail_compressed:
                if (tmp_compressed)
                        (void) unlink(tmp_compressed);
        }

uncompressed:
#endif

        r = fix_permissions(fd, tmp, fn, context, uid);
        if (r < 0)
                goto fail;

        *ret_filename = TAKE_PTR(fn);
        *ret_data_fd = TAKE_FD(fd);
        *ret_node_fd = -1;
        *ret_size = (uint64_t) st.st_size;

        return 0;

fail:
        if (tmp)
                (void) unlink(tmp);
        return r;
}

static int allocate_journal_field(int fd, size_t size, char **ret, size_t *ret_size) {
        _cleanup_free_ char *field = NULL;
        ssize_t n;

        assert(fd >= 0);
        assert(ret);
        assert(ret_size);

        if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
                return log_warning_errno(errno, "Failed to seek: %m");

        field = malloc(9 + size);
        if (!field) {
                log_warning("Failed to allocate memory for coredump, coredump will not be stored.");
                return -ENOMEM;
        }

        memcpy(field, "COREDUMP=", 9);

        n = read(fd, field + 9, size);
        if (n < 0)
                return log_error_errno((int) n, "Failed to read core data: %m");
        if ((size_t) n < size) {
                log_error("Core data too short.");
                return -EIO;
        }

        *ret = TAKE_PTR(field);
        *ret_size = size + 9;

        return 0;
}

/* Joins /proc/[pid]/fd/ and /proc/[pid]/fdinfo/ into the following lines:
 * 0:/dev/pts/23
 * pos:    0
 * flags:  0100002
 *
 * 1:/dev/pts/23
 * pos:    0
 * flags:  0100002
 *
 * 2:/dev/pts/23
 * pos:    0
 * flags:  0100002
 * EOF
 */
static int compose_open_fds(pid_t pid, char **open_fds) {
        _cleanup_closedir_ DIR *proc_fd_dir = NULL;
        _cleanup_close_ int proc_fdinfo_fd = -1;
        _cleanup_free_ char *buffer = NULL;
        _cleanup_fclose_ FILE *stream = NULL;
        const char *fddelim = "", *path;
        struct dirent *dent = NULL;
        size_t size = 0;
        int r;

        assert(pid >= 0);
        assert(open_fds != NULL);

        path = procfs_file_alloca(pid, "fd");
        proc_fd_dir = opendir(path);
        if (!proc_fd_dir)
                return -errno;

        proc_fdinfo_fd = openat(dirfd(proc_fd_dir), "../fdinfo", O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_PATH);
        if (proc_fdinfo_fd < 0)
                return -errno;

        stream = open_memstream(&buffer, &size);
        if (!stream)
                return -ENOMEM;

        (void) __fsetlocking(stream, FSETLOCKING_BYCALLER);

        FOREACH_DIRENT(dent, proc_fd_dir, return -errno) {
                _cleanup_fclose_ FILE *fdinfo = NULL;
                _cleanup_free_ char *fdname = NULL;
                int fd;

                r = readlinkat_malloc(dirfd(proc_fd_dir), dent->d_name, &fdname);
                if (r < 0)
                        return r;

                fprintf(stream, "%s%s:%s\n", fddelim, dent->d_name, fdname);
                fddelim = "\n";

                /* Use the directory entry from /proc/[pid]/fd with /proc/[pid]/fdinfo */
                fd = openat(proc_fdinfo_fd, dent->d_name, O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
                if (fd < 0)
                        continue;

                fdinfo = fdopen(fd, "re");
                if (!fdinfo) {
                        safe_close(fd);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;

                        r = read_line(fdinfo, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        fputs(line, stream);
                        fputc('\n', stream);
                }
        }

        errno = 0;
        stream = safe_fclose(stream);

        if (errno > 0)
                return -errno;

        *open_fds = TAKE_PTR(buffer);

        return 0;
}

static int get_process_ns(pid_t pid, const char *namespace, ino_t *ns) {
        const char *p;
        struct stat stbuf;
        _cleanup_close_ int proc_ns_dir_fd;

        p = procfs_file_alloca(pid, "ns");

        proc_ns_dir_fd = open(p, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
        if (proc_ns_dir_fd < 0)
                return -errno;

        if (fstatat(proc_ns_dir_fd, namespace, &stbuf, /* flags */0) < 0)
                return -errno;

        *ns = stbuf.st_ino;
        return 0;
}

static int get_mount_namespace_leader(pid_t pid, pid_t *container_pid) {
        pid_t cpid = pid, ppid = 0;
        ino_t proc_mntns;
        int r = 0;

        r = get_process_ns(pid, "mnt", &proc_mntns);
        if (r < 0)
                return r;

        for (;;) {
                ino_t parent_mntns;

                r = get_process_ppid(cpid, &ppid);
                if (r < 0)
                        return r;

                r = get_process_ns(ppid, "mnt", &parent_mntns);
                if (r < 0)
                        return r;

                if (proc_mntns != parent_mntns)
                        break;

                if (ppid == 1)
                        return -ENOENT;

                cpid = ppid;
        }

        *container_pid = ppid;
        return 0;
}

/* Returns 1 if the parent was found.
 * Returns 0 if there is not a process we can call the pid's
 * container parent (the pid's process isn't 'containerized').
 * Returns a negative number on errors.
 */
static int get_process_container_parent_cmdline(pid_t pid, char** cmdline) {
        int r = 0;
        pid_t container_pid;
        const char *proc_root_path;
        struct stat root_stat, proc_root_stat;

        /* To compare inodes of / and /proc/[pid]/root */
        if (stat("/", &root_stat) < 0)
                return -errno;

        proc_root_path = procfs_file_alloca(pid, "root");
        if (stat(proc_root_path, &proc_root_stat) < 0)
                return -errno;

        /* The process uses system root. */
        if (proc_root_stat.st_ino == root_stat.st_ino) {
                *cmdline = NULL;
                return 0;
        }

        r = get_mount_namespace_leader(pid, &container_pid);
        if (r < 0)
                return r;

        r = get_process_cmdline(container_pid, 0, false, cmdline);
        if (r < 0)
                return r;

        return 1;
}

static int change_uid_gid(const char *context[]) {
        uid_t uid;
        gid_t gid;
        int r;

        r = parse_uid(context[CONTEXT_UID], &uid);
        if (r < 0)
                return r;

        if (uid <= SYSTEM_UID_MAX) {
                const char *user = "systemd-coredump";

                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0) {
                        log_warning_errno(r, "Cannot resolve %s user. Proceeding to dump core as root: %m", user);
                        uid = gid = 0;
                }
        } else {
                r = parse_gid(context[CONTEXT_GID], &gid);
                if (r < 0)
                        return r;
        }

        return drop_privileges(uid, gid, 0);
}

static bool is_journald_crash(const char *context[_CONTEXT_MAX]) {
        assert(context);

        return streq_ptr(context[CONTEXT_UNIT], SPECIAL_JOURNALD_SERVICE);
}

static bool is_pid1_crash(const char *context[_CONTEXT_MAX]) {
        assert(context);

        return streq_ptr(context[CONTEXT_UNIT], SPECIAL_INIT_SCOPE) ||
                streq_ptr(context[CONTEXT_PID], "1");
}

#define SUBMIT_COREDUMP_FIELDS 4

static int submit_coredump(
                const char *context[_CONTEXT_MAX],
                struct iovec *iovec,
                size_t n_iovec_allocated,
                size_t n_iovec,
                int input_fd) {

        _cleanup_close_ int coredump_fd = -1, coredump_node_fd = -1;
        _cleanup_free_ char *core_message = NULL, *filename = NULL, *coredump_data = NULL;
        uint64_t coredump_size = UINT64_MAX;
        bool truncated = false, journald_crash;
        int r;

        assert(context);
        assert(iovec);
        assert(n_iovec_allocated >= n_iovec + SUBMIT_COREDUMP_FIELDS);
        assert(input_fd >= 0);

        journald_crash = is_journald_crash(context);

        /* Vacuum before we write anything again */
        (void) coredump_vacuum(-1, arg_keep_free, arg_max_use);

        /* Always stream the coredump to disk, if that's possible */
        r = save_external_coredump(context, input_fd,
                                   &filename, &coredump_node_fd, &coredump_fd, &coredump_size, &truncated);
        if (r < 0)
                /* Skip whole core dumping part */
                goto log;

        /* If we don't want to keep the coredump on disk, remove it now, as later on we will lack the privileges for
         * it. However, we keep the fd to it, so that we can still process it and log it. */
        r = maybe_remove_external_coredump(filename, coredump_size);
        if (r < 0)
                return r;
        if (r == 0) {
                const char *coredump_filename;

                coredump_filename = strjoina("COREDUMP_FILENAME=", filename);
                iovec[n_iovec++] = IOVEC_MAKE_STRING(coredump_filename);
        } else if (arg_storage == COREDUMP_STORAGE_EXTERNAL)
                log_info("The core will not be stored: size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                         coredump_size, arg_external_size_max);

        /* Vacuum again, but exclude the coredump we just created */
        (void) coredump_vacuum(coredump_node_fd >= 0 ? coredump_node_fd : coredump_fd, arg_keep_free, arg_max_use);

        /* Now, let's drop privileges to become the user who owns the segfaulted process and allocate the coredump
         * memory under the user's uid. This also ensures that the credentials journald will see are the ones of the
         * coredumping user, thus making sure the user gets access to the core dump. Let's also get rid of all
         * capabilities, if we run as root, we won't need them anymore. */
        r = change_uid_gid(context);
        if (r < 0)
                return log_error_errno(r, "Failed to drop privileges: %m");

#if HAVE_ELFUTILS
        /* Try to get a strack trace if we can */
        if (coredump_size <= arg_process_size_max) {
                _cleanup_free_ char *stacktrace = NULL;

                r = coredump_make_stack_trace(coredump_fd, context[CONTEXT_EXE], &stacktrace);
                if (r >= 0)
                        core_message = strjoin("MESSAGE=Process ", context[CONTEXT_PID],
                                               " (", context[CONTEXT_COMM], ") of user ",
                                               context[CONTEXT_UID], " dumped core.",
                                               journald_crash ? "\nCoredump diverted to " : "",
                                               journald_crash ? filename : "",
                                               "\n\n", stacktrace);
                else if (r == -EINVAL)
                        log_warning("Failed to generate stack trace: %s", dwfl_errmsg(dwfl_errno()));
                else
                        log_warning_errno(r, "Failed to generate stack trace: %m");
        } else
                log_debug("Not generating stack trace: core size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                          coredump_size, arg_process_size_max);

        if (!core_message)
#endif
log:
        core_message = strjoin("MESSAGE=Process ", context[CONTEXT_PID],
                               " (", context[CONTEXT_COMM], ") of user ",
                               context[CONTEXT_UID], " dumped core.",
                               journald_crash ? "\nCoredump diverted to " : NULL,
                               journald_crash ? filename : NULL);
        if (!core_message)
                return log_oom();

        if (journald_crash) {
                /* We cannot log to the journal, so just print the MESSAGE.
                 * The target was set previously to something safe. */
                log_dispatch(LOG_ERR, 0, core_message);
                return 0;
        }

        iovec[n_iovec++] = IOVEC_MAKE_STRING(core_message);

        if (truncated)
                iovec[n_iovec++] = IOVEC_MAKE_STRING("COREDUMP_TRUNCATED=1");

        /* Optionally store the entire coredump in the journal */
        if (arg_storage == COREDUMP_STORAGE_JOURNAL) {
                if (coredump_size <= arg_journal_size_max) {
                        size_t sz = 0;

                        /* Store the coredump itself in the journal */

                        r = allocate_journal_field(coredump_fd, (size_t) coredump_size, &coredump_data, &sz);
                        if (r >= 0)
                                iovec[n_iovec++] = IOVEC_MAKE(coredump_data, sz);
                        else
                                log_warning_errno(r, "Failed to attach the core to the journal entry: %m");
                } else
                        log_info("The core will not be stored: size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                                 coredump_size, arg_journal_size_max);
        }

        assert(n_iovec <= n_iovec_allocated);

        r = sd_journal_sendv(iovec, n_iovec);
        if (r < 0)
                return log_error_errno(r, "Failed to log coredump: %m");

        return 0;
}

static void map_context_fields(const struct iovec *iovec, const char* context[]) {

        static const char * const context_field_names[] = {
                [CONTEXT_PID] = "COREDUMP_PID=",
                [CONTEXT_UID] = "COREDUMP_UID=",
                [CONTEXT_GID] = "COREDUMP_GID=",
                [CONTEXT_SIGNAL] = "COREDUMP_SIGNAL=",
                [CONTEXT_TIMESTAMP] = "COREDUMP_TIMESTAMP=",
                [CONTEXT_RLIMIT] = "COREDUMP_RLIMIT=",
                [CONTEXT_HOSTNAME] = "COREDUMP_HOSTNAME=",
                [CONTEXT_COMM] = "COREDUMP_COMM=",
                [CONTEXT_EXE] = "COREDUMP_EXE=",
        };

        unsigned i;

        assert(iovec);
        assert(context);

        for (i = 0; i < ELEMENTSOF(context_field_names); i++) {
                char *p;

                if (!context_field_names[i])
                        continue;

                p = memory_startswith(iovec->iov_base, iovec->iov_len, context_field_names[i]);
                if (!p)
                        continue;

                /* Note that these strings are NUL terminated, because we made sure that a trailing NUL byte is in the
                 * buffer, though not included in the iov_len count. (see below) */
                context[i] = p;
                break;
        }
}

static int process_socket(int fd) {
        _cleanup_close_ int coredump_fd = -1;
        struct iovec *iovec = NULL;
        size_t n_iovec = 0, n_allocated = 0, i, k;
        const char *context[_CONTEXT_MAX] = {};
        int r;

        assert(fd >= 0);

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        log_debug("Processing coredump received on stdin...");

        for (;;) {
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(int))];
                } control = {};
                struct msghdr mh = {
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                        .msg_iovlen = 1,
                };
                ssize_t n;
                ssize_t l;

                if (!GREEDY_REALLOC(iovec, n_allocated, n_iovec + SUBMIT_COREDUMP_FIELDS)) {
                        r = log_oom();
                        goto finish;
                }

                l = next_datagram_size_fd(fd);
                if (l < 0) {
                        r = log_error_errno(l, "Failed to determine datagram size to read: %m");
                        goto finish;
                }

                assert(l >= 0);

                iovec[n_iovec].iov_len = l;
                iovec[n_iovec].iov_base = malloc(l + 1);
                if (!iovec[n_iovec].iov_base) {
                        r = log_oom();
                        goto finish;
                }

                mh.msg_iov = iovec + n_iovec;

                n = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC);
                if (n < 0)  {
                        free(iovec[n_iovec].iov_base);
                        r = log_error_errno(errno, "Failed to receive datagram: %m");
                        goto finish;
                }

                if (n == 0) {
                        struct cmsghdr *cmsg, *found = NULL;
                        /* The final zero-length datagram carries the file descriptor and tells us that we're done. */

                        free(iovec[n_iovec].iov_base);

                        CMSG_FOREACH(cmsg, &mh) {
                                if (cmsg->cmsg_level == SOL_SOCKET &&
                                    cmsg->cmsg_type == SCM_RIGHTS &&
                                    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
                                        assert(!found);
                                        found = cmsg;
                                }
                        }

                        if (!found) {
                                log_error("Coredump file descriptor missing.");
                                r = -EBADMSG;
                                goto finish;
                        }

                        assert(coredump_fd < 0);
                        coredump_fd = *(int*) CMSG_DATA(found);
                        break;
                }

                /* Add trailing NUL byte, in case these are strings */
                ((char*) iovec[n_iovec].iov_base)[n] = 0;
                iovec[n_iovec].iov_len = (size_t) n;

                cmsg_close_all(&mh);
                map_context_fields(iovec + n_iovec, context);
                n_iovec++;
        }

        if (!GREEDY_REALLOC(iovec, n_allocated, n_iovec + SUBMIT_COREDUMP_FIELDS)) {
                r = log_oom();
                goto finish;
        }

        /* Make sure we got all data we really need */
        assert(context[CONTEXT_PID]);
        assert(context[CONTEXT_UID]);
        assert(context[CONTEXT_GID]);
        assert(context[CONTEXT_SIGNAL]);
        assert(context[CONTEXT_TIMESTAMP]);
        assert(context[CONTEXT_RLIMIT]);
        assert(context[CONTEXT_HOSTNAME]);
        assert(context[CONTEXT_COMM]);
        assert(coredump_fd >= 0);

        /* Small quirk: the journal fields contain the timestamp padded with six zeroes, so that the kernel-supplied 1s
         * granularity timestamps becomes 1µs granularity, i.e. the granularity systemd usually operates in. Since we
         * are reconstructing the original kernel context, we chop this off again, here. */
        k = strlen(context[CONTEXT_TIMESTAMP]);
        if (k > 6)
                context[CONTEXT_TIMESTAMP] = strndupa(context[CONTEXT_TIMESTAMP], k - 6);

        r = submit_coredump(context, iovec, n_allocated, n_iovec, coredump_fd);

finish:
        for (i = 0; i < n_iovec; i++)
                free(iovec[i].iov_base);
        free(iovec);

        return r;
}

static int send_iovec(const struct iovec iovec[], size_t n_iovec, int input_fd) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/coredump",
        };
        _cleanup_close_ int fd = -1;
        size_t i;
        int r;

        assert(iovec || n_iovec <= 0);
        assert(input_fd >= 0);

        fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create coredump socket: %m");

        if (connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                return log_error_errno(errno, "Failed to connect to coredump service: %m");

        for (i = 0; i < n_iovec; i++) {
                struct msghdr mh = {
                        .msg_iov = (struct iovec*) iovec + i,
                        .msg_iovlen = 1,
                };
                struct iovec copy[2];

                for (;;) {
                        if (sendmsg(fd, &mh, MSG_NOSIGNAL) >= 0)
                                break;

                        if (errno == EMSGSIZE && mh.msg_iov[0].iov_len > 0) {
                                /* This field didn't fit? That's a pity. Given that this is just metadata,
                                 * let's truncate the field at half, and try again. We append three dots, in
                                 * order to show that this is truncated. */

                                if (mh.msg_iov != copy) {
                                        /* We don't want to modify the caller's iovec, hence let's create our
                                         * own array, consisting of two new iovecs, where the first is a
                                         * (truncated) copy of what we want to send, and the second one
                                         * contains the trailing dots. */
                                        copy[0] = iovec[i];
                                        copy[1] = (struct iovec) {
                                                .iov_base = (char[]) { '.', '.', '.' },
                                                .iov_len = 3,
                                        };

                                        mh.msg_iov = copy;
                                        mh.msg_iovlen = 2;
                                }

                                copy[0].iov_len /= 2; /* halve it, and try again */
                                continue;
                        }

                        return log_error_errno(errno, "Failed to send coredump datagram: %m");
                }
        }

        r = send_one_fd(fd, input_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send coredump fd: %m");

        return 0;
}

static char* set_iovec_field(struct iovec *iovec, size_t *n_iovec, const char *field, const char *value) {
        char *x;

        x = strappend(field, value);
        if (x)
                iovec[(*n_iovec)++] = IOVEC_MAKE_STRING(x);
        return x;
}

static char* set_iovec_field_free(struct iovec *iovec, size_t *n_iovec, const char *field, char *value) {
        char *x;

        x = set_iovec_field(iovec, n_iovec, field, value);
        free(value);
        return x;
}

static int gather_pid_metadata(
                char* context[_CONTEXT_MAX],
                char **comm_fallback,
                struct iovec *iovec, size_t *n_iovec) {

        /* We need 27 empty slots in iovec!
         *
         * Note that if we fail on oom later on, we do not roll-back changes to the iovec structure. (It remains valid,
         * with the first n_iovec fields initialized.) */

        uid_t owner_uid;
        pid_t pid;
        char *t;
        const char *p;
        int r, signo;

        r = parse_pid(context[CONTEXT_PID], &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PID \"%s\": %m", context[CONTEXT_PID]);

        r = get_process_comm(pid, &context[CONTEXT_COMM]);
        if (r < 0) {
                log_warning_errno(r, "Failed to get COMM, falling back to the command line: %m");
                context[CONTEXT_COMM] = strv_join(comm_fallback, " ");
                if (!context[CONTEXT_COMM])
                        return log_oom();
        }

        r = get_process_exe(pid, &context[CONTEXT_EXE]);
        if (r < 0)
                log_warning_errno(r, "Failed to get EXE, ignoring: %m");

        if (cg_pid_get_unit(pid, &context[CONTEXT_UNIT]) >= 0) {
                if (!is_journald_crash((const char**) context)) {
                        /* OK, now we know it's not the journal, hence we can make use of it now. */
                        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                        log_open();
                }

                /* If this is PID 1 disable coredump collection, we'll unlikely be able to process it later on. */
                if (is_pid1_crash((const char**) context)) {
                        log_notice("Due to PID 1 having crashed coredump collection will now be turned off.");
                        disable_coredumps();
                }

                set_iovec_field(iovec, n_iovec, "COREDUMP_UNIT=", context[CONTEXT_UNIT]);
        }

        if (cg_pid_get_user_unit(pid, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_USER_UNIT=", t);

        /* The next few are mandatory */
        if (!set_iovec_field(iovec, n_iovec, "COREDUMP_PID=", context[CONTEXT_PID]))
                return log_oom();

        if (!set_iovec_field(iovec, n_iovec, "COREDUMP_UID=", context[CONTEXT_UID]))
                return log_oom();

        if (!set_iovec_field(iovec, n_iovec, "COREDUMP_GID=", context[CONTEXT_GID]))
                return log_oom();

        if (!set_iovec_field(iovec, n_iovec, "COREDUMP_SIGNAL=", context[CONTEXT_SIGNAL]))
                return log_oom();

        if (!set_iovec_field(iovec, n_iovec, "COREDUMP_RLIMIT=", context[CONTEXT_RLIMIT]))
                return log_oom();

        if (!set_iovec_field(iovec, n_iovec, "COREDUMP_HOSTNAME=", context[CONTEXT_HOSTNAME]))
                return log_oom();

        if (!set_iovec_field(iovec, n_iovec, "COREDUMP_COMM=", context[CONTEXT_COMM]))
                return log_oom();

        if (context[CONTEXT_EXE] &&
            !set_iovec_field(iovec, n_iovec, "COREDUMP_EXE=", context[CONTEXT_EXE]))
                return log_oom();

        if (sd_pid_get_session(pid, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_SESSION=", t);

        if (sd_pid_get_owner_uid(pid, &owner_uid) >= 0) {
                r = asprintf(&t, "COREDUMP_OWNER_UID=" UID_FMT, owner_uid);
                if (r > 0)
                        iovec[(*n_iovec)++] = IOVEC_MAKE_STRING(t);
        }

        if (sd_pid_get_slice(pid, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_SLICE=", t);

        if (get_process_cmdline(pid, 0, false, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_CMDLINE=", t);

        if (cg_pid_get_path_shifted(pid, NULL, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_CGROUP=", t);

        if (compose_open_fds(pid, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_OPEN_FDS=", t);

        p = procfs_file_alloca(pid, "status");
        if (read_full_file(p, &t, NULL) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_PROC_STATUS=", t);

        p = procfs_file_alloca(pid, "maps");
        if (read_full_file(p, &t, NULL) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_PROC_MAPS=", t);

        p = procfs_file_alloca(pid, "limits");
        if (read_full_file(p, &t, NULL) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_PROC_LIMITS=", t);

        p = procfs_file_alloca(pid, "cgroup");
        if (read_full_file(p, &t, NULL) >=0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_PROC_CGROUP=", t);

        p = procfs_file_alloca(pid, "mountinfo");
        if (read_full_file(p, &t, NULL) >=0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_PROC_MOUNTINFO=", t);

        if (get_process_cwd(pid, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_CWD=", t);

        if (get_process_root(pid, &t) >= 0) {
                bool proc_self_root_is_slash;

                proc_self_root_is_slash = strcmp(t, "/") == 0;

                set_iovec_field_free(iovec, n_iovec, "COREDUMP_ROOT=", t);

                /* If the process' root is "/", then there is a chance it has
                 * mounted own root and hence being containerized. */
                if (proc_self_root_is_slash && get_process_container_parent_cmdline(pid, &t) > 0)
                        set_iovec_field_free(iovec, n_iovec, "COREDUMP_CONTAINER_CMDLINE=", t);
        }

        if (get_process_environ(pid, &t) >= 0)
                set_iovec_field_free(iovec, n_iovec, "COREDUMP_ENVIRON=", t);

        t = strjoin("COREDUMP_TIMESTAMP=", context[CONTEXT_TIMESTAMP], "000000");
        if (t)
                iovec[(*n_iovec)++] = IOVEC_MAKE_STRING(t);

        if (safe_atoi(context[CONTEXT_SIGNAL], &signo) >= 0 && SIGNAL_VALID(signo))
                set_iovec_field(iovec, n_iovec, "COREDUMP_SIGNAL_NAME=SIG", signal_to_string(signo));

        return 0; /* we successfully acquired all metadata */
}

static int process_kernel(int argc, char* argv[]) {

        char* context[_CONTEXT_MAX] = {};
        struct iovec iovec[29 + SUBMIT_COREDUMP_FIELDS];
        size_t i, n_iovec, n_to_free = 0;
        int r;

        log_debug("Processing coredump received from the kernel...");

        if (argc < CONTEXT_COMM + 1) {
                log_error("Not enough arguments passed by the kernel (%i, expected %i).", argc - 1, CONTEXT_COMM + 1 - 1);
                return -EINVAL;
        }

        context[CONTEXT_PID]       = argv[1 + CONTEXT_PID];
        context[CONTEXT_UID]       = argv[1 + CONTEXT_UID];
        context[CONTEXT_GID]       = argv[1 + CONTEXT_GID];
        context[CONTEXT_SIGNAL]    = argv[1 + CONTEXT_SIGNAL];
        context[CONTEXT_TIMESTAMP] = argv[1 + CONTEXT_TIMESTAMP];
        context[CONTEXT_RLIMIT]    = argv[1 + CONTEXT_RLIMIT];
        context[CONTEXT_HOSTNAME]  = argv[1 + CONTEXT_HOSTNAME];

        r = gather_pid_metadata(context, argv + 1 + CONTEXT_COMM, iovec, &n_to_free);
        if (r < 0)
                goto finish;

        n_iovec = n_to_free;

        iovec[n_iovec++] = IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_COREDUMP_STR);

        assert_cc(2 == LOG_CRIT);
        iovec[n_iovec++] = IOVEC_MAKE_STRING("PRIORITY=2");

        assert(n_iovec <= ELEMENTSOF(iovec));

        if (is_journald_crash((const char**) context) || is_pid1_crash((const char**) context))
                r = submit_coredump((const char**) context,
                                    iovec, ELEMENTSOF(iovec), n_iovec,
                                    STDIN_FILENO);
        else
                r = send_iovec(iovec, n_iovec, STDIN_FILENO);

 finish:
        for (i = 0; i < n_to_free; i++)
                free(iovec[i].iov_base);

        /* Those fields are allocated by gather_pid_metadata */
        free(context[CONTEXT_COMM]);
        free(context[CONTEXT_EXE]);
        free(context[CONTEXT_UNIT]);

        return r;
}

static int process_backtrace(int argc, char *argv[]) {
        char *context[_CONTEXT_MAX] = {};
        _cleanup_free_ char *message = NULL;
        _cleanup_free_ struct iovec *iovec = NULL;
        size_t n_iovec, n_allocated, n_to_free = 0, i;
        int r;
        JournalImporter importer = {
                .fd = STDIN_FILENO,
        };

        log_debug("Processing backtrace on stdin...");

        if (argc < CONTEXT_COMM + 1) {
                log_error("Not enough arguments passed (%i, expected %i).", argc - 1, CONTEXT_COMM + 1 - 1);
                return -EINVAL;
        }

        context[CONTEXT_PID]       = argv[2 + CONTEXT_PID];
        context[CONTEXT_UID]       = argv[2 + CONTEXT_UID];
        context[CONTEXT_GID]       = argv[2 + CONTEXT_GID];
        context[CONTEXT_SIGNAL]    = argv[2 + CONTEXT_SIGNAL];
        context[CONTEXT_TIMESTAMP] = argv[2 + CONTEXT_TIMESTAMP];
        context[CONTEXT_RLIMIT]    = argv[2 + CONTEXT_RLIMIT];
        context[CONTEXT_HOSTNAME]  = argv[2 + CONTEXT_HOSTNAME];

        n_allocated = 34 + COREDUMP_STORAGE_EXTERNAL;
        /* 26 metadata, 2 static, +unknown input, 4 storage, rounded up */
        iovec = new(struct iovec, n_allocated);
        if (!iovec)
                return log_oom();

        r = gather_pid_metadata(context, argv + 2 + CONTEXT_COMM, iovec, &n_to_free);
        if (r < 0)
                goto finish;
        if (r > 0) {
                /* This was a special crash, and has already been processed. */
                r = 0;
                goto finish;
        }
        n_iovec = n_to_free;

        for (;;) {
                r = journal_importer_process_data(&importer);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse journal entry on stdin: %m");
                        goto finish;
                }
                if (r == 1 ||                        /* complete entry */
                    journal_importer_eof(&importer)) /* end of data */
                        break;
        }

        if (!GREEDY_REALLOC(iovec, n_allocated, n_iovec + importer.iovw.count + 2))
                return log_oom();

        if (journal_importer_eof(&importer)) {
                log_warning("Did not receive a full journal entry on stdin, ignoring message sent by reporter");

                message = strjoin("MESSAGE=Process ", context[CONTEXT_PID],
                                  " (", context[CONTEXT_COMM], ")"
                                  " of user ", context[CONTEXT_UID],
                                  " failed with ", context[CONTEXT_SIGNAL]);
                if (!message) {
                        r = log_oom();
                        goto finish;
                }
                iovec[n_iovec++] = IOVEC_MAKE_STRING(message);
        } else {
                for (i = 0; i < importer.iovw.count; i++)
                        iovec[n_iovec++] = importer.iovw.iovec[i];
        }

        iovec[n_iovec++] = IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_BACKTRACE_STR);
        assert_cc(2 == LOG_CRIT);
        iovec[n_iovec++] = IOVEC_MAKE_STRING("PRIORITY=2");

        assert(n_iovec <= n_allocated);

        r = sd_journal_sendv(iovec, n_iovec);
        if (r < 0)
                log_error_errno(r, "Failed to log backtrace: %m");

 finish:
        for (i = 0; i < n_to_free; i++)
                free(iovec[i].iov_base);

        /* Those fields are allocated by gather_pid_metadata */
        free(context[CONTEXT_COMM]);
        free(context[CONTEXT_EXE]);
        free(context[CONTEXT_UNIT]);

        return r;
}

int main(int argc, char *argv[]) {
        int r;

        /* First, log to a safe place, since we don't know what crashed and it might
         * be journald which we'd rather not log to then. */

        log_set_target(LOG_TARGET_KMSG);
        log_open();

        /* Make sure we never enter a loop */
        (void) prctl(PR_SET_DUMPABLE, 0);

        /* Ignore all parse errors */
        (void) parse_config();

        log_debug("Selected storage '%s'.", coredump_storage_to_string(arg_storage));
        log_debug("Selected compression %s.", yes_no(arg_compress));

        r = sd_listen_fds(false);
        if (r < 0) {
                log_error_errno(r, "Failed to determine number of file descriptor: %m");
                goto finish;
        }

        /* If we got an fd passed, we are running in coredumpd mode. Otherwise we
         * are invoked from the kernel as coredump handler. */
        if (r == 0) {
                if (streq_ptr(argv[1], "--backtrace"))
                        r = process_backtrace(argc, argv);
                else
                        r = process_kernel(argc, argv);
        } else if (r == 1)
                r = process_socket(SD_LISTEN_FDS_START);
        else {
                log_error("Received unexpected number of file descriptors.");
                r = -EINVAL;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
