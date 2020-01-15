#include <errno.h>
#include <stdio.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-journal.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "capability-util.h"
#include "compress.h"
#include "conf-parser.h"
#include "copy.h"
#include "coredump.h"
#include "coredump-vacuum.h"
#include "def.h"
#include "escape.h"
#include "fd-util.h"
#include "fs-util.h"
#include "journal-importer.h"
#include "memory-util.h"
#include "mkdir.h"
#include "special.h"
#include "stacktrace.h"
#include "string-table.h"
#include "tmpfile-util.h"
#include "user-util.h"


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

int coredump_parse_config(void) {
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

static uint64_t storage_size_max(void) {
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

static int fix_xattr(int fd, const Context *context) {

        static const char * const xattrs[_META_MAX] = {
                [META_PID]          = "user.coredump.pid",
                [META_SIGNAL]       = "user.coredump.signal",
                [META_TIMESTAMP]    = "user.coredump.timestamp",
                [META_RLIMIT]       = "user.coredump.rlimit",
                [META_HOSTNAME]     = "user.coredump.hostname",
                [META_COMM]         = "user.coredump.comm",
                [META_UID]          = "user.coredump.uid",
                [META_GID]          = "user.coredump.gid",
                [META_EXE]          = "user.coredump.exe",
        };

        int r = 0;
        unsigned i;

        assert(fd >= 0);

        /* Attach some metadata to coredumps via extended
         * attributes. Just because we can. */

        for (i = 0; i < _META_MAX; i++) {
                int k;

                if (isempty(context->meta[i]) || !xattrs[i])
                        continue;

                k = fsetxattr(fd, xattrs[i], context->meta[i], strlen(context->meta[i]), XATTR_CREATE);
                if (k < 0 && r == 0)
                        r = -errno;
        }

        return r;
}

#define filename_escape(s) xescape((s), "./ ")

static const char *coredump_tmpfile_name(const char *s) {
        return s ? s : "(unnamed temporary file)";
}

static int fix_permissions(
                int fd,
                const char *filename,
                const char *target,
                const Context *context) {

        int r;

        assert(fd >= 0);
        assert(target);
        assert(context);

        /* Ignore errors on these */
        (void) fchmod(fd, 0640);
        (void) fix_acl(fd, context->uid);
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

static int make_filename(const Context *context, char **ret) {
        _cleanup_free_ char *c = NULL, *u = NULL, *p = NULL, *t = NULL;
        sd_id128_t boot = {};
        int r;

        assert(context);

        c = filename_escape(context->meta[META_COMM]);
        if (!c)
                return -ENOMEM;

        u = filename_escape(context->meta[META_UID]);
        if (!u)
                return -ENOMEM;

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return r;

        p = filename_escape(context->meta[META_PID]);
        if (!p)
                return -ENOMEM;

        t = filename_escape(context->meta[META_TIMESTAMP]);
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
                const Context *context,
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
        int r;

        assert(context);
        assert(ret_filename);
        assert(ret_node_fd);
        assert(ret_data_fd);
        assert(ret_size);

        r = safe_atou64(context->meta[META_RLIMIT], &rlimit);
        if (r < 0)
                return log_error_errno(r, "Failed to parse resource limit '%s': %m",
                                       context->meta[META_RLIMIT]);
        if (rlimit < page_size()) {
                /* Is coredumping disabled? Then don't bother saving/processing the
                 * coredump.  Anything below PAGE_SIZE cannot give a readable coredump
                 * (the kernel uses ELF_EXEC_PAGESIZE which is not easily accessible, but
                 * is usually the same as PAGE_SIZE. */
                return log_info_errno(SYNTHETIC_ERRNO(EBADSLT),
                                      "Resource limits disable core dumping for process %s (%s).",
                                      context->meta[META_PID], context->meta[META_COMM]);
        }

        process_limit = MAX(arg_process_size_max, storage_size_max());
        if (process_limit == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADSLT),
                                       "Limits for coredump processing and storage are both 0, not dumping core.");

        /* Never store more than the process configured, or than we actually shall keep or process */
        max_size = MIN(rlimit, process_limit);

        r = make_filename(context, &fn);
        if (r < 0)
                return log_error_errno(r, "Failed to determine coredump file name: %m");

        (void) mkdir_p_label("/var/lib/systemd/coredump", 0755);

        fd = open_tmpfile_linkable(fn, O_RDWR|O_CLOEXEC, &tmp);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create temporary file for coredump %s: %m", fn);

        r = copy_bytes(input_fd, fd, max_size, 0);
        if (r < 0) {
                log_error_errno(r, "Cannot store coredump of %s (%s): %m",
                                context->meta[META_PID], context->meta[META_COMM]);
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

                fn_compressed = strjoin(fn, COMPRESSED_EXT);
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

                r = fix_permissions(fd_compressed, tmp_compressed, fn_compressed, context);
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

        r = fix_permissions(fd, tmp, fn, context);
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
        if ((size_t) n < size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Core data too short.");

        *ret = TAKE_PTR(field);
        *ret_size = size + 9;

        return 0;
}

static int change_uid_gid(const Context *context) {
        uid_t uid = context->uid;
        gid_t gid = context->gid;
        int r;

        if (uid <= SYSTEM_UID_MAX) {
                const char *user = "systemd-coredump";

                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0) {
                        log_warning_errno(r, "Cannot resolve %s user. Proceeding to dump core as root: %m", user);
                        uid = gid = 0;
                }
        }

        return drop_privileges(uid, gid, 0);
}

int coredump_submit(
                Context *context,
                struct iovec_wrapper *iovw,
                int input_fd) {

        _cleanup_close_ int coredump_fd = -1, coredump_node_fd = -1;
        _cleanup_free_ char *filename = NULL, *coredump_data = NULL;
        _cleanup_free_ char *stacktrace = NULL;
        char *core_message;
        uint64_t coredump_size = UINT64_MAX;
        bool truncated = false;
        int r;

        assert(context);
        assert(iovw);
        assert(input_fd >= 0);

        log_debug("Selected storage '%s'.", coredump_storage_to_string(arg_storage));
        log_debug("Selected compression %s.", yes_no(arg_compress));

        /* Vacuum before we write anything again */
        (void) coredump_vacuum(-1, arg_keep_free, arg_max_use);

        /* Always stream the coredump to disk, if that's possible */
        r = save_external_coredump(context, input_fd,
                                   &filename, &coredump_node_fd, &coredump_fd, &coredump_size, &truncated);
        if (r < 0)
                /* Skip whole core dumping part */
                goto log;

        /* If we don't want to keep the coredump on disk, remove it now, as later on we
         * will lack the privileges for it. However, we keep the fd to it, so that we can
         * still process it and log it. */
        r = maybe_remove_external_coredump(filename, coredump_size);
        if (r < 0)
                return r;
        if (r == 0) {
                (void) iovw_put_string_field(iovw, "COREDUMP_FILENAME=", filename);

        } else if (arg_storage == COREDUMP_STORAGE_EXTERNAL)
                log_info("The core will not be stored: size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                         coredump_size, arg_external_size_max);

        /* Vacuum again, but exclude the coredump we just created */
        (void) coredump_vacuum(coredump_node_fd >= 0 ? coredump_node_fd : coredump_fd, arg_keep_free, arg_max_use);

        /* Now, let's drop privileges to become the user who owns the segfaulted process
         * and allocate the coredump memory under the user's uid. This also ensures that
         * the credentials journald will see are the ones of the coredumping user, thus
         * making sure the user gets access to the core dump. Let's also get rid of all
         * capabilities, if we run as root, we won't need them anymore. */
        r = change_uid_gid(context);
        if (r < 0)
                return log_error_errno(r, "Failed to drop privileges: %m");

#if HAVE_ELFUTILS
        /* Try to get a stack trace if we can */
        if (coredump_size > arg_process_size_max) {
                log_debug("Not generating stack trace: core size %"PRIu64" is greater "
                          "than %"PRIu64" (the configured maximum)",
                          coredump_size, arg_process_size_max);
        } else
                coredump_make_stack_trace(coredump_fd, context->meta[META_EXE], &stacktrace);
#endif

log:
        core_message = strjoina("Process ", context->meta[META_PID],
                                " (", context->meta[META_COMM], ") of user ",
                                context->meta[META_UID], " dumped core.",
                                context->is_journald && filename ? "\nCoredump diverted to " : NULL,
                                context->is_journald && filename ? filename : NULL);

        core_message = strjoina(core_message, stacktrace ? "\n\n" : NULL, stacktrace);

        if (context->is_journald) {
                /* We cannot log to the journal, so just print the message.
                 * The target was set previously to something safe. */
                log_dispatch(LOG_ERR, 0, core_message);
                return 0;
        }

        (void) iovw_put_string_field(iovw, "MESSAGE=", core_message);

        if (truncated)
                (void) iovw_put_string_field(iovw, "COREDUMP_TRUNCATED=", "1");

        /* Optionally store the entire coredump in the journal */
        if (arg_storage == COREDUMP_STORAGE_JOURNAL) {
                if (coredump_size <= arg_journal_size_max) {
                        size_t sz = 0;

                        /* Store the coredump itself in the journal */

                        r = allocate_journal_field(coredump_fd, (size_t) coredump_size, &coredump_data, &sz);
                        if (r >= 0) {
                                if (iovw_put(iovw, coredump_data, sz) >= 0)
                                        TAKE_PTR(coredump_data);
                        } else
                                log_warning_errno(r, "Failed to attach the core to the journal entry: %m");
                } else
                        log_info("The core will not be stored: size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                                 coredump_size, arg_journal_size_max);
        }

        r = sd_journal_sendv(iovw->iovec, iovw->count);
        if (r < 0)
                return log_error_errno(r, "Failed to log coredump: %m");

        return 0;
}
