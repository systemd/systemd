/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/auxv.h>
#include <sys/xattr.h>
#include <unistd.h>
#if WANT_LINUX_FS_H
#  include <linux/fs.h>
#endif

#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-json.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "compress.h"
#include "conf-parser.h"
#include "copy.h"
#include "coredump-util.h"
#include "coredump-vacuum.h"
#include "dirent-util.h"
#include "elf-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "journal-importer.h"
#include "journal-send.h"
#include "json-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "missing_mount.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "user-util.h"

/* The maximum size up to which we process coredumps. We use 1G on 32-bit systems, and 32G on 64-bit systems */
#if __SIZEOF_POINTER__ == 4
#define PROCESS_SIZE_MAX ((uint64_t) (1LLU*1024LLU*1024LLU*1024LLU))
#elif __SIZEOF_POINTER__ == 8
#define PROCESS_SIZE_MAX ((uint64_t) (32LLU*1024LLU*1024LLU*1024LLU))
#else
#error "Unexpected pointer size"
#endif

/* The maximum size up to which we leave the coredump around on disk */
#define EXTERNAL_SIZE_MAX PROCESS_SIZE_MAX

/* The maximum size up to which we store the coredump in the journal */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define JOURNAL_SIZE_MAX ((size_t) (767LU*1024LU*1024LU))
#else
/* oss-fuzz limits memory usage. */
#define JOURNAL_SIZE_MAX ((size_t) (10LU*1024LU*1024LU))
#endif

/* When checking for available memory and setting lower limits, don't
 * go below 4MB for writing core files to storage. */
#define PROCESS_SIZE_MIN (4U*1024U*1024U)

/* Make sure to not make this larger than the maximum journal entry
 * size. See DATA_SIZE_MAX in journal-importer.h. */
assert_cc(JOURNAL_SIZE_MAX <= DATA_SIZE_MAX);

#define MOUNT_TREE_ROOT "/run/systemd/mount-rootfs"

enum {
        /* We use these as array indexes for our process metadata cache.
         *
         * The first indices of the cache stores the same metadata as the ones passed by
         * the kernel via argv[], ie the strings array passed by the kernel according to
         * our pattern defined in /proc/sys/kernel/core_pattern (see man:core(5)). */

        META_ARGV_PID,          /* %P: as seen in the initial pid namespace */
        META_ARGV_UID,          /* %u: as seen in the initial user namespace */
        META_ARGV_GID,          /* %g: as seen in the initial user namespace */
        META_ARGV_SIGNAL,       /* %s: number of signal causing dump */
        META_ARGV_TIMESTAMP,    /* %t: time of dump, expressed as seconds since the Epoch (we expand this to μs granularity) */
        META_ARGV_RLIMIT,       /* %c: core file size soft resource limit */
        META_ARGV_HOSTNAME,     /* %h: hostname */
        _META_ARGV_MAX,

        /* The following indexes are cached for a couple of special fields we use (and
         * thereby need to be retrieved quickly) for naming coredump files, and attaching
         * xattrs. Unlike the previous ones they are retrieved from the runtime
         * environment. */

        META_COMM = _META_ARGV_MAX,
        _META_MANDATORY_MAX,

        /* The rest are similar to the previous ones except that we won't fail if one of
         * them is missing. */

        META_EXE = _META_MANDATORY_MAX,
        META_UNIT,
        META_PROC_AUXV,
        _META_MAX
};

static const char * const meta_field_names[_META_MAX] = {
        [META_ARGV_PID]       = "COREDUMP_PID=",
        [META_ARGV_UID]       = "COREDUMP_UID=",
        [META_ARGV_GID]       = "COREDUMP_GID=",
        [META_ARGV_SIGNAL]    = "COREDUMP_SIGNAL=",
        [META_ARGV_TIMESTAMP] = "COREDUMP_TIMESTAMP=",
        [META_ARGV_RLIMIT]    = "COREDUMP_RLIMIT=",
        [META_ARGV_HOSTNAME]  = "COREDUMP_HOSTNAME=",
        [META_COMM]           = "COREDUMP_COMM=",
        [META_EXE]            = "COREDUMP_EXE=",
        [META_UNIT]           = "COREDUMP_UNIT=",
        [META_PROC_AUXV]      = "COREDUMP_PROC_AUXV=",
};

typedef struct Context {
        PidRef pidref;
        uid_t uid;
        gid_t gid;
        int signo;
        uint64_t rlimit;
        bool is_pid1;
        bool is_journald;
        int mount_tree_fd;

        /* These point into external memory, are not owned by this object */
        const char *meta[_META_MAX];
        size_t meta_size[_META_MAX];
} Context;

#define CONTEXT_NULL                            \
        (Context) {                             \
                .pidref = PIDREF_NULL,          \
                .uid = UID_INVALID,             \
                .gid = GID_INVALID,             \
                .mount_tree_fd = -EBADF,        \
        }

typedef enum CoredumpStorage {
        COREDUMP_STORAGE_NONE,
        COREDUMP_STORAGE_EXTERNAL,
        COREDUMP_STORAGE_JOURNAL,
        _COREDUMP_STORAGE_MAX,
        _COREDUMP_STORAGE_INVALID = -EINVAL,
} CoredumpStorage;

static const char* const coredump_storage_table[_COREDUMP_STORAGE_MAX] = {
        [COREDUMP_STORAGE_NONE]     = "none",
        [COREDUMP_STORAGE_EXTERNAL] = "external",
        [COREDUMP_STORAGE_JOURNAL]  = "journal",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(coredump_storage, CoredumpStorage);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_coredump_storage, coredump_storage, CoredumpStorage);

static CoredumpStorage arg_storage = COREDUMP_STORAGE_EXTERNAL;
static bool arg_compress = true;
static uint64_t arg_process_size_max = PROCESS_SIZE_MAX;
static uint64_t arg_external_size_max = EXTERNAL_SIZE_MAX;
static uint64_t arg_journal_size_max = JOURNAL_SIZE_MAX;
static uint64_t arg_keep_free = UINT64_MAX;
static uint64_t arg_max_use = UINT64_MAX;
#if HAVE_DWFL_SET_SYSROOT
static bool arg_enter_namespace = false;
#endif

static void context_done(Context *c) {
        assert(c);

        pidref_done(&c->pidref);
        c->mount_tree_fd = safe_close(c->mount_tree_fd);
}

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "Coredump", "Storage",         config_parse_coredump_storage,    0,                      &arg_storage           },
                { "Coredump", "Compress",        config_parse_bool,                0,                      &arg_compress          },
                { "Coredump", "ProcessSizeMax",  config_parse_iec_uint64,          0,                      &arg_process_size_max  },
                { "Coredump", "ExternalSizeMax", config_parse_iec_uint64_infinity, 0,                      &arg_external_size_max },
                { "Coredump", "JournalSizeMax",  config_parse_iec_size,            0,                      &arg_journal_size_max  },
                { "Coredump", "KeepFree",        config_parse_iec_uint64,          0,                      &arg_keep_free         },
                { "Coredump", "MaxUse",          config_parse_iec_uint64,          0,                      &arg_max_use           },
#if HAVE_DWFL_SET_SYSROOT
                { "Coredump", "EnterNamespace",  config_parse_bool,                0,                      &arg_enter_namespace   },
#else
                { "Coredump", "EnterNamespace",  config_parse_warn_compat,         DISABLED_CONFIGURATION, 0                      },
#endif
                {}
        };

        int r;

        r = config_parse_standard_file_with_dropins(
                        "systemd/coredump.conf",
                        "Coredump\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
        if (r < 0)
                return r;

        /* Let's make sure we fix up the maximum size we send to the journal here on the client side, for
         * efficiency reasons. journald wouldn't accept anything larger anyway. */
        if (arg_journal_size_max > JOURNAL_SIZE_MAX) {
                log_warning("JournalSizeMax= set to larger value (%s) than journald would accept (%s), lowering automatically.",
                            FORMAT_BYTES(arg_journal_size_max), FORMAT_BYTES(JOURNAL_SIZE_MAX));
                arg_journal_size_max = JOURNAL_SIZE_MAX;
        }

        return 0;
}

static uint64_t storage_size_max(void) {
        if (arg_storage == COREDUMP_STORAGE_EXTERNAL)
                return arg_external_size_max;
        if (arg_storage == COREDUMP_STORAGE_JOURNAL)
                return arg_journal_size_max;
        assert(arg_storage == COREDUMP_STORAGE_NONE);
        return 0;
}

static int fix_acl(int fd, uid_t uid, bool allow_user) {
        assert(fd >= 0);
        assert(uid_is_valid(uid));

#if HAVE_ACL
        int r;

        /* We don't allow users to read coredumps if the uid or capabilities were changed. */
        if (!allow_user)
                return 0;

        if (uid_is_system(uid) || uid_is_dynamic(uid) || uid == UID_NOBODY)
                return 0;

        /* Make sure normal users can read (but not write or delete) their own coredumps */
        r = fd_add_uid_acl_permission(fd, uid, ACL_READ);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust ACL of the coredump: %m");
#endif

        return 0;
}

static int fix_xattr(int fd, const Context *context) {

        static const char * const xattrs[_META_MAX] = {
                [META_ARGV_PID]       = "user.coredump.pid",
                [META_ARGV_UID]       = "user.coredump.uid",
                [META_ARGV_GID]       = "user.coredump.gid",
                [META_ARGV_SIGNAL]    = "user.coredump.signal",
                [META_ARGV_TIMESTAMP] = "user.coredump.timestamp",
                [META_ARGV_RLIMIT]    = "user.coredump.rlimit",
                [META_ARGV_HOSTNAME]  = "user.coredump.hostname",
                [META_COMM]           = "user.coredump.comm",
                [META_EXE]            = "user.coredump.exe",
        };

        int r = 0;

        assert(fd >= 0);

        /* Attach some metadata to coredumps via extended attributes. Just because we can. */

        for (unsigned i = 0; i < _META_MAX; i++) {
                int k;

                if (isempty(context->meta[i]) || !xattrs[i])
                        continue;

                k = RET_NERRNO(fsetxattr(fd, xattrs[i], context->meta[i], strlen(context->meta[i]), XATTR_CREATE));
                RET_GATHER(r, k);
        }

        return r;
}

#define filename_escape(s) xescape((s), "./ ")

static const char *coredump_tmpfile_name(const char *s) {
        return s ?: "(unnamed temporary file)";
}

static int fix_permissions(
                int fd,
                const char *filename,
                const char *target,
                const Context *context,
                bool allow_user) {

        int r;

        assert(fd >= 0);
        assert(target);
        assert(context);

        /* Ignore errors on these */
        (void) fchmod(fd, 0640);
        (void) fix_acl(fd, context->uid, allow_user);
        (void) fix_xattr(fd, context);

        r = link_tmpfile(fd, filename, target, LINK_TMPFILE_SYNC);
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

        u = filename_escape(context->meta[META_ARGV_UID]);
        if (!u)
                return -ENOMEM;

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return r;

        p = filename_escape(context->meta[META_ARGV_PID]);
        if (!p)
                return -ENOMEM;

        t = filename_escape(context->meta[META_ARGV_TIMESTAMP]);
        if (!t)
                return -ENOMEM;

        if (asprintf(ret,
                     "/var/lib/systemd/coredump/core.%s.%s." SD_ID128_FORMAT_STR ".%s.%s",
                     c,
                     u,
                     SD_ID128_FORMAT_VAL(boot),
                     p,
                     t) < 0)
                return -ENOMEM;

        return 0;
}

static int grant_user_access(int core_fd, const Context *context) {
        int at_secure = -1;
        uid_t uid = UID_INVALID, euid = UID_INVALID;
        uid_t gid = GID_INVALID, egid = GID_INVALID;
        int r;

        assert(core_fd >= 0);
        assert(context);

        if (!context->meta[META_PROC_AUXV])
                return log_warning_errno(SYNTHETIC_ERRNO(ENODATA), "No auxv data, not adjusting permissions.");

        uint8_t elf[EI_NIDENT];
        errno = 0;
        if (pread(core_fd, &elf, sizeof(elf), 0) != sizeof(elf))
                return log_warning_errno(errno_or_else(EIO),
                                         "Failed to pread from coredump fd: %s", STRERROR_OR_EOF(errno));

        if (elf[EI_MAG0] != ELFMAG0 ||
            elf[EI_MAG1] != ELFMAG1 ||
            elf[EI_MAG2] != ELFMAG2 ||
            elf[EI_MAG3] != ELFMAG3 ||
            elf[EI_VERSION] != EV_CURRENT)
                return log_info_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                      "Core file does not have ELF header, not adjusting permissions.");
        if (!IN_SET(elf[EI_CLASS], ELFCLASS32, ELFCLASS64) ||
            !IN_SET(elf[EI_DATA], ELFDATA2LSB, ELFDATA2MSB))
                return log_info_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                      "Core file has strange ELF class, not adjusting permissions.");

        if ((elf[EI_DATA] == ELFDATA2LSB) != (__BYTE_ORDER == __LITTLE_ENDIAN))
                return log_info_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                      "Core file has non-native endianness, not adjusting permissions.");

        r = parse_auxv(LOG_WARNING,
                       /* elf_class= */ elf[EI_CLASS],
                       context->meta[META_PROC_AUXV],
                       context->meta_size[META_PROC_AUXV],
                       &at_secure, &uid, &euid, &gid, &egid);
        if (r < 0)
                return r;

        /* We allow access if we got all the data and at_secure is not set and
         * the uid/gid matches euid/egid. */
        bool ret =
                at_secure == 0 &&
                uid != UID_INVALID && euid != UID_INVALID && uid == euid &&
                gid != GID_INVALID && egid != GID_INVALID && gid == egid;
        log_debug("Will %s access (uid="UID_FMT " euid="UID_FMT " gid="GID_FMT " egid="GID_FMT " at_secure=%s)",
                  ret ? "permit" : "restrict",
                  uid, euid, gid, egid, yes_no(at_secure));
        return ret;
}

static int save_external_coredump(
                const Context *context,
                int input_fd,
                char **ret_filename,
                int *ret_node_fd,
                int *ret_data_fd,
                uint64_t *ret_size,
                uint64_t *ret_compressed_size,
                bool *ret_truncated) {

        _cleanup_(unlink_and_freep) char *tmp = NULL;
        _cleanup_free_ char *fn = NULL;
        _cleanup_close_ int fd = -EBADF;
        uint64_t process_limit, max_size;
        bool truncated, storage_on_tmpfs;
        struct stat st;
        int r;

        assert(context);
        assert(ret_filename);
        assert(ret_node_fd);
        assert(ret_data_fd);
        assert(ret_size);
        assert(ret_compressed_size);
        assert(ret_truncated);

        if (context->rlimit < page_size())
                /* Is coredumping disabled? Then don't bother saving/processing the
                 * coredump. Anything below PAGE_SIZE cannot give a readable coredump
                 * (the kernel uses ELF_EXEC_PAGESIZE which is not easily accessible, but
                 * is usually the same as PAGE_SIZE. */
                return log_info_errno(SYNTHETIC_ERRNO(EBADSLT),
                                      "Resource limits disable core dumping for process %s (%s).",
                                      context->meta[META_ARGV_PID], context->meta[META_COMM]);

        process_limit = MAX(arg_process_size_max, storage_size_max());
        if (process_limit == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADSLT),
                                       "Limits for coredump processing and storage are both 0, not dumping core.");

        /* Never store more than the process configured, or than we actually shall keep or process */
        max_size = MIN(context->rlimit, process_limit);

        r = make_filename(context, &fn);
        if (r < 0)
                return log_error_errno(r, "Failed to determine coredump file name: %m");

        (void) mkdir_parents_label(fn, 0755);

        fd = open_tmpfile_linkable(fn, O_RDWR|O_CLOEXEC, &tmp);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create temporary file for coredump %s: %m", fn);

        /* If storage is on tmpfs, the kernel oomd might kill us if there's MemoryMax set on
         * the service or the slice it belongs to. This is common on low-resources systems,
         * to avoid crashing processes to take away too many system resources.
         * Check the cgroup settings, and set max_size to a bit less than half of the
         * available memory left to the process.
         * Then, attempt to write the core file uncompressed first - if the write gets
         * interrupted, we know we won't be able to write it all, so instead compress what
         * was written so far, delete the uncompressed truncated core, and then continue
         * compressing from STDIN. Given the compressed core cannot be larger than the
         * uncompressed one, and 1KB for metadata is accounted for in the calculation, we
         * should be able to at least store the full compressed core file. */

        storage_on_tmpfs = fd_is_temporary_fs(fd) > 0;
        if (storage_on_tmpfs && arg_compress) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                uint64_t cgroup_limit = UINT64_MAX;
                struct statvfs sv;

                /* If we can't get the cgroup limit, just ignore it, but don't fail,
                 * try anyway with the config settings. */
                r = sd_bus_default_system(&bus);
                if (r < 0)
                        log_info_errno(r, "Failed to connect to system bus, skipping MemoryAvailable check: %m");
                else {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                        r = sd_bus_get_property_trivial(
                                        bus,
                                        "org.freedesktop.systemd1",
                                        "/org/freedesktop/systemd1/unit/self",
                                        "org.freedesktop.systemd1.Service",
                                        "MemoryAvailable",
                                        &error,
                                        't', &cgroup_limit);
                        if (r < 0)
                                log_warning_errno(r,
                                                  "Failed to query MemoryAvailable for current unit, "
                                                  "falling back to static config settings: %s",
                                                  bus_error_message(&error, r));
                }

                /* First, ensure we are not going to go over the cgroup limit */
                max_size = MIN(cgroup_limit, max_size);
                /* tmpfs might get full quickly, so check the available space too. But don't worry about
                 * errors here, failing to access the storage location will be better logged when writing to
                 * it. */
                if (fstatvfs(fd, &sv) >= 0)
                        max_size = MIN((uint64_t)sv.f_frsize * (uint64_t)sv.f_bfree, max_size);
                /* Impose a lower minimum, otherwise we will miss the basic headers. */
                max_size = MAX(PROCESS_SIZE_MIN, max_size);
                /* Ensure we can always switch to compressing on the fly in case we are running out of space
                 * by keeping half of the space/memory available, plus 1KB metadata overhead from the
                 * compression algorithm. */
                max_size = LESS_BY(max_size, 1024U) / 2;

                log_debug("Limiting core file size to %" PRIu64 " bytes due to cgroup and/or filesystem limits.", max_size);
        }

        r = copy_bytes(input_fd, fd, max_size, 0);
        if (r < 0)
                return log_error_errno(r, "Cannot store coredump of %s (%s): %m",
                                context->meta[META_ARGV_PID], context->meta[META_COMM]);
        truncated = r == 1;

        bool allow_user = grant_user_access(fd, context) > 0;

#if HAVE_COMPRESSION
        if (arg_compress) {
                _cleanup_(unlink_and_freep) char *tmp_compressed = NULL;
                _cleanup_free_ char *fn_compressed = NULL;
                _cleanup_close_ int fd_compressed = -EBADF;
                uint64_t uncompressed_size = 0;

                if (lseek(fd, 0, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek on coredump %s: %m", fn);

                fn_compressed = strjoin(fn, default_compression_extension());
                if (!fn_compressed)
                        return log_oom();

                fd_compressed = open_tmpfile_linkable(fn_compressed, O_RDWR|O_CLOEXEC, &tmp_compressed);
                if (fd_compressed < 0)
                        return log_error_errno(fd_compressed, "Failed to create temporary file for coredump %s: %m", fn_compressed);

                r = compress_stream(fd, fd_compressed, max_size, &uncompressed_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to compress %s: %m", coredump_tmpfile_name(tmp_compressed));

                if (truncated && storage_on_tmpfs) {
                        uint64_t partial_uncompressed_size = 0;

                        /* Uncompressed write was truncated and we are writing to tmpfs: delete
                         * the uncompressed core, and compress the remaining part from STDIN. */

                        tmp = unlink_and_free(tmp);
                        fd = safe_close(fd);

                        r = compress_stream(input_fd, fd_compressed, max_size, &partial_uncompressed_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to compress %s: %m", coredump_tmpfile_name(tmp_compressed));
                        uncompressed_size += partial_uncompressed_size;
                }

                r = fix_permissions(fd_compressed, tmp_compressed, fn_compressed, context, allow_user);
                if (r < 0)
                        return r;

                if (fstat(fd_compressed, &st) < 0)
                        return log_error_errno(errno,
                                        "Failed to fstat core file %s: %m",
                                        coredump_tmpfile_name(tmp_compressed));

                *ret_filename = TAKE_PTR(fn_compressed);       /* compressed */
                *ret_node_fd = TAKE_FD(fd_compressed);         /* compressed */
                *ret_compressed_size = (uint64_t) st.st_size;  /* compressed */
                *ret_data_fd = TAKE_FD(fd);
                *ret_size = uncompressed_size;
                *ret_truncated = truncated;
                tmp_compressed = mfree(tmp_compressed);

                return 0;
        }
#endif

        if (truncated)
                log_struct(LOG_INFO,
                           LOG_MESSAGE("Core file was truncated to %"PRIu64" bytes.", max_size),
                           "SIZE_LIMIT=%"PRIu64, max_size,
                           "MESSAGE_ID=" SD_MESSAGE_TRUNCATED_CORE_STR);

        r = fix_permissions(fd, tmp, fn, context, allow_user);
        if (r < 0)
                return log_error_errno(r, "Failed to fix permissions and finalize coredump %s into %s: %m", coredump_tmpfile_name(tmp), fn);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to fstat core file %s: %m", coredump_tmpfile_name(tmp));

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek on coredump %s: %m", fn);

        *ret_filename = TAKE_PTR(fn);
        *ret_data_fd = TAKE_FD(fd);
        *ret_size = (uint64_t) st.st_size;
        *ret_truncated = truncated;

        return 0;
}

static int allocate_journal_field(int fd, size_t size, char **ret, size_t *ret_size) {
        _cleanup_free_ char *field = NULL;
        ssize_t n;

        assert(fd >= 0);
        assert(ret);
        assert(ret_size);

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_warning_errno(errno, "Failed to seek: %m");

        field = malloc(9 + size);
        if (!field)
                return log_warning_errno(SYNTHETIC_ERRNO(ENOMEM),
                                         "Failed to allocate memory for coredump, coredump will not be stored.");

        memcpy(field, "COREDUMP=", 9);

        /* NB: simple read() would fail for overly large coredumps, since read() on Linux can only deal with
         * 0x7ffff000 bytes max. Hence call things in a loop. */
        n = loop_read(fd, field + 9, size, /* do_poll= */ false);
        if (n < 0)
                return log_error_errno((int) n, "Failed to read core data: %m");
        if ((size_t) n < size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Core data too short.");

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
static int compose_open_fds(pid_t pid, char **ret) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_closedir_ DIR *proc_fd_dir = NULL;
        _cleanup_close_ int proc_fdinfo_fd = -EBADF;
        const char *fddelim = "", *path;
        FILE *stream;
        int r;

        assert(pid >= 0);
        assert(ret);

        path = procfs_file_alloca(pid, "fd");
        proc_fd_dir = opendir(path);
        if (!proc_fd_dir)
                return -errno;

        proc_fdinfo_fd = openat(dirfd(proc_fd_dir), "../fdinfo", O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_PATH);
        if (proc_fdinfo_fd < 0)
                return -errno;

        stream = memstream_init(&m);
        if (!stream)
                return -ENOMEM;

        FOREACH_DIRENT(de, proc_fd_dir, return -errno) {
                _cleanup_fclose_ FILE *fdinfo = NULL;
                _cleanup_free_ char *fdname = NULL;
                _cleanup_close_ int fd = -EBADF;

                r = readlinkat_malloc(dirfd(proc_fd_dir), de->d_name, &fdname);
                if (r < 0)
                        return r;

                fprintf(stream, "%s%s:%s\n", fddelim, de->d_name, fdname);
                fddelim = "\n";

                /* Use the directory entry from /proc/[pid]/fd with /proc/[pid]/fdinfo */
                fd = openat(proc_fdinfo_fd, de->d_name, O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
                if (fd < 0)
                        continue;

                fdinfo = take_fdopen(&fd, "r");
                if (!fdinfo)
                        continue;

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

        return memstream_finalize(&m, ret, NULL);
}

/* Returns 1 if the parent was found.
 * Returns 0 if there is not a process we can call the pid's
 * container parent (the pid's process isn't 'containerized').
 * Returns a negative number on errors.
 */
static int get_process_container_parent_cmdline(PidRef *pid, char** ret_cmdline) {
        int r;

        assert(pidref_is_set(pid));
        assert(!pidref_is_remote(pid));

        r = pidref_from_same_root_fs(pid, &PIDREF_MAKE_FROM_PID(1));
        if (r < 0)
                return r;
        if (r > 0) {
                /* The process uses system root. */
                *ret_cmdline = NULL;
                return 0;
        }

        _cleanup_(pidref_done) PidRef container_pid = PIDREF_NULL;
        r = namespace_get_leader(pid, NAMESPACE_MOUNT, &container_pid);
        if (r < 0)
                return r;

        r = pidref_get_cmdline(&container_pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, ret_cmdline);
        if (r < 0)
                return r;

        return 1;
}

static int change_uid_gid(const Context *context) {
        int r;

        assert(context);

        uid_t uid = context->uid;
        gid_t gid = context->gid;

        if (uid_is_system(uid)) {
                const char *user = "systemd-coredump";

                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0) {
                        log_warning_errno(r, "Cannot resolve %s user. Proceeding to dump core as root: %m", user);
                        uid = gid = 0;
                }
        }

        return drop_privileges(uid, gid, 0);
}

static int attach_mount_tree(int mount_tree_fd) {
        int r;

        assert(mount_tree_fd >= 0);

        r = detach_mount_namespace();
        if (r < 0)
                return log_warning_errno(r, "Failed to detach mount namespace: %m");

        r = mkdir_p_label(MOUNT_TREE_ROOT, 0555);
        if (r < 0)
                return log_warning_errno(r, "Failed to create directory: %m");

        r = mount_setattr(mount_tree_fd, "", AT_EMPTY_PATH,
                                &(struct mount_attr) {
                                        .attr_set = MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NOSYMFOLLOW,
                                        .propagation = MS_SLAVE,
                                }, sizeof(struct mount_attr));
        if (r < 0)
                return log_warning_errno(errno, "Failed to change properties of mount tree: %m");

        r = move_mount(mount_tree_fd, "", -EBADF, MOUNT_TREE_ROOT, MOVE_MOUNT_F_EMPTY_PATH);
        if (r < 0)
                return log_warning_errno(errno, "Failed to attach mount tree: %m");

        return 0;
}

static int submit_coredump(
                const Context *context,
                struct iovec_wrapper *iovw,
                int input_fd) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json_metadata = NULL;
        _cleanup_close_ int coredump_fd = -EBADF, coredump_node_fd = -EBADF;
        _cleanup_free_ char *filename = NULL, *coredump_data = NULL, *stacktrace = NULL;
        const char *module_name, *root = NULL;
        uint64_t coredump_size = UINT64_MAX, coredump_compressed_size = UINT64_MAX;
        bool truncated = false, written = false;
        sd_json_variant *module_json;
        int r;

        assert(context);
        assert(iovw);
        assert(input_fd >= 0);

        /* Vacuum before we write anything again */
        (void) coredump_vacuum(-1, arg_keep_free, arg_max_use);

        /* Always stream the coredump to disk, if that's possible */
        written = save_external_coredump(
                        context, input_fd,
                        &filename, &coredump_node_fd, &coredump_fd,
                        &coredump_size, &coredump_compressed_size, &truncated) >= 0;
        if (written) {
                /* If we could write it to disk we can now process it. */
                /* If we don't want to keep the coredump on disk, remove it now, as later on we
                 * will lack the privileges for it. However, we keep the fd to it, so that we can
                 * still process it and log it. */
                r = maybe_remove_external_coredump(filename, coredump_node_fd >= 0 ? coredump_compressed_size : coredump_size);
                if (r < 0)
                        return r;
                if (r == 0)
                        (void) iovw_put_string_field(iovw, "COREDUMP_FILENAME=", filename);
                else if (arg_storage == COREDUMP_STORAGE_EXTERNAL)
                        log_info("The core will not be stored: size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                                 coredump_node_fd >= 0 ? coredump_compressed_size : coredump_size, arg_external_size_max);

                /* Vacuum again, but exclude the coredump we just created */
                (void) coredump_vacuum(coredump_node_fd >= 0 ? coredump_node_fd : coredump_fd, arg_keep_free, arg_max_use);
        }

        if (context->mount_tree_fd >= 0 && attach_mount_tree(context->mount_tree_fd) >= 0)
                root = MOUNT_TREE_ROOT;

        /* Now, let's drop privileges to become the user who owns the segfaulted process and allocate the
         * coredump memory under the user's uid. This also ensures that the credentials journald will see are
         * the ones of the coredumping user, thus making sure the user gets access to the core dump. Let's
         * also get rid of all capabilities, if we run as root, we won't need them anymore. */
        r = change_uid_gid(context);
        if (r < 0)
                return log_error_errno(r, "Failed to drop privileges: %m");

        if (written) {
                /* Try to get a stack trace if we can */
                if (coredump_size > arg_process_size_max)
                        log_debug("Not generating stack trace: core size %"PRIu64" is greater "
                                  "than %"PRIu64" (the configured maximum)",
                                  coredump_size, arg_process_size_max);
                else if (coredump_fd >= 0) {
                        bool skip = startswith(context->meta[META_COMM], "systemd-coredum"); /* COMM is 16 bytes usually */

                        (void) parse_elf_object(coredump_fd,
                                                context->meta[META_EXE],
                                                root,
                                                /* fork_disable_dump= */ skip, /* avoid loops */
                                                &stacktrace,
                                                &json_metadata);
                }
        }

        _cleanup_free_ char *core_message = NULL;
        core_message = strjoin(
                        "Process ", context->meta[META_ARGV_PID],
                        " (", context->meta[META_COMM],
                        ") of user ", context->meta[META_ARGV_UID],
                        written ? " dumped core." : " terminated abnormally without generating a coredump.");
        if (!core_message)
                return log_oom();

        if (context->is_journald && filename)
                if (!strextend(&core_message, "\nCoredump diverted to ", filename))
                        return log_oom();

        if (stacktrace)
                if (!strextend(&core_message, "\n\n", stacktrace))
                        return log_oom();

        if (context->is_journald)
                /* We might not be able to log to the journal, so let's always print the message to another
                 * log target. The target was set previously to something safe. */
                log_dispatch(LOG_ERR, 0, core_message);

        (void) iovw_put_string_field(iovw, "MESSAGE=", core_message);

        if (truncated)
                (void) iovw_put_string_field(iovw, "COREDUMP_TRUNCATED=", "1");

        /* If we managed to parse any ELF metadata (build-id, ELF package meta),
         * attach it as journal metadata. */
        if (json_metadata) {
                _cleanup_free_ char *formatted_json = NULL;

                r = sd_json_variant_format(json_metadata, 0, &formatted_json);
                if (r < 0)
                        return log_error_errno(r, "Failed to format JSON package metadata: %m");

                (void) iovw_put_string_field(iovw, "COREDUMP_PACKAGE_JSON=", formatted_json);
        }

        /* In the unlikely scenario that context->meta[META_EXE] is not available,
         * let's avoid guessing the module name and skip the loop. */
        if (context->meta[META_EXE])
                JSON_VARIANT_OBJECT_FOREACH(module_name, module_json, json_metadata) {
                        sd_json_variant *t;

                        /* We only add structured fields for the 'main' ELF module, and only if we can identify it. */
                        if (!path_equal_filename(module_name, context->meta[META_EXE]))
                                continue;

                        t = sd_json_variant_by_key(module_json, "name");
                        if (t)
                                (void) iovw_put_string_field(iovw, "COREDUMP_PACKAGE_NAME=", sd_json_variant_string(t));

                        t = sd_json_variant_by_key(module_json, "version");
                        if (t)
                                (void) iovw_put_string_field(iovw, "COREDUMP_PACKAGE_VERSION=", sd_json_variant_string(t));
                }

        /* Optionally store the entire coredump in the journal */
        if (arg_storage == COREDUMP_STORAGE_JOURNAL && coredump_fd >= 0) {
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

        /* If journald is coredumping, we have to be careful that we don't deadlock when trying to write the
         * coredump to the journal, so we put the journal socket in nonblocking mode before trying to write
         * the coredump to the socket. */

        if (context->is_journald) {
                r = journal_fd_nonblock(true);
                if (r < 0)
                        return log_error_errno(r, "Failed to make journal socket non-blocking: %m");
        }

        r = sd_journal_sendv(iovw->iovec, iovw->count);

        if (context->is_journald) {
                int k;

                k = journal_fd_nonblock(false);
                if (k < 0)
                        return log_error_errno(k, "Failed to make journal socket blocking: %m");
        }

        if (r == -EAGAIN && context->is_journald)
                log_warning_errno(r, "Failed to log journal coredump, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Failed to log coredump: %m");

        return 0;
}

static int context_parse_iovw(Context *context, struct iovec_wrapper *iovw) {
        const char *unit;
        int r;

        assert(context);
        assert(iovw);
        assert(iovw->count >= _META_ARGV_MAX);

        /* Converts the data in the iovec array iovw into separate fields. Fills in context->meta[] (for
         * which no memory is allocated, it just contains direct pointers into the iovec array memory). */

        bool have_signal_name = false;
        FOREACH_ARRAY(iovec, iovw->iovec, iovw->count) {
                for (size_t i = 0; i < ELEMENTSOF(meta_field_names); i++) {
                        /* Note that these strings are NUL terminated, because we made sure that a
                         * trailing NUL byte is in the buffer, though not included in the iov_len
                         * count (see process_socket() and gather_pid_metadata_*()) */
                        assert(((char*) iovec->iov_base)[iovec->iov_len] == 0);

                        const char *p = memory_startswith(iovec->iov_base, iovec->iov_len, meta_field_names[i]);
                        if (p) {
                                context->meta[i] = p;
                                context->meta_size[i] = iovec->iov_len - strlen(meta_field_names[i]);
                                break;
                        }
                }

                have_signal_name = have_signal_name ||
                        memory_startswith(iovec->iov_base, iovec->iov_len, "COREDUMP_SIGNAL_NAME=");
        }

        /* The basic fields from argv[] should always be there, refuse early if not */
        for (int i = 0; i < _META_ARGV_MAX; i++)
                if (!context->meta[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "A required (%s) has not been sent, aborting.", meta_field_names[i]);

        pid_t parsed_pid;
        r = parse_pid(context->meta[META_ARGV_PID], &parsed_pid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PID \"%s\": %m", context->meta[META_ARGV_PID]);
        if (pidref_is_set(&context->pidref)) {
                if (context->pidref.pid != parsed_pid)
                        return log_error_errno(r, "Passed PID " PID_FMT " does not match passed " PID_FMT ": %m", parsed_pid, context->pidref.pid);
        } else {
                r = pidref_set_pid(&context->pidref, parsed_pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to initialize pidref from pid " PID_FMT ": %m", parsed_pid);
        }

        r = parse_uid(context->meta[META_ARGV_UID], &context->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse UID \"%s\": %m", context->meta[META_ARGV_UID]);

        r = parse_gid(context->meta[META_ARGV_GID], &context->gid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse GID \"%s\": %m", context->meta[META_ARGV_GID]);

        r = parse_signo(context->meta[META_ARGV_SIGNAL], &context->signo);
        if (r < 0)
                log_warning_errno(r, "Failed to parse signal number \"%s\", ignoring: %m", context->meta[META_ARGV_SIGNAL]);

        r = safe_atou64(context->meta[META_ARGV_RLIMIT], &context->rlimit);
        if (r < 0)
                log_warning_errno(r, "Failed to parse resource limit \"%s\", ignoring: %m", context->meta[META_ARGV_RLIMIT]);

        unit = context->meta[META_UNIT];
        context->is_pid1 = streq(context->meta[META_ARGV_PID], "1") || streq_ptr(unit, SPECIAL_INIT_SCOPE);
        context->is_journald = streq_ptr(unit, SPECIAL_JOURNALD_SERVICE);

        /* After parsing everything, let's also synthesize a new iovw field for the textual signal name if it
         * isn't already set. */
        if (SIGNAL_VALID(context->signo) && !have_signal_name)
                (void) iovw_put_string_field(iovw, "COREDUMP_SIGNAL_NAME=SIG", signal_to_string(context->signo));

        return 0;
}

static int process_socket(int fd) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        _cleanup_close_ int input_fd = -EBADF;
        enum {
                STATE_PAYLOAD,
                STATE_INPUT_FD_DONE,
                STATE_PID_FD_DONE,
        } state = STATE_PAYLOAD;
        int r;

        assert(fd >= 0);

        log_setup();

        log_debug("Processing coredump received via socket...");

        for (;;) {
                CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(int))) control;
                struct msghdr mh = {
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                        .msg_iovlen = 1,
                };
                ssize_t n, l;

                l = next_datagram_size_fd(fd);
                if (l < 0)
                        return log_error_errno(l, "Failed to determine datagram size to read: %m");

                _cleanup_(iovec_done) struct iovec iovec = {
                        .iov_len = l,
                        .iov_base = malloc(l + 1),
                };
                if (!iovec.iov_base)
                        return log_oom();

                mh.msg_iov = &iovec;

                n = recvmsg_safe(fd, &mh, MSG_CMSG_CLOEXEC);
                if (n < 0)
                        return log_error_errno(n, "Failed to receive datagram: %m");

                /* The final zero-length datagrams ("sentinels") carry file descriptors and tell us that
                 * we're done. There are three sentinels: one with just the coredump fd, followed by one with
                 * the pidfd, and finally one with the mount tree fd. The latter two or the last one may be
                 * omitted (which is supported for compatibility with older systemd version, in particular to
                 * facilitate cross-container coredumping). */
                if (n == 0) {
                        struct cmsghdr *found;

                        found = cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, CMSG_LEN(sizeof(int)));
                        if (!found) {
                                /* This is zero length message but it either doesn't carry a single
                                 * descriptor, or it has more than one. This is a protocol violation so let's
                                 * bail out.
                                 *
                                 * Well, not quite! In practice there's one more complication: EOF on
                                 * SOCK_SEQPACKET is not distinguishable from a zero length datagram. Hence
                                 * if we get a zero length datagram without fds we consider it EOF, and
                                 * that's permissible for the final two fds. Hence let's be strict on the
                                 * first fd, but lenient on the other two. */

                                if (!cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, (socklen_t) -1) && state != STATE_PAYLOAD) /* no fds, and already got the first fd → we are done */
                                        break;

                                cmsg_close_all(&mh);
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Received zero length message with zero or more than one file descriptor(s), expected one.");
                        }

                        switch (state) {

                        case STATE_PAYLOAD:
                                assert(input_fd < 0);
                                input_fd = *CMSG_TYPED_DATA(found, int);
                                state = STATE_INPUT_FD_DONE;
                                continue;

                        case STATE_INPUT_FD_DONE:
                                assert(!pidref_is_set(&context.pidref));

                                r = pidref_set_pidfd_consume(&context.pidref, *CMSG_TYPED_DATA(found, int));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to initialize pidref: %m");

                                state = STATE_PID_FD_DONE;
                                continue;

                        case STATE_PID_FD_DONE:
                                assert(context.mount_tree_fd < 0);
                                context.mount_tree_fd = *CMSG_TYPED_DATA(found, int);
                                /* We have all FDs we need so we are done. */
                                break;
                        }

                        break;
                }

                cmsg_close_all(&mh);

                /* Only zero length messages are allowed after the first message that carried a file descriptor. */
                if (state != STATE_PAYLOAD)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Received unexpected message with non-zero length.");

                /* Payload messages should not carry fds */
                if (cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, (socklen_t) -1))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                            "Received payload message with file descriptor(s), expected none.");

                /* Add trailing NUL byte, in case these are strings */
                ((char*) iovec.iov_base)[n] = 0;
                iovec.iov_len = (size_t) n;

                if (iovw_put(&iovw, iovec.iov_base, iovec.iov_len) < 0)
                        return log_oom();

                TAKE_STRUCT(iovec);
        }

        /* Make sure we got all data we really need */
        assert(input_fd >= 0);

        r = context_parse_iovw(&context, &iovw);
        if (r < 0)
                return r;

        /* Make sure we received at least all fields we need. */
        for (int i = 0; i < _META_MANDATORY_MAX; i++)
                if (!context.meta[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "A mandatory argument (%i) has not been sent, aborting.", i);

        return submit_coredump(&context, &iovw, input_fd);
}

static int send_iovec(const struct iovec_wrapper *iovw, int input_fd, PidRef *pidref, int mount_tree_fd) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(iovw);
        assert(input_fd >= 0);

        fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create coredump socket: %m");

        r = connect_unix_path(fd, AT_FDCWD, "/run/systemd/coredump");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to coredump service: %m");

        for (size_t i = 0; i < iovw->count; i++) {
                struct msghdr mh = {
                        .msg_iov = iovw->iovec + i,
                        .msg_iovlen = 1,
                };
                struct iovec copy[2];

                for (;;) {
                        if (sendmsg(fd, &mh, MSG_NOSIGNAL) >= 0)
                                break;

                        if (errno == EMSGSIZE && mh.msg_iov[0].iov_len > 0) {
                                /* This field didn't fit? That's a pity. Given that this is
                                 * just metadata, let's truncate the field at half, and try
                                 * again. We append three dots, in order to show that this is
                                 * truncated. */

                                if (mh.msg_iov != copy) {
                                        /* We don't want to modify the caller's iovec, hence
                                         * let's create our own array, consisting of two new
                                         * iovecs, where the first is a (truncated) copy of
                                         * what we want to send, and the second one contains
                                         * the trailing dots. */
                                        copy[0] = iovw->iovec[i];
                                        copy[1] = IOVEC_MAKE(((const char[]){'.', '.', '.'}), 3);

                                        mh.msg_iov = copy;
                                        mh.msg_iovlen = 2;
                                }

                                copy[0].iov_len /= 2; /* halve it, and try again */
                                continue;
                        }

                        return log_error_errno(errno, "Failed to send coredump datagram: %m");
                }
        }

        /* First sentinel: the coredump fd */
        r = send_one_fd(fd, input_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send coredump fd: %m");

        /* The optional second sentinel: the pidfd */
        if (!pidref_is_set(pidref) || pidref->fd < 0) /* If we have no pidfd, stop now */
                return 0;

        r = send_one_fd(fd, pidref->fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send pidfd: %m");

        /* The optional third sentinel: the mount tree fd */
        if (mount_tree_fd < 0) /* If we have no mount tree, stop now */
                return 0;

        r = send_one_fd(fd, mount_tree_fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send mount tree fd: %m");

        return 0;
}

static int gather_pid_metadata_from_argv(
                struct iovec_wrapper *iovw,
                Context *context,
                int argc, char **argv) {

        int r;

        assert(iovw);
        assert(context);

        /* We gather all metadata that were passed via argv[] into an array of iovecs that
         * we'll forward to the socket unit */

        if (argc < _META_ARGV_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough arguments passed by the kernel (%i, expected %i).",
                                       argc, _META_ARGV_MAX);

        for (int i = 0; i < _META_ARGV_MAX; i++) {
                _cleanup_free_ char *buf = NULL;
                const char *t = argv[i];

                if (i == META_ARGV_TIMESTAMP) {
                        /* The journal fields contain the timestamp padded with six
                         * zeroes, so that the kernel-supplied 1s granularity timestamps
                         * becomes 1μs granularity, i.e. the granularity systemd usually
                         * operates in. */
                        buf = strjoin(argv[i], "000000");
                        if (!buf)
                                return log_oom();

                        t = buf;
                }

                r = iovw_put_string_field(iovw, meta_field_names[i], t);
                if (r < 0)
                        return r;
        }

        /* Cache some of the process metadata we collected so far and that we'll need to
         * access soon */
        return context_parse_iovw(context, iovw);
}

static int gather_pid_metadata_from_procfs(struct iovec_wrapper *iovw, Context *context) {
        uid_t owner_uid;
        pid_t pid;
        char *t;
        size_t size;
        const char *p;
        int r;

        assert(iovw);
        assert(context);

        /* Note that if we fail on oom later on, we do not roll-back changes to the iovec
         * structure. (It remains valid, with the first iovec fields initialized.) */

        pid = context->pidref.pid;

        /* The following is mandatory */
        r = pidref_get_comm(&context->pidref, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to get COMM: %m");

        r = iovw_put_string_field_free(iovw, "COREDUMP_COMM=", t);
        if (r < 0)
                return r;

        /* The following are optional, but we use them if present. */
        r = get_process_exe(pid, &t);
        if (r >= 0)
                r = iovw_put_string_field_free(iovw, "COREDUMP_EXE=", t);
        if (r < 0)
                log_warning_errno(r, "Failed to get EXE, ignoring: %m");

        if (cg_pidref_get_unit(&context->pidref, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_UNIT=", t);

        if (cg_pid_get_user_unit(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_USER_UNIT=", t);

        if (cg_pidref_get_session(&context->pidref, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_SESSION=", t);

        if (cg_pidref_get_owner_uid(&context->pidref, &owner_uid) >= 0) {
                r = asprintf(&t, UID_FMT, owner_uid);
                if (r > 0)
                        (void) iovw_put_string_field_free(iovw, "COREDUMP_OWNER_UID=", t);
        }

        if (sd_pid_get_slice(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_SLICE=", t);

        if (pidref_get_cmdline(&context->pidref, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CMDLINE=", t);

        if (cg_pid_get_path_shifted(pid, NULL, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CGROUP=", t);

        if (compose_open_fds(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_OPEN_FDS=", t);

        p = procfs_file_alloca(pid, "status");
        if (read_full_virtual_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_STATUS=", t);

        p = procfs_file_alloca(pid, "maps");
        if (read_full_virtual_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_MAPS=", t);

        p = procfs_file_alloca(pid, "limits");
        if (read_full_virtual_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_LIMITS=", t);

        p = procfs_file_alloca(pid, "cgroup");
        if (read_full_virtual_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_CGROUP=", t);

        p = procfs_file_alloca(pid, "mountinfo");
        if (read_full_virtual_file(p, &t, NULL) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_PROC_MOUNTINFO=", t);

        /* We attach /proc/auxv here. ELF coredumps also contain a note for this (NT_AUXV), see elf(5). */
        p = procfs_file_alloca(pid, "auxv");
        if (read_full_virtual_file(p, &t, &size) >= 0) {
                char *buf = malloc(strlen("COREDUMP_PROC_AUXV=") + size + 1);
                if (buf) {
                        /* Add a dummy terminator to make context_parse_iovw() happy. */
                        *mempcpy_typesafe(stpcpy(buf, "COREDUMP_PROC_AUXV="), t, size) = '\0';
                        (void) iovw_consume(iovw, buf, size + strlen("COREDUMP_PROC_AUXV="));
                }

                free(t);
        }

        if (get_process_cwd(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_CWD=", t);

        if (get_process_root(pid, &t) >= 0) {
                bool proc_self_root_is_slash;

                proc_self_root_is_slash = strcmp(t, "/") == 0;

                (void) iovw_put_string_field_free(iovw, "COREDUMP_ROOT=", t);

                /* If the process' root is "/", then there is a chance it has
                 * mounted own root and hence being containerized. */
                if (proc_self_root_is_slash && get_process_container_parent_cmdline(&context->pidref, &t) > 0)
                        (void) iovw_put_string_field_free(iovw, "COREDUMP_CONTAINER_CMDLINE=", t);
        }

        if (get_process_environ(pid, &t) >= 0)
                (void) iovw_put_string_field_free(iovw, "COREDUMP_ENVIRON=", t);

        /* we successfully acquired all metadata */
        return context_parse_iovw(context, iovw);
}

static int send_ucred(int transport_fd, const struct ucred *ucred) {
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;

        assert(transport_fd >= 0);
        assert(ucred);

        cmsg = CMSG_FIRSTHDR(&mh);
        *cmsg = (struct cmsghdr) {
                .cmsg_level = SOL_SOCKET,
                .cmsg_type = SCM_CREDENTIALS,
                .cmsg_len = CMSG_LEN(sizeof(struct ucred)),
        };
        memcpy(CMSG_DATA(cmsg), ucred, sizeof(struct ucred));

        return RET_NERRNO(sendmsg(transport_fd, &mh, MSG_NOSIGNAL));
}

static int receive_ucred(int transport_fd, struct ucred *ret_ucred) {
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg = NULL;
        struct ucred *ucred = NULL;
        ssize_t n;

        assert(transport_fd >= 0);
        assert(ret_ucred);

        n = recvmsg_safe(transport_fd, &mh, 0);
        if (n < 0)
                return n;

        CMSG_FOREACH(cmsg, &mh)
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        assert(!ucred);
                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
                }

        if (!ucred)
                return -EIO;

        *ret_ucred = *ucred;

        return 0;
}

static int can_forward_coredump(const PidRef *pid) {
        _cleanup_free_ char *cgroup = NULL, *path = NULL, *unit = NULL;
        int r;

        assert(pidref_is_set(pid));
        assert(!pidref_is_remote(pid));

        r = cg_pidref_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cgroup);
        if (r < 0)
                return r;

        r = path_extract_directory(cgroup, &path);
        if (r < 0)
                return r;

        r = cg_path_get_unit_path(path, &unit);
        if (r == -ENOMEM)
                return log_oom();
        if (r == -ENXIO)
                /* No valid units in this path. */
                return false;
        if (r < 0)
                return r;

        /* We require that this process belongs to a delegated cgroup
         * (i.e. Delegate=yes), with CoredumpReceive=yes also. */
        r = cg_is_delegated(unit);
        if (r <= 0)
                return r;

        return cg_has_coredump_receive(unit);
}

static int forward_coredump_to_container(Context *context) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, netnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        pid_t child;
        struct ucred ucred = {
                .pid = context->pidref.pid,
                .uid = context->uid,
                .gid = context->gid,
        };
        int r;

        assert(context);

        _cleanup_(pidref_done) PidRef leader_pid = PIDREF_NULL;
        r = namespace_get_leader(&context->pidref, NAMESPACE_PID, &leader_pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get namespace leader: %m");

        r = can_forward_coredump(&leader_pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if coredump can be forwarded: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Coredump will not be forwarded because no target cgroup was found.");

        r = RET_NERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pair));
        if (r < 0)
                return log_debug_errno(r, "Failed to create socket pair: %m");

        r = setsockopt_int(pair[1], SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to set SO_PASSCRED: %m");

        r = pidref_namespace_open(&leader_pid, &pidnsfd, &mntnsfd, &netnsfd, &usernsfd, &rootfd);
        if (r < 0)
                return log_debug_errno(r, "Failed to open namespaces of PID " PID_FMT ": %m", leader_pid.pid);

        r = namespace_fork("(sd-coredumpns)", "(sd-coredump)", NULL, 0,
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM,
                           pidnsfd, mntnsfd, netnsfd, usernsfd, rootfd, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork into namespaces of PID " PID_FMT ": %m", leader_pid.pid);
        if (r == 0) {
                pair[0] = safe_close(pair[0]);

                r = access_nofollow("/run/systemd/coredump", W_OK);
                if (r < 0) {
                        log_debug_errno(r, "Cannot find coredump socket, exiting: %m");
                        _exit(EXIT_FAILURE);
                }

                r = receive_ucred(pair[1], &ucred);
                if (r < 0) {
                        log_debug_errno(r, "Failed to receive ucred and fd: %m");
                        _exit(EXIT_FAILURE);
                }

                _cleanup_(iovw_free_freep) struct iovec_wrapper *iovw = iovw_new();
                if (!iovw) {
                        log_oom();
                        _exit(EXIT_FAILURE);
                }

                (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_COREDUMP_STR);
                (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));
                (void) iovw_put_string_field(iovw, "COREDUMP_FORWARDED=", "1");

                for (int i = 0; i < _META_ARGV_MAX; i++) {
                        char buf[DECIMAL_STR_MAX(pid_t)];
                        const char *t = context->meta[i];

                        /* Patch some of the fields with the translated ucred data */
                        switch (i) {

                        case META_ARGV_PID:
                                xsprintf(buf, PID_FMT, ucred.pid);
                                t = buf;
                                break;

                        case META_ARGV_UID:
                                xsprintf(buf, UID_FMT, ucred.uid);
                                t = buf;
                                break;

                        case META_ARGV_GID:
                                xsprintf(buf, GID_FMT, ucred.gid);
                                t = buf;
                                break;

                        default:
                                break;
                        }

                        r = iovw_put_string_field(iovw, meta_field_names[i], t);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to construct iovec: %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                _cleanup_(context_done) Context child_context = CONTEXT_NULL;
                r = context_parse_iovw(&child_context, iovw);
                if (r < 0) {
                        log_debug_errno(r, "Failed to save context: %m");
                        _exit(EXIT_FAILURE);
                }

                r = gather_pid_metadata_from_procfs(iovw, &child_context);
                if (r < 0) {
                        log_debug_errno(r, "Failed to gather metadata from procfs: %m");
                        _exit(EXIT_FAILURE);
                }

                r = send_iovec(iovw, STDIN_FILENO, &context->pidref, /* mount_tree_fd= */ -EBADF);
                if (r < 0) {
                        log_debug_errno(r, "Failed to send iovec to coredump socket: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        /* We need to translate the PID, UID, and GID of the crashing process
         * to the container's namespaces. Do this by sending an SCM_CREDENTIALS
         * message on a socket pair, and read the result when we join the
         * container. The kernel will perform the translation for us. */
        r = send_ucred(pair[0], &ucred);
        if (r < 0)
                return log_debug_errno(r, "Failed to send metadata to container: %m");

        r = wait_for_terminate_and_check("(sd-coredumpns)", child, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to wait for child to terminate: %m");
        if (r != EXIT_SUCCESS)
                return log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Failed to process coredump in container.");

        return 0;
}

static int acquire_pid_mount_tree_fd(const Context *context, int *ret_fd) {
        /* Don't bother preparing environment if we can't pass it to libdwfl. */
#if !HAVE_DWFL_SET_SYSROOT
        *ret_fd = -EOPNOTSUPP;
        log_debug("dwfl_set_sysroot() is not supported.");
#else
        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, fd = -EBADF;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        assert(context);
        assert(ret_fd);

        if (!arg_enter_namespace) {
                *ret_fd = -EHOSTDOWN;
                log_debug("EnterNamespace=no so we won't use mount tree of the crashed process for generating backtrace.");
                return 0;
        }

        if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pair) < 0)
                return log_error_errno(errno, "Failed to create socket pair: %m");

        r = pidref_namespace_open(
                        &context->pidref,
                        /* ret_pidns_fd= */ NULL,
                        &mntns_fd,
                        /* ret_netns_fd= */ NULL,
                        /* ret_userns_fd= */ NULL,
                        &root_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open mount namespace of crashing process: %m");

        r = namespace_fork("(sd-mount-tree-ns)",
                           "(sd-mount-tree)",
                           /* except_fds= */ NULL,
                           /* n_except_fds= */ 0,
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT,
                           /* pidns_fd= */ -EBADF,
                           mntns_fd,
                           /* netns_fd= */ -EBADF,
                           /* userns_fd= */ -EBADF,
                           root_fd,
                           NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                pair[0] = safe_close(pair[0]);

                fd = open_tree(-EBADF, "/", AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE);
                if (fd < 0) {
                        log_error_errno(errno, "Failed to clone mount tree: %m");
                        _exit(EXIT_FAILURE);
                }

                r = send_one_fd(pair[1], fd, 0);
                if (r < 0) {
                        log_error_errno(r, "Failed to send mount tree to parent: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        fd = receive_one_fd(pair[0], MSG_DONTWAIT);
        if (fd < 0)
                return log_error_errno(fd, "Failed to receive mount tree: %m");

        *ret_fd = TAKE_FD(fd);
#endif
        return 0;
}

static int process_kernel(int argc, char *argv[]) {
        _cleanup_(iovw_free_freep) struct iovec_wrapper *iovw = NULL;
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        int r;

        /* When we're invoked by the kernel, stdout/stderr are closed which is dangerous because the fds
         * could get reallocated. To avoid hard to debug issues, let's instead bind stdout/stderr to
         * /dev/null. */
        r = rearrange_stdio(STDIN_FILENO, -EBADF, -EBADF);
        if (r < 0)
                return log_error_errno(r, "Failed to connect stdout/stderr to /dev/null: %m");

        log_debug("Processing coredump received from the kernel...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        /* Collect all process metadata passed by the kernel through argv[] */
        r = gather_pid_metadata_from_argv(iovw, &context, argc - 1, argv + 1);
        if (r < 0)
                return r;

        /* Collect the rest of the process metadata retrieved from the runtime */
        r = gather_pid_metadata_from_procfs(iovw, &context);
        if (r < 0)
                return r;

        if (!context.is_journald)
                /* OK, now we know it's not the journal, hence we can make use of it now. */
                log_set_target_and_open(LOG_TARGET_JOURNAL_OR_KMSG);

        /* Log minimal metadata now, so it is not lost if the system is about to shut down. */
        log_info("Process %s (%s) of user %s terminated abnormally with signal %s/%s, processing...",
                 context.meta[META_ARGV_PID], context.meta[META_COMM],
                 context.meta[META_ARGV_UID], context.meta[META_ARGV_SIGNAL],
                 signal_to_string(context.signo));

        r = pidref_in_same_namespace(/* pid1 = */ NULL, &context.pidref, NAMESPACE_PID);
        if (r < 0)
                log_debug_errno(r, "Failed to check pidns of crashing process, ignoring: %m");
        if (r == 0) {
                /* If this fails, fallback to the old behavior so that
                 * there is still some record of the crash. */
                r = forward_coredump_to_container(&context);
                if (r >= 0)
                        return 0;

                r = acquire_pid_mount_tree_fd(&context, &context.mount_tree_fd);
                if (r < 0)
                        log_warning_errno(r, "Failed to access the mount tree of a container, ignoring: %m");
        }

        /* If this is PID 1 disable coredump collection, we'll unlikely be able to process
         * it later on.
         *
         * FIXME: maybe we should disable coredumps generation from the beginning and
         * re-enable it only when we know it's either safe (ie we're not running OOM) or
         * it's not pid1 ? */
        if (context.is_pid1) {
                log_notice("Due to PID 1 having crashed coredump collection will now be turned off.");
                disable_coredumps();
        }

        (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_COREDUMP_STR);
        (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));

        if (context.is_journald || context.is_pid1)
                return submit_coredump(&context, iovw, STDIN_FILENO);

        return send_iovec(iovw, STDIN_FILENO, &context.pidref, context.mount_tree_fd);
}

static int process_backtrace(int argc, char *argv[]) {
        _cleanup_(journal_importer_cleanup) JournalImporter importer = JOURNAL_IMPORTER_INIT(STDIN_FILENO);
        _cleanup_(iovw_free_freep) struct iovec_wrapper *iovw = NULL;
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        char *message;
        int r;

        assert(argc >= 2);

        log_debug("Processing backtrace on stdin...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_BACKTRACE_STR);
        (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));

        /* Collect all process metadata from argv[] by making sure to skip the
         * '--backtrace' option */
        r = gather_pid_metadata_from_argv(iovw, &context, argc - 2, argv + 2);
        if (r < 0)
                return r;

        /* Collect the rest of the process metadata retrieved from the runtime */
        r = gather_pid_metadata_from_procfs(iovw, &context);
        if (r < 0)
                return r;

        for (;;) {
                r = journal_importer_process_data(&importer);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse journal entry on stdin: %m");
                if (r == 1 ||                        /* complete entry */
                    journal_importer_eof(&importer)) /* end of data */
                        break;
        }

        if (journal_importer_eof(&importer)) {
                log_warning("Did not receive a full journal entry on stdin, ignoring message sent by reporter");

                message = strjoina("Process ", context.meta[META_ARGV_PID],
                                  " (", context.meta[META_COMM], ")"
                                  " of user ", context.meta[META_ARGV_UID],
                                  " failed with ", context.meta[META_ARGV_SIGNAL]);

                r = iovw_put_string_field(iovw, "MESSAGE=", message);
                if (r < 0)
                        return r;
        } else {
                /* The imported iovecs are not supposed to be freed by us so let's copy and merge them at the
                 * end of the array. */
                r = iovw_append(iovw, &importer.iovw);
                if (r < 0)
                        return r;
        }

        r = sd_journal_sendv(iovw->iovec, iovw->count);
        if (r < 0)
                return log_error_errno(r, "Failed to log backtrace: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        /* First, log to a safe place, since we don't know what crashed and it might
         * be journald which we'd rather not log to then. */

        log_set_target_and_open(LOG_TARGET_KMSG);

        /* Make sure we never enter a loop */
        (void) prctl(PR_SET_DUMPABLE, 0);

        /* Ignore all parse errors */
        (void) parse_config();

        log_debug("Selected storage '%s'.", coredump_storage_to_string(arg_storage));
        log_debug("Selected compression %s.", yes_no(arg_compress));

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");

        /* If we got an fd passed, we are running in coredumpd mode. Otherwise we
         * are invoked from the kernel as coredump handler. */
        if (r == 0) {
                if (streq_ptr(argv[1], "--backtrace"))
                        return process_backtrace(argc, argv);
                else
                        return process_kernel(argc, argv);
        } else if (r == 1)
                return process_socket(SD_LISTEN_FDS_START);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Received unexpected number of file descriptors.");
}

DEFINE_MAIN_FUNCTION(run);
