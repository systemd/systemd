/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-id128.h"
#include "sd-journal.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "bus-error.h"
#include "capability-util.h"
#include "compress.h"
#include "copy.h"
#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-submit.h"
#include "coredump-util.h"
#include "coredump-vacuum.h"
#include "elf-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "iovec-wrapper.h"
#include "journal-send.h"
#include "json-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "user-util.h"

/* When checking for available memory and setting lower limits, don't
 * go below 4MB for writing core files to storage. */
#define PROCESS_SIZE_MIN (4U*1024U*1024U)

#define MOUNT_TREE_ROOT "/run/systemd/mount-rootfs"

static const char* coredump_tmpfile_name(const char *s) {
        return s ?: "(unnamed temporary file)";
}

static int make_filename(const CoredumpContext *context, char **ret) {
        _cleanup_free_ char *c = NULL;
        sd_id128_t boot;
        int r;

        assert(context);

        c = xescape(context->comm, "./ ");
        if (!c)
                return -ENOMEM;

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return r;

        if (asprintf(ret,
                     "/var/lib/systemd/coredump/core.%s."UID_FMT"." SD_ID128_FORMAT_STR "."PID_FMT"."USEC_FMT,
                     c, context->uid, SD_ID128_FORMAT_VAL(boot), context->pidref.pid, context->timestamp) < 0)
                return -ENOMEM;

        return 0;
}

static int grant_user_access(int core_fd, const CoredumpContext *context) {
        int at_secure = -1;
        uid_t uid = UID_INVALID, euid = UID_INVALID;
        uid_t gid = GID_INVALID, egid = GID_INVALID;
        int r;

        assert(core_fd >= 0);
        assert(context);

        if (!context->auxv)
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
                       context->auxv,
                       context->auxv_size,
                       &at_secure, &uid, &euid, &gid, &egid);
        if (r < 0)
                return r;

        /* We allow access if %d/dumpable on the command line was exactly 1, we got all the data,
         * at_secure is not set, and the uid/gid match euid/egid. */
        bool ret =
                context->dumpable == SUID_DUMP_USER &&
                at_secure == 0 &&
                uid != UID_INVALID && euid != UID_INVALID && uid == euid &&
                gid != GID_INVALID && egid != GID_INVALID && gid == egid;
        log_debug("Will %s access (dumpable=%u uid="UID_FMT " euid="UID_FMT " gid="GID_FMT " egid="GID_FMT " at_secure=%s)",
                  ret ? "permit" : "restrict",
                  context->dumpable,
                  uid, euid, gid, egid, yes_no(at_secure));
        return ret;
}

static int fix_acl(int fd, uid_t uid, bool allow_user) {
        assert(fd >= 0);
        assert(uid_is_valid(uid));

#if HAVE_ACL
        int r;

        /* We don't allow users to read coredumps if the uid or capabilities were changed. */
        if (!allow_user)
                return 0;

        if (uid_is_system(uid) || uid_is_dynamic(uid) || uid_is_greeter(uid) || uid == UID_NOBODY)
                return 0;

        /* Make sure normal users can read (but not write or delete) their own coredumps */
        r = fd_add_uid_acl_permission(fd, uid, ACL_READ);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust ACL of the coredump: %m");
#endif

        return 0;
}

static int fix_xattr_one(int fd, const char *xattr, const char *val) {
        assert(fd >= 0);
        assert(xattr);

        if (isempty(val))
                return 0;

        return RET_NERRNO(fsetxattr(fd, xattr, val, strlen(val), XATTR_CREATE));
}

_printf_(3, 4)
static int fix_xattr_format(int fd, const char *xattr, const char *format, ...) {
        _cleanup_free_ char *value = NULL;
        va_list ap;
        int r;

        assert(format);

        va_start(ap, format);
        r = vasprintf(&value, format, ap);
        va_end(ap);
        if (r < 0)
                return -ENOMEM;

        return fix_xattr_one(fd, xattr, value);
}

static int fix_xattr(int fd, const CoredumpContext *context) {
        int r;

        assert(fd >= 0);
        assert(context);

        /* Attach some metadata to coredumps via extended attributes. Just because we can. */

        r = fix_xattr_format(fd, "user.coredump.pid", PID_FMT, context->pidref.pid);
        RET_GATHER(r, fix_xattr_format(fd, "user.coredump.uid", UID_FMT, context->uid));
        RET_GATHER(r, fix_xattr_format(fd, "user.coredump.gid", GID_FMT, context->gid));
        RET_GATHER(r, fix_xattr_format(fd, "user.coredump.signal", "%i", context->signo));
        RET_GATHER(r, fix_xattr_format(fd, "user.coredump.timestamp", USEC_FMT, context->timestamp));
        RET_GATHER(r, fix_xattr_format(fd, "user.coredump.rlimit", "%"PRIu64, context->rlimit));
        RET_GATHER(r, fix_xattr_one(fd, "user.coredump.hostname", context->hostname));
        RET_GATHER(r, fix_xattr_one(fd, "user.coredump.comm", context->comm));
        RET_GATHER(r, fix_xattr_one(fd, "user.coredump.exe", context->exe));

        return r;
}

static int fix_permissions_and_link(
                int fd,
                const char *filename,
                const char *target,
                const CoredumpContext *context,
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

static int save_external_coredump(
                const CoredumpConfig *config,
                const CoredumpContext *context,
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

        assert(config);
        assert(context);
        assert(context->input_fd >= 0);
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
                                      "Resource limits disable core dumping for process "PID_FMT" (%s).",
                                      context->pidref.pid, context->comm);

        process_limit = MAX(config->process_size_max, coredump_storage_size_max(config));
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
        if (storage_on_tmpfs && config->compress) {
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

        r = copy_bytes(context->input_fd, fd, max_size, 0);
        if (r < 0)
                return log_error_errno(r, "Cannot store coredump of "PID_FMT" (%s): %m",
                                       context->pidref.pid, context->comm);
        truncated = r == 1;

        bool allow_user = grant_user_access(fd, context) > 0;

#if HAVE_COMPRESSION
        if (config->compress) {
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

                        r = compress_stream(context->input_fd, fd_compressed, max_size, &partial_uncompressed_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to compress %s: %m", coredump_tmpfile_name(tmp_compressed));
                        uncompressed_size += partial_uncompressed_size;
                }

                r = fix_permissions_and_link(fd_compressed, tmp_compressed, fn_compressed, context, allow_user);
                if (r < 0)
                        return r;

                if (fstat(fd_compressed, &st) < 0)
                        return log_error_errno(errno,
                                        "Failed to fstat core file %s: %m",
                                        coredump_tmpfile_name(tmp_compressed));

                *ret_filename = TAKE_PTR(fn_compressed);       /* compressed */
                *ret_node_fd = TAKE_FD(fd_compressed);         /* compressed */
                *ret_data_fd = TAKE_FD(fd);
                *ret_size = uncompressed_size;
                *ret_compressed_size = (uint64_t) st.st_size;  /* compressed */
                *ret_truncated = truncated;

                return 0;
        }
#endif

        if (truncated)
                log_struct(LOG_INFO,
                           LOG_MESSAGE("Core file was truncated to %"PRIu64" bytes.", max_size),
                           LOG_ITEM("SIZE_LIMIT=%"PRIu64, max_size),
                           LOG_MESSAGE_ID(SD_MESSAGE_TRUNCATED_CORE_STR));

        r = fix_permissions_and_link(fd, tmp, fn, context, allow_user);
        if (r < 0)
                return log_error_errno(r, "Failed to fix permissions and finalize coredump %s into %s: %m", coredump_tmpfile_name(tmp), fn);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to fstat core file %s: %m", coredump_tmpfile_name(tmp));

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek on coredump %s: %m", fn);

        *ret_filename = TAKE_PTR(fn);
        *ret_node_fd = -EBADF;
        *ret_data_fd = TAKE_FD(fd);
        *ret_size = (uint64_t) st.st_size;
        *ret_compressed_size = UINT64_MAX;
        *ret_truncated = truncated;

        return 0;
}

static int maybe_remove_external_coredump(
                const CoredumpConfig *config,
                CoredumpContext *context,
                const char *filename,
                uint64_t size) {

        assert(config);
        assert(context);

        /* Returns true if might remove, false if will not remove, < 0 on error. */

        /* Always keep around in case of journald/pid1, since we cannot rely on the journal to accept them. */
        if (config->storage != COREDUMP_STORAGE_NONE &&
            (coredump_context_is_pid1(context) || coredump_context_is_journald(context)))
                return false;

        if (config->storage == COREDUMP_STORAGE_EXTERNAL &&
            size <= config->external_size_max)
                return false;

        if (!filename)
                return true;

        if (unlink(filename) < 0 && errno != ENOENT)
                return log_error_errno(errno, "Failed to unlink %s: %m", filename);

        return true;
}

static int acquire_pid_mount_tree_fd(const CoredumpConfig *config, CoredumpContext *context) {
#if HAVE_DWFL_SET_SYSROOT
        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, fd = -EBADF;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        assert(config);
        assert(context);

        if (context->mount_tree_fd >= 0)
                return 0;

        if (!config->enter_namespace)
                return log_debug_errno(SYNTHETIC_ERRNO(EHOSTDOWN),
                                       "EnterNamespace=no so we won't use mount tree of the crashed process for generating backtrace.");

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
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT,
                           /* pidns_fd= */ -EBADF,
                           mntns_fd,
                           /* netns_fd= */ -EBADF,
                           /* userns_fd= */ -EBADF,
                           root_fd,
                           /* ret= */ NULL);
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

        context->mount_tree_fd = TAKE_FD(fd);
        return 0;
#else
        /* Don't bother preparing environment if we can't pass it to libdwfl. */
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "dwfl_set_sysroot() is not supported.");
#endif
}

static int attach_mount_tree(const CoredumpConfig *config, CoredumpContext *context) {
        int r;

        assert(config);
        assert(context);

        r = acquire_pid_mount_tree_fd(config, context);
        if (r < 0)
                return r;

        assert(context->mount_tree_fd >= 0);

        r = detach_mount_namespace();
        if (r < 0)
                return log_warning_errno(r, "Failed to detach mount namespace: %m");

        r = mkdir_p_label(MOUNT_TREE_ROOT, 0555);
        if (r < 0)
                return log_warning_errno(r, "Failed to create directory: %m");

        r = mount_setattr(context->mount_tree_fd, "", AT_EMPTY_PATH,
                          &(struct mount_attr) {
                                  /* MOUNT_ATTR_NOSYMFOLLOW is left out on purpose to allow libdwfl to resolve symlinks.
                                   * libdwfl will use openat2() with RESOLVE_IN_ROOT so there is no risk of symlink escape.
                                   * https://sourceware.org/git/?p=elfutils.git;a=patch;h=06f0520f9a78b07c11c343181d552791dd630346 */
                                  .attr_set = MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC,
                                  .propagation = MS_SLAVE,
                          }, sizeof(struct mount_attr));
        if (r < 0)
                return log_warning_errno(errno, "Failed to change properties of mount tree: %m");

        r = move_mount(context->mount_tree_fd, "", -EBADF, MOUNT_TREE_ROOT, MOVE_MOUNT_F_EMPTY_PATH);
        if (r < 0)
                return log_warning_errno(errno, "Failed to attach mount tree: %m");

        return 0;
}

static int change_uid_gid(const CoredumpContext *context) {
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

int coredump_submit(const CoredumpConfig *config, CoredumpContext *context) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json_metadata = NULL;
        _cleanup_close_ int coredump_fd = -EBADF, coredump_node_fd = -EBADF;
        _cleanup_free_ char *filename = NULL, *coredump_data = NULL, *stacktrace = NULL;
        const char *module_name, *root = NULL;
        uint64_t coredump_size = UINT64_MAX, coredump_compressed_size = UINT64_MAX;
        bool truncated = false, written = false;
        sd_json_variant *module_json;
        int r;

        assert(config);
        assert(context);

        /* Vacuum before we write anything again */
        (void) coredump_vacuum(-1, config->keep_free, config->max_use);

        /* Always stream the coredump to disk, if that's possible */
        written = save_external_coredump(
                        config, context,
                        &filename, &coredump_node_fd, &coredump_fd,
                        &coredump_size, &coredump_compressed_size, &truncated) >= 0;
        if (written) {
                /* If we could write it to disk we can now process it. */
                /* If we don't want to keep the coredump on disk, remove it now, as later on we
                 * will lack the privileges for it. However, we keep the fd to it, so that we can
                 * still process it and log it. */
                r = maybe_remove_external_coredump(
                                config,
                                context,
                                filename,
                                coredump_node_fd >= 0 ? coredump_compressed_size : coredump_size);
                if (r < 0)
                        return r;
                if (r > 0) {
                        filename = mfree(filename);

                        if (config->storage == COREDUMP_STORAGE_EXTERNAL)
                                log_info("The core will not be stored: size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                                         coredump_node_fd >= 0 ? coredump_compressed_size : coredump_size, config->external_size_max);
                }

                /* Vacuum again, but exclude the coredump we just created */
                (void) coredump_vacuum(coredump_node_fd >= 0 ? coredump_node_fd : coredump_fd, config->keep_free, config->max_use);
        }

        if (attach_mount_tree(config, context) >= 0)
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
                if (coredump_size > config->process_size_max)
                        log_debug("Not generating stack trace: core size %"PRIu64" is greater "
                                  "than %"PRIu64" (the configured maximum)",
                                  coredump_size, config->process_size_max);
                else if (coredump_fd >= 0) {
                        bool skip = startswith(context->comm, "systemd-coredum"); /* COMM is 16 bytes usually */

                        (void) parse_elf_object(coredump_fd,
                                                context->exe,
                                                root,
                                                /* fork_disable_dump= */ skip, /* avoid loops */
                                                &stacktrace,
                                                &json_metadata,
                                                /* ret_dlopen_metadata= */ NULL);
                }
        }

        r = coredump_context_build_iovw(context);
        if (r < 0)
                return r;

        _cleanup_free_ char *core_message = NULL;
        if (asprintf(&core_message, "Process "PID_FMT" (%s) of user "UID_FMT" %s",
                     context->pidref.pid, context->comm, context->uid,
                     written ? "dumped core." : "terminated abnormally without generating a coredump.") < 0)
                return log_oom();

        if (coredump_context_is_journald(context) && filename)
                if (!strextend(&core_message, "\nCoredump diverted to ", filename))
                        return log_oom();

        if (stacktrace)
                if (!strextend(&core_message, "\n\n", stacktrace))
                        return log_oom();

        if (coredump_context_is_journald(context))
                /* We might not be able to log to the journal, so let's always print the message to another
                 * log target. The target was set previously to something safe. */
                log_dispatch(LOG_ERR, 0, core_message);

        (void) iovw_put_string_field(&context->iovw, "MESSAGE=", core_message);

        if (filename)
                (void) iovw_put_string_field(&context->iovw, "COREDUMP_FILENAME=", filename);
        if (truncated)
                (void) iovw_put_string_field(&context->iovw, "COREDUMP_TRUNCATED=", "1");

        /* If we managed to parse any ELF metadata (build-id, ELF package meta),
         * attach it as journal metadata. */
        if (json_metadata) {
                _cleanup_free_ char *formatted_json = NULL;

                r = sd_json_variant_format(json_metadata, 0, &formatted_json);
                if (r < 0)
                        return log_error_errno(r, "Failed to format JSON package metadata: %m");

                (void) iovw_put_string_field(&context->iovw, "COREDUMP_PACKAGE_JSON=", formatted_json);
        }

        /* In the unlikely scenario that context->meta[META_EXE] is not available,
         * let's avoid guessing the module name and skip the loop. */
        if (context->exe)
                JSON_VARIANT_OBJECT_FOREACH(module_name, module_json, json_metadata) {
                        sd_json_variant *t;

                        /* We only add structured fields for the 'main' ELF module, and only if we can identify it. */
                        if (!path_equal_filename(module_name, context->exe))
                                continue;

                        t = sd_json_variant_by_key(module_json, "name");
                        if (t)
                                (void) iovw_put_string_field(&context->iovw, "COREDUMP_PACKAGE_NAME=", sd_json_variant_string(t));

                        t = sd_json_variant_by_key(module_json, "version");
                        if (t)
                                (void) iovw_put_string_field(&context->iovw, "COREDUMP_PACKAGE_VERSION=", sd_json_variant_string(t));
                }

        /* Optionally store the entire coredump in the journal */
        if (config->storage == COREDUMP_STORAGE_JOURNAL && coredump_fd >= 0) {
                if (coredump_size <= config->journal_size_max) {
                        size_t sz = 0;

                        /* Store the coredump itself in the journal */

                        r = allocate_journal_field(coredump_fd, (size_t) coredump_size, &coredump_data, &sz);
                        if (r >= 0) {
                                if (iovw_put(&context->iovw, coredump_data, sz) >= 0)
                                        TAKE_PTR(coredump_data);
                        } else
                                log_warning_errno(r, "Failed to attach the core to the journal entry: %m");
                } else
                        log_info("The core will not be stored: size %"PRIu64" is greater than %"PRIu64" (the configured maximum)",
                                 coredump_size, config->journal_size_max);
        }

        /* If journald is coredumping, we have to be careful that we don't deadlock when trying to write the
         * coredump to the journal, so we put the journal socket in nonblocking mode before trying to write
         * the coredump to the socket. */

        if (coredump_context_is_journald(context)) {
                r = journal_fd_nonblock(true);
                if (r < 0)
                        return log_error_errno(r, "Failed to make journal socket non-blocking: %m");
        }

        r = sd_journal_sendv(context->iovw.iovec, context->iovw.count);

        if (coredump_context_is_journald(context)) {
                int k;

                k = journal_fd_nonblock(false);
                if (k < 0)
                        return log_error_errno(k, "Failed to make journal socket blocking: %m");
        }

        if (r == -EAGAIN && coredump_context_is_journald(context))
                log_warning_errno(r, "Failed to log journal coredump, ignoring: %m");
        else if (r < 0)
                return log_error_errno(r, "Failed to log coredump: %m");

        return 0;
}
