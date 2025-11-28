/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>
#include <sched.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-messages.h"
#include "sd-varlink.h"

#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "chase.h"
#include "conf-files.h"
#include "copy.h"
#include "cryptsetup-util.h"
#include "data-fd-util.h"
#include "dirent-util.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "env-file.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "extension-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "image-policy.h"
#include "install.h"
#include "iovec-util.h"
#include "libmount-util.h"
#include "log-context.h"
#include "log.h"
#include "loop-util.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "nsresource.h"
#include "os-util.h"
#include "path-lookup.h"
#include "pidref.h"
#include "portable.h"
#include "portable-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "set.h"
#include "socket-util.h"
#include "sort-util.h"
#include "string-table.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "unit-name.h"
#include "vpick.h"

/* Markers used in the first line of our 20-portable.conf unit file drop-in to determine, that a) the unit file was
 * dropped there by the portable service logic and b) for which image it was dropped there. */
#define PORTABLE_DROPIN_MARKER_BEGIN "# Drop-in created for image '"
#define PORTABLE_DROPIN_MARKER_END "', do not edit."

static bool prefix_match(const char *unit, const char *prefix) {
        const char *p;

        p = startswith(unit, prefix);
        if (!p)
                return false;

        /* Only respect prefixes followed by dash or dot or when there's a complete match */
        return IN_SET(*p, '-', '.', '@', 0);
}

static bool unit_match(const char *unit, char **matches) {
        const char *dot;

        dot = strrchr(unit, '.');
        if (!dot)
                return false;

        if (!STR_IN_SET(dot, ".service", ".socket", ".target", ".timer", ".path"))
                return false;

        /* Empty match expression means: everything */
        if (strv_isempty(matches))
                return true;

        /* Otherwise, at least one needs to match */
        STRV_FOREACH(i, matches)
                if (prefix_match(unit, *i))
                        return true;

        return false;
}

static PortableMetadata *portable_metadata_new(const char *name, const char *path, const char *selinux_label, int fd) {
        PortableMetadata *m;

        m = malloc0(offsetof(PortableMetadata, name) + strlen(name) + 1);
        if (!m)
                return NULL;

        /* In case of a layered attach, we want to remember which image the unit came from */
        if (path) {
                m->image_path = strdup(path);
                if (!m->image_path)
                        return mfree(m);
        }

        /* The metadata file might have SELinux labels, we need to carry them and reapply them */
        if (!isempty(selinux_label)) {
                m->selinux_label = strdup(selinux_label);
                if (!m->selinux_label) {
                        free(m->image_path);
                        return mfree(m);
                }
        }

        strcpy(m->name, name);
        m->fd = fd;

        return TAKE_PTR(m);
}

PortableMetadata *portable_metadata_unref(PortableMetadata *i) {
        if (!i)
                return NULL;

        safe_close(i->fd);
        free(i->source);
        free(i->image_path);
        free(i->selinux_label);

        return mfree(i);
}

static int compare_metadata(PortableMetadata *const *x, PortableMetadata *const *y) {
        return strcmp((*x)->name, (*y)->name);
}

int portable_metadata_hashmap_to_sorted_array(Hashmap *unit_files, PortableMetadata ***ret) {

        _cleanup_free_ PortableMetadata **sorted = NULL;
        PortableMetadata *item;
        size_t k = 0;

        sorted = new(PortableMetadata*, hashmap_size(unit_files));
        if (!sorted)
                return -ENOMEM;

        HASHMAP_FOREACH(item, unit_files)
                sorted[k++] = item;

        assert(k == hashmap_size(unit_files));

        typesafe_qsort(sorted, k, compare_metadata);

        *ret = TAKE_PTR(sorted);
        return 0;
}

static int send_one_fd_iov_with_data_fd(
                int socket_fd,
                const struct iovec *iov,
                size_t iovlen,
                int fd) {

        _cleanup_close_ int data_fd = -EBADF;

        assert(iov || iovlen == 0);
        assert(socket_fd >= 0);
        assert(fd >= 0);

        data_fd = copy_data_fd(fd);
        if (data_fd < 0)
                return data_fd;

        return send_one_fd_iov(socket_fd, data_fd, iov, iovlen, 0);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(portable_metadata_hash_ops, char, string_hash_func, string_compare_func,
                                              PortableMetadata, portable_metadata_unref);

static int receive_portable_metadata(
                int socket_fd,
                const char *path,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files) {

        _cleanup_(portable_metadata_unrefp) PortableMetadata* os_release = NULL;
        _cleanup_(hashmap_freep) Hashmap *unit_files = NULL;
        int r;

        assert(socket_fd >= 0);
        assert(path);
        assert(ret_os_release);
        assert(ret_unit_files);

        unit_files = hashmap_new(&portable_metadata_hash_ops);
        if (!unit_files)
                return -ENOMEM;

        for (;;) {
                _cleanup_(portable_metadata_unrefp) PortableMetadata *add = NULL;
                _cleanup_close_ int fd = -EBADF;
                /* We use NAME_MAX space for the SELinux label here. The kernel currently enforces no limit,
                 * but according to suggestions from the SELinux people this will change and it will probably
                 * be identical to NAME_MAX. For now we use that, but this should be updated one day when the
                 * final limit is known. */
                char iov_buffer[PATH_MAX + NAME_MAX + 2];
                struct iovec iov = IOVEC_MAKE(iov_buffer, sizeof(iov_buffer));

                ssize_t n = receive_one_fd_iov(socket_fd, &iov, 1, 0, &fd);
                if (n == -EIO)
                        break;
                if (n < 0)
                        return log_debug_errno(n, "Failed to receive item: %m");
                iov_buffer[n] = 0;

                /* We can't really distinguish a zero-length datagram without any fds from EOF (both are
                 * signalled the same way by recvmsg()). Hence, accept either as end notification. */
                if (isempty(iov_buffer) && fd < 0)
                        break;

                if (isempty(iov_buffer) || fd < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                "Invalid item sent from child.");

                /* Given recvmsg cannot be used with multiple io vectors if you don't know the size in
                 * advance, use a marker to separate the name and the optional SELinux context. */
                char *selinux_label = memchr(iov_buffer, 0, n);
                assert(selinux_label);
                selinux_label++;

                add = portable_metadata_new(iov_buffer, path, selinux_label, fd);
                if (!add)
                        return -ENOMEM;
                fd = -EBADF;

                /* Note that we do not initialize 'add->source' here, as the source path is not usable here
                 * as it refers to a path only valid in the short-living namespaced child process we forked
                 * here. */

                if (PORTABLE_METADATA_IS_UNIT(add)) {
                        r = hashmap_put(unit_files, add->name, add);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add item to unit file list: %m");

                        add = NULL;

                } else if (PORTABLE_METADATA_IS_OS_RELEASE(add) || PORTABLE_METADATA_IS_EXTENSION_RELEASE(add)) {

                        assert(!os_release);
                        os_release = TAKE_PTR(add);
                } else
                        assert_not_reached();
        }

        *ret_os_release = TAKE_PTR(os_release);
        *ret_unit_files = TAKE_PTR(unit_files);
        return 0;
}

static int extract_now(
                RuntimeScope scope,
                int rfd,
                const char *image_path,
                char **matches,
                const char *image_name,
                bool path_is_extension,
                bool relax_extension_release_check,
                int socket_fd,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files) {

        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_(lookup_paths_done) LookupPaths paths = {};
        _cleanup_close_ int os_release_fd = -EBADF;
        _cleanup_free_ char *os_release_path = NULL;
        const char *os_release_id;
        int r;

        /* Extracts the metadata from a directory tree 'dir_fd'. Extracts two kinds of information: the /etc/os-release
         * data, and all unit files matching the specified expression. Note that this function is called in two very
         * different but also similar contexts. When the tool gets invoked on a directory tree, we'll process it
         * directly, and in-process, and thus can return the requested data directly, via 'ret_os_release' and
         * 'ret_unit_files'. However, if the tool is invoked on a raw disk image — which needs to be mounted first — we
         * are invoked in a child process with private mounts and then need to send the collected data to our
         * parent. To handle both cases in one call this function also gets a 'socket_fd' parameter, which when >= 0 is
         * used to send the data to the parent. */

        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(rfd >= 0);

        /* First, find os-release/extension-release and send it upstream (or just save it). */
        if (path_is_extension) {
                ImageClass class = IMAGE_SYSEXT;

                r = open_extension_release_at(rfd, IMAGE_SYSEXT, image_name, relax_extension_release_check, &os_release_path, &os_release_fd);
                if (r == -ENOENT) {
                        r = open_extension_release_at(rfd, IMAGE_CONFEXT, image_name, relax_extension_release_check, &os_release_path, &os_release_fd);
                        if (r >= 0)
                                class = IMAGE_CONFEXT;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to open extension release from '%s': %m", image_name);

                os_release_id = strjoina((class == IMAGE_SYSEXT) ? "/usr/lib" : "/etc", "/extension-release.d/extension-release.", image_name);
        } else {
                os_release_id = "/etc/os-release";
                r = open_os_release_at(rfd, &os_release_path, &os_release_fd);
        }
        if (r < 0)
                log_debug_errno(r,
                                "Couldn't acquire %s file, ignoring: %m",
                                path_is_extension ? "extension-release " : "os-release");
        else {
                if (socket_fd >= 0) {
                        struct iovec iov[] = {
                                IOVEC_MAKE_STRING(os_release_id),
                                IOVEC_MAKE((char *)"\0", sizeof(char)),
                        };

                        r = send_one_fd_iov_with_data_fd(socket_fd, iov, ELEMENTSOF(iov), os_release_fd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to send os-release file: %m");
                }

                if (ret_os_release) {
                        os_release = portable_metadata_new(os_release_id, NULL, NULL, os_release_fd);
                        if (!os_release)
                                return -ENOMEM;

                        os_release_fd = -EBADF;
                        os_release->source = TAKE_PTR(os_release_path);
                }
        }

        /* Then, send unit file data to the parent (or/and add it to the hashmap). For that we use our usual
         * unit discovery logic. If we're running in a user session, we look for units in
         * /usr/lib/systemd/user/ and corresponding directories. */
        r = lookup_paths_init(
                        &paths,
                        scope == RUNTIME_SCOPE_USER ? RUNTIME_SCOPE_GLOBAL : RUNTIME_SCOPE_SYSTEM,
                        LOOKUP_PATHS_SPLIT_USR,
                        /* root_dir= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire lookup paths: %m");

        unit_files = hashmap_new(&portable_metadata_hash_ops);
        if (!unit_files)
                return -ENOMEM;

        STRV_FOREACH(i, paths.search_path) {
                _cleanup_free_ char *relative = NULL, *resolved = NULL;
                _cleanup_closedir_ DIR *d = NULL;

                r = chase_and_opendirat(rfd, *i, CHASE_AT_RESOLVE_IN_ROOT, &relative, &d);
                if (r < 0) {
                        log_debug_errno(r, "Failed to open unit path '%s', ignoring: %m", *i);
                        continue;
                }

                r = chaseat_prefix_root(relative, image_path, &resolved);
                if (r < 0)
                        return r;

                FOREACH_DIRENT(de, d, return log_debug_errno(errno, "Failed to read directory: %m")) {
                        _cleanup_(portable_metadata_unrefp) PortableMetadata *m = NULL;
                        _cleanup_freecon_ char *con = NULL;
                        _cleanup_close_ int fd = -EBADF;
                        struct stat st;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        if (!unit_match(de->d_name, matches))
                                continue;

                        /* Filter out duplicates */
                        if (hashmap_get(unit_files, de->d_name))
                                continue;

                        if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                                continue;

                        fd = openat(dirfd(d), de->d_name, O_CLOEXEC|O_RDONLY);
                        if (fd < 0) {
                                log_debug_errno(errno, "Failed to open unit file '%s', ignoring: %m", de->d_name);
                                continue;
                        }

                        /* Reject empty files, just in case */
                        if (fstat(fd, &st) < 0) {
                                log_debug_errno(errno, "Failed to stat unit file '%s', ignoring: %m", de->d_name);
                                continue;
                        }

                        if (st.st_size <= 0) {
                                log_debug("Unit file '%s' is empty, ignoring.", de->d_name);
                                continue;
                        }

#if HAVE_SELINUX
                        /* The units will be copied on the host's filesystem, so if they had a SELinux label
                         * we have to preserve it. Copy it out so that it can be applied later. */
                        if (mac_selinux_use()) {
                                r = sym_fgetfilecon_raw(fd, &con);
                                if (r < 0 && !ERRNO_IS_XATTR_ABSENT(errno))
                                        log_debug_errno(errno, "Failed to get SELinux file context from '%s', ignoring: %m", de->d_name);
                        }
#endif

                        if (socket_fd >= 0) {
                                struct iovec iov[] = {
                                        IOVEC_MAKE_STRING(de->d_name),
                                        IOVEC_MAKE((char *)"\0", sizeof(char)),
                                        IOVEC_MAKE_STRING(strempty(con)),
                                };

                                r = send_one_fd_iov_with_data_fd(socket_fd, iov, ELEMENTSOF(iov), fd);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to send unit metadata to parent: %m");
                        }

                        m = portable_metadata_new(de->d_name, image_path, con, fd);
                        if (!m)
                                return -ENOMEM;
                        fd = -EBADF;

                        m->source = path_join(resolved, de->d_name);
                        if (!m->source)
                                return -ENOMEM;

                        r = hashmap_put(unit_files, m->name, m);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add unit to hashmap: %m");
                        m = NULL;
                }
        }

        if (ret_os_release)
                *ret_os_release = TAKE_PTR(os_release);
        if (ret_unit_files)
                *ret_unit_files = TAKE_PTR(unit_files);

        return 0;
}

static int portable_extract_by_path(
                RuntimeScope scope,
                const char *path,
                bool path_is_extension,
                bool relax_extension_release_check,
                char **matches,
                const ImagePolicy *image_policy,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files,
                ImagePolicy **ret_pinned_image_policy,
                sd_bus_error *error) {

        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata* os_release = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *pinned_image_policy = NULL;
        int r;

        assert(path);

        _cleanup_close_ int rfd = open(path, O_PATH|O_CLOEXEC);
        if (rfd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", path);

        struct stat st;
        if (fstat(rfd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat '%s': %m", path);

        if (S_ISDIR(st.st_mode)) {
                _cleanup_free_ char *image_name = NULL;
                r = path_extract_filename(path, &image_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract image name from path '%s': %m", path);

                if (scope == RUNTIME_SCOPE_USER && uid_is_foreign(st.st_uid)) {
                        _cleanup_close_ int userns_fd = nsresource_allocate_userns(
                                        /* vl= */ NULL,
                                        /* name= */ NULL,
                                        NSRESOURCE_UIDS_64K);
                        if (userns_fd < 0)
                                return log_debug_errno(userns_fd, "Failed to allocate user namespace: %m");

                        _cleanup_close_ int mfd = -EBADF;
                        r = mountfsd_mount_directory_fd(
                                        /* vl= */ NULL,
                                        rfd,
                                        userns_fd,
                                        DISSECT_IMAGE_FOREIGN_UID,
                                        &mfd);
                        if (r < 0)
                                return r;

                        _cleanup_close_pair_ int seq[2] = EBADF_PAIR;
                        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, seq) < 0)
                                return log_debug_errno(errno, "Failed to allocated SOCK_SEQPACKET socket: %m");

                        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
                        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                                return log_debug_errno(errno, "Failed to create pipe: %m");

                        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
                        r = pidref_safe_fork("(sd-extract)",
                                             FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_REOPEN_LOG,
                                             &child);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                seq[0] = safe_close(seq[0]);
                                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                                if (setns(CLONE_NEWUSER, userns_fd) < 0) {
                                        r = log_debug_errno(errno, "Failed to join userns: %m");
                                        report_errno_and_exit(errno_pipe_fd[1], r);
                                }

                                r = extract_now(scope,
                                                mfd,
                                                path,
                                                matches,
                                                image_name,
                                                path_is_extension,
                                                /* relax_extension_release_check= */ false,
                                                seq[1],
                                                /* ret_os_release= */ NULL,
                                                /* ret_unit_files= */ NULL);
                                report_errno_and_exit(errno_pipe_fd[1], r);
                        }

                        seq[1] = safe_close(seq[1]);
                        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                        r = receive_portable_metadata(seq[0], path, &os_release, &unit_files);
                        if (r < 0)
                                return r;

                        r = pidref_wait_for_terminate_and_check("(sd-extract)", &child, 0);
                        if (r < 0)
                                return r;
                        if (r != EXIT_SUCCESS) {
                                if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r))
                                        return log_debug_errno(r, "Failed to extract portable metadata from '%s': %m", path);

                                return log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Child failed.");
                        }
                } else {
                        r = extract_now(scope,
                                        rfd,
                                        path,
                                        matches,
                                        image_name,
                                        path_is_extension,
                                        /* relax_extension_release_check= */ false,
                                        /* socket_fd= */ -EBADF,
                                        &os_release,
                                        &unit_files);
                        if (r < 0)
                                return r;
                }
        } else {
                _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
                _cleanup_(rmdir_and_freep) char *tmpdir = NULL;
                _cleanup_close_pair_ int seq[2] = EBADF_PAIR, errno_pipe_fd[2] = EBADF_PAIR;
                _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
                _cleanup_close_ int userns_fd = -EBADF;
                DissectImageFlags flags =
                        DISSECT_IMAGE_READ_ONLY |
                        DISSECT_IMAGE_GENERIC_ROOT |
                        DISSECT_IMAGE_REQUIRE_ROOT |
                        DISSECT_IMAGE_DISCARD_ON_LOOP |
                        DISSECT_IMAGE_RELAX_VAR_CHECK |
                        DISSECT_IMAGE_USR_NO_ROOT |
                        DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                        DISSECT_IMAGE_PIN_PARTITION_DEVICES |
                        DISSECT_IMAGE_ALLOW_USERSPACE_VERITY;

                if (path_is_extension)
                        flags |= DISSECT_IMAGE_VALIDATE_OS_EXT | (relax_extension_release_check ? DISSECT_IMAGE_RELAX_EXTENSION_CHECK : 0);
                else
                        flags |= DISSECT_IMAGE_VALIDATE_OS;

                _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
                r = verity_settings_load(
                                &verity,
                                path,
                                /* root_hash_path= */ NULL,
                                /* root_hash_sig_path= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to read verity artifacts for %s: %m", path);

                if (verity.data_path)
                        flags |= DISSECT_IMAGE_NO_PARTITION_TABLE;

                /* We now have a loopback block device, let's fork off a child in its own mount namespace, mount it
                 * there, and extract the metadata we need. The metadata is sent from the child back to us. */

                /* Load some libraries before we fork workers off that want to use them */
                (void) dlopen_cryptsetup();
                (void) dlopen_libmount();

                r = mkdtemp_malloc("/tmp/inspect-XXXXXX", &tmpdir);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create temporary directory: %m");

                if (scope == RUNTIME_SCOPE_USER) {
                        userns_fd = nsresource_allocate_userns(
                                        /* vl= */ NULL,
                                        /* name= */ NULL,
                                        NSRESOURCE_UIDS_64K);
                        if (userns_fd < 0)
                                return log_debug_errno(userns_fd, "Failed to allocate user namespace: %m");

                        r = mountfsd_mount_image_fd(
                                        /* vl= */ NULL,
                                        rfd,
                                        userns_fd,
                                        /* options= */ NULL,
                                        image_policy,
                                        &verity,
                                        flags,
                                        &m);
                        if (r < 0)
                                return r;
                } else {
                        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;

                        r = loop_device_make_by_path_at(
                                        rfd,
                                        /* path= */ NULL,
                                        O_RDONLY,
                                        /* sector_size= */ UINT32_MAX,
                                        LO_FLAGS_PARTSCAN,
                                        LOCK_SH,
                                        &d);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to set up loopback device for %s: %m", path);

                        r = dissect_loop_device(
                                        d,
                                        &verity,
                                        /* mount_options= */ NULL,
                                        image_policy,
                                        /* image_filter= */ NULL,
                                        flags,
                                        &m);
                        if (r == -ENOPKG)
                                sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Couldn't identify a suitable partition table or file system in '%s'.", path);
                        else if (r == -EADDRNOTAVAIL)
                                sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "No root partition for specified root hash found in '%s'.", path);
                        else if (r == -ENOTUNIQ)
                                sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Multiple suitable root partitions found in image '%s'.", path);
                        else if (r == -ENXIO)
                                sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "No suitable root partition found in image '%s'.", path);
                        else if (r == -EPROTONOSUPPORT)
                                sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Device '%s' is loopback block device with partition scanning turned off, please turn it on.", path);
                        if (r < 0)
                                return r;

                        r = dissected_image_load_verity_sig_partition(m, d->fd, &verity);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to load verity sig partition for '%s': %m", path);

                        r = dissected_image_guess_verity_roothash(m, &verity);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to guess verity roothash for '%s': %m", path);
                }

                if (!m->image_name) {
                        r = dissected_image_name_from_path(path, &m->image_name);
                        if (r < 0)
                                return r;
                }

                if (ret_pinned_image_policy) {
                        pinned_image_policy = image_policy_new_from_dissected(m, &verity);
                        if (!pinned_image_policy)
                                return -ENOMEM;
                }

                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, seq) < 0)
                        return log_debug_errno(errno, "Failed to allocated SOCK_SEQPACKET socket: %m");

                if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                        return log_debug_errno(errno, "Failed to create pipe: %m");

                r = pidref_safe_fork(
                                "(sd-dissect)",
                                FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|(scope == RUNTIME_SCOPE_SYSTEM ? FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE : 0),
                                &child);
                if (r < 0)
                        return r;
                if (r == 0) {
                        seq[0] = safe_close(seq[0]);
                        errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                        if (scope == RUNTIME_SCOPE_USER) {
                                r = detach_mount_namespace_userns(userns_fd);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to detach mount namespace: %m");
                                        report_errno_and_exit(errno_pipe_fd[1], r);
                                }
                        }

                        r = dissected_image_mount(
                                        m,
                                        tmpdir,
                                        /* uid_shift= */ UID_INVALID,
                                        /* uid_range= */ UID_INVALID,
                                        userns_fd,
                                        flags);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to mount dissected image '%s': %m", path);
                                report_errno_and_exit(errno_pipe_fd[1], r);
                        }

                        _cleanup_close_ int mfd = open(tmpdir, O_DIRECTORY|O_CLOEXEC);
                        if (mfd < 0) {
                                r = log_debug_errno(errno, "Failed to open '%s': %m", tmpdir);
                                report_errno_and_exit(errno_pipe_fd[1], r);
                        }

                        r = extract_now(scope,
                                        mfd,
                                        path,
                                        matches,
                                        m->image_name,
                                        path_is_extension,
                                        relax_extension_release_check,
                                        seq[1],
                                        /* ret_os_release= */ NULL,
                                        /* ret_unit_files= */ NULL);
                        report_errno_and_exit(errno_pipe_fd[1], r);
                }

                seq[1] = safe_close(seq[1]);
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                r = receive_portable_metadata(seq[0], path, &os_release, &unit_files);
                if (r < 0)
                        return r;

                r = pidref_wait_for_terminate_and_check("(sd-dissect)", &child, 0);
                if (r < 0)
                        return r;

                pidref_done(&child);

                if (r != EXIT_SUCCESS) {
                        if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r))
                                return log_debug_errno(r, "Failed to extract portable metadata from '%s': %m", path);

                        return log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Child failed.");
                }
        }

        if (!os_release)
                return sd_bus_error_setf(error,
                                         SD_BUS_ERROR_INVALID_ARGS,
                                         "Image '%s' lacks %s data, refusing.",
                                         path,
                                         path_is_extension ? "extension-release" : "os-release");

        if (ret_unit_files)
                *ret_unit_files = TAKE_PTR(unit_files);

        if (ret_os_release)
                *ret_os_release = TAKE_PTR(os_release);

        if (ret_pinned_image_policy)
                *ret_pinned_image_policy = TAKE_PTR(pinned_image_policy);

        return 0;
}

static int extract_image_and_extensions(
                RuntimeScope scope,
                const char *name_or_path,
                char **matches,
                char **extension_image_paths,
                bool validate_extension,
                bool relax_extension_release_check,
                const ImagePolicy *image_policy,
                Image **ret_image,
                OrderedHashmap **ret_extension_images,
                OrderedHashmap **ret_extension_releases,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files,
                char ***ret_valid_prefixes,
                ImagePolicy **ret_pinned_root_image_policy,
                ImagePolicy **ret_pinned_ext_image_policy,
                sd_bus_error *error) {

        _cleanup_free_ char *id = NULL, *id_like = NULL, *version_id = NULL, *sysext_level = NULL, *confext_level = NULL;
        _cleanup_(image_policy_freep) ImagePolicy *pinned_root_image_policy = NULL, *pinned_ext_image_policy = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *extension_images = NULL, *extension_releases = NULL;
        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_strv_free_ char **valid_prefixes = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        Image *ext;
        int r;

        assert(name_or_path);

        /* If we get a path, then check if it can be resolved with vpick. We need this as we might just
         * get a simple image name, which would make vpick error out. */
        if (path_is_absolute(name_or_path)) {
                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              name_or_path,
                              pick_filter_image_any,
                              ELEMENTSOF(pick_filter_image_any),
                              PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                              &result);
                if (r < 0)
                        return r;
                if (!result.path)
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(ENOENT),
                                        "No matching entry in .v/ directory %s found.",
                                        name_or_path);

                name_or_path = result.path;
        }

        r = image_find_harder(scope, IMAGE_PORTABLE, name_or_path, /* root= */ NULL, &image);
        if (r < 0)
                return r;

        if (!strv_isempty(extension_image_paths)) {
                extension_images = ordered_hashmap_new(&image_hash_ops);
                if (!extension_images)
                        return -ENOMEM;

                if (ret_extension_releases) {
                        extension_releases = ordered_hashmap_new(&portable_metadata_hash_ops);
                        if (!extension_releases)
                                return -ENOMEM;
                }

                STRV_FOREACH(p, extension_image_paths) {
                        _cleanup_(pick_result_done) PickResult ext_result = PICK_RESULT_NULL;
                        _cleanup_(image_unrefp) Image *new = NULL;
                        const char *path = *p;

                        if (path_is_absolute(*p)) {
                                r = path_pick(/* toplevel_path= */ NULL,
                                              /* toplevel_fd= */ AT_FDCWD,
                                              *p,
                                              pick_filter_image_any,
                                              ELEMENTSOF(pick_filter_image_any),
                                              PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                                              &ext_result);
                                if (r < 0)
                                        return r;
                                if (!ext_result.path)
                                        return log_debug_errno(
                                                        SYNTHETIC_ERRNO(ENOENT),
                                                        "No matching entry in .v/ directory %s found.",
                                                        *p);

                                path = ext_result.path;
                        }

                        r = image_find_harder(scope, IMAGE_PORTABLE, path, NULL, &new);
                        if (r < 0)
                                return r;

                        r = ordered_hashmap_put(extension_images, new->name, new);
                        if (r < 0)
                                return r;
                        TAKE_PTR(new);
                }
        }

        r = portable_extract_by_path(
                        scope,
                        image->path,
                        /* path_is_extension= */ false,
                        /* relax_extension_release_check= */ false,
                        matches,
                        image_policy,
                        &os_release,
                        &unit_files,
                        &pinned_root_image_policy,
                        error);
        if (r < 0)
                return r;

        /* If we are layering extension images on top of a runtime image, check that the os-release and
         * extension-release metadata match, otherwise reject it immediately as invalid, or it will fail when
         * the units are started. Also, collect valid portable prefixes if caller requested that. */
        if (validate_extension || ret_valid_prefixes) {
                _cleanup_free_ char *prefixes = NULL, *portable_scope_str = NULL;

                r = parse_env_file_fd(
                                os_release->fd, os_release->name,
                                "ID", &id,
                                "ID_LIKE", &id_like,
                                "VERSION_ID", &version_id,
                                "SYSEXT_LEVEL", &sysext_level,
                                "CONFEXT_LEVEL", &confext_level,
                                "PORTABLE_PREFIXES", &prefixes,
                                "PORTABLE_SCOPE", &portable_scope_str);
                if (r < 0)
                        return r;
                if (isempty(id))
                        return sd_bus_error_set_errnof(error, ESTALE, "Image %s os-release metadata lacks the ID field", name_or_path);

                if (prefixes) {
                        valid_prefixes = strv_split(prefixes, WHITESPACE);
                        if (!valid_prefixes)
                                return -ENOMEM;
                }

                RuntimeScope portable_scope = RUNTIME_SCOPE_SYSTEM;
                if (portable_scope_str) {
                        if (streq(portable_scope_str, "any"))
                                portable_scope = _RUNTIME_SCOPE_INVALID;
                        else {
                                portable_scope = runtime_scope_from_string(portable_scope_str);
                                if (portable_scope < 0)
                                        return sd_bus_error_setf(
                                                        error,
                                                        SD_BUS_ERROR_INVALID_ARGS,
                                                        "Invalid PORTABLE_SCOPE value '%s' in image %s.",
                                                        portable_scope_str,
                                                        name_or_path);
                        }
                }

                if (portable_scope != _RUNTIME_SCOPE_INVALID && portable_scope != scope)
                        return sd_bus_error_setf(
                                        error,
                                        SD_BUS_ERROR_INVALID_ARGS,
                                        "Image %s portable scope '%s' incompatible with portabled runtime scope '%s'.",
                                        name_or_path,
                                        runtime_scope_to_string(portable_scope),
                                        runtime_scope_to_string(scope));
        }

        ORDERED_HASHMAP_FOREACH(ext, extension_images) {
                _cleanup_(portable_metadata_unrefp) PortableMetadata *extension_release_meta = NULL;
                _cleanup_(image_policy_freep) ImagePolicy *policy = NULL;
                _cleanup_hashmap_free_ Hashmap *extra_unit_files = NULL;
                _cleanup_strv_free_ char **extension_release = NULL;
                const char *e;

                r = portable_extract_by_path(
                                scope,
                                ext->path,
                                /* path_is_extension= */ true,
                                relax_extension_release_check,
                                matches,
                                image_policy,
                                &extension_release_meta,
                                &extra_unit_files,
                                &policy,
                                error);
                if (r < 0)
                        return r;

                r = hashmap_move(unit_files, extra_unit_files);
                if (r < 0)
                        return r;

                if (!pinned_ext_image_policy && policy)
                        pinned_ext_image_policy = TAKE_PTR(policy);
                else if (policy) {
                        _cleanup_(image_policy_freep) ImagePolicy *intersected_policy = NULL;

                        /* There is a single policy for all extension images, so we need a union */
                        r = image_policy_union(pinned_ext_image_policy, policy, &intersected_policy);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to merge extension image policies: %m");

                        free_and_replace(pinned_ext_image_policy, intersected_policy);
                }

                if (!validate_extension && !ret_valid_prefixes && !ret_extension_releases)
                        continue;

                r = load_env_file_pairs_fd(extension_release_meta->fd, extension_release_meta->name, &extension_release);
                if (r < 0)
                        return r;

                if (validate_extension) {
                        r = extension_release_validate(ext->path, id, id_like, version_id, sysext_level, "portable", extension_release, IMAGE_SYSEXT);
                        if (r < 0)
                                r = extension_release_validate(ext->path, id, id_like, version_id, confext_level, "portable", extension_release, IMAGE_CONFEXT);

                        if (r == 0)
                                return sd_bus_error_set_errnof(error, ESTALE, "Image %s extension-release metadata does not match the root's", ext->path);
                        if (r < 0)
                                return sd_bus_error_set_errnof(error, r, "Failed to compare image %s extension-release metadata with the root's os-release: %m", ext->path);
                }

                e = strv_env_pairs_get(extension_release, "PORTABLE_PREFIXES");
                if (e) {
                        r = strv_split_and_extend(&valid_prefixes, e, WHITESPACE, /* filter_duplicates= */ true);
                        if (r < 0)
                                return r;
                }

                if (ret_extension_releases) {
                        r = ordered_hashmap_put(extension_releases, ext->name, extension_release_meta);
                        if (r < 0)
                                return r;
                        TAKE_PTR(extension_release_meta);
                }
        }

        strv_sort(valid_prefixes);

        if (ret_image)
                *ret_image = TAKE_PTR(image);
        if (ret_extension_images)
                *ret_extension_images = TAKE_PTR(extension_images);
        if (ret_extension_releases)
                *ret_extension_releases = TAKE_PTR(extension_releases);
        if (ret_os_release)
                *ret_os_release = TAKE_PTR(os_release);
        if (ret_unit_files)
                *ret_unit_files = TAKE_PTR(unit_files);
        if (ret_valid_prefixes)
                *ret_valid_prefixes = TAKE_PTR(valid_prefixes);
        if (ret_pinned_root_image_policy)
                *ret_pinned_root_image_policy = TAKE_PTR(pinned_root_image_policy);
        if (ret_pinned_ext_image_policy)
                *ret_pinned_ext_image_policy = TAKE_PTR(pinned_ext_image_policy);

        return 0;
}

int portable_extract(
                RuntimeScope scope,
                const char *name_or_path,
                char **matches,
                char **extension_image_paths,
                const ImagePolicy *image_policy,
                PortableFlags flags,
                PortableMetadata **ret_os_release,
                OrderedHashmap **ret_extension_releases,
                Hashmap **ret_unit_files,
                char ***ret_valid_prefixes,
                sd_bus_error *error) {

        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *extension_images = NULL, *extension_releases = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_strv_free_ char **valid_prefixes = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(name_or_path);

        r = extract_image_and_extensions(
                        scope,
                        name_or_path,
                        matches,
                        extension_image_paths,
                        /* validate_extension= */ false,
                        /* relax_extension_release_check= */ FLAGS_SET(flags, PORTABLE_FORCE_EXTENSION),
                        image_policy,
                        &image,
                        &extension_images,
                        &extension_releases,
                        &os_release,
                        &unit_files,
                        ret_valid_prefixes ? &valid_prefixes : NULL,
                        /* pinned_root_image_policy= */ NULL,
                        /* pinned_ext_image_policy= */ NULL,
                        error);
        if (r < 0)
                return r;

        if (hashmap_isempty(unit_files)) {
                _cleanup_free_ char *extensions = strv_join(extension_image_paths, ", ");
                if (!extensions)
                        return -ENOMEM;

                return sd_bus_error_setf(error,
                                         SD_BUS_ERROR_INVALID_ARGS,
                                         "Couldn't find any matching unit files in image '%s%s%s', refusing.",
                                         image->path,
                                         isempty(extensions) ? "" : "' or any of its extensions '",
                                         isempty(extensions) ? "" : extensions);
        }

        if (ret_os_release)
                *ret_os_release = TAKE_PTR(os_release);
        if (ret_extension_releases)
                *ret_extension_releases = TAKE_PTR(extension_releases);
        if (ret_unit_files)
                *ret_unit_files = TAKE_PTR(unit_files);
        if (ret_valid_prefixes)
                *ret_valid_prefixes = TAKE_PTR(valid_prefixes);

        return 0;
}

static int unit_file_is_active(
                sd_bus *bus,
                const char *name,
                sd_bus_error *error) {

        static const char *const active_states[] = {
                "activating",
                "active",
                "reloading",
                "deactivating",
                NULL,
        };
        int r;

        if (!bus)
                return false;

        /* If we are looking at a plain or instance things are easy, we can just query the state */
        if (unit_name_is_valid(name, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                _cleanup_free_ char *path = NULL, *buf = NULL;

                path = unit_dbus_path_from_name(name);
                if (!path)
                        return -ENOMEM;

                r = sd_bus_get_property_string(
                                bus,
                                "org.freedesktop.systemd1",
                                path,
                                "org.freedesktop.systemd1.Unit",
                                "ActiveState",
                                error,
                                &buf);
                if (r < 0)
                        return log_debug_errno(r, "Failed to retrieve unit state: %s", bus_error_message(error, r));

                return strv_contains((char**) active_states, buf);
        }

        /* Otherwise we need to enumerate. But let's build the most restricted query we can */
        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
                const char *at, *prefix, *joined;

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitsByPatterns");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_strv(m, (char**) active_states);
                if (r < 0)
                        return r;

                at = strchr(name, '@');
                assert(at);

                prefix = strndupa_safe(name, at + 1 - name);
                joined = strjoina(prefix, "*", at + 1);

                r = sd_bus_message_append_strv(m, STRV_MAKE(joined));
                if (r < 0)
                        return r;

                r = sd_bus_call(bus, m, 0, error, &reply);
                if (r < 0)
                        return log_debug_errno(r, "Failed to list units: %s", bus_error_message(error, r));

                r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
                if (r < 0)
                        return r;

                r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_STRUCT, "ssssssouso");
                if (r < 0)
                        return r;

                return r > 0;
        }

        return -EINVAL;
}

static int portable_changes_add(
                PortableChange **changes,
                size_t *n_changes,
                int type_or_errno, /* PORTABLE_COPY, PORTABLE_SYMLINK, … if positive, or errno if negative */
                const char *path,
                const char *source) {

        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert(path);
        assert(!changes == !n_changes);

        if (type_or_errno >= 0)
                assert(type_or_errno < _PORTABLE_CHANGE_TYPE_MAX);
        else
                assert(type_or_errno >= -ERRNO_MAX);

        if (!changes)
                return 0;

        if (!GREEDY_REALLOC(*changes, *n_changes + 1))
                return -ENOMEM;

        r = path_simplify_alloc(path, &p);
        if (r < 0)
                return r;

        r = path_simplify_alloc(source, &s);
        if (r < 0)
                return r;

        (*changes)[(*n_changes)++] = (PortableChange) {
                .type_or_errno = type_or_errno,
                .path = TAKE_PTR(p),
                .source = TAKE_PTR(s),
        };

        return 0;
}

static int portable_changes_add_with_prefix(
                PortableChange **changes,
                size_t *n_changes,
                int type_or_errno,
                const char *prefix,
                const char *path,
                const char *source) {

        _cleanup_free_ char *path_buf = NULL, *source_buf = NULL;

        assert(path);
        assert(!changes == !n_changes);

        if (!changes)
                return 0;

        if (prefix) {
                path_buf = path_join(prefix, path);
                if (!path_buf)
                        return -ENOMEM;

                path = path_buf;

                if (source) {
                        source_buf = path_join(prefix, source);
                        if (!source_buf)
                                return -ENOMEM;

                        source = source_buf;
                }
        }

        return portable_changes_add(changes, n_changes, type_or_errno, path, source);
}

void portable_changes_free(PortableChange *changes, size_t n_changes) {
        size_t i;

        assert(changes || n_changes == 0);

        for (i = 0; i < n_changes; i++) {
                free(changes[i].path);
                free(changes[i].source);
        }

        free(changes);
}

static const char *root_setting_from_image(ImageType type) {
        switch (type) {
        case IMAGE_DIRECTORY:
        case IMAGE_SUBVOLUME:
                return "RootDirectory=";

        case IMAGE_RAW:
        case IMAGE_BLOCK:
                return "RootImage=";

        case IMAGE_MSTACK:
                return "RootMStack=";

        default:
                return NULL;
        }
}

static const char *extension_setting_from_image(ImageType type) {
        switch (type) {
        case IMAGE_DIRECTORY:
        case IMAGE_SUBVOLUME:
                return "ExtensionDirectories=";

        case IMAGE_RAW:
        case IMAGE_BLOCK:
                return "ExtensionImages=";

        default:
                return NULL;
        }
}

static int make_marker_text(const char *image_path, OrderedHashmap *extension_images, char **ret_text) {
        _cleanup_free_ char *text = NULL, *escaped_image_path = NULL;
        Image *ext;

        assert(image_path);
        assert(ret_text);

        escaped_image_path = xescape(image_path, ":");
        if (!escaped_image_path)
                return -ENOMEM;

        /* If the image is layered, include all layers in the marker as a colon-separated
         * list of paths, so that we can do exact matches on removal. */
        text = strjoin(PORTABLE_DROPIN_MARKER_BEGIN, escaped_image_path);
        if (!text)
                return -ENOMEM;

        ORDERED_HASHMAP_FOREACH(ext, extension_images) {
                _cleanup_free_ char *escaped = NULL;

                escaped = xescape(ext->path, ":");
                if (!escaped)
                        return -ENOMEM;

                if (!strextend(&text, ":", escaped))
                        return -ENOMEM;
        }

        if (!strextend(&text, PORTABLE_DROPIN_MARKER_END "\n"))
                return -ENOMEM;

        *ret_text = TAKE_PTR(text);
        return 0;
}

static int append_release_log_fields(
                char **text,
                const PortableMetadata *release,
                ImageClass type,
                const char *field_name) {

        static const char *const field_versions[_IMAGE_CLASS_MAX][4]= {
                 [IMAGE_PORTABLE] = { "IMAGE_VERSION", "VERSION_ID", "BUILD_ID", NULL },
                 [IMAGE_SYSEXT] = { "SYSEXT_IMAGE_VERSION", "SYSEXT_VERSION_ID", "SYSEXT_BUILD_ID", NULL },
                 [IMAGE_CONFEXT] = { "CONFEXT_IMAGE_VERSION", "CONFEXT_VERSION_ID", "CONFEXT_BUILD_ID", NULL },
        };
        static const char *const field_ids[_IMAGE_CLASS_MAX][3]= {
                 [IMAGE_PORTABLE] = { "IMAGE_ID", "ID", NULL },
                 [IMAGE_SYSEXT] = { "SYSEXT_IMAGE_ID", "SYSEXT_ID", NULL },
                 [IMAGE_CONFEXT] = { "CONFEXT_IMAGE_ID", "CONFEXT_ID", NULL },
        };
        _cleanup_strv_free_ char **fields = NULL;
        const char *id = NULL, *version = NULL;
        int r;

        assert(IN_SET(type, IMAGE_PORTABLE, IMAGE_SYSEXT, IMAGE_CONFEXT));
        assert(!strv_isempty((char *const *)field_ids[type]));
        assert(!strv_isempty((char *const *)field_versions[type]));
        assert(field_name);
        assert(text);

        if (!release)
                return 0; /* Nothing to do. */

        r = load_env_file_pairs_fd(release->fd, release->name, &fields);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse '%s': %m", release->name);

        /* Find an ID first, in order of preference from more specific to less specific: IMAGE_ID -> ID */
        id = strv_find_first_field((char *const *)field_ids[type], fields);

        /* Then the version, same logic, prefer the more specific one */
        version = strv_find_first_field((char *const *)field_versions[type], fields);

        /* If there's no valid version to be found, simply omit it. */
        if (!id && !version)
                return 0;

        if (!strextend(text,
                       "LogExtraFields=",
                       field_name,
                       "=",
                       strempty(id),
                       id && version ? "_" : "",
                       strempty(version),
                       "\n"))
                return -ENOMEM;

        return 0;
}

static int install_chroot_dropin(
                const char *image_path,
                ImageType type,
                OrderedHashmap *extension_images,
                OrderedHashmap *extension_releases,
                const ImagePolicy *pinned_root_image_policy,
                const ImagePolicy *pinned_ext_image_policy,
                const PortableMetadata *m,
                const PortableMetadata *os_release,
                const char *dropin_dir,
                PortableFlags flags,
                char **ret_dropin,
                PortableChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *text = NULL, *dropin = NULL;
        int r;

        assert(image_path);
        assert(m);
        assert(dropin_dir);

        dropin = path_join(dropin_dir, "20-portable.conf");
        if (!dropin)
                return -ENOMEM;

        r = make_marker_text(image_path, extension_images, &text);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate marker string for portable drop-in: %m");

        if (endswith(m->name, ".service")) {
                const char *root_type;
                _cleanup_free_ char *base_name = NULL;
                Image *ext;

                root_type = root_setting_from_image(type);
                if (!root_type)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Image type '%s' not supported as portable service.", image_type_to_string(type));

                r = path_extract_filename(m->image_path ?: image_path, &base_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to extract basename from '%s': %m", m->image_path ?: image_path);

                if (!strextend(&text,
                               "\n"
                               "[Service]\n",
                               root_type, image_path, "\n"
                               "Environment=PORTABLE=", base_name, "\n"
                               "LogExtraFields=PORTABLE=", base_name, "\n"))
                        return -ENOMEM;

                if (pinned_root_image_policy) {
                        _cleanup_free_ char *policy_str = NULL;

                        r = image_policy_to_string(pinned_root_image_policy, /* simplify= */ true, &policy_str);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to serialize pinned image policy: %m");

                        if (!strextend(&text,
                                       "RootImagePolicy=", policy_str, "\n"))
                                return -ENOMEM;
                }

                /* If we have a single image then PORTABLE= will point to it, so we add
                 * PORTABLE_NAME_AND_VERSION= with the os-release fields and we are done. But if we have
                 * extensions, PORTABLE= will point to the image where the current unit was found in. So we
                 * also list PORTABLE_ROOT= and PORTABLE_ROOT_NAME_AND_VERSION= for the base image, and
                 * PORTABLE_EXTENSION= and PORTABLE_EXTENSION_NAME_AND_VERSION= for each extension, so that
                 * all needed metadata is available. */
                if (ordered_hashmap_isempty(extension_images))
                        r = append_release_log_fields(&text, os_release, IMAGE_PORTABLE, "PORTABLE_NAME_AND_VERSION");
                else {
                        _cleanup_free_ char *root_base_name = NULL;

                        r = path_extract_filename(image_path, &root_base_name);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract basename from '%s': %m", image_path);

                        if (!strextend(&text,
                                       "Environment=PORTABLE_ROOT=", root_base_name, "\n",
                                       "LogExtraFields=PORTABLE_ROOT=", root_base_name, "\n"))
                                return -ENOMEM;

                        r = append_release_log_fields(&text, os_release, IMAGE_PORTABLE, "PORTABLE_ROOT_NAME_AND_VERSION");
                }
                if (r < 0)
                        return r;

                if (m->image_path && !path_equal(m->image_path, image_path))
                        ORDERED_HASHMAP_FOREACH(ext, extension_images) {

                                const char *extension_setting = extension_setting_from_image(ext->type);
                                if (!extension_setting)
                                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Image type '%s' not supported for extensions: %m", image_type_to_string(ext->type));

                                _cleanup_free_ char *extension_base_name = NULL;
                                r = path_extract_filename(ext->path, &extension_base_name);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to extract basename from '%s': %m", ext->path);

                                if (!strextend(&text,
                                               "\n",
                                               extension_setting,
                                               ext->path,
                                               /* With --force tell PID1 to avoid enforcing that the image <name> and
                                                * extension-release.<name> have to match. */
                                               !IN_SET(ext->type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME) &&
                                                   FLAGS_SET(flags, PORTABLE_FORCE_EXTENSION) ?
                                                       ":x-systemd.relax-extension-release-check\n" :
                                                       "\n",
                                               /* In PORTABLE= we list the 'main' image name for this unit
                                                * (the image where the unit was extracted from), but we are
                                                * stacking multiple images, so list those too. */
                                               "LogExtraFields=PORTABLE_EXTENSION=", extension_base_name, "\n"))
                                        return -ENOMEM;

                                if (pinned_ext_image_policy && !IN_SET(ext->type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME)) {
                                        _cleanup_free_ char *policy_str = NULL;

                                        r = image_policy_to_string(pinned_ext_image_policy, /* simplify= */ true, &policy_str);
                                        if (r < 0)
                                                return log_debug_errno(r, "Failed to serialize pinned image policy: %m");

                                        if (!strextend(&text,
                                                       "ExtensionImagePolicy=", policy_str, "\n"))
                                                return -ENOMEM;
                                }

                                /* Look for image/version identifiers in the extension release files. We
                                 * look for all possible IDs, but typically only 1 or 2 will be set, so
                                 * the number of fields added shouldn't be too large. We prefix the DDI
                                 * name to the value, so that we can add the same field multiple times and
                                 * still be able to identify what applies to what. */
                                r = append_release_log_fields(&text,
                                                              ordered_hashmap_get(extension_releases, ext->name),
                                                              IMAGE_SYSEXT,
                                                              "PORTABLE_EXTENSION_NAME_AND_VERSION");
                                if (r < 0)
                                        return r;

                                r = append_release_log_fields(&text,
                                                              ordered_hashmap_get(extension_releases, ext->name),
                                                              IMAGE_CONFEXT,
                                                              "PORTABLE_EXTENSION_NAME_AND_VERSION");
                                if (r < 0)
                                        return r;
                        }
        }

        r = write_string_file(dropin, text, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_SYNC);
        if (r < 0)
                return log_debug_errno(r, "Failed to write '%s': %m", dropin);

        (void) portable_changes_add(changes, n_changes, PORTABLE_WRITE, dropin, NULL);

        if (ret_dropin)
                *ret_dropin = TAKE_PTR(dropin);

        return 0;
}

static int install_profile_dropin(
                RuntimeScope scope,
                const char *image_path,
                const PortableMetadata *m,
                const char *dropin_dir,
                const char *profile,
                PortableFlags flags,
                char **ret_dropin,
                PortableChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *dropin = NULL, *from = NULL;
        int r;

        assert(image_path);
        assert(m);
        assert(dropin_dir);

        if (!profile)
                return 0;

        r = find_portable_profile(scope, profile, m->name, &from);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_debug_errno(errno, "Profile '%s' is not accessible: %m", profile);

                log_debug_errno(errno, "Skipping link to profile '%s', as it does not exist: %m", profile);
                return 0;
        }

        dropin = path_join(dropin_dir, "10-profile.conf");
        if (!dropin)
                return -ENOMEM;

        if (flags & PORTABLE_PREFER_COPY) {
                CopyFlags copy_flags = COPY_REFLINK|COPY_FSYNC;

                if (flags & PORTABLE_FORCE_ATTACH)
                        copy_flags |= COPY_REPLACE;

                r = copy_file_atomic(from, dropin, 0644, copy_flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy %s %s %s: %m", from, glyph(GLYPH_ARROW_RIGHT), dropin);

                (void) portable_changes_add(changes, n_changes, PORTABLE_COPY, dropin, from);

        } else {

                if (flags & PORTABLE_FORCE_ATTACH)
                        r = symlink_atomic(from, dropin);
                else
                        r = RET_NERRNO(symlink(from, dropin));
                if (r < 0)
                        return log_debug_errno(r, "Failed to link %s %s %s: %m", from, glyph(GLYPH_ARROW_RIGHT), dropin);

                (void) portable_changes_add(changes, n_changes, PORTABLE_SYMLINK, dropin, from);
        }

        if (ret_dropin)
                *ret_dropin = TAKE_PTR(dropin);

        return 0;
}

static const char *attached_path(const LookupPaths *paths, PortableFlags flags) {
        const char *where;

        assert(paths);

        if (flags & PORTABLE_RUNTIME)
                where = paths->runtime_attached;
        else
                where = paths->persistent_attached;

        assert(where);
        return where;
}

static int attach_unit_file(
                RuntimeScope scope,
                const LookupPaths *paths,
                const char *image_path,
                ImageType type,
                OrderedHashmap *extension_images,
                OrderedHashmap *extension_releases,
                const ImagePolicy *pinned_root_image_policy,
                const ImagePolicy *pinned_ext_image_policy,
                const PortableMetadata *m,
                const PortableMetadata *os_release,
                const char *profile,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes) {

        _cleanup_(unlink_and_freep) char *chroot_dropin = NULL, *profile_dropin = NULL;
        _cleanup_(rmdir_and_freep) char *dropin_dir = NULL;
        _cleanup_free_ char *path = NULL;
        const char *where;
        int r;

        assert(paths);
        assert(image_path);
        assert(m);
        assert(PORTABLE_METADATA_IS_UNIT(m));

        where = attached_path(paths, flags);

        (void) mkdir_parents(where, 0755);
        if (mkdir(where, 0755) < 0) {
                if (errno != EEXIST)
                        return log_debug_errno(errno, "Failed to create attach directory %s: %m", where);
        } else
                (void) portable_changes_add(changes, n_changes, PORTABLE_MKDIR, where, NULL);

        path = path_join(where, m->name);
        if (!path)
                return -ENOMEM;

        dropin_dir = strjoin(path, ".d");
        if (!dropin_dir)
                return -ENOMEM;

        if (mkdir(dropin_dir, 0755) < 0) {
                if (errno != EEXIST)
                        return log_debug_errno(errno, "Failed to create drop-in directory %s: %m", dropin_dir);
        } else
                (void) portable_changes_add(changes, n_changes, PORTABLE_MKDIR, dropin_dir, NULL);

        /* We install the drop-ins first, and the actual unit file last to achieve somewhat atomic behaviour if PID 1
         * is reloaded while we are creating things here: as long as only the drop-ins exist the unit doesn't exist at
         * all for PID 1. */

        r = install_chroot_dropin(
                        image_path,
                        type,
                        extension_images,
                        extension_releases,
                        pinned_root_image_policy,
                        pinned_ext_image_policy,
                        m,
                        os_release,
                        dropin_dir,
                        flags,
                        &chroot_dropin,
                        changes,
                        n_changes);
        if (r < 0)
                return r;

        r = install_profile_dropin(scope, image_path, m, dropin_dir, profile, flags, &profile_dropin, changes, n_changes);
        if (r < 0)
                return r;

        if ((flags & PORTABLE_PREFER_SYMLINK) && m->source) {

                if (flags & PORTABLE_FORCE_ATTACH)
                        r = symlink_atomic(m->source, path);
                else
                        r = RET_NERRNO(symlink(m->source, path));
                if (r < 0)
                        return log_debug_errno(r, "Failed to symlink unit file '%s': %m", path);

                (void) portable_changes_add(changes, n_changes, PORTABLE_SYMLINK, path, m->source);

        } else {
                LinkTmpfileFlags link_flags = LINK_TMPFILE_SYNC;
                _cleanup_(unlink_and_freep) char *tmp = NULL;
                _cleanup_close_ int fd = -EBADF;

                if (flags & PORTABLE_FORCE_ATTACH)
                        link_flags |= LINK_TMPFILE_REPLACE;

                (void) mac_selinux_create_file_prepare_label(path, m->selinux_label);

                fd = open_tmpfile_linkable(path, O_WRONLY|O_CLOEXEC, &tmp);
                mac_selinux_create_file_clear(); /* Clear immediately in case of errors */
                if (fd < 0)
                        return log_debug_errno(fd, "Failed to create unit file '%s': %m", path);

                r = copy_bytes(m->fd, fd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy unit file '%s': %m", path);

                if (fchmod(fd, 0644) < 0)
                        return log_debug_errno(errno, "Failed to change unit file access mode for '%s': %m", path);

                r = link_tmpfile(fd, tmp, path, link_flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to install unit file '%s': %m", path);

                tmp = mfree(tmp);

                (void) portable_changes_add(changes, n_changes, PORTABLE_COPY, path, m->source);
        }

        /* All is established now, now let's disable any rollbacks */
        chroot_dropin = mfree(chroot_dropin);
        profile_dropin = mfree(profile_dropin);
        dropin_dir = mfree(dropin_dir);

        return 0;
}

static int image_target_path(RuntimeScope scope, const char *image_path, PortableFlags flags, char **ret) {
        _cleanup_free_ char *where = NULL;
        const char *fn;
        char *joined = NULL;
        int r;

        assert(image_path);
        assert(ret);

        fn = last_path_component(image_path);

        if (flags & PORTABLE_RUNTIME)
                r = runtime_directory_generic(scope, "portables", &where);
        else
                r = config_directory_generic(scope, "portables", &where);
        if (r < 0)
                return r;

        joined = path_join(where, fn);
        if (!joined)
                return -ENOMEM;

        *ret = joined;
        return 0;
}

static int install_image(
                RuntimeScope scope,
                const char *image_path,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *target = NULL;
        int r;

        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(image_path);

        /* If the image is outside of the image search also link it into it, so that it can be found with
         * short image names and is listed among the images. If we are operating in mixed mode, the image is
         * copied instead. */

        if (image_in_search_path(scope, IMAGE_PORTABLE, NULL, image_path))
                return 0;

        r = image_target_path(scope, image_path, flags, &target);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate image symlink path: %m");

        (void) mkdir_parents(target, 0755);

        if (flags & PORTABLE_MIXED_COPY_LINK) {
                if (scope == RUNTIME_SCOPE_USER) {
                        _cleanup_close_ int userns_fd = nsresource_allocate_userns(
                                        /* vl= */ NULL,
                                        /* name= */ NULL,
                                        NSRESOURCE_UIDS_64K);
                        if (userns_fd < 0)
                                return log_debug_errno(userns_fd, "Failed to allocate user namespace: %m");

                        _cleanup_close_ int fd = open(image_path, O_DIRECTORY|O_CLOEXEC);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to open '%s': %m", image_path);

                        struct stat st;
                        if (fstat(fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat '%s': %m", image_path);

                        _cleanup_(sd_varlink_unrefp) sd_varlink *mountfsd_link = NULL;
                        r = mountfsd_connect(&mountfsd_link);
                        if (r < 0)
                                return r;

                        _cleanup_close_ int tree_fd = -EBADF;
                        if (uid_is_foreign(st.st_uid)) {
                                r = mountfsd_mount_directory_fd(
                                                mountfsd_link,
                                                fd,
                                                userns_fd,
                                                DISSECT_IMAGE_FOREIGN_UID,
                                                &tree_fd);
                                if (r < 0)
                                        return r;
                        } else
                                tree_fd = TAKE_FD(fd);

                        _cleanup_close_ int directory_fd = -EBADF;
                        r = mountfsd_make_directory(mountfsd_link, target, MODE_INVALID, /* flags= */ 0, &directory_fd);
                        if (r < 0)
                                return r;

                        _cleanup_close_ int copy_fd = -EBADF;
                        r = mountfsd_mount_directory_fd(mountfsd_link, directory_fd, userns_fd, DISSECT_IMAGE_FOREIGN_UID, &copy_fd);
                        if (r < 0)
                                return r;

                        r = copy_tree_at_foreign(tree_fd, copy_fd, userns_fd);
                        if (r < 0)
                                return r;
                } else {
                        r = copy_tree(image_path,
                                      target,
                                      UID_INVALID,
                                      GID_INVALID,
                                      COPY_REFLINK | COPY_FSYNC | COPY_FSYNC_FULL | COPY_SYNCFS,
                                      /* denylist= */ NULL,
                                      /* subvolumes= */ NULL);
                        if (r < 0)
                                return log_debug_errno(
                                                r,
                                                "Failed to copy %s %s %s: %m",
                                                image_path,
                                                glyph(GLYPH_ARROW_RIGHT),
                                                target);
                }
        } else {
                if (symlink(image_path, target) < 0)
                        return log_debug_errno(
                                        errno,
                                        "Failed to link %s %s %s: %m",
                                        image_path,
                                        glyph(GLYPH_ARROW_RIGHT),
                                        target);
        }

        (void) portable_changes_add(
                        changes,
                        n_changes,
                        (flags & PORTABLE_MIXED_COPY_LINK) ? PORTABLE_COPY : PORTABLE_SYMLINK,
                        target,
                        image_path);
        return 0;
}

static int install_image_and_extensions(
                RuntimeScope scope,
                const Image *image,
                OrderedHashmap *extension_images,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes) {

        Image *ext;
        int r;

        assert(image);

        ORDERED_HASHMAP_FOREACH(ext, extension_images) {
                r = install_image(scope, ext->path, flags, changes, n_changes);
                if (r < 0)
                        return r;
        }

        r = install_image(scope, image->path, flags, changes, n_changes);
        if (r < 0)
                return r;

        return 0;
}

static bool prefix_matches_compatible(char **matches, char **valid_prefixes) {
        /* Checks if all 'matches' are included in the list of 'valid_prefixes' */

        STRV_FOREACH(m, matches)
                if (!strv_contains(valid_prefixes, *m))
                        return false;

        return true;
}

static void log_portable_verb(
                const char *verb,
                const char *message_id,
                const char *image_path,
                const char *profile,
                OrderedHashmap *extension_images,
                char **extension_image_paths,
                PortableFlags flags) {

        _cleanup_free_ char *root_base_name = NULL, *extensions_joined = NULL;
        _cleanup_strv_free_ char **extension_base_names = NULL;
        Image *ext;
        int r;

        assert(verb);
        assert(message_id);
        assert(image_path);
        assert(!extension_images || !extension_image_paths);

        /* Use the same structured metadata as it is attached to units via LogExtraFields=. The main image
         * is logged as PORTABLE_ROOT= and extensions, if any, as individual PORTABLE_EXTENSION= fields. */

        r = path_extract_filename(image_path, &root_base_name);
        if (r < 0)
                log_debug_errno(r, "Failed to extract basename from '%s', ignoring: %m", image_path);

        ORDERED_HASHMAP_FOREACH(ext, extension_images) {
                _cleanup_free_ char *extension_base_name = NULL;

                r = path_extract_filename(ext->path, &extension_base_name);
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract basename from '%s', ignoring: %m", ext->path);
                        continue;
                }

                r = strv_extendf(&extension_base_names, "PORTABLE_EXTENSION=%s", extension_base_name);
                if (r < 0)
                        log_oom_debug();

                if (!strextend_with_separator(&extensions_joined, ", ", ext->path))
                        log_oom_debug();
        }

        STRV_FOREACH(e, extension_image_paths) {
                _cleanup_free_ char *extension_base_name = NULL;

                r = path_extract_filename(*e, &extension_base_name);
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract basename from '%s', ignoring: %m", *e);
                        continue;
                }

                r = strv_extendf(&extension_base_names, "PORTABLE_EXTENSION=%s", extension_base_name);
                if (r < 0)
                        log_oom_debug();

                if (!strextend_with_separator(&extensions_joined, ", ", *e))
                        log_oom_debug();
        }

        LOG_CONTEXT_PUSH_STRV(extension_base_names);

        log_struct(LOG_INFO,
                   LOG_MESSAGE("Successfully %s%s '%s%s%s%s%s'",
                               verb,
                               FLAGS_SET(flags, PORTABLE_RUNTIME) ? " ephemeral" : "",
                               image_path,
                               isempty(extensions_joined) ? "" : "' and its extension(s) '",
                               strempty(extensions_joined),
                               isempty(profile) ? "" : "' using profile '",
                               strempty(profile)),
                   message_id,
                   LOG_ITEM("PORTABLE_ROOT=%s", strna(root_base_name)));
}

int portable_attach(
                RuntimeScope scope,
                sd_bus *bus,
                const char *name_or_path,
                char **matches,
                const char *profile,
                char **extension_image_paths,
                const ImagePolicy *image_policy,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes,
                sd_bus_error *error) {

        _cleanup_(image_policy_freep) ImagePolicy *pinned_root_image_policy = NULL, *pinned_ext_image_policy = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *extension_images = NULL, *extension_releases = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(lookup_paths_done) LookupPaths paths = {};
        _cleanup_strv_free_ char **valid_prefixes = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        PortableMetadata *item;
        int r;

        assert(scope < _RUNTIME_SCOPE_MAX);

        r = extract_image_and_extensions(
                        scope,
                        name_or_path,
                        matches,
                        extension_image_paths,
                        /* validate_extension= */ true,
                        /* relax_extension_release_check= */ FLAGS_SET(flags, PORTABLE_FORCE_EXTENSION),
                        image_policy,
                        &image,
                        &extension_images,
                        &extension_releases,
                        &os_release,
                        &unit_files,
                        &valid_prefixes,
                        &pinned_root_image_policy,
                        &pinned_ext_image_policy,
                        error);
        if (r < 0)
                return r;

        if (valid_prefixes && !prefix_matches_compatible(matches, valid_prefixes)) {
                _cleanup_free_ char *matches_joined = NULL, *extensions_joined = NULL, *valid_prefixes_joined = NULL;

                matches_joined = strv_join(matches, "', '");
                if (!matches_joined)
                        return -ENOMEM;

                extensions_joined = strv_join(extension_image_paths, ", ");
                if (!extensions_joined)
                        return -ENOMEM;

                valid_prefixes_joined = strv_join(valid_prefixes, ", ");
                if (!valid_prefixes_joined)
                        return -ENOMEM;

                return sd_bus_error_setf(
                                error,
                                SD_BUS_ERROR_INVALID_ARGS,
                                "Selected matches '%s' are not compatible with portable service image '%s%s%s', refusing. (Acceptable prefix matches are: %s)",
                                matches_joined,
                                image->path,
                                isempty(extensions_joined) ? "" : "' or any of its extensions '",
                                strempty(extensions_joined),
                                valid_prefixes_joined);
        }

        if (hashmap_isempty(unit_files)) {
                _cleanup_free_ char *extensions_joined = strv_join(extension_image_paths, ", ");
                if (!extensions_joined)
                        return -ENOMEM;

                return sd_bus_error_setf(
                                error,
                                SD_BUS_ERROR_INVALID_ARGS,
                                "Couldn't find any matching unit files in image '%s%s%s', refusing.",
                                image->path,
                                isempty(extensions_joined) ? "" : "' or any of its extensions '",
                                strempty(extensions_joined));
        }

        r = lookup_paths_init(&paths, scope, /* flags= */ 0, NULL);
        if (r < 0)
                return r;

        if (!FLAGS_SET(flags, PORTABLE_REATTACH) && !FLAGS_SET(flags, PORTABLE_FORCE_ATTACH))
                HASHMAP_FOREACH(item, unit_files) {
                        r = unit_file_exists_full(scope, &paths, SEARCH_IGNORE_TEMPLATE, item->name, /* ret_path= */ NULL);
                        if (r < 0)
                                return sd_bus_error_set_errnof(error, r, "Failed to determine whether unit '%s' exists on the host: %m", item->name);
                        if (r > 0)
                                return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' exists on the host already, refusing.", item->name);

                        r = unit_file_is_active(bus, item->name, error);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' is active already, refusing.", item->name);
                }

        HASHMAP_FOREACH(item, unit_files) {
                r = attach_unit_file(
                                scope,
                                &paths,
                                image->path,
                                image->type,
                                extension_images,
                                extension_releases,
                                pinned_root_image_policy,
                                pinned_ext_image_policy,
                                item,
                                os_release,
                                profile,
                                flags,
                                changes,
                                n_changes);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to attach unit '%s': %m", item->name);
        }

        /* We don't care too much for the image symlink/copy, it's just a convenience thing, it's not necessary for
         * proper operation otherwise. */
        (void) install_image_and_extensions(scope, image, extension_images, flags, changes, n_changes);

        log_portable_verb(
                        "attached",
                        "MESSAGE_ID=" SD_MESSAGE_PORTABLE_ATTACHED_STR,
                        image->path,
                        profile,
                        extension_images,
                        /* extension_image_paths= */ NULL,
                        flags);

        return 0;
}

static bool marker_matches_images(const char *marker, const char *name_or_path, char **extension_image_paths, bool match_all) {
        _cleanup_strv_free_ char **root_and_extensions = NULL;
        int r;

        assert(marker);
        assert(name_or_path);

        /* If extensions were used when attaching, the marker will be a colon-separated
         * list of images/paths. We enforce strict 1:1 matching, so that we are sure
         * we are detaching exactly what was attached.
         * For each image, starting with the root, we look for a token in the marker,
         * and return a negative answer on any non-matching combination.
         * If a partial match is allowed, then return immediately once it is found, otherwise
         * ensure that everything matches. */

        root_and_extensions = strv_new(name_or_path);
        if (!root_and_extensions)
                return -ENOMEM;

        r = strv_extend_strv(&root_and_extensions, extension_image_paths, false);
        if (r < 0)
                return r;

        /* Ensure the number of images passed matches the number of images listed in the marker */
        while (!isempty(marker))
                STRV_FOREACH(image_name_or_path, root_and_extensions) {
                        _cleanup_free_ char *image = NULL, *base_image = NULL, *base_image_name_or_path = NULL;
                        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;

                        r = extract_first_word(&marker, &image, ":", EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse marker: %s", marker);
                        if (r == 0)
                                return false;

                        r = path_extract_image_name(image, &base_image);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract image name from %s, ignoring: %m", image);

                        r = path_pick(/* toplevel_path= */ NULL,
                                      /* toplevel_fd= */ AT_FDCWD,
                                      *image_name_or_path,
                                      pick_filter_image_any,
                                      ELEMENTSOF(pick_filter_image_any),
                                      PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                                      &result);
                        if (r < 0)
                                return r;
                        if (!result.path)
                                return log_debug_errno(
                                                SYNTHETIC_ERRNO(ENOENT),
                                                "No matching entry in .v/ directory %s found.",
                                                *image_name_or_path);

                        r = path_extract_image_name(result.path, &base_image_name_or_path);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract image name from %s, ignoring: %m", result.path);

                        if (!streq(base_image, base_image_name_or_path)) {
                                if (match_all)
                                        return false;
                        } else if (!match_all)
                                return true;
                }

        return match_all;
}

static int test_chroot_dropin(
                DIR *d,
                const char *where,
                const char *fname,
                const char *name_or_path,
                char **extension_image_paths,
                char **ret_marker) {

        _cleanup_free_ char *line = NULL, *marker = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *p, *e, *k;
        int r;

        assert(d);
        assert(where);
        assert(fname);

        /* We recognize unis created from portable images via the drop-in we created for them */

        p = strjoina(fname, ".d/20-portable.conf");
        fd = openat(dirfd(d), p, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_debug_errno(errno, "Failed to open %s/%s: %m", where, p);
        }

        r = take_fdopen_unlocked(&fd, "r", &f);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert file handle: %m");

        r = read_line(f, LONG_LINE_MAX, &line);
        if (r < 0)
                return log_debug_errno(r, "Failed to read from %s/%s: %m", where, p);

        e = startswith(line, PORTABLE_DROPIN_MARKER_BEGIN);
        if (!e)
                return 0;

        k = endswith(e, PORTABLE_DROPIN_MARKER_END);
        if (!k)
                return 0;

        marker = strndup(e, k - e);
        if (!marker)
                return -ENOMEM;

        if (!name_or_path)
                r = true;
        else
                /* When detaching we want to match exactly on all images, but when inspecting we only need
                 * to get the state of one component */
                r = marker_matches_images(marker, name_or_path, extension_image_paths, ret_marker != NULL);

        if (ret_marker)
                *ret_marker = TAKE_PTR(marker);

        return r;
}

int portable_detach(
                RuntimeScope scope,
                sd_bus *bus,
                const char *name_or_path,
                char **extension_image_paths,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes,
                sd_bus_error *error) {

        _cleanup_(lookup_paths_done) LookupPaths paths = {};
        _cleanup_set_free_ Set *unit_files = NULL, *markers = NULL;
        _cleanup_free_ char *extensions = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *where, *item;
        int r, ret = 0;

        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(name_or_path);

        r = lookup_paths_init(&paths, scope, /* flags= */ 0, NULL);
        if (r < 0)
                return r;

        where = attached_path(&paths, flags);

        d = opendir(where);
        if (!d) {
                if (errno == ENOENT)
                        goto not_found;

                return log_debug_errno(errno, "Failed to open '%s' directory: %m", where);
        }

        FOREACH_DIRENT(de, d, return log_debug_errno(errno, "Failed to enumerate '%s' directory: %m", where)) {
                _cleanup_free_ char *marker = NULL, *unit_name = NULL;
                const char *dot;

                /* When a portable service is enabled with "portablectl --copy=symlink --enable --now attach",
                 * and is disabled with "portablectl --enable --now detach", which calls DisableUnitFilesWithFlags
                 * DBus method, the main unit file is removed, but its drop-ins are not. Hence, here we need
                 * to list both main unit files and drop-in directories (without the main unit files). */

                dot = endswith(de->d_name, ".d");
                if (dot)
                        unit_name = strndup(de->d_name, dot - de->d_name);
                else
                        unit_name = strdup(de->d_name);
                if (!unit_name)
                        return -ENOMEM;

                if (!unit_name_is_valid(unit_name, UNIT_NAME_ANY))
                        continue;

                /* Filter out duplicates */
                if (set_contains(unit_files, unit_name))
                        continue;

                if (dot ? !IN_SET(de->d_type, DT_LNK, DT_DIR) : !IN_SET(de->d_type, DT_LNK, DT_REG))
                        continue;

                r = test_chroot_dropin(d, where, unit_name, name_or_path, extension_image_paths, &marker);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (!FLAGS_SET(flags, PORTABLE_REATTACH) && !FLAGS_SET(flags, PORTABLE_FORCE_ATTACH)) {
                        r = unit_file_is_active(bus, unit_name, error);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' is active, can't detach.", unit_name);
                }

                r = set_ensure_consume(&unit_files, &string_hash_ops_free, TAKE_PTR(unit_name));
                if (r < 0)
                        return log_oom_debug();

                for (const char *p = marker;;) {
                        _cleanup_free_ char *image = NULL;

                        r = extract_first_word(&p, &image, ":", EXTRACT_UNESCAPE_SEPARATORS|EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse marker: %s", p);
                        if (r == 0)
                                break;

                        if (path_is_absolute(image) && !image_in_search_path(scope, IMAGE_PORTABLE, NULL, image)) {
                                r = set_ensure_consume(&markers, &path_hash_ops_free, TAKE_PTR(image));
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (set_isempty(unit_files))
                goto not_found;

        SET_FOREACH(item, unit_files) {
                _cleanup_free_ char *md = NULL;

                if (unlinkat(dirfd(d), item, 0) < 0) {
                        log_debug_errno(errno, "Can't remove unit file %s/%s: %m", where, item);

                        if (errno != ENOENT && ret >= 0)
                                ret = -errno;
                } else
                        portable_changes_add_with_prefix(changes, n_changes, PORTABLE_UNLINK, where, item, NULL);

                FOREACH_STRING(suffix, ".d/10-profile.conf", ".d/20-portable.conf") {
                        _cleanup_free_ char *dropin = NULL;

                        dropin = strjoin(item, suffix);
                        if (!dropin)
                                return -ENOMEM;

                        if (unlinkat(dirfd(d), dropin, 0) < 0) {
                                log_debug_errno(errno, "Can't remove drop-in %s/%s: %m", where, dropin);

                                if (errno != ENOENT && ret >= 0)
                                        ret = -errno;
                        } else
                                portable_changes_add_with_prefix(changes, n_changes, PORTABLE_UNLINK, where, dropin, NULL);
                }

                md = strjoin(item, ".d");
                if (!md)
                        return -ENOMEM;

                if (unlinkat(dirfd(d), md, AT_REMOVEDIR) < 0) {
                        log_debug_errno(errno, "Can't remove drop-in directory %s/%s: %m", where, md);

                        if (errno != ENOENT && ret >= 0)
                                ret = -errno;
                } else
                        portable_changes_add_with_prefix(changes, n_changes, PORTABLE_UNLINK, where, md, NULL);
        }

        /* Now, also drop any image symlink or copy, for images outside of the sarch path */
        SET_FOREACH(item, markers) {
                _cleanup_free_ char *target = NULL;

                r = image_target_path(scope, item, flags, &target);
                if (r < 0) {
                        log_debug_errno(r, "Failed to determine image path for '%s', ignoring: %m", item);
                        continue;
                }

                r = rm_rf(target, REMOVE_ROOT | REMOVE_PHYSICAL | REMOVE_MISSING_OK | REMOVE_SYNCFS);
                if (r < 0) {
                        log_debug_errno(r, "Can't remove image '%s': %m", target);

                        if (r != -ENOENT)
                                RET_GATHER(ret, r);
                } else
                        portable_changes_add(changes, n_changes, PORTABLE_UNLINK, target, NULL);
        }

        /* Try to remove the unit file directory, if we can */
        if (rmdir(where) >= 0)
                portable_changes_add(changes, n_changes, PORTABLE_UNLINK, where, NULL);

        log_portable_verb(
                        "detached",
                        "MESSAGE_ID=" SD_MESSAGE_PORTABLE_DETACHED_STR,
                        name_or_path,
                        /* profile= */ NULL,
                        /* extension_images= */ NULL,
                        extension_image_paths,
                        flags);

        return ret;

not_found:
        extensions = strv_join(extension_image_paths, ", ");
        if (!extensions)
                return -ENOMEM;

        r = sd_bus_error_setf(error,
                              BUS_ERROR_NO_SUCH_UNIT,
                              "No unit files associated with '%s%s%s' found attached to the system. Image not attached?",
                              name_or_path,
                              isempty(extensions) ? "" : "' or any of its extensions '",
                              isempty(extensions) ? "" : extensions);
        return log_debug_errno(r, "%s", error->message);
}

static int portable_get_state_internal(
                RuntimeScope scope,
                sd_bus *bus,
                const char *name_or_path,
                char **extension_image_paths,
                PortableFlags flags,
                PortableState *ret,
                sd_bus_error *error) {

        _cleanup_(lookup_paths_done) LookupPaths paths = {};
        bool found_enabled = false, found_running = false;
        _cleanup_set_free_ Set *unit_files = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *where;
        int r;

        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(name_or_path);
        assert(ret);

        r = lookup_paths_init(&paths, scope, /* flags= */ 0, NULL);
        if (r < 0)
                return r;

        where = attached_path(&paths, flags);

        d = opendir(where);
        if (!d) {
                if (errno == ENOENT) {
                        /* If the 'attached' directory doesn't exist at all, then we know for sure this image isn't attached. */
                        *ret = PORTABLE_DETACHED;
                        return 0;
                }

                return log_debug_errno(errno, "Failed to open '%s' directory: %m", where);
        }

        FOREACH_DIRENT(de, d, return log_debug_errno(errno, "Failed to enumerate '%s' directory: %m", where)) {
                UnitFileState state;

                if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                        continue;

                /* Filter out duplicates */
                if (set_contains(unit_files, de->d_name))
                        continue;

                if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                        continue;

                r = test_chroot_dropin(d, where, de->d_name, name_or_path, extension_image_paths, NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = unit_file_lookup_state(scope, &paths, de->d_name, &state);
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine unit file state of '%s': %m", de->d_name);
                if (!IN_SET(state, UNIT_FILE_STATIC, UNIT_FILE_DISABLED, UNIT_FILE_LINKED, UNIT_FILE_LINKED_RUNTIME))
                        found_enabled = true;

                r = unit_file_is_active(bus, de->d_name, error);
                if (r < 0)
                        return r;
                if (r > 0)
                        found_running = true;

                r = set_put_strdup(&unit_files, de->d_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add unit name '%s' to set: %m", de->d_name);
        }

        *ret = found_running ? (!set_isempty(unit_files) && (flags & PORTABLE_RUNTIME) ? PORTABLE_RUNNING_RUNTIME : PORTABLE_RUNNING) :
                found_enabled ?            (flags & PORTABLE_RUNTIME ? PORTABLE_ENABLED_RUNTIME : PORTABLE_ENABLED) :
                !set_isempty(unit_files) ? (flags & PORTABLE_RUNTIME ? PORTABLE_ATTACHED_RUNTIME : PORTABLE_ATTACHED) : PORTABLE_DETACHED;

        return 0;
}

int portable_get_state(
                RuntimeScope scope,
                sd_bus *bus,
                const char *name_or_path,
                char **extension_image_paths,
                PortableFlags flags,
                PortableState *ret,
                sd_bus_error *error) {

        PortableState state;
        int r;

        assert(name_or_path);
        assert(ret);

        /* We look for matching units twice: once in the regular directories, and once in the runtime directories — but
         * the latter only if we didn't find anything in the former. */

        r = portable_get_state_internal(
                        scope,
                        bus,
                        name_or_path,
                        extension_image_paths,
                        flags & ~PORTABLE_RUNTIME,
                        &state,
                        error);
        if (r < 0)
                return r;

        if (state == PORTABLE_DETACHED) {
                r = portable_get_state_internal(scope, bus, name_or_path, extension_image_paths, flags | PORTABLE_RUNTIME, &state, error);
                if (r < 0)
                        return r;
        }

        *ret = state;
        return 0;
}

int portable_get_profiles(RuntimeScope scope, char ***ret) {
        _cleanup_strv_free_ char **dirs = NULL;
        int r;

        assert(ret);

        r = portable_profile_dirs(scope, &dirs);
        if (r < 0)
                return r;

        return conf_files_list_strv(ret, NULL, NULL, CONF_FILES_DIRECTORY|CONF_FILES_BASENAME|CONF_FILES_FILTER_MASKED, (const char* const*) dirs);
}

static const char* const portable_change_type_table[_PORTABLE_CHANGE_TYPE_MAX] = {
        [PORTABLE_COPY] = "copy",
        [PORTABLE_MKDIR] = "mkdir",
        [PORTABLE_SYMLINK] = "symlink",
        [PORTABLE_UNLINK] = "unlink",
        [PORTABLE_WRITE] = "write",
};

DEFINE_STRING_TABLE_LOOKUP(portable_change_type, int);

static const char* const portable_state_table[_PORTABLE_STATE_MAX] = {
        [PORTABLE_DETACHED] = "detached",
        [PORTABLE_ATTACHED] = "attached",
        [PORTABLE_ATTACHED_RUNTIME] = "attached-runtime",
        [PORTABLE_ENABLED] = "enabled",
        [PORTABLE_ENABLED_RUNTIME] = "enabled-runtime",
        [PORTABLE_RUNNING] = "running",
        [PORTABLE_RUNNING_RUNTIME] = "running-runtime",
};

DEFINE_STRING_TABLE_LOOKUP(portable_state, PortableState);
