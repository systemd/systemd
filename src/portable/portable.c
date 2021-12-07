/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>

#include "bus-common-errors.h"
#include "bus-error.h"
#include "chase-symlinks.h"
#include "conf-files.h"
#include "copy.h"
#include "data-fd-util.h"
#include "def.h"
#include "dirent-util.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "env-file.h"
#include "env-util.h"
#include "errno-list.h"
#include "escape.h"
#include "extension-release.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "install.h"
#include "io-util.h"
#include "locale-util.h"
#include "loop-util.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-lookup.h"
#include "portable.h"
#include "process-util.h"
#include "selinux-util.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "string-table.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

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
        char **i;

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

        _cleanup_close_ int data_fd = -1;

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

static int extract_now(
                const char *where,
                char **matches,
                const char *image_name,
                bool path_is_extension,
                int socket_fd,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files) {

        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_close_ int os_release_fd = -1;
        _cleanup_free_ char *os_release_path = NULL;
        const char *os_release_id;
        char **i;
        int r;

        /* Extracts the metadata from a directory tree 'where'. Extracts two kinds of information: the /etc/os-release
         * data, and all unit files matching the specified expression. Note that this function is called in two very
         * different but also similar contexts. When the tool gets invoked on a directory tree, we'll process it
         * directly, and in-process, and thus can return the requested data directly, via 'ret_os_release' and
         * 'ret_unit_files'. However, if the tool is invoked on a raw disk image — which needs to be mounted first — we
         * are invoked in a child process with private mounts and then need to send the collected data to our
         * parent. To handle both cases in one call this function also gets a 'socket_fd' parameter, which when >= 0 is
         * used to send the data to the parent. */

        assert(where);

        /* First, find os-release/extension-release and send it upstream (or just save it). */
        if (path_is_extension) {
                os_release_id = strjoina("/usr/lib/extension-release.d/extension-release.", image_name);
                r = open_extension_release(where, image_name, &os_release_path, &os_release_fd);
        } else {
                os_release_id = "/etc/os-release";
                r = open_os_release(where, &os_release_path, &os_release_fd);
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

                        os_release_fd = -1;
                        os_release->source = TAKE_PTR(os_release_path);
                }
        }

        /* Then, send unit file data to the parent (or/and add it to the hashmap). For that we use our usual unit
         * discovery logic. Note that we force looking inside of /lib/systemd/system/ for units too, as we mightbe
         * compiled for a split-usr system but the image might be a legacy-usr one. */
        r = lookup_paths_init(&paths, UNIT_FILE_SYSTEM, LOOKUP_PATHS_SPLIT_USR, where);
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire lookup paths: %m");

        unit_files = hashmap_new(&portable_metadata_hash_ops);
        if (!unit_files)
                return -ENOMEM;

        STRV_FOREACH(i, paths.search_path) {
                _cleanup_free_ char *resolved = NULL;
                _cleanup_closedir_ DIR *d = NULL;

                r = chase_symlinks_and_opendir(*i, where, 0, &resolved, &d);
                if (r < 0) {
                        log_debug_errno(r, "Failed to open unit path '%s', ignoring: %m", *i);
                        continue;
                }

                FOREACH_DIRENT(de, d, return log_debug_errno(errno, "Failed to read directory: %m")) {
                        _cleanup_(portable_metadata_unrefp) PortableMetadata *m = NULL;
                        _cleanup_close_ int fd = -1;

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

                        if (socket_fd >= 0) {
                                _cleanup_(mac_selinux_freep) char *con = NULL;
#if HAVE_SELINUX
                                /* The units will be copied on the host's filesystem, so if they had a SELinux label
                                 * we have to preserve it. Copy it out so that it can be applied later. */

                                r = fgetfilecon_raw(fd, &con);
                                if (r < 0 && errno != ENODATA)
                                        log_debug_errno(errno, "Failed to get SELinux file context from '%s', ignoring: %m", de->d_name);
#endif
                                struct iovec iov[] = {
                                        IOVEC_MAKE_STRING(de->d_name),
                                        IOVEC_MAKE((char *)"\0", sizeof(char)),
                                        IOVEC_MAKE_STRING(strempty(con)),
                                };

                                r = send_one_fd_iov_with_data_fd(socket_fd, iov, ELEMENTSOF(iov), fd);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to send unit metadata to parent: %m");
                        }

                        m = portable_metadata_new(de->d_name, NULL, NULL, fd);
                        if (!m)
                                return -ENOMEM;
                        fd = -1;

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
                const char *path,
                bool path_is_extension,
                char **matches,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files,
                sd_bus_error *error) {

        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata* os_release = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        int r;

        assert(path);

        r = loop_device_make_by_path(path, O_RDONLY, LO_FLAGS_PARTSCAN, &d);
        if (r == -EISDIR) {
                /* We can't turn this into a loop-back block device, and this returns EISDIR? Then this is a directory
                 * tree and not a raw device. It's easy then. */

                r = extract_now(path, matches, NULL, path_is_extension, -1, &os_release, &unit_files);
                if (r < 0)
                        return r;

        } else if (r < 0)
                return log_debug_errno(r, "Failed to set up loopback device for %s: %m", path);
        else {
                _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
                _cleanup_(rmdir_and_freep) char *tmpdir = NULL;
                _cleanup_(close_pairp) int seq[2] = { -1, -1 };
                _cleanup_(sigkill_waitp) pid_t child = 0;

                /* We now have a loopback block device, let's fork off a child in its own mount namespace, mount it
                 * there, and extract the metadata we need. The metadata is sent from the child back to us. */

                BLOCK_SIGNALS(SIGCHLD);

                r = mkdtemp_malloc("/tmp/inspect-XXXXXX", &tmpdir);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create temporary directory: %m");

                r = dissect_image(
                                d->fd,
                                NULL, NULL,
                                d->diskseq,
                                d->uevent_seqnum_not_before,
                                d->timestamp_not_before,
                                DISSECT_IMAGE_READ_ONLY |
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_DISCARD_ON_LOOP |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_USR_NO_ROOT,
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

                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, seq) < 0)
                        return log_debug_errno(errno, "Failed to allocated SOCK_SEQPACKET socket: %m");

                r = safe_fork("(sd-dissect)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE|FORK_LOG, &child);
                if (r < 0)
                        return r;
                if (r == 0) {
                        DissectImageFlags flags = DISSECT_IMAGE_READ_ONLY;

                        seq[0] = safe_close(seq[0]);

                        if (path_is_extension)
                                flags |= DISSECT_IMAGE_VALIDATE_OS_EXT;
                        else
                                flags |= DISSECT_IMAGE_VALIDATE_OS;

                        r = dissected_image_mount(m, tmpdir, UID_INVALID, UID_INVALID, flags);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to mount dissected image: %m");
                                goto child_finish;
                        }

                        r = extract_now(tmpdir, matches, m->image_name, path_is_extension, seq[1], NULL, NULL);

                child_finish:
                        _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
                }

                seq[1] = safe_close(seq[1]);

                unit_files = hashmap_new(&portable_metadata_hash_ops);
                if (!unit_files)
                        return -ENOMEM;

                for (;;) {
                        _cleanup_(portable_metadata_unrefp) PortableMetadata *add = NULL;
                        _cleanup_close_ int fd = -1;
                        /* We use NAME_MAX space for the SELinux label here. The kernel currently enforces no limit, but
                         * according to suggestions from the SELinux people this will change and it will probably be
                         * identical to NAME_MAX. For now we use that, but this should be updated one day when the final
                         * limit is known. */
                        char iov_buffer[PATH_MAX + NAME_MAX + 2];
                        struct iovec iov = IOVEC_INIT(iov_buffer, sizeof(iov_buffer));

                        ssize_t n = receive_one_fd_iov(seq[0], &iov, 1, 0, &fd);
                        if (n == -EIO)
                                break;
                        if (n < 0)
                                return log_debug_errno(n, "Failed to receive item: %m");
                        iov_buffer[n] = 0;

                        /* We can't really distinguish a zero-length datagram without any fds from EOF (both are signalled the
                         * same way by recvmsg()). Hence, accept either as end notification. */
                        if (isempty(iov_buffer) && fd < 0)
                                break;

                        if (isempty(iov_buffer) || fd < 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid item sent from child.");

                        /* Given recvmsg cannot be used with multiple io vectors if you don't know the size in advance,
                         * use a marker to separate the name and the optional SELinux context. */
                        char *selinux_label = memchr(iov_buffer, 0, n);
                        assert(selinux_label);
                        selinux_label++;

                        add = portable_metadata_new(iov_buffer, path, selinux_label, fd);
                        if (!add)
                                return -ENOMEM;
                        fd = -1;

                        /* Note that we do not initialize 'add->source' here, as the source path is not usable here as
                         * it refers to a path only valid in the short-living namespaced child process we forked
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

                r = wait_for_terminate_and_check("(sd-dissect)", child, 0);
                if (r < 0)
                        return r;
                child = 0;
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

        return 0;
}

static int extract_image_and_extensions(
                const char *name_or_path,
                char **matches,
                char **extension_image_paths,
                bool validate_sysext,
                Image **ret_image,
                OrderedHashmap **ret_extension_images,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files,
                char ***ret_valid_prefixes,
                sd_bus_error *error) {

        _cleanup_free_ char *id = NULL, *version_id = NULL, *sysext_level = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *extension_images = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_strv_free_ char **valid_prefixes = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        Image *ext;
        int r;

        assert(name_or_path);
        assert(matches);

        r = image_find_harder(IMAGE_PORTABLE, name_or_path, NULL, &image);
        if (r < 0)
                return r;

        if (!strv_isempty(extension_image_paths)) {
                char **p;

                extension_images = ordered_hashmap_new(&image_hash_ops);
                if (!extension_images)
                        return -ENOMEM;

                STRV_FOREACH(p, extension_image_paths) {
                        _cleanup_(image_unrefp) Image *new = NULL;

                        r = image_find_harder(IMAGE_PORTABLE, *p, NULL, &new);
                        if (r < 0)
                                return r;

                        r = ordered_hashmap_put(extension_images, new->name, new);
                        if (r < 0)
                                return r;
                        TAKE_PTR(new);
                }
        }

        r = portable_extract_by_path(image->path, /* path_is_extension= */ false, matches, &os_release, &unit_files, error);
        if (r < 0)
                return r;

        /* If we are layering extension images on top of a runtime image, check that the os-release and
         * extension-release metadata match, otherwise reject it immediately as invalid, or it will fail when
         * the units are started. Also, collect valid portable prefixes if caller requested that. */
        if (validate_sysext || ret_valid_prefixes) {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *prefixes = NULL;

                r = take_fdopen_unlocked(&os_release->fd, "r", &f);
                if (r < 0)
                        return r;

                r = parse_env_file(f, os_release->name,
                                   "ID", &id,
                                   "VERSION_ID", &version_id,
                                   "SYSEXT_LEVEL", &sysext_level,
                                   "PORTABLE_PREFIXES", &prefixes);
                if (r < 0)
                        return r;

                if (prefixes) {
                        valid_prefixes = strv_split(prefixes, WHITESPACE);
                        if (!valid_prefixes)
                                return -ENOMEM;
                }
        }

        ORDERED_HASHMAP_FOREACH(ext, extension_images) {
                _cleanup_(portable_metadata_unrefp) PortableMetadata *extension_release_meta = NULL;
                _cleanup_hashmap_free_ Hashmap *extra_unit_files = NULL;
                _cleanup_strv_free_ char **extension_release = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                const char *e;

                r = portable_extract_by_path(ext->path, /* path_is_extension= */ true, matches, &extension_release_meta, &extra_unit_files, error);
                if (r < 0)
                        return r;

                r = hashmap_move(unit_files, extra_unit_files);
                if (r < 0)
                        return r;

                if (!validate_sysext && !ret_valid_prefixes)
                        continue;

                r = take_fdopen_unlocked(&extension_release_meta->fd, "r", &f);
                if (r < 0)
                        return r;

                r = load_env_file_pairs(f, extension_release_meta->name, &extension_release);
                if (r < 0)
                        return r;

                if (validate_sysext) {
                        r = extension_release_validate(ext->path, id, version_id, sysext_level, "portable", extension_release);
                        if (r == 0)
                                return sd_bus_error_set_errnof(error, SYNTHETIC_ERRNO(ESTALE), "Image %s extension-release metadata does not match the root's", ext->path);
                        if (r < 0)
                                return sd_bus_error_set_errnof(error, r, "Failed to compare image %s extension-release metadata with the root's os-release: %m", ext->path);
                }

                e = strv_env_pairs_get(extension_release, "PORTABLE_PREFIXES");
                if (e) {
                        _cleanup_strv_free_ char **l = NULL;

                        l = strv_split(e, WHITESPACE);
                        if (!l)
                                return -ENOMEM;

                        r = strv_extend_strv(&valid_prefixes, l, true);
                        if (r < 0)
                                return r;
                }
        }

        strv_sort(valid_prefixes);

        if (ret_image)
                *ret_image = TAKE_PTR(image);
        if (ret_extension_images)
                *ret_extension_images = TAKE_PTR(extension_images);
        if (ret_os_release)
                *ret_os_release = TAKE_PTR(os_release);
        if (ret_unit_files)
                *ret_unit_files = TAKE_PTR(unit_files);
        if (ret_valid_prefixes)
                *ret_valid_prefixes = TAKE_PTR(valid_prefixes);

        return 0;
}

int portable_extract(
                const char *name_or_path,
                char **matches,
                char **extension_image_paths,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files,
                char ***ret_valid_prefixes,
                sd_bus_error *error) {

        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *extension_images = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(strv_freep) char **valid_prefixes = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(name_or_path);

        r = extract_image_and_extensions(
                        name_or_path,
                        matches,
                        extension_image_paths,
                        /* validate_sysext= */ false,
                        &image,
                        &extension_images,
                        &os_release,
                        &unit_files,
                        ret_valid_prefixes ? &valid_prefixes : NULL,
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

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "ListUnitsByPatterns");
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
        PortableChange *c;

        assert(path);
        assert(!changes == !n_changes);

        if (type_or_errno >= 0)
                assert(type_or_errno < _PORTABLE_CHANGE_TYPE_MAX);
        else
                assert(type_or_errno >= -ERRNO_MAX);

        if (!changes)
                return 0;

        c = reallocarray(*changes, *n_changes + 1, sizeof(PortableChange));
        if (!c)
                return -ENOMEM;
        *changes = c;

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        path_simplify(p);

        if (source) {
                s = strdup(source);
                if (!s)
                        return -ENOMEM;

                path_simplify(s);
        }

        c[(*n_changes)++] = (PortableChange) {
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

        assert(path);
        assert(!changes == !n_changes);

        if (!changes)
                return 0;

        if (prefix) {
                path = prefix_roota(prefix, path);

                if (source)
                        source = prefix_roota(prefix, source);
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
        return IN_SET(type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME) ? "RootDirectory=" : "RootImage=";
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

static int install_chroot_dropin(
                const char *image_path,
                ImageType type,
                OrderedHashmap *extension_images,
                const PortableMetadata *m,
                const char *dropin_dir,
                char **ret_dropin,
                PortableChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *text = NULL, *dropin = NULL;
        Image *ext;
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
                const char *os_release_source, *root_type;
                _cleanup_free_ char *base_name = NULL;

                root_type = root_setting_from_image(type);

                if (access("/etc/os-release", F_OK) < 0) {
                        if (errno != ENOENT)
                                return log_debug_errno(errno, "Failed to check if /etc/os-release exists: %m");

                        os_release_source = "/usr/lib/os-release";
                } else
                        os_release_source = "/etc/os-release";

                r = path_extract_filename(m->image_path ?: image_path, &base_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to extract basename from '%s': %m", m->image_path ?: image_path);

                if (!strextend(&text,
                               "\n"
                               "[Service]\n",
                               root_type, image_path, "\n"
                               "Environment=PORTABLE=", base_name, "\n"
                               "BindReadOnlyPaths=", os_release_source, ":/run/host/os-release\n"
                               "LogExtraFields=PORTABLE=", base_name, "\n"))
                        return -ENOMEM;

                if (m->image_path && !path_equal(m->image_path, image_path))
                        ORDERED_HASHMAP_FOREACH(ext, extension_images)
                                if (!strextend(&text, "ExtensionImages=", ext->path, "\n"))
                                        return -ENOMEM;
        }

        r = write_string_file(dropin, text, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_debug_errno(r, "Failed to write '%s': %m", dropin);

        (void) portable_changes_add(changes, n_changes, PORTABLE_WRITE, dropin, NULL);

        if (ret_dropin)
                *ret_dropin = TAKE_PTR(dropin);

        return 0;
}

static int install_profile_dropin(
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

        r = find_portable_profile(profile, m->name, &from);
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

                r = copy_file_atomic(from, dropin, 0644, 0, 0, COPY_REFLINK);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy %s %s %s: %m", from, special_glyph(SPECIAL_GLYPH_ARROW), dropin);

                (void) portable_changes_add(changes, n_changes, PORTABLE_COPY, dropin, from);

        } else {

                if (symlink(from, dropin) < 0)
                        return log_debug_errno(errno, "Failed to link %s %s %s: %m", from, special_glyph(SPECIAL_GLYPH_ARROW), dropin);

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
                const LookupPaths *paths,
                const char *image_path,
                ImageType type,
                OrderedHashmap *extension_images,
                const PortableMetadata *m,
                const char *profile,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes) {

        _cleanup_(unlink_and_freep) char *chroot_dropin = NULL, *profile_dropin = NULL;
        _cleanup_(rmdir_and_freep) char *dropin_dir = NULL;
        const char *where, *path;
        int r;

        assert(paths);
        assert(image_path);
        assert(m);
        assert(PORTABLE_METADATA_IS_UNIT(m));

        where = attached_path(paths, flags);

        (void) mkdir_parents(where, 0755);
        if (mkdir(where, 0755) < 0) {
                if (errno != EEXIST)
                        return -errno;
        } else
                (void) portable_changes_add(changes, n_changes, PORTABLE_MKDIR, where, NULL);

        path = prefix_roota(where, m->name);
        dropin_dir = strjoin(path, ".d");
        if (!dropin_dir)
                return -ENOMEM;

        if (mkdir(dropin_dir, 0755) < 0) {
                if (errno != EEXIST)
                        return -errno;
        } else
                (void) portable_changes_add(changes, n_changes, PORTABLE_MKDIR, dropin_dir, NULL);

        /* We install the drop-ins first, and the actual unit file last to achieve somewhat atomic behaviour if PID 1
         * is reloaded while we are creating things here: as long as only the drop-ins exist the unit doesn't exist at
         * all for PID 1. */

        r = install_chroot_dropin(image_path, type, extension_images, m, dropin_dir, &chroot_dropin, changes, n_changes);
        if (r < 0)
                return r;

        r = install_profile_dropin(image_path, m, dropin_dir, profile, flags, &profile_dropin, changes, n_changes);
        if (r < 0)
                return r;

        if ((flags & PORTABLE_PREFER_SYMLINK) && m->source) {

                if (symlink(m->source, path) < 0)
                        return log_debug_errno(errno, "Failed to symlink unit file '%s': %m", path);

                (void) portable_changes_add(changes, n_changes, PORTABLE_SYMLINK, path, m->source);

        } else {
                _cleanup_(unlink_and_freep) char *tmp = NULL;
                _cleanup_close_ int fd = -1;

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

                r = link_tmpfile(fd, tmp, path);
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

static int image_symlink(
                const char *image_path,
                PortableFlags flags,
                char **ret) {

        const char *fn, *where;
        char *joined = NULL;

        assert(image_path);
        assert(ret);

        fn = last_path_component(image_path);

        if (flags & PORTABLE_RUNTIME)
                where = "/run/portables/";
        else
                where = "/etc/portables/";

        joined = strjoin(where, fn);
        if (!joined)
                return -ENOMEM;

        *ret = joined;
        return 0;
}

static int install_image_symlink(
                const char *image_path,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *sl = NULL;
        int r;

        assert(image_path);

        /* If the image is outside of the image search also link it into it, so that it can be found with short image
         * names and is listed among the images. */

        if (image_in_search_path(IMAGE_PORTABLE, NULL, image_path))
                return 0;

        r = image_symlink(image_path, flags, &sl);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate image symlink path: %m");

        (void) mkdir_parents(sl, 0755);

        if (symlink(image_path, sl) < 0)
                return log_debug_errno(errno, "Failed to link %s %s %s: %m", image_path, special_glyph(SPECIAL_GLYPH_ARROW), sl);

        (void) portable_changes_add(changes, n_changes, PORTABLE_SYMLINK, sl, image_path);
        return 0;
}

static int install_image_and_extensions_symlinks(
                const Image *image,
                OrderedHashmap *extension_images,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes) {

        Image *ext;
        int r;

        assert(image);

        ORDERED_HASHMAP_FOREACH(ext, extension_images) {
                r = install_image_symlink(ext->path, flags, changes, n_changes);
                if (r < 0)
                        return r;
        }

        r = install_image_symlink(image->path, flags, changes, n_changes);
        if (r < 0)
                return r;

        return 0;
}

static bool prefix_matches_compatible(char **matches, char **valid_prefixes) {
        char **m;

        /* Checks if all 'matches' are included in the list of 'valid_prefixes' */

        STRV_FOREACH(m, matches)
                if (!strv_contains(valid_prefixes, *m))
                        return false;

        return true;
}

int portable_attach(
                sd_bus *bus,
                const char *name_or_path,
                char **matches,
                const char *profile,
                char **extension_image_paths,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes,
                sd_bus_error *error) {

        _cleanup_ordered_hashmap_free_ OrderedHashmap *extension_images = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_strv_free_ char **valid_prefixes = NULL;
        _cleanup_(image_unrefp) Image *image = NULL;
        PortableMetadata *item;
        int r;

        r = extract_image_and_extensions(
                        name_or_path,
                        matches,
                        extension_image_paths,
                        /* validate_sysext= */ true,
                        &image,
                        &extension_images,
                        /* os_release= */ NULL,
                        &unit_files,
                        &valid_prefixes,
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

        r = lookup_paths_init(&paths, UNIT_FILE_SYSTEM, LOOKUP_PATHS_SPLIT_USR, NULL);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(item, unit_files) {
                r = unit_file_exists(UNIT_FILE_SYSTEM, &paths, item->name);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to determine whether unit '%s' exists on the host: %m", item->name);
                if (!FLAGS_SET(flags, PORTABLE_REATTACH) && r > 0)
                        return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' exists on the host already, refusing.", item->name);

                r = unit_file_is_active(bus, item->name, error);
                if (r < 0)
                        return r;
                if (!FLAGS_SET(flags, PORTABLE_REATTACH) && r > 0)
                        return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' is active already, refusing.", item->name);
        }

        HASHMAP_FOREACH(item, unit_files) {
                r = attach_unit_file(&paths, image->path, image->type, extension_images,
                                     item, profile, flags, changes, n_changes);
                if (r < 0)
                        return r;
        }

        /* We don't care too much for the image symlink, it's just a convenience thing, it's not necessary for proper
         * operation otherwise. */
        (void) install_image_and_extensions_symlinks(image, extension_images, flags, changes, n_changes);

        return 0;
}

static bool marker_matches_images(const char *marker, const char *name_or_path, char **extension_image_paths) {
        _cleanup_strv_free_ char **root_and_extensions = NULL;
        char **image_name_or_path;
        const char *a;
        int r;

        assert(marker);
        assert(name_or_path);

        /* If extensions were used when attaching, the marker will be a colon-separated
         * list of images/paths. We enforce strict 1:1 matching, so that we are sure
         * we are detaching exactly what was attached.
         * For each image, starting with the root, we look for a token in the marker,
         * and return a negative answer on any non-matching combination. */

        root_and_extensions = strv_new(name_or_path);
        if (!root_and_extensions)
                return -ENOMEM;

        r = strv_extend_strv(&root_and_extensions, extension_image_paths, false);
        if (r < 0)
                return r;

        STRV_FOREACH(image_name_or_path, root_and_extensions) {
                _cleanup_free_ char *image = NULL;

                r = extract_first_word(&marker, &image, ":", EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse marker: %s", marker);
                if (r == 0)
                        return false;

                a = last_path_component(image);

                if (image_name_is_valid(*image_name_or_path)) {
                        const char *e, *underscore;

                        /* We shall match against an image name. In that case let's compare the last component, and optionally
                        * allow either a suffix of ".raw" or a series of "/".
                        * But allow matching on a different version of the same image, when a "_" is used as a separator. */
                        underscore = strchr(*image_name_or_path, '_');
                        if (underscore) {
                                if (strneq(a, *image_name_or_path, underscore - *image_name_or_path))
                                        continue;
                                return false;
                        }

                        e = startswith(a, *image_name_or_path);
                        if (!e)
                                return false;

                        if(!(e[strspn(e, "/")] == 0 || streq(e, ".raw")))
                                return false;
                } else {
                        const char *b, *underscore;
                        size_t l;

                        /* We shall match against a path. Let's ignore any prefix here though, as often there are many ways to
                        * reach the same file. However, in this mode, let's validate any file suffix. */

                        l = strcspn(a, "/");
                        b = last_path_component(*image_name_or_path);

                        if (strcspn(b, "/") != l)
                                return false;

                        underscore = strchr(b, '_');
                        if (underscore)
                                l = underscore - b;

                        if (!strneq(a, b, l))
                                return false;
                }
        }

        return true;
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
        _cleanup_close_ int fd = -1;
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
                r = marker_matches_images(marker, name_or_path, extension_image_paths);

        if (ret_marker)
                *ret_marker = TAKE_PTR(marker);

        return r;
}

int portable_detach(
                sd_bus *bus,
                const char *name_or_path,
                char **extension_image_paths,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes,
                sd_bus_error *error) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_set_free_ Set *unit_files = NULL, *markers = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *where, *item;
        int ret = 0;
        int r;

        assert(name_or_path);

        r = lookup_paths_init(&paths, UNIT_FILE_SYSTEM, LOOKUP_PATHS_SPLIT_USR, NULL);
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
                _cleanup_free_ char *marker = NULL;
                UnitFileState state;

                if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                        continue;

                /* Filter out duplicates */
                if (set_contains(unit_files, de->d_name))
                        continue;

                if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                        continue;

                r = test_chroot_dropin(d, where, de->d_name, name_or_path, extension_image_paths, &marker);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = unit_file_lookup_state(UNIT_FILE_SYSTEM, &paths, de->d_name, &state);
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine unit file state of '%s': %m", de->d_name);
                if (!IN_SET(state, UNIT_FILE_STATIC, UNIT_FILE_DISABLED, UNIT_FILE_LINKED, UNIT_FILE_RUNTIME, UNIT_FILE_LINKED_RUNTIME))
                        return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' is in state '%s', can't detach.", de->d_name, unit_file_state_to_string(state));

                r = unit_file_is_active(bus, de->d_name, error);
                if (r < 0)
                        return r;
                if (!FLAGS_SET(flags, PORTABLE_REATTACH) && r > 0)
                        return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' is active, can't detach.", de->d_name);

                r = set_put_strdup(&unit_files, de->d_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add unit name '%s' to set: %m", de->d_name);

                for (const char *p = marker;;) {
                        _cleanup_free_ char *image = NULL;

                        r = extract_first_word(&p, &image, ":", EXTRACT_UNESCAPE_SEPARATORS|EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse marker: %s", p);
                        if (r == 0)
                                break;

                        if (path_is_absolute(image) && !image_in_search_path(IMAGE_PORTABLE, NULL, image)) {
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
                const char *suffix;

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

        /* Now, also drop any image symlink, for images outside of the sarch path */
        SET_FOREACH(item, markers) {
                _cleanup_free_ char *sl = NULL;
                struct stat st;

                r = image_symlink(item, flags, &sl);
                if (r < 0) {
                        log_debug_errno(r, "Failed to determine image symlink for '%s', ignoring: %m", item);
                        continue;
                }

                if (lstat(sl, &st) < 0) {
                        log_debug_errno(errno, "Failed to stat '%s', ignoring: %m", sl);
                        continue;
                }

                if (!S_ISLNK(st.st_mode)) {
                        log_debug("Image '%s' is not a symlink, ignoring.", sl);
                        continue;
                }

                if (unlink(sl) < 0) {
                        log_debug_errno(errno, "Can't remove image symlink '%s': %m", sl);

                        if (errno != ENOENT && ret >= 0)
                                ret = -errno;
                } else
                        portable_changes_add(changes, n_changes, PORTABLE_UNLINK, sl, NULL);
        }

        /* Try to remove the unit file directory, if we can */
        if (rmdir(where) >= 0)
                portable_changes_add(changes, n_changes, PORTABLE_UNLINK, where, NULL);

        return ret;

not_found:
        log_debug("No unit files associated with '%s' found. Image not attached?", name_or_path);
        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "No unit files associated with '%s' found. Image not attached?", name_or_path);
}

static int portable_get_state_internal(
                sd_bus *bus,
                const char *name_or_path,
                PortableFlags flags,
                PortableState *ret,
                sd_bus_error *error) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        bool found_enabled = false, found_running = false;
        _cleanup_set_free_ Set *unit_files = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *where;
        int r;

        assert(name_or_path);
        assert(ret);

        r = lookup_paths_init(&paths, UNIT_FILE_SYSTEM, LOOKUP_PATHS_SPLIT_USR, NULL);
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

                r = test_chroot_dropin(d, where, de->d_name, name_or_path, NULL, NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = unit_file_lookup_state(UNIT_FILE_SYSTEM, &paths, de->d_name, &state);
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
                sd_bus *bus,
                const char *name_or_path,
                PortableFlags flags,
                PortableState *ret,
                sd_bus_error *error) {

        PortableState state;
        int r;

        assert(name_or_path);
        assert(ret);

        /* We look for matching units twice: once in the regular directories, and once in the runtime directories — but
         * the latter only if we didn't find anything in the former. */

        r = portable_get_state_internal(bus, name_or_path, flags & ~PORTABLE_RUNTIME, &state, error);
        if (r < 0)
                return r;

        if (state == PORTABLE_DETACHED) {
                r = portable_get_state_internal(bus, name_or_path, flags | PORTABLE_RUNTIME, &state, error);
                if (r < 0)
                        return r;
        }

        *ret = state;
        return 0;
}

int portable_get_profiles(char ***ret) {
        assert(ret);

        return conf_files_list_nulstr(ret, NULL, NULL, CONF_FILES_DIRECTORY|CONF_FILES_BASENAME|CONF_FILES_FILTER_MASKED, PORTABLE_PROFILE_DIRS);
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
