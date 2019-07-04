/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-common-errors.h"
#include "bus-error.h"
#include "conf-files.h"
#include "copy.h"
#include "def.h"
#include "dirent-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "install.h"
#include "io-util.h"
#include "locale-util.h"
#include "loop-util.h"
#include "machine-image.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-lookup.h"
#include "portable.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "string-table.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

static const char profile_dirs[] = CONF_PATHS_NULSTR("systemd/portable/profile");

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

static PortableMetadata *portable_metadata_new(const char *name, int fd) {
        PortableMetadata *m;

        m = malloc0(offsetof(PortableMetadata, name) + strlen(name) + 1);
        if (!m)
                return NULL;

        strcpy(m->name, name);
        m->fd = fd;

        return m;
}

PortableMetadata *portable_metadata_unref(PortableMetadata *i) {
        if (!i)
                return NULL;

        safe_close(i->fd);
        free(i->source);

        return mfree(i);
}

static int compare_metadata(PortableMetadata *const *x, PortableMetadata *const *y) {
        return strcmp((*x)->name, (*y)->name);
}

int portable_metadata_hashmap_to_sorted_array(Hashmap *unit_files, PortableMetadata ***ret) {

        _cleanup_free_ PortableMetadata **sorted = NULL;
        Iterator iterator;
        PortableMetadata *item;
        size_t k = 0;

        sorted = new(PortableMetadata*, hashmap_size(unit_files));
        if (!sorted)
                return -ENOMEM;

        HASHMAP_FOREACH(item, unit_files, iterator)
                sorted[k++] = item;

        assert(k == hashmap_size(unit_files));

        typesafe_qsort(sorted, k, compare_metadata);

        *ret = TAKE_PTR(sorted);
        return 0;
}

static int send_item(
                int socket_fd,
                const char *name,
                int fd) {

        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct iovec iovec;
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_iov = &iovec,
                .msg_iovlen = 1,
        };
        struct cmsghdr *cmsg;
        _cleanup_close_ int data_fd = -1;

        assert(socket_fd >= 0);
        assert(name);
        assert(fd >= 0);

        data_fd = fd_duplicate_data_fd(fd);
        if (data_fd < 0)
                return data_fd;

        cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &data_fd, sizeof(int));

        mh.msg_controllen = CMSG_SPACE(sizeof(int));
        iovec = IOVEC_MAKE_STRING(name);

        if (sendmsg(socket_fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static int recv_item(
                int socket_fd,
                char **ret_name,
                int *ret_fd) {

        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        char buffer[PATH_MAX+2];
        struct iovec iov = IOVEC_INIT(buffer, sizeof(buffer)-1);
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        struct cmsghdr *cmsg;
        _cleanup_close_ int found_fd = -1;
        char *copy;
        ssize_t n;

        assert(socket_fd >= 0);
        assert(ret_name);
        assert(ret_fd);

        n = recvmsg(socket_fd, &mh, MSG_CMSG_CLOEXEC);
        if (n < 0)
                return -errno;

        CMSG_FOREACH(cmsg, &mh) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {

                        if (cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
                                assert(found_fd < 0);
                                found_fd = *(int*) CMSG_DATA(cmsg);
                                break;
                        }

                        cmsg_close_all(&mh);
                        return -EIO;
                }
        }

        buffer[n] = 0;

        copy = strdup(buffer);
        if (!copy)
                return -ENOMEM;

        *ret_name = copy;
        *ret_fd = TAKE_FD(found_fd);

        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(portable_metadata_hash_ops, char, string_hash_func, string_compare_func,
                                              PortableMetadata, portable_metadata_unref);

static int extract_now(
                const char *where,
                char **matches,
                int socket_fd,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files) {

        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_close_ int os_release_fd = -1;
        _cleanup_free_ char *os_release_path = NULL;
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

        /* First, find /etc/os-release and send it upstream (or just save it). */
        r = open_os_release(where, &os_release_path, &os_release_fd);
        if (r < 0)
                log_debug_errno(r, "Couldn't acquire os-release file, ignoring: %m");
        else {
                if (socket_fd >= 0) {
                        r = send_item(socket_fd, "/etc/os-release", os_release_fd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to send os-release file: %m");
                }

                if (ret_os_release) {
                        os_release = portable_metadata_new("/etc/os-release", os_release_fd);
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
                struct dirent *de;

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

                        dirent_ensure_type(d, de);
                        if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                                continue;

                        fd = openat(dirfd(d), de->d_name, O_CLOEXEC|O_RDONLY);
                        if (fd < 0) {
                                log_debug_errno(errno, "Failed to open unit file '%s', ignoring: %m", de->d_name);
                                continue;
                        }

                        if (socket_fd >= 0) {
                                r = send_item(socket_fd, de->d_name, fd);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to send unit metadata to parent: %m");
                        }

                        m = portable_metadata_new(de->d_name, fd);
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
                char **matches,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files,
                sd_bus_error *error) {

        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata* os_release = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        int r;

        assert(path);

        r = loop_device_make_by_path(path, O_RDONLY, &d);
        if (r == -EISDIR) {
                /* We can't turn this into a loop-back block device, and this returns EISDIR? Then this is a directory
                 * tree and not a raw device. It's easy then. */

                r = extract_now(path, matches, -1, &os_release, &unit_files);
                if (r < 0)
                        return r;

        } else if (r < 0)
                return log_debug_errno(r, "Failed to set up loopback device: %m");
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

                r = dissect_image(d->fd, NULL, 0, DISSECT_IMAGE_READ_ONLY|DISSECT_IMAGE_REQUIRE_ROOT|DISSECT_IMAGE_DISCARD_ON_LOOP, &m);
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
                        seq[0] = safe_close(seq[0]);

                        r = dissected_image_mount(m, tmpdir, UID_INVALID, DISSECT_IMAGE_READ_ONLY|DISSECT_IMAGE_VALIDATE_OS);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to mount dissected image: %m");
                                goto child_finish;
                        }

                        r = extract_now(tmpdir, matches, seq[1], NULL, NULL);

                child_finish:
                        _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
                }

                seq[1] = safe_close(seq[1]);

                unit_files = hashmap_new(&portable_metadata_hash_ops);
                if (!unit_files)
                        return -ENOMEM;

                for (;;) {
                        _cleanup_(portable_metadata_unrefp) PortableMetadata *add = NULL;
                        _cleanup_free_ char *name = NULL;
                        _cleanup_close_ int fd = -1;

                        r = recv_item(seq[0], &name, &fd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to receive item: %m");

                        /* We can't really distinguish a zero-length datagram without any fds from EOF (both are signalled the
                         * same way by recvmsg()). Hence, accept either as end notification. */
                        if (isempty(name) && fd < 0)
                                break;

                        if (isempty(name) || fd < 0) {
                                log_debug("Invalid item sent from child.");
                                return -EINVAL;
                        }

                        add = portable_metadata_new(name, fd);
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

                        } else if (PORTABLE_METADATA_IS_OS_RELEASE(add)) {

                                assert(!os_release);
                                os_release = TAKE_PTR(add);
                        } else
                                assert_not_reached("Unexpected metadata item from child.");
                }

                r = wait_for_terminate_and_check("(sd-dissect)", child, 0);
                if (r < 0)
                        return r;
                child = 0;
        }

        if (!os_release)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image '%s' lacks os-release data, refusing.", path);

        if (hashmap_isempty(unit_files))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Couldn't find any matching unit files in image '%s', refusing.", path);

        if (ret_unit_files)
                *ret_unit_files = TAKE_PTR(unit_files);

        if (ret_os_release)
                *ret_os_release = TAKE_PTR(os_release);

        return 0;
}

int portable_extract(
                const char *name_or_path,
                char **matches,
                PortableMetadata **ret_os_release,
                Hashmap **ret_unit_files,
                sd_bus_error *error) {

        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(name_or_path);

        r = image_find_harder(IMAGE_PORTABLE, name_or_path, &image);
        if (r < 0)
                return r;

        return portable_extract_by_path(image->path, matches, ret_os_release, ret_unit_files, error);
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

                prefix = strndupa(name, at + 1 - name);
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
                PortableChangeType type,
                const char *path,
                const char *source) {

        _cleanup_free_ char *p = NULL, *s = NULL;
        PortableChange *c;

        assert(path);
        assert(!changes == !n_changes);

        if (!changes)
                return 0;

        c = reallocarray(*changes, *n_changes + 1, sizeof(PortableChange));
        if (!c)
                return -ENOMEM;
        *changes = c;

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        path_simplify(p, false);

        if (source) {
                s = strdup(source);
                if (!s)
                        return -ENOMEM;

                path_simplify(s, false);
        }

        c[(*n_changes)++] = (PortableChange) {
                .type = type,
                .path = TAKE_PTR(p),
                .source = TAKE_PTR(s),
        };

        return 0;
}

static int portable_changes_add_with_prefix(
                PortableChange **changes,
                size_t *n_changes,
                PortableChangeType type,
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

        return portable_changes_add(changes, n_changes, type, path, source);
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

static int install_chroot_dropin(
                const char *image_path,
                ImageType type,
                const PortableMetadata *m,
                const char *dropin_dir,
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

        text = strjoin(PORTABLE_DROPIN_MARKER_BEGIN, image_path, PORTABLE_DROPIN_MARKER_END "\n");
        if (!text)
                return -ENOMEM;

        if (endswith(m->name, ".service"))
                if (!strextend(&text,
                               "\n"
                               "[Service]\n",
                               IN_SET(type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME) ? "RootDirectory=" : "RootImage=", image_path, "\n"
                               "Environment=PORTABLE=", basename(image_path), "\n"
                               "LogExtraFields=PORTABLE=", basename(image_path), "\n",
                               NULL))

                        return -ENOMEM;

        r = write_string_file(dropin, text, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_debug_errno(r, "Failed to write '%s': %m", dropin);

        (void) portable_changes_add(changes, n_changes, PORTABLE_WRITE, dropin, NULL);

        if (ret_dropin)
                *ret_dropin = TAKE_PTR(dropin);

        return 0;
}

static int find_profile(const char *name, const char *unit, char **ret) {
        const char *p, *dot;

        assert(name);
        assert(ret);

        assert_se(dot = strrchr(unit, '.'));

        NULSTR_FOREACH(p, profile_dirs) {
                _cleanup_free_ char *joined;

                joined = strjoin(p, "/", name, "/", dot + 1, ".conf");
                if (!joined)
                        return -ENOMEM;

                if (laccess(joined, F_OK) >= 0) {
                        *ret = TAKE_PTR(joined);
                        return 0;
                }

                if (errno != ENOENT)
                        return -errno;
        }

        return -ENOENT;
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

        r = find_profile(profile, m->name, &from);
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

        r = install_chroot_dropin(image_path, type, m, dropin_dir, &chroot_dropin, changes, n_changes);
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

                fd = open_tmpfile_linkable(where, O_WRONLY|O_CLOEXEC, &tmp);
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

        if (image_in_search_path(IMAGE_PORTABLE, image_path))
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

int portable_attach(
                sd_bus *bus,
                const char *name_or_path,
                char **matches,
                const char *profile,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes,
                sd_bus_error *error) {

        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(image_unrefp) Image *image = NULL;
        PortableMetadata *item;
        Iterator iterator;
        int r;

        assert(name_or_path);

        r = image_find_harder(IMAGE_PORTABLE, name_or_path, &image);
        if (r < 0)
                return r;

        r = portable_extract_by_path(image->path, matches, NULL, &unit_files, error);
        if (r < 0)
                return r;

        r = lookup_paths_init(&paths, UNIT_FILE_SYSTEM, LOOKUP_PATHS_SPLIT_USR, NULL);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(item, unit_files, iterator) {
                r = unit_file_exists(UNIT_FILE_SYSTEM, &paths, item->name);
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

        HASHMAP_FOREACH(item, unit_files, iterator) {
                r = attach_unit_file(&paths, image->path, image->type, item, profile, flags, changes, n_changes);
                if (r < 0)
                        return r;
        }

        /* We don't care too much for the image symlink, it's just a convenience thing, it's not necessary for proper
         * operation otherwise. */
        (void) install_image_symlink(image->path, flags, changes, n_changes);

        return 0;
}

static bool marker_matches_image(const char *marker, const char *name_or_path) {
        const char *a;

        assert(marker);
        assert(name_or_path);

        a = last_path_component(marker);

        if (image_name_is_valid(name_or_path)) {
                const char *e;

                /* We shall match against an image name. In that case let's compare the last component, and optionally
                 * allow either a suffix of ".raw" or a series of "/". */

                e = startswith(a, name_or_path);
                if (!e)
                        return false;

                return
                        e[strspn(e, "/")] == 0 ||
                        streq(e, ".raw");
        } else {
                const char *b;
                size_t l;

                /* We shall match against a path. Let's ignore any prefix here though, as often there are many ways to
                 * reach the same file. However, in this mode, let's validate any file suffix. */

                l = strcspn(a, "/");
                b = last_path_component(name_or_path);

                if (strcspn(b, "/") != l)
                        return false;

                return memcmp(a, b, l) == 0;
        }
}

static int test_chroot_dropin(
                DIR *d,
                const char *where,
                const char *fname,
                const char *name_or_path,
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

        r = fdopen_unlocked(fd, "r", &f);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert file handle: %m");
        TAKE_FD(fd);

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
                r = marker_matches_image(marker, name_or_path);

        if (ret_marker)
                *ret_marker = TAKE_PTR(marker);

        return r;
}

int portable_detach(
                sd_bus *bus,
                const char *name_or_path,
                PortableFlags flags,
                PortableChange **changes,
                size_t *n_changes,
                sd_bus_error *error) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_set_free_free_ Set *unit_files = NULL, *markers = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *where, *item;
        Iterator iterator;
        struct dirent *de;
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

        unit_files = set_new(&string_hash_ops);
        if (!unit_files)
                return -ENOMEM;

        markers = set_new(&path_hash_ops);
        if (!markers)
                return -ENOMEM;

        FOREACH_DIRENT(de, d, return log_debug_errno(errno, "Failed to enumerate '%s' directory: %m", where)) {
                _cleanup_free_ char *marker = NULL;
                UnitFileState state;

                if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                        continue;

                /* Filter out duplicates */
                if (set_get(unit_files, de->d_name))
                        continue;

                dirent_ensure_type(d, de);
                if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                        continue;

                r = test_chroot_dropin(d, where, de->d_name, name_or_path, &marker);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = unit_file_lookup_state(UNIT_FILE_SYSTEM, &paths, de->d_name, &state);
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine unit file state of '%s': %m", de->d_name);
                if (!IN_SET(state, UNIT_FILE_STATIC, UNIT_FILE_DISABLED, UNIT_FILE_LINKED, UNIT_FILE_RUNTIME))
                        return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' is in state '%s', can't detach.", de->d_name, unit_file_state_to_string(state));

                r = unit_file_is_active(bus, de->d_name, error);
                if (r < 0)
                        return r;
                if (r > 0)
                        return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit file '%s' is active, can't detach.", de->d_name);

                r = set_put_strdup(unit_files, de->d_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add unit name '%s' to set: %m", de->d_name);

                if (path_is_absolute(marker) &&
                    !image_in_search_path(IMAGE_PORTABLE, marker)) {

                        r = set_ensure_allocated(&markers, &path_hash_ops);
                        if (r < 0)
                                return r;

                        r = set_put(markers, marker);
                        if (r >= 0)
                                marker = NULL;
                        else if (r != -EEXIST)
                                return r;
                }
        }

        if (set_isempty(unit_files))
                goto not_found;

        SET_FOREACH(item, unit_files, iterator) {
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
        SET_FOREACH(item, markers, iterator) {
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
        _cleanup_set_free_free_ Set *unit_files = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *where;
        struct dirent *de;
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

        unit_files = set_new(&string_hash_ops);
        if (!unit_files)
                return -ENOMEM;

        FOREACH_DIRENT(de, d, return log_debug_errno(errno, "Failed to enumerate '%s' directory: %m", where)) {
                UnitFileState state;

                if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                        continue;

                /* Filter out duplicates */
                if (set_get(unit_files, de->d_name))
                        continue;

                dirent_ensure_type(d, de);
                if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                        continue;

                r = test_chroot_dropin(d, where, de->d_name, name_or_path, NULL);
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

                r = set_put_strdup(unit_files, de->d_name);
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

        return conf_files_list_nulstr(ret, NULL, NULL, CONF_FILES_DIRECTORY|CONF_FILES_BASENAME|CONF_FILES_FILTER_MASKED, profile_dirs);
}

static const char* const portable_change_type_table[_PORTABLE_CHANGE_TYPE_MAX] = {
        [PORTABLE_COPY] = "copy",
        [PORTABLE_MKDIR] = "mkdir",
        [PORTABLE_SYMLINK] = "symlink",
        [PORTABLE_UNLINK] = "unlink",
        [PORTABLE_WRITE] = "write",
};

DEFINE_STRING_TABLE_LOOKUP(portable_change_type, PortableChangeType);

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
