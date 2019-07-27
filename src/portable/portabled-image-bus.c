/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-label.h"
#include "bus-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "machine-image.h"
#include "missing_capability.h"
#include "portable.h"
#include "portabled-bus.h"
#include "portabled-image-bus.h"
#include "portabled-image.h"
#include "portabled.h"
#include "process-util.h"
#include "strv.h"
#include "user-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, image_type, ImageType);

int bus_image_common_get_os_release(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        int r;

        assert(name_or_path || image);
        assert(message);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        r = bus_image_acquire(m,
                              message,
                              name_or_path,
                              image,
                              BUS_IMAGE_AUTHENTICATE_BY_PATH,
                              "org.freedesktop.portable1.inspect-images",
                              &image,
                              error);
        if (r < 0)
                return r;
        if (r == 0) /* Will call us back */
                return 1;

        if (!image->metadata_valid) {
                r = image_read_metadata(image);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to read image metadata: %m");
        }

        return bus_reply_pair_array(message, image->os_release);
}

static int bus_image_method_get_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_get_os_release(NULL, message, NULL, userdata, error);
}

static int append_fd(sd_bus_message *m, PortableMetadata *d) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *buf = NULL;
        size_t n;
        int r;

        assert(m);
        assert(d);
        assert(d->fd >= 0);

        f = fdopen(d->fd, "r");
        if (!f)
                return -errno;

        d->fd = -1;

        r = read_full_stream(f, &buf, &n);
        if (r < 0)
                return r;

        return sd_bus_message_append_array(m, 'y', buf, n);
}

int bus_image_common_get_metadata(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ PortableMetadata **sorted = NULL;
        _cleanup_strv_free_ char **matches = NULL;
        size_t i;
        int r;

        assert(name_or_path || image);
        assert(message);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        r = sd_bus_message_read_strv(message, &matches);
        if (r < 0)
                return r;

        r = bus_image_acquire(m,
                              message,
                              name_or_path,
                              image,
                              BUS_IMAGE_AUTHENTICATE_BY_PATH,
                              "org.freedesktop.portable1.inspect-images",
                              &image,
                              error);
        if (r < 0)
                return r;
        if (r == 0) /* Will call us back */
                return 1;

        r = portable_extract(
                        image->path,
                        matches,
                        &os_release,
                        &unit_files,
                        error);
        if (r < 0)
                return r;

        r = portable_metadata_hashmap_to_sorted_array(unit_files, &sorted);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", image->path);
        if (r < 0)
                return r;

        r = append_fd(reply, os_release);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "{say}");
        if (r < 0)
                return r;

        for (i = 0; i < hashmap_size(unit_files); i++) {

                r = sd_bus_message_open_container(reply, 'e', "say");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "s", sorted[i]->name);
                if (r < 0)
                        return r;

                r = append_fd(reply, sorted[i]);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int bus_image_method_get_metadata(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_get_metadata(NULL, message, NULL, userdata, error);
}

static int bus_image_method_get_state(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        PortableState state;
        int r;

        assert(message);
        assert(image);

        r = portable_get_state(
                        sd_bus_message_get_bus(message),
                        image->path,
                        0,
                        &state,
                        error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", portable_state_to_string(state));
}

int bus_image_common_attach(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **matches = NULL;
        PortableChange *changes = NULL;
        PortableFlags flags = 0;
        const char *profile, *copy_mode;
        size_t n_changes = 0;
        int runtime, r;

        assert(message);
        assert(name_or_path || image);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        r = sd_bus_message_read_strv(message, &matches);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbs", &profile, &runtime, &copy_mode);
        if (r < 0)
                return r;

        if (streq(copy_mode, "symlink"))
                flags |= PORTABLE_PREFER_SYMLINK;
        else if (streq(copy_mode, "copy"))
                flags |= PORTABLE_PREFER_COPY;
        else if (!isempty(copy_mode))
                return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS, "Unknown copy mode '%s'", copy_mode);

        if (runtime)
                flags |= PORTABLE_RUNTIME;

        r = bus_image_acquire(m,
                              message,
                              name_or_path,
                              image,
                              BUS_IMAGE_AUTHENTICATE_ALL,
                              "org.freedesktop.portable1.attach-images",
                              &image,
                              error);
        if (r < 0)
                return r;
        if (r == 0) /* Will call us back */
                return 1;

        r = portable_attach(
                        sd_bus_message_get_bus(message),
                        image->path,
                        matches,
                        profile,
                        flags,
                        &changes,
                        &n_changes,
                        error);
        if (r < 0)
                goto finish;

        r = reply_portable_changes(message, changes, n_changes);

finish:
        portable_changes_free(changes, n_changes);
        return r;
}

static int bus_image_method_attach(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_attach(NULL, message, NULL, userdata, error);
}

static int bus_image_method_detach(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        PortableChange *changes = NULL;
        Image *image = userdata;
        Manager *m = image->userdata;
        size_t n_changes = 0;
        int r, runtime;

        assert(message);
        assert(image);
        assert(m);

        r = sd_bus_message_read(message, "b", &runtime);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.portable1.attach-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = portable_detach(
                        sd_bus_message_get_bus(message),
                        image->path,
                        runtime ? PORTABLE_RUNTIME : 0,
                        &changes,
                        &n_changes,
                        error);
        if (r < 0)
                goto finish;

        r = reply_portable_changes(message, changes, n_changes);

finish:
        portable_changes_free(changes, n_changes);
        return r;
}

int bus_image_common_remove(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        _cleanup_(sigkill_waitp) pid_t child = 0;
        PortableState state;
        int r;

        assert(message);
        assert(name_or_path || image);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        if (m->n_operations >= OPERATIONS_MAX)
                return sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing operations.");

        r = bus_image_acquire(m,
                              message,
                              name_or_path,
                              image,
                              BUS_IMAGE_AUTHENTICATE_ALL,
                              "org.freedesktop.portable1.manage-images",
                              &image,
                              error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = portable_get_state(
                        sd_bus_message_get_bus(message),
                        image->path,
                        0,
                        &state,
                        error);
        if (r < 0)
                return r;

        if (state != PORTABLE_DETACHED)
                return sd_bus_error_set_errnof(error, EBUSY, "Image '%s' is not detached, refusing.", image->path);

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create pipe: %m");

        r = safe_fork("(sd-imgrm)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to fork(): %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                r = image_remove(image);
                if (r < 0) {
                        (void) write(errno_pipe_fd[1], &r, sizeof(r));
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = operation_new(m, child, message, errno_pipe_fd[0], NULL);
        if (r < 0)
                return r;

        child = 0;
        errno_pipe_fd[0] = -1;

        return 1;
}

static int bus_image_method_remove(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_remove(NULL, message, NULL, userdata, error);
}

int bus_image_common_mark_read_only(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        int r, read_only;

        assert(message);
        assert(name_or_path || image);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        r = sd_bus_message_read(message, "b", &read_only);
        if (r < 0)
                return r;

        r = bus_image_acquire(m,
                              message,
                              name_or_path,
                              image,
                              BUS_IMAGE_AUTHENTICATE_ALL,
                              "org.freedesktop.portable1.manage-images",
                              &image,
                              error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_read_only(image, read_only);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int bus_image_method_mark_read_only(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_mark_read_only(NULL, message, NULL, userdata, error);
}

int bus_image_common_set_limit(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        uint64_t limit;
        int r;

        assert(message);
        assert(name_or_path || image);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        r = sd_bus_message_read(message, "t", &limit);
        if (r < 0)
                return r;
        if (!FILE_SIZE_VALID_OR_INFINITY(limit))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "New limit out of range");

        r = bus_image_acquire(m,
                              message,
                              name_or_path,
                              image,
                              BUS_IMAGE_AUTHENTICATE_ALL,
                              "org.freedesktop.portable1.manage-images",
                              &image,
                              error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_set_limit(image, limit);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int bus_image_method_set_limit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_set_limit(NULL, message, NULL, userdata, error);
}

const sd_bus_vtable image_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(Image, name), 0),
        SD_BUS_PROPERTY("Path", "s", NULL, offsetof(Image, path), 0),
        SD_BUS_PROPERTY("Type", "s", property_get_type,  offsetof(Image, type), 0),
        SD_BUS_PROPERTY("ReadOnly", "b", bus_property_get_bool, offsetof(Image, read_only), 0),
        SD_BUS_PROPERTY("CreationTimestamp", "t", NULL, offsetof(Image, crtime), 0),
        SD_BUS_PROPERTY("ModificationTimestamp", "t", NULL, offsetof(Image, mtime), 0),
        SD_BUS_PROPERTY("Usage", "t", NULL, offsetof(Image, usage), 0),
        SD_BUS_PROPERTY("Limit", "t", NULL, offsetof(Image, limit), 0),
        SD_BUS_PROPERTY("UsageExclusive", "t", NULL, offsetof(Image, usage_exclusive), 0),
        SD_BUS_PROPERTY("LimitExclusive", "t", NULL, offsetof(Image, limit_exclusive), 0),
        SD_BUS_METHOD("GetOSRelease", NULL, "a{ss}", bus_image_method_get_os_release, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMetadata", "as", "saya{say}", bus_image_method_get_metadata, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetState", NULL, "s", bus_image_method_get_state, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Attach", "assbs", "a(sss)", bus_image_method_attach, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Detach", "b", "a(sss)", bus_image_method_detach, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Remove", NULL, NULL, bus_image_method_remove, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MarkReadOnly", "b", NULL, bus_image_method_mark_read_only, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLimit", "t", NULL, bus_image_method_set_limit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

int bus_image_path(Image *image, char **ret) {
        assert(image);
        assert(ret);

        if (!image->discoverable)
                return -EINVAL;

        return sd_bus_path_encode("/org/freedesktop/portable1/image", image->name, ret);
}

int bus_image_acquire(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                ImageAcquireMode mode,
                const char *polkit_action,
                Image **ret,
                sd_bus_error *error) {

        _cleanup_(image_unrefp) Image *loaded = NULL;
        Image *cached;
        int r;

        assert(m);
        assert(message);
        assert(name_or_path || image);
        assert(mode >= 0);
        assert(mode < _BUS_IMAGE_ACQUIRE_MODE_MAX);
        assert(polkit_action || mode == BUS_IMAGE_REFUSE_BY_PATH);
        assert(ret);

        /* Acquires an 'Image' object if not acquired yet, and enforces necessary authentication while doing so. */

        if (mode == BUS_IMAGE_AUTHENTICATE_ALL) {
                r = bus_verify_polkit_async(
                                message,
                                CAP_SYS_ADMIN,
                                polkit_action,
                                NULL,
                                false,
                                UID_INVALID,
                                &m->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0) { /* Will call us back */
                        *ret = NULL;
                        return 0;
                }
        }

        /* Already passed in? */
        if (image) {
                *ret = image;
                return 1;
        }

        /* Let's see if this image is already cached? */
        cached = manager_image_cache_get(m, name_or_path);
        if (cached) {
                *ret = cached;
                return 1;
        }

        if (image_name_is_valid(name_or_path)) {

                /* If it's a short name, let's search for it */
                r = image_find(IMAGE_PORTABLE, name_or_path, &loaded);
                if (r == -ENOENT)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_PORTABLE_IMAGE, "No image '%s' found.", name_or_path);

                /* other errors are handled below… */
        } else {
                /* Don't accept path if this is always forbidden */
                if (mode == BUS_IMAGE_REFUSE_BY_PATH)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Expected image name, not path in place of '%s'.", name_or_path);

                if (!path_is_absolute(name_or_path))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is not valid or not a valid path.", name_or_path);

                if (!path_is_normalized(name_or_path))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image path '%s' is not normalized.", name_or_path);

                if (mode == BUS_IMAGE_AUTHENTICATE_BY_PATH) {
                        r = bus_verify_polkit_async(
                                        message,
                                        CAP_SYS_ADMIN,
                                        polkit_action,
                                        NULL,
                                        false,
                                        UID_INVALID,
                                        &m->polkit_registry,
                                        error);
                        if (r < 0)
                                return r;
                        if (r == 0) { /* Will call us back */
                                *ret = NULL;
                                return 0;
                        }
                }

                r = image_from_path(name_or_path, &loaded);
        }
        if (r == -EMEDIUMTYPE) {
                sd_bus_error_setf(error, BUS_ERROR_BAD_PORTABLE_IMAGE_TYPE, "Typ of image '%s' not recognized; supported image types are directories/btrfs subvolumes, block devices, and raw disk image files with suffix '.raw'.", name_or_path);
                return r;
        }
        if (r < 0)
                return r;

        /* Add what we just loaded to the cache. This has as side-effect that the object stays in memory until the
         * cache is purged again, i.e. at least for the current event loop iteration, which is all we need, and which
         * means we don't actually need to ref the return object. */
        r = manager_image_cache_add(m, loaded);
        if (r < 0)
                return r;

        *ret = loaded;
        return 1;
}

int bus_image_object_find(
                sd_bus *bus,
                const char *path,
                const char *interface,
                void *userdata,
                void **found,
                sd_bus_error *error) {

        _cleanup_free_ char *e = NULL;
        Manager *m = userdata;
        Image *image = NULL;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = sd_bus_path_decode(path, "/org/freedesktop/portable1/image", &e);
        if (r < 0)
                return 0;
        if (r == 0)
                goto not_found;

        r = bus_image_acquire(m, sd_bus_get_current_message(bus), e, NULL, BUS_IMAGE_REFUSE_BY_PATH, NULL, &image, error);
        if (r == -ENOENT)
                goto not_found;
        if (r < 0)
                return r;

        *found = image;
        return 1;

not_found:
        *found = NULL;
        return 0;
}

int bus_image_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        _cleanup_strv_free_ char **l = NULL;
        size_t n_allocated = 0, n = 0;
        Manager *m = userdata;
        Image *image;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        images = hashmap_new(&image_hash_ops);
        if (!images)
                return -ENOMEM;

        r = manager_image_cache_discover(m, images, error);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images, i) {
                char *p;

                r = bus_image_path(image, &p);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(l, n_allocated, n+2)) {
                        free(p);
                        return -ENOMEM;
                }

                l[n++] = p;
                l[n] = NULL;
        }

        *nodes = TAKE_PTR(l);

        return 1;
}
