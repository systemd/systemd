/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-label.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "discover-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "missing_capability.h"
#include "os-util.h"
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
                r = image_read_metadata(image, &image_policy_service);
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
        size_t n = 0;
        int r;

        assert(m);

        if (d) {
                assert(d->fd >= 0);

                r = fdopen_independent(d->fd, "r", &f);
                if (r < 0)
                        return r;

                r = read_full_stream(f, &buf, &n);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_append_array(m, 'y', buf, n);
}

int bus_image_common_get_metadata(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        _cleanup_ordered_hashmap_free_ OrderedHashmap *extension_releases = NULL;
        _cleanup_(portable_metadata_unrefp) PortableMetadata *os_release = NULL;
        _cleanup_strv_free_ char **matches = NULL, **extension_images = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ PortableMetadata **sorted = NULL;
        PortableFlags flags = 0;
        int r;

        assert(name_or_path || image);
        assert(message);

        if (!m)
                m = ASSERT_PTR(ASSERT_PTR(image)->userdata);

        bool have_exti = sd_bus_message_is_method_call(message, NULL, "GetImageMetadataWithExtensions") ||
                         sd_bus_message_is_method_call(message, NULL, "GetMetadataWithExtensions");

        if (have_exti) {
                r = sd_bus_message_read_strv(message, &extension_images);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_read_strv(message, &matches);
        if (r < 0)
                return r;

        if (have_exti) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read(message, "t", &input_flags);
                if (r < 0)
                        return r;

                if ((input_flags & ~_PORTABLE_MASK_PUBLIC) != 0)
                        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Invalid 'flags' parameter '%" PRIu64 "'",
                                                          input_flags);
                flags |= input_flags;
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

        r = portable_extract(
                        m->runtime_scope,
                        image->path,
                        matches,
                        extension_images,
                        /* image_policy= */ NULL,
                        flags,
                        &os_release,
                        &extension_releases,
                        &unit_files,
                        NULL,
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

        /* If it was requested, also send back the extension path and the content
         * of each extension-release file. Behind a flag, as it's an incompatible
         * change. */
        if (have_exti) {
                PortableMetadata *extension_release;

                r = sd_bus_message_open_container(reply, 'a', "{say}");
                if (r < 0)
                        return r;

                ORDERED_HASHMAP_FOREACH(extension_release, extension_releases) {

                        r = sd_bus_message_open_container(reply, 'e', "say");
                        if (r < 0)
                                return r;

                        r = sd_bus_message_append(reply, "s", extension_release->image_path);
                        if (r < 0)
                                return r;

                        r = append_fd(reply, extension_release);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_close_container(reply);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_open_container(reply, 'a', "{say}");
        if (r < 0)
                return r;

        for (size_t i = 0; i < hashmap_size(unit_files); i++) {

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

        _cleanup_strv_free_ char **extension_images = NULL;
        Image *image = ASSERT_PTR(userdata);
        Manager *m = ASSERT_PTR(image->userdata);
        PortableState state;
        int r;

        assert(message);

        if (sd_bus_message_is_method_call(message, NULL, "GetStateWithExtensions")) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read_strv(message, &extension_images);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(message, "t", &input_flags);
                if (r < 0)
                        return r;

                /* No flags are supported by this method for now. */
                if (input_flags != 0)
                        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Invalid 'flags' parameter '%" PRIu64 "'",
                                                          input_flags);
        }

        r = portable_get_state(
                        m->runtime_scope,
                        sd_bus_message_get_bus(message),
                        image->path,
                        extension_images,
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

        _cleanup_strv_free_ char **matches = NULL, **extension_images = NULL;
        PortableChange *changes = NULL;
        PortableFlags flags = 0;
        const char *profile, *copy_mode;
        size_t n_changes = 0;
        int r;

        assert(message);
        assert(name_or_path || image);

        CLEANUP_ARRAY(changes, n_changes, portable_changes_free);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        if (sd_bus_message_is_method_call(message, NULL, "AttachImageWithExtensions") ||
            sd_bus_message_is_method_call(message, NULL, "AttachWithExtensions")) {
                r = sd_bus_message_read_strv(message, &extension_images);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_read_strv(message, &matches);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &profile);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "AttachImageWithExtensions") ||
            sd_bus_message_is_method_call(message, NULL, "AttachWithExtensions")) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read(message, "st", &copy_mode, &input_flags);
                if (r < 0)
                        return r;
                if ((input_flags & ~_PORTABLE_MASK_PUBLIC) != 0)
                        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Invalid 'flags' parameter '%" PRIu64 "'",
                                                          input_flags);
                flags |= input_flags;
        } else {
                int runtime;

                r = sd_bus_message_read(message, "bs", &runtime, &copy_mode);
                if (r < 0)
                        return r;

                if (runtime)
                        flags |= PORTABLE_RUNTIME;
        }

        if (streq(copy_mode, "symlink"))
                flags |= PORTABLE_PREFER_SYMLINK;
        else if (streq(copy_mode, "copy"))
                flags |= PORTABLE_PREFER_COPY;
        else if (streq(copy_mode, "mixed"))
                flags |= PORTABLE_MIXED_COPY_LINK;
        else if (!isempty(copy_mode))
                return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS, "Unknown copy mode '%s'", copy_mode);

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
                        m->runtime_scope,
                        sd_bus_message_get_bus(message),
                        image->path,
                        matches,
                        profile,
                        extension_images,
                        /* image_policy= */ NULL,
                        flags,
                        &changes,
                        &n_changes,
                        error);
        if (r < 0)
                return r;

        return reply_portable_changes(message, changes, n_changes);
}

static int bus_image_method_attach(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_attach(NULL, message, NULL, userdata, error);
}

static int bus_image_method_detach(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **extension_images = NULL;
        PortableChange *changes = NULL;
        Image *image = ASSERT_PTR(userdata);
        Manager *m = ASSERT_PTR(image->userdata);
        PortableFlags flags = 0;
        size_t n_changes = 0;
        int r;

        assert(message);

        CLEANUP_ARRAY(changes, n_changes, portable_changes_free);

        if (sd_bus_message_is_method_call(message, NULL, "DetachWithExtensions")) {
                r = sd_bus_message_read_strv(message, &extension_images);
                if (r < 0)
                        return r;
        }

        if (sd_bus_message_is_method_call(message, NULL, "DetachWithExtensions")) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read(message, "t", &input_flags);
                if (r < 0)
                        return r;

                if ((input_flags & ~_PORTABLE_MASK_PUBLIC) != 0)
                        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Invalid 'flags' parameter '%" PRIu64 "'",
                                                          input_flags);
                flags |= input_flags;
        } else {
                int runtime;

                r = sd_bus_message_read(message, "b", &runtime);
                if (r < 0)
                        return r;

                if (runtime)
                        flags |= PORTABLE_RUNTIME;
        }

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.portable1.attach-images",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = portable_detach(
                        m->runtime_scope,
                        sd_bus_message_get_bus(message),
                        image->path,
                        extension_images,
                        flags,
                        &changes,
                        &n_changes,
                        error);
        if (r < 0)
                return r;

        return reply_portable_changes(message, changes, n_changes);
}

int bus_image_common_remove(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
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
                return sd_bus_error_set(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing operations.");

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
                        m->runtime_scope,
                        sd_bus_message_get_bus(message),
                        image->path,
                        NULL,
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
        errno_pipe_fd[0] = -EBADF;

        return 1;
}

static int bus_image_method_remove(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_remove(NULL, message, NULL, userdata, error);
}

/* Given two PortableChange arrays, return a new array that has all elements of the first that are
 * not also present in the second, comparing the basename of the path values. */
static int normalize_portable_changes(
                const PortableChange *changes_attached,
                size_t n_changes_attached,
                const PortableChange *changes_detached,
                size_t n_changes_detached,
                PortableChange **ret_changes,
                size_t *ret_n_changes) {

        PortableChange *changes = NULL;
        size_t n_changes = 0;

        assert(ret_n_changes);
        assert(ret_changes);

        if (n_changes_detached == 0)
                return 0; /* Nothing to do */

        changes = new0(PortableChange, n_changes_attached + n_changes_detached);
        if (!changes)
                return -ENOMEM;

        CLEANUP_ARRAY(changes, n_changes, portable_changes_free);

        /* Corner case: only detached, nothing attached */
        if (n_changes_attached == 0) {
                memcpy(changes, changes_detached, sizeof(PortableChange) * n_changes_detached);
                *ret_changes = TAKE_PTR(changes);
                *ret_n_changes = n_changes_detached;
                return 0;
        }

        for (size_t i = 0; i < n_changes_detached; ++i) {
                bool found = false;

                for (size_t j = 0; j < n_changes_attached; ++j)
                        if (path_equal_filename(changes_detached[i].path, changes_attached[j].path)) {
                                found = true;
                                break;
                        }

                if (!found) {
                        _cleanup_free_ char *path = NULL, *source = NULL;

                        path = strdup(changes_detached[i].path);
                        if (!path)
                                return -ENOMEM;

                        if (changes_detached[i].source) {
                                source = strdup(changes_detached[i].source);
                                if (!source)
                                        return -ENOMEM;
                        }

                        changes[n_changes++] = (PortableChange) {
                                .type_or_errno = changes_detached[i].type_or_errno,
                                .path = TAKE_PTR(path),
                                .source = TAKE_PTR(source),
                        };
                }
        }

        *ret_n_changes = n_changes;
        *ret_changes = TAKE_PTR(changes);

        return 0;
}

int bus_image_common_reattach(
                Manager *m,
                sd_bus_message *message,
                const char *name_or_path,
                Image *image,
                sd_bus_error *error) {

        PortableChange *changes_detached = NULL, *changes_attached = NULL, *changes_gone = NULL;
        size_t n_changes_detached = 0, n_changes_attached = 0, n_changes_gone = 0;
        _cleanup_strv_free_ char **matches = NULL, **extension_images = NULL;
        PortableFlags flags = PORTABLE_REATTACH;
        const char *profile, *copy_mode;
        int r;

        assert(message);
        assert(name_or_path || image);

        CLEANUP_ARRAY(changes_detached, n_changes_detached, portable_changes_free);
        CLEANUP_ARRAY(changes_attached, n_changes_attached, portable_changes_free);
        CLEANUP_ARRAY(changes_gone, n_changes_gone, portable_changes_free);

        if (!m) {
                assert(image);
                m = image->userdata;
        }

        if (sd_bus_message_is_method_call(message, NULL, "ReattachImageWithExtensions") ||
            sd_bus_message_is_method_call(message, NULL, "ReattachWithExtensions")) {
                r = sd_bus_message_read_strv(message, &extension_images);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_read_strv(message, &matches);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &profile);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "ReattachImageWithExtensions") ||
            sd_bus_message_is_method_call(message, NULL, "ReattachWithExtensions")) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read(message, "st", &copy_mode, &input_flags);
                if (r < 0)
                        return r;

                if ((input_flags & ~_PORTABLE_MASK_PUBLIC) != 0)
                        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Invalid 'flags' parameter '%" PRIu64 "'",
                                                          input_flags);
                flags |= input_flags;
        } else {
                int runtime;

                r = sd_bus_message_read(message, "bs", &runtime, &copy_mode);
                if (r < 0)
                        return r;

                if (runtime)
                        flags |= PORTABLE_RUNTIME;
        }

        if (streq(copy_mode, "symlink"))
                flags |= PORTABLE_PREFER_SYMLINK;
        else if (streq(copy_mode, "copy"))
                flags |= PORTABLE_PREFER_COPY;
        else if (streq(copy_mode, "mixed"))
                flags |= PORTABLE_MIXED_COPY_LINK;
        else if (!isempty(copy_mode))
                return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS, "Unknown copy mode '%s'", copy_mode);

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

        r = portable_detach(
                        m->runtime_scope,
                        sd_bus_message_get_bus(message),
                        image->path,
                        extension_images,
                        flags,
                        &changes_detached,
                        &n_changes_detached,
                        error);
        if (r < 0)
                return r;

        r = portable_attach(
                        m->runtime_scope,
                        sd_bus_message_get_bus(message),
                        image->path,
                        matches,
                        profile,
                        extension_images,
                        /* image_policy= */ NULL,
                        flags,
                        &changes_attached,
                        &n_changes_attached,
                        error);
        if (r < 0)
                return r;

        /* We want to return the list of units really removed by the detach,
         * and not added again by the attach */
        r = normalize_portable_changes(changes_attached, n_changes_attached,
                                       changes_detached, n_changes_detached,
                                       &changes_gone, &n_changes_gone);
        if (r < 0)
                return r;

        /* First, return the units that are gone (so that the caller can stop them)
         * Then, return the units that are changed/added (so that the caller can
         * start/restart/enable them) */
        return reply_portable_changes_pair(message,
                                           changes_gone, n_changes_gone,
                                           changes_attached, n_changes_attached);
}

static int bus_image_method_reattach(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_image_common_reattach(NULL, message, NULL, userdata, error);
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
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "New limit out of range");

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
        SD_BUS_METHOD_WITH_ARGS("GetOSRelease",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a{ss}", os_release),
                                bus_image_method_get_os_release,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetMetadata",
                                SD_BUS_ARGS("as", matches),
                                SD_BUS_RESULT("s", image,
                                              "ay", os_release,
                                              "a{say}", units),
                                bus_image_method_get_metadata,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetMetadataWithExtensions",
                                SD_BUS_ARGS("as", extensions,
                                            "as", matches,
                                            "t", flags),
                                SD_BUS_RESULT("s", image,
                                              "ay", os_release,
                                              "a{say}", extensions,
                                              "a{say}", units),
                                bus_image_method_get_metadata,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetState",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", state),
                                bus_image_method_get_state,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetStateWithExtensions",
                                SD_BUS_ARGS("as", extensions,
                                            "t", flags),
                                SD_BUS_RESULT("s", state),
                                bus_image_method_get_state,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Attach",
                                SD_BUS_ARGS("as", matches,
                                            "s", profile,
                                            "b", runtime,
                                            "s", copy_mode),
                                SD_BUS_RESULT("a(sss)", changes),
                                bus_image_method_attach,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AttachWithExtensions",
                                SD_BUS_ARGS("as", extensions,
                                            "as", matches,
                                            "s", profile,
                                            "s", copy_mode,
                                            "t", flags),
                                SD_BUS_RESULT("a(sss)", changes),
                                bus_image_method_attach,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Detach",
                                SD_BUS_ARGS("b", runtime),
                                SD_BUS_RESULT("a(sss)", changes),
                                bus_image_method_detach,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DetachWithExtensions",
                                SD_BUS_ARGS("as", extensions,
                                            "t", flags),
                                SD_BUS_RESULT("a(sss)", changes),
                                bus_image_method_detach,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Reattach",
                                SD_BUS_ARGS("as", matches,
                                            "s", profile,
                                            "b", runtime,
                                            "s", copy_mode),
                                SD_BUS_RESULT("a(sss)", changes_removed,
                                              "a(sss)", changes_updated),
                                bus_image_method_reattach,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReattachWithExtensions",
                                SD_BUS_ARGS("as", extensions,
                                            "as", matches,
                                            "s", profile,
                                            "s", copy_mode,
                                            "t", flags),
                                SD_BUS_RESULT("a(sss)", changes_removed,
                                              "a(sss)", changes_updated),
                                bus_image_method_reattach,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Remove",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_RESULT,
                                bus_image_method_remove,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MarkReadOnly",
                                SD_BUS_ARGS("b", read_only),
                                SD_BUS_NO_RESULT,
                                bus_image_method_mark_read_only,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLimit",
                                SD_BUS_ARGS("t", limit),
                                SD_BUS_NO_RESULT,
                                bus_image_method_set_limit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        /* Deprecated silly typo */
        SD_BUS_METHOD_WITH_ARGS("ReattacheWithExtensions",
                                SD_BUS_ARGS("as", extensions,
                                            "as", matches,
                                            "s", profile,
                                            "s", copy_mode,
                                            "t", flags),
                                SD_BUS_RESULT("a(sss)", changes_removed,
                                              "a(sss)", changes_updated),
                                bus_image_method_reattach,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_HIDDEN),
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
                                polkit_action,
                                /* details= */ NULL,
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
                r = image_find(m->runtime_scope, IMAGE_PORTABLE, name_or_path, NULL, &loaded);
                if (r == -ENOENT)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_PORTABLE_IMAGE,
                                                 "No image '%s' found.", name_or_path);

                /* other errors are handled below… */
        } else {
                /* Don't accept path if this is always forbidden */
                if (mode == BUS_IMAGE_REFUSE_BY_PATH)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Expected image name, not path in place of '%s'.", name_or_path);

                if (!path_is_absolute(name_or_path))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Image name '%s' is not valid or not a valid path.", name_or_path);

                if (!path_is_normalized(name_or_path))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Image path '%s' is not normalized.", name_or_path);

                if (mode == BUS_IMAGE_AUTHENTICATE_BY_PATH) {
                        r = bus_verify_polkit_async(
                                        message,
                                        polkit_action,
                                        /* details= */ NULL,
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
                sd_bus_error_setf(error, BUS_ERROR_BAD_PORTABLE_IMAGE_TYPE,
                                  "Type of image '%s' not recognized; supported image types are directories/btrfs subvolumes, block devices, and raw disk image files with suffix '.raw'.",
                                  name_or_path);
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
        if (isempty(e))
                /* The path is "/org/freedesktop/portable1/image" itself */
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
        Manager *m = userdata;
        size_t n = 0;
        Image *image;
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

        HASHMAP_FOREACH(image, images) {
                char *p;

                r = bus_image_path(image, &p);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(l, n+2)) {
                        free(p);
                        return -ENOMEM;
                }

                l[n++] = p;
                l[n] = NULL;
        }

        *nodes = TAKE_PTR(l);

        return 1;
}

const BusObjectImplementation image_object = {
        "/org/freedesktop/portable1/image",
        "org.freedesktop.portable1.Image",
        .fallback_vtables = BUS_FALLBACK_VTABLES({image_vtable, bus_image_object_find}),
        .node_enumerator = bus_image_node_enumerator,
};
