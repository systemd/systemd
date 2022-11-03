/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "btrfs-util.h"
#include "bus-common-errors.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "discover-image.h"
#include "fd-util.h"
#include "io-util.h"
#include "missing_capability.h"
#include "portable.h"
#include "portabled-bus.h"
#include "portabled-image-bus.h"
#include "portabled-image.h"
#include "portabled.h"
#include "strv.h"
#include "user-util.h"

static int property_get_pool_path(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", "/var/lib/portables");
}

static int property_get_pool_usage(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_ int fd = -1;
        uint64_t usage = UINT64_MAX;

        assert(bus);
        assert(reply);

        fd = open("/var/lib/portables", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd >= 0) {
                BtrfsQuotaInfo q;

                if (btrfs_subvol_get_subtree_quota_fd(fd, 0, &q) >= 0)
                        usage = q.referenced;
        }

        return sd_bus_message_append(reply, "t", usage);
}

static int property_get_pool_limit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_ int fd = -1;
        uint64_t size = UINT64_MAX;

        assert(bus);
        assert(reply);

        fd = open("/var/lib/portables", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd >= 0) {
                BtrfsQuotaInfo q;

                if (btrfs_subvol_get_subtree_quota_fd(fd, 0, &q) >= 0)
                        size = q.referenced_max;
        }

        return sd_bus_message_append(reply, "t", size);
}

static int property_get_profiles(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = portable_get_profiles(&l);
        if (r < 0)
                return r;

        return sd_bus_message_append_strv(reply, l);
}

static int method_get_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Image *image;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_image_acquire(m, message, name, NULL, BUS_IMAGE_REFUSE_BY_PATH, NULL, &image, error);
        if (r < 0)
                return r;

        r = bus_image_path(image, &p);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_list_images(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Image *image;
        int r;

        assert(message);

        images = hashmap_new(&image_hash_ops);
        if (!images)
                return -ENOMEM;

        r = manager_image_cache_discover(m, images, error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssbtttso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images) {
                _cleanup_(sd_bus_error_free) sd_bus_error error_state = SD_BUS_ERROR_NULL;
                PortableState state = _PORTABLE_STATE_INVALID;
                _cleanup_free_ char *p = NULL;

                r = bus_image_path(image, &p);
                if (r < 0)
                        return r;

                r = portable_get_state(
                                sd_bus_message_get_bus(message),
                                image->path,
                                NULL,
                                0,
                                &state,
                                &error_state);
                if (r < 0)
                        log_debug_errno(r, "Failed to get state of image '%s', ignoring: %s",
                                        image->path, bus_error_message(&error_state, r));

                r = sd_bus_message_append(reply, "(ssbtttso)",
                                          image->name,
                                          image_type_to_string(image->type),
                                          image->read_only,
                                          image->crtime,
                                          image->mtime,
                                          image->usage,
                                          portable_state_to_string(state),
                                          p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int redirect_method_to_image(
                Manager *m,
                sd_bus_message *message,
                sd_bus_error *error,
                int (*method)(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error* error)) {

        const char *name_or_path;
        int r;

        assert(m);
        assert(message);
        assert(method);

        r = sd_bus_message_read(message, "s", &name_or_path);
        if (r < 0)
                return r;

        return method(m, message, name_or_path, NULL, error);
}

static int method_get_image_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(userdata, message, error, bus_image_common_get_os_release);
}

static int method_get_image_metadata(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(userdata, message, error, bus_image_common_get_metadata);
}

static int method_get_image_state(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **extension_images = NULL;
        const char *name_or_path;
        PortableState state;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name_or_path);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "GetImageStateWithExtensions")) {
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
                        sd_bus_message_get_bus(message),
                        name_or_path,
                        extension_images,
                        0,
                        &state,
                        error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", portable_state_to_string(state));
}

static int method_attach_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(userdata, message, error, bus_image_common_attach);
}

static int method_detach_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **extension_images = NULL;
        PortableChange *changes = NULL;
        PortableFlags flags = 0;
        Manager *m = ASSERT_PTR(userdata);
        size_t n_changes = 0;
        const char *name_or_path;
        int r;

        assert(message);

        /* Note that we do not redirect detaching to the image object here, because we want to allow that users can
         * detach already deleted images too, in case the user already deleted an image before properly detaching
         * it. */

        r = sd_bus_message_read(message, "s", &name_or_path);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "DetachImageWithExtensions")) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read_strv(message, &extension_images);
                if (r < 0)
                        return r;

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
                        name_or_path,
                        extension_images,
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

static int method_reattach_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(userdata, message, error, bus_image_common_reattach);
}

static int method_remove_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(userdata, message, error, bus_image_common_remove);
}

static int method_mark_image_read_only(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(userdata, message, error, bus_image_common_mark_read_only);
}

static int method_set_image_limit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(userdata, message, error, bus_image_common_set_limit);
}

static int method_set_pool_limit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint64_t limit;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "t", &limit);
        if (r < 0)
                return r;
        if (!FILE_SIZE_VALID_OR_INFINITY(limit))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "New limit out of range");

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.portable1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        (void) btrfs_qgroup_set_limit("/var/lib/portables", 0, limit);

        r = btrfs_subvol_set_subtree_quota_limit("/var/lib/portables", 0, limit);
        if (r == -ENOTTY)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Quota is only supported on btrfs.");
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to adjust quota limit: %m");

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("PoolPath", "s", property_get_pool_path, 0, 0),
        SD_BUS_PROPERTY("PoolUsage", "t", property_get_pool_usage, 0, 0),
        SD_BUS_PROPERTY("PoolLimit", "t", property_get_pool_limit, 0, 0),
        SD_BUS_PROPERTY("Profiles", "as", property_get_profiles, 0, 0),
        SD_BUS_METHOD_WITH_ARGS("GetImage",
                                SD_BUS_ARGS("s", image),
                                SD_BUS_RESULT("o", object),
                                method_get_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListImages",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(ssbtttso)", images),
                                method_list_images,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageOSRelease",
                                SD_BUS_ARGS("s", image),
                                SD_BUS_RESULT("a{ss}", os_release),
                                method_get_image_os_release,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageMetadata",
                                SD_BUS_ARGS("s", image,
                                            "as", matches),
                                SD_BUS_RESULT("s", image,
                                              "ay", os_release,
                                              "a{say}", units),
                                method_get_image_metadata,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageMetadataWithExtensions",
                                SD_BUS_ARGS("s", image,
                                            "as", extensions,
                                            "as", matches,
                                            "t", flags),
                                SD_BUS_RESULT("s", image,
                                              "ay", os_release,
                                              "a{say}", extensions,
                                              "a{say}", units),
                                method_get_image_metadata,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageState",
                                SD_BUS_ARGS("s", image),
                                SD_BUS_RESULT("s", state),
                                method_get_image_state,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageStateWithExtensions",
                                SD_BUS_ARGS("s", image,
                                            "as", extensions,
                                            "t", flags),
                                SD_BUS_RESULT("s", state),
                                method_get_image_state,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AttachImage",
                                SD_BUS_ARGS("s", image,
                                            "as", matches,
                                            "s", profile,
                                            "b", runtime,
                                            "s", copy_mode),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_attach_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AttachImageWithExtensions",
                                SD_BUS_ARGS("s", image,
                                            "as", extensions,
                                            "as", matches,
                                            "s", profile,
                                            "s", copy_mode,
                                            "t", flags),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_attach_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DetachImage",
                                SD_BUS_ARGS("s", image,
                                            "b", runtime),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_detach_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DetachImageWithExtensions",
                                SD_BUS_ARGS("s", image,
                                            "as", extensions,
                                            "t", flags),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_detach_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReattachImage",
                                SD_BUS_ARGS("s", image,
                                            "as", matches,
                                            "s", profile,
                                            "b", runtime,
                                            "s", copy_mode),
                                SD_BUS_RESULT("a(sss)", changes_removed,
                                              "a(sss)", changes_updated),
                                method_reattach_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReattachImageWithExtensions",
                                SD_BUS_ARGS("s", image,
                                            "as", extensions,
                                            "as", matches,
                                            "s", profile,
                                            "s", copy_mode,
                                            "t", flags),
                                SD_BUS_RESULT("a(sss)", changes_removed,
                                              "a(sss)", changes_updated),
                                method_reattach_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RemoveImage",
                                SD_BUS_ARGS("s", image),
                                SD_BUS_NO_RESULT,
                                method_remove_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MarkImageReadOnly",
                                SD_BUS_ARGS("s", image,
                                            "b", read_only),
                                SD_BUS_NO_RESULT,
                                method_mark_image_read_only,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetImageLimit",
                                SD_BUS_ARGS("s", image,
                                            "t", limit),
                                SD_BUS_NO_RESULT,
                                method_set_image_limit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetPoolLimit",
                                SD_BUS_ARGS("t", limit),
                                SD_BUS_NO_RESULT,
                                method_set_pool_limit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

const BusObjectImplementation manager_object = {
        "/org/freedesktop/portable1",
        "org.freedesktop.portable1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
        .children = BUS_IMPLEMENTATIONS(&image_object),
};

static int reply_portable_compose_message(sd_bus_message *reply, const PortableChange *changes, size_t n_changes) {
        size_t i;
        int r;

        assert(reply);
        assert(changes || n_changes == 0);

        r = sd_bus_message_open_container(reply, 'a', "(sss)");
        if (r < 0)
                return r;

        for (i = 0; i < n_changes; i++) {
                if (changes[i].type_or_errno < 0)
                        continue;

                r = sd_bus_message_append(reply, "(sss)",
                                          portable_change_type_to_string(changes[i].type_or_errno),
                                          changes[i].path,
                                          changes[i].source);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return 0;
}

int reply_portable_changes(sd_bus_message *m, const PortableChange *changes, size_t n_changes) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(m);

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = reply_portable_compose_message(reply, changes, n_changes);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

int reply_portable_changes_pair(
                sd_bus_message *m,
                const PortableChange *changes_first,
                size_t n_changes_first,
                const PortableChange *changes_second,
                size_t n_changes_second) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(m);

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = reply_portable_compose_message(reply, changes_first, n_changes_first);
        if (r < 0)
                return r;

        r = reply_portable_compose_message(reply, changes_second, n_changes_second);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}
