/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>
#include <sys/mount.h>

#include "alloc-util.h"
#include "bus-get-properties.h"
#include "bus-label.h"
#include "bus-polkit.h"
#include "copy.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "image-dbus.h"
#include "io-util.h"
#include "loop-util.h"
#include "missing_capability.h"
#include "mount-util.h"
#include "os-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "strv.h"
#include "user-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, image_type, ImageType);

int bus_image_method_remove(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        Image *image = ASSERT_PTR(userdata);
        Manager *m = image->userdata;
        pid_t child;
        int r;

        assert(message);

        if (m->n_operations >= OPERATIONS_MAX)
                return sd_bus_error_set(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing operations.");

        const char *details[] = {
                "image", image->name,
                "verb", "remove",
                NULL
        };

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.machine1.manage-images",
                        details,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

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

        r = operation_new(m, NULL, child, message, errno_pipe_fd[0], NULL);
        if (r < 0) {
                (void) sigkill_wait(child);
                return r;
        }

        errno_pipe_fd[0] = -EBADF;

        return 1;
}

int bus_image_method_rename(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = ASSERT_PTR(userdata);
        Manager *m = image->userdata;
        const char *new_name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &new_name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(new_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", new_name);

        const char *details[] = {
                "image", image->name,
                "verb", "rename",
                "new_name", new_name,
                NULL
        };

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.machine1.manage-images",
                        details,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_rename(image, new_name);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_image_method_clone(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        Image *image = ASSERT_PTR(userdata);
        Manager *m = ASSERT_PTR(image->userdata);
        const char *new_name;
        int r, read_only;
        pid_t child;

        assert(message);

        if (m->n_operations >= OPERATIONS_MAX)
                return sd_bus_error_set(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing operations.");

        r = sd_bus_message_read(message, "sb", &new_name, &read_only);
        if (r < 0)
                return r;

        if (!image_name_is_valid(new_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", new_name);

        const char *details[] = {
                "image", image->name,
                "verb", "clone",
                "new_name", new_name,
                NULL
        };

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.machine1.manage-images",
                        details,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create pipe: %m");

        r = safe_fork("(sd-imgclone)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to fork(): %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                r = image_clone(image, new_name, read_only);
                if (r < 0) {
                        (void) write(errno_pipe_fd[1], &r, sizeof(r));
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = operation_new(m, NULL, child, message, errno_pipe_fd[0], NULL);
        if (r < 0) {
                (void) sigkill_wait(child);
                return r;
        }

        errno_pipe_fd[0] = -EBADF;

        return 1;
}

int bus_image_method_mark_read_only(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        int read_only, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &read_only);
        if (r < 0)
                return r;

        const char *details[] = {
                "image", image->name,
                "verb", "mark_read_only",
                "read_only", one_zero(read_only),
                NULL
        };

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.machine1.manage-images",
                        details,
                        &m->polkit_registry,
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

int bus_image_method_set_limit(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        uint64_t limit;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "t", &limit);
        if (r < 0)
                return r;
        if (!FILE_SIZE_VALID_OR_INFINITY(limit))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "New limit out of range");

        const char *details[] = {
                "machine", image->name,
                "verb", "set_limit",
                NULL
        };

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.machine1.manage-images",
                        details,
                        &m->polkit_registry,
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

int bus_image_method_get_hostname(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        int r;

        if (!image->metadata_valid) {
                r = image_read_metadata(image, &image_policy_container);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to read image metadata: %m");
        }

        return sd_bus_reply_method_return(message, "s", image->hostname);
}

int bus_image_method_get_machine_id(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Image *image = userdata;
        int r;

        if (!image->metadata_valid) {
                r = image_read_metadata(image, &image_policy_container);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to read image metadata: %m");
        }

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        if (sd_id128_is_null(image->machine_id)) /* Add an empty array if the ID is zero */
                r = sd_bus_message_append(reply, "ay", 0);
        else
                r = sd_bus_message_append_array(reply, 'y', image->machine_id.bytes, 16);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

int bus_image_method_get_machine_info(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        int r;

        if (!image->metadata_valid) {
                r = image_read_metadata(image, &image_policy_container);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to read image metadata: %m");
        }

        return bus_reply_pair_array(message, image->machine_info);
}

int bus_image_method_get_os_release(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        int r;

        if (!image->metadata_valid) {
                r = image_read_metadata(image, &image_policy_container);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to read image metadata: %m");
        }

        return bus_reply_pair_array(message, image->os_release);
}

static int image_flush_cache(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        hashmap_clear(m->image_cache);
        return 0;
}

static int image_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *e = NULL;
        Manager *m = userdata;
        Image *image = NULL;
        const char *p;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        p = startswith(path, "/org/freedesktop/machine1/image/");
        if (!p)
                return 0;

        e = bus_label_unescape(p);
        if (!e)
                return -ENOMEM;

        image = hashmap_get(m->image_cache, e);
        if (image) {
                *found = image;
                return 1;
        }

        if (!m->image_cache_defer_event) {
                r = sd_event_add_defer(m->event, &m->image_cache_defer_event, image_flush_cache, m);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(m->image_cache_defer_event, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_enabled(m->image_cache_defer_event, SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        r = image_find(IMAGE_MACHINE, e, NULL, &image);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        image->userdata = m;

        r = hashmap_ensure_put(&m->image_cache, &image_hash_ops, image->name, image);
        if (r < 0) {
                image_unref(image);
                return r;
        }

        *found = image;
        return 1;
}

char *image_bus_path(const char *name) {
        _cleanup_free_ char *e = NULL;

        assert(name);

        e = bus_label_escape(name);
        if (!e)
                return NULL;

        return strjoin("/org/freedesktop/machine1/image/", e);
}

static int image_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        _cleanup_strv_free_ char **l = NULL;
        Image *image;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        images = hashmap_new(&image_hash_ops);
        if (!images)
                return -ENOMEM;

        r = image_discover(IMAGE_MACHINE, NULL, images);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images) {
                char *p;

                p = image_bus_path(image->name);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        *nodes = TAKE_PTR(l);

        return 1;
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
        SD_BUS_METHOD("Remove", NULL, NULL, bus_image_method_remove, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Rename", "s", NULL, bus_image_method_rename, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Clone", "sb", NULL, bus_image_method_clone, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MarkReadOnly", "b", NULL, bus_image_method_mark_read_only, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLimit", "t", NULL, bus_image_method_set_limit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetHostname", NULL, "s", bus_image_method_get_hostname, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMachineID", NULL, "ay", bus_image_method_get_machine_id, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMachineInfo", NULL, "a{ss}", bus_image_method_get_machine_info, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetOSRelease", NULL, "a{ss}", bus_image_method_get_os_release, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

const BusObjectImplementation image_object = {
        "/org/freedesktop/machine1/image",
        "org.freedesktop.machine1.Image",
        .fallback_vtables = BUS_FALLBACK_VTABLES({image_vtable, image_object_find}),
        .node_enumerator = image_node_enumerator,
};
