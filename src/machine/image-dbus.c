/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/file.h>
#include <sys/mount.h>

#include "alloc-util.h"
#include "bus-label.h"
#include "bus-util.h"
#include "copy.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "image-dbus.h"
#include "io-util.h"
#include "loop-util.h"
#include "machine-image.h"
#include "mount-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "strv.h"
#include "user-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, image_type, ImageType);

int bus_image_method_remove(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        Image *image = userdata;
        Manager *m = image->userdata;
        pid_t child;
        int r;

        assert(message);
        assert(image);

        if (m->n_operations >= OPERATIONS_MAX)
                return sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing operations.");

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create pipe: %m");

        child = fork();
        if (child < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to fork(): %m");
        if (child == 0) {
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

        errno_pipe_fd[0] = -1;

        return 1;
}

int bus_image_method_rename(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        const char *new_name;
        int r;

        assert(message);
        assert(image);

        r = sd_bus_message_read(message, "s", &new_name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(new_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", new_name);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
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

        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        Image *image = userdata;
        Manager *m = image->userdata;
        const char *new_name;
        int r, read_only;
        pid_t child;

        assert(message);
        assert(image);
        assert(m);

        if (m->n_operations >= OPERATIONS_MAX)
                return sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing operations.");

        r = sd_bus_message_read(message, "sb", &new_name, &read_only);
        if (r < 0)
                return r;

        if (!image_name_is_valid(new_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", new_name);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create pipe: %m");

        child = fork();
        if (child < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to fork(): %m");
        if (child == 0) {
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

        errno_pipe_fd[0] = -1;

        return 1;
}

int bus_image_method_mark_read_only(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        int r, read_only;

        assert(message);

        r = sd_bus_message_read(message, "b", &read_only);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
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
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "New limit out of range");

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
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

#define EXIT_NOT_FOUND 2

static int directory_image_get_os_release(Image *image, char ***ret, sd_bus_error *error) {

        _cleanup_free_ char *path = NULL;
        int r;

        assert(image);
        assert(ret);

        r = chase_symlinks("/etc/os-release", image->path, CHASE_PREFIX_ROOT, &path);
        if (r == -ENOENT)
                r = chase_symlinks("/usr/lib/os-release", image->path, CHASE_PREFIX_ROOT, &path);
        if (r == -ENOENT)
                return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Image does not contain OS release information");
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to resolve %s: %m", image->path);

        r = load_env_file_pairs(NULL, path, NULL, ret);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to open %s: %m", path);

        return 0;
}

static int raw_image_get_os_release(Image *image, char ***ret, sd_bus_error *error) {
        _cleanup_(rmdir_and_freep) char *t = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_(sigkill_waitp) pid_t child = 0;
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **v = NULL;
        siginfo_t si;
        int r;

        assert(image);
        assert(ret);

        r = mkdtemp_malloc("/tmp/machined-root-XXXXXX", &t);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to create temporary directory: %m");

        r = loop_device_make_by_path(image->path, O_RDONLY, &d);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to set up loop block device for %s: %m", image->path);

        r = dissect_image(d->fd, NULL, 0, DISSECT_IMAGE_REQUIRE_ROOT, &m);
        if (r == -ENOPKG)
                return sd_bus_error_set_errnof(error, r, "Disk image %s not understood: %m", image->path);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to dissect image %s: %m", image->path);

        if (pipe2(pair, O_CLOEXEC) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create communication pipe: %m");

        child = raw_clone(SIGCHLD|CLONE_NEWNS);
        if (child < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to fork(): %m");

        if (child == 0) {
                int fd;

                pair[0] = safe_close(pair[0]);

                /* Make sure we never propagate to the host */
                if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
                        _exit(EXIT_FAILURE);

                r = dissected_image_mount(m, t, DISSECT_IMAGE_READ_ONLY);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                r = mount_move_root(t);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                fd = open("/etc/os-release", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0 && errno == ENOENT) {
                        fd = open("/usr/lib/os-release", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (fd < 0 && errno == ENOENT)
                                _exit(EXIT_NOT_FOUND);
                }
                if (fd < 0)
                        _exit(EXIT_FAILURE);

                r = copy_bytes(fd, pair[1], (uint64_t) -1, 0);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        f = fdopen(pair[0], "re");
        if (!f)
                return -errno;

        pair[0] = -1;

        r = load_env_file_pairs(f, "os-release", NULL, &v);
        if (r < 0)
                return r;

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to wait for child: %m");
        child = 0;
        if (si.si_code == CLD_EXITED && si.si_status == EXIT_NOT_FOUND)
                return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Image does not contain OS release information");
        if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS)
                return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Child died abnormally.");

        *ret = v;
        v = NULL;

        return 0;
}

int bus_image_method_get_os_release(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_release_lock_file_ LockFile tree_global_lock = LOCK_FILE_INIT, tree_local_lock = LOCK_FILE_INIT;
        _cleanup_strv_free_ char **v = NULL;
        Image *image = userdata;
        int r;

        r = image_path_lock(image->path, LOCK_SH|LOCK_NB, &tree_global_lock, &tree_local_lock);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to lock image: %m");

        switch (image->type) {

        case IMAGE_DIRECTORY:
        case IMAGE_SUBVOLUME:
                r = directory_image_get_os_release(image, &v, error);
                break;

        case IMAGE_RAW:
                r = raw_image_get_os_release(image, &v, error);
                break;

        default:
                assert_not_reached("Unknown image type");
        }
        if (r < 0)
                return r;

        return bus_reply_pair_array(message, v);
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
        SD_BUS_METHOD("GetOSRelease", NULL, "a{ss}", bus_image_method_get_os_release, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

static int image_flush_cache(sd_event_source *s, void *userdata) {
        Manager *m = userdata;
        Image *i;

        assert(s);
        assert(m);

        while ((i = hashmap_steal_first(m->image_cache)))
                image_unref(i);

        return 0;
}

int image_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
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

        r = hashmap_ensure_allocated(&m->image_cache, &string_hash_ops);
        if (r < 0)
                return r;

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

        r = image_find(e, &image);
        if (r <= 0)
                return r;

        image->userdata = m;

        r = hashmap_put(m->image_cache, image->name, image);
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

        return strappend("/org/freedesktop/machine1/image/", e);
}

int image_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_(image_hashmap_freep) Hashmap *images = NULL;
        _cleanup_strv_free_ char **l = NULL;
        Image *image;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        images = hashmap_new(&string_hash_ops);
        if (!images)
                return -ENOMEM;

        r = image_discover(images);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images, i) {
                char *p;

                p = image_bus_path(image->name);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        *nodes = l;
        l = NULL;

        return 1;
}
