/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "fd-util.h"
#include "image-varlink.h"
#include "machine.h"
#include "string-util.h"

typedef struct ImageUpdateParameters {
        const char *name;
        const char *new_name;
        int read_only;
        uint64_t limit;
} ImageUpdateParameters;

#define IMAGE_UPDATE_PARAMETERS_NULL \
        (ImageUpdateParameters) {    \
                .read_only = -1,     \
                .limit = UINT64_MAX, \
        }

int vl_method_update_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(ImageUpdateParameters, name),      SD_JSON_MANDATORY },
                { "newName",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(ImageUpdateParameters, new_name),  0                 },
                { "readOnly", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     offsetof(ImageUpdateParameters, read_only), 0                 },
                { "limit",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(ImageUpdateParameters, limit),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        ImageUpdateParameters p = IMAGE_UPDATE_PARAMETERS_NULL;
        Image *image;
        int r, ret = 0;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!image_name_is_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (p.new_name && !image_name_is_valid(p.new_name))
                return sd_varlink_error_invalid_parameter_name(link, "newName");

        r = manager_acquire_image(manager, p.name, &image);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.MachineImage.NoSuchImage", NULL);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-images",
                        (const char**) STRV_MAKE("image", image->name,
                                                 "verb", "update"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (p.new_name) {
                r = rename_image_and_update_cache(manager, image, p.new_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to rename image: %m");
        }

        if (p.read_only >= 0) {
                r = image_read_only(image, p.read_only);
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to toggle image read only, ignoring: %m"));
        }

        if (p.limit != UINT64_MAX) {
                r = image_set_limit(image, p.limit);
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to set image limit, ignoring: %m"));
        }

        /* We intentionally swallowed errors from image_read_only() and image_set_limit(). Here we return first one to the user if any */
        if (ret < 0)
                return ret;

        return sd_varlink_reply(link, NULL);
}

int vl_method_clone_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",     SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(ImageUpdateParameters, name),      SD_JSON_MANDATORY },
                { "newName",  SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(ImageUpdateParameters, new_name),  SD_JSON_MANDATORY },
                { "readOnly", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     offsetof(ImageUpdateParameters, read_only), 0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        ImageUpdateParameters p = IMAGE_UPDATE_PARAMETERS_NULL;
        Image *image;
        pid_t child;
        int r;

        assert(link);
        assert(parameters);

        if (manager->n_operations >= OPERATIONS_MAX)
                return sd_varlink_error(link, "io.systemd.MachineImage.TooManyOperations", NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!image_name_is_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (!image_name_is_valid(p.new_name))
                return sd_varlink_error_invalid_parameter_name(link, "newName");

        r = manager_acquire_image(manager, p.name, &image);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.MachineImage.NoSuchImage", NULL);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-images",
                        (const char**) STRV_MAKE("image", image->name,
                                                 "verb", "clone",
                                                 "new_name", p.new_name),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to open pipe: %m");

        r = safe_fork("(sd-imgclone)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork: %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);
                r = image_clone(image, p.new_name, p.read_only > 0);
                report_errno_and_exit(errno_pipe_fd[1], r);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = operation_new_with_varlink_reply(manager, /* machine= */ NULL, child, link, errno_pipe_fd[0], /* ret= */ NULL);
        if (r < 0) {
                sigkill_wait(child);
                return r;
        }

        TAKE_FD(errno_pipe_fd[0]);
        return 1;
}

int vl_method_remove_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        const char *image_name;
        Image *image;
        pid_t child;
        int r;

        assert(link);
        assert(parameters);

        if (manager->n_operations >= OPERATIONS_MAX)
                return sd_varlink_error(link, "io.systemd.MachineImage.TooManyOperations", NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &image_name);
        if (r != 0)
                return r;

        if (!image_name_is_valid(image_name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        r = manager_acquire_image(manager, image_name, &image);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.MachineImage.NoSuchImage", NULL);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-images",
                        (const char**) STRV_MAKE("image", image->name,
                                                 "verb", "remove"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to open pipe: %m");

        r = safe_fork("(sd-imgrm)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork: %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);
                r = image_remove(image);
                report_errno_and_exit(errno_pipe_fd[1], r);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = operation_new_with_varlink_reply(manager, /* machine= */ NULL, child, link, errno_pipe_fd[0], /* ret= */ NULL);
        if (r < 0) {
                sigkill_wait(child);
                return r;
        }

        TAKE_FD(errno_pipe_fd[0]);
        return 1;
}
