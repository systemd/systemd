/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "discover-image.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "image.h"
#include "image-varlink.h"
#include "io-util.h"
#include "json-util.h"
#include "machined.h"
#include "operation.h"
#include "process-util.h"

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
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_NO_SUCH_IMAGE, NULL);
        if (r < 0)
                return r;

        if (manager->runtime_scope != RUNTIME_SCOPE_USER) {
                r = varlink_verify_polkit_async(
                                link,
                                manager->system_bus,
                                "org.freedesktop.machine1.manage-images",
                                (const char**) STRV_MAKE("image", image->name,
                                                         "verb", "update"),
                                &manager->polkit_registry);
                if (r <= 0)
                        return r;
        }

        if (p.new_name) {
                r = rename_image_and_update_cache(manager, image, p.new_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to rename image: %m");
        }

        if (p.read_only >= 0) {
                r = image_read_only(image, p.read_only, manager->runtime_scope);
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
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        int r;

        assert(link);
        assert(parameters);

        if (manager->n_operations >= OPERATIONS_MAX)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_TOO_MANY_OPERATIONS, NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!image_name_is_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (!image_name_is_valid(p.new_name))
                return sd_varlink_error_invalid_parameter_name(link, "newName");

        r = manager_acquire_image(manager, p.name, &image);
        if (r == -ENOENT)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_NO_SUCH_IMAGE, NULL);
        if (r < 0)
                return r;

        if (manager->runtime_scope != RUNTIME_SCOPE_USER) {
                r = varlink_verify_polkit_async(
                                link,
                                manager->system_bus,
                                "org.freedesktop.machine1.manage-images",
                                (const char**) STRV_MAKE("image", image->name,
                                                         "verb", "clone",
                                                         "new_name", p.new_name),
                                &manager->polkit_registry);
                if (r <= 0)
                        return r;
        }

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to open pipe: %m");

        r = pidref_safe_fork("(sd-imgclone)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork: %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);
                r = image_clone(image, p.new_name, p.read_only > 0, manager->runtime_scope);
                report_errno_and_exit(errno_pipe_fd[1], r);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = operation_new_with_varlink_reply(manager, /* machine= */ NULL, &child, link, errno_pipe_fd[0], /* ret= */ NULL);
        if (r < 0)
                return r;

        TAKE_PIDREF(child);
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
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        int r;

        assert(link);
        assert(parameters);

        if (manager->n_operations >= OPERATIONS_MAX)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_TOO_MANY_OPERATIONS, NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &image_name);
        if (r != 0)
                return r;

        if (!image_name_is_valid(image_name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        r = manager_acquire_image(manager, image_name, &image);
        if (r == -ENOENT)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_NO_SUCH_IMAGE, NULL);
        if (r < 0)
                return r;

        if (manager->runtime_scope != RUNTIME_SCOPE_USER) {
                r = varlink_verify_polkit_async(
                                link,
                                manager->system_bus,
                                "org.freedesktop.machine1.manage-images",
                                (const char**) STRV_MAKE("image", image->name,
                                                         "verb", "remove"),
                                &manager->polkit_registry);
                if (r <= 0)
                        return r;
        }

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to open pipe: %m");

        r = pidref_safe_fork("(sd-imgrm)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork: %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);
                r = image_remove(image, manager->runtime_scope);
                report_errno_and_exit(errno_pipe_fd[1], r);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = operation_new_with_varlink_reply(manager, /* machine= */ NULL, &child, link, errno_pipe_fd[0], /* ret= */ NULL);
        if (r < 0)
                return r;

        TAKE_PIDREF(child);
        TAKE_FD(errno_pipe_fd[0]);
        return 1;
}

int vl_method_set_pool_limit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "limit", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, 0, SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        uint64_t limit;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &limit);
        if (r != 0)
                return r;

        if (!FILE_SIZE_VALID_OR_INFINITY(limit))
                return sd_varlink_error_invalid_parameter_name(link, "limit");

        if (manager->runtime_scope != RUNTIME_SCOPE_USER) {
                r = varlink_verify_polkit_async(
                                link,
                                manager->system_bus,
                                "org.freedesktop.machine1.manage-images",
                                (const char**) STRV_MAKE("verb", "set_pool_limit"),
                                &manager->polkit_registry);
                if (r <= 0)
                        return r;
        }

        /* Set up the machine directory if necessary */
        r = image_setup_pool(
                        manager->runtime_scope,
                        IMAGE_MACHINE,
                        /* use_btrfs_subvol= */ true,
                        /* use_btrfs_quota= */ true);
        if (r < 0)
                return r;

        r = image_set_pool_limit(manager->runtime_scope, IMAGE_MACHINE, limit);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_NOT_SUPPORTED, NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int clean_pool_list_one_image(sd_varlink *link, const char *name, uint64_t usage_exclusive, bool more) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(name);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("name", name),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("usageExclusive", usage_exclusive, UINT64_MAX));
        if (r < 0)
                return r;

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

static int clean_pool_done_internal(Operation *operation, FILE *file, int child_error) {
        int r;

        assert(operation);
        assert(operation->link);

        r = clean_pool_read_first_entry(file, child_error, /* error= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to read first entry from tmp file: %m");

        /* On success the resulting temporary file will contain a list of image names that were removed followed by
         * their size on disk. Let's read that and turn it into a bus message. */
        _cleanup_free_ char *previous_name = NULL;
        uint64_t previous_usage;
        for (;;) {
                _cleanup_free_ char *name = NULL;
                uint64_t usage;
                r = clean_pool_read_next_entry(file, &name, &usage);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read next entry from tmp file: %m");
                if (r == 0)
                        break;

                if (previous_name) {
                        r = clean_pool_list_one_image(operation->link, previous_name, previous_usage, /* more= */ true);
                        if (r < 0)
                                return r;
                        /* freeing memory to avoid memleak at the following assignment */
                        previous_name = mfree(previous_name);
                }

                previous_name = TAKE_PTR(name);
                previous_usage = usage;
        }

        if (previous_name)
                return clean_pool_list_one_image(operation->link, previous_name, previous_usage, /* more= */ false);

        return sd_varlink_error(operation->link, "io.systemd.MachineImage.NoSuchImage", NULL);
}

static int clean_pool_done(Operation *operation, int child_error, sd_bus_error *error) {
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        assert(operation);
        assert(operation->link);
        assert(operation->extra_fd >= 0);

        file = take_fdopen(&operation->extra_fd, "r");
        if (!file)
                return log_debug_errno(errno, "Failed to take opened tmp file's fd: %m");

        r = clean_pool_done_internal(operation, file, child_error);
        if (r < 0) {
                r =  sd_varlink_error_errno(operation->link, r);
                if (r < 0)
                        log_debug_errno(r, "Failed to reply to varlink request, ignoring: %m");
        }

        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_image_clean_pool_mode, ImageCleanPoolMode, image_clean_pool_mode_from_string);

int vl_method_clean_pool(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "mode", SD_JSON_VARIANT_STRING, json_dispatch_image_clean_pool_mode, 0, SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        ImageCleanPoolMode mode;
        int r;

        assert(link);
        assert(parameters);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        if (manager->n_operations >= OPERATIONS_MAX)
                return sd_varlink_error(link, "io.systemd.MachineImage.TooManyOperations", NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &mode);
        if (r != 0)
                return r;

        if (manager->runtime_scope != RUNTIME_SCOPE_USER) {
                r = varlink_verify_polkit_async(
                                link,
                                manager->system_bus,
                                "org.freedesktop.machine1.manage-images",
                                (const char**) STRV_MAKE("mode", image_clean_pool_mode_to_string(mode),
                                                         "verb", "clean_pool"),
                                &manager->polkit_registry);
                if (r <= 0)
                        return r;
        }

        Operation *op;
        r = image_clean_pool_operation(manager, mode, &op);
        if (r < 0)
                return log_debug_errno(r, "Failed to clean pool of images: %m");

        operation_attach_varlink_reply(op, link);
        op->done = clean_pool_done;
        return 1;
}
