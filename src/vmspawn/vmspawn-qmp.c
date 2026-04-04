/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "bus-polkit.h"
#include "ether-addr-util.h"
#include "errno-util.h"
#include "json-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-io.systemd.MachineInstance.h"
#include "varlink-io.systemd.QemuMachineInstance.h"
#include "varlink-io.systemd.VirtualMachineInstance.h"
#include "varlink-util.h"
#include "vmspawn-qmp.h"

struct VmspawnQmpContext {
        sd_varlink_server *varlink_server;
        QmpClient *qmp_client;
        /* Each entry holds one ref on the sd_varlink* key (taken in vl_method_subscribe_events,
         * released in vl_disconnect / on_qmp_disconnect / vmspawn_qmp_context_free).
         * The value is an owned strv filter (NULL means all events). */
        Hashmap *subscribed;
        Hashmap *polkit_registry;
        RuntimeScope runtime_scope;
        uid_t owner_uid;
};

static int vmspawn_verify_polkit(sd_varlink *link, VmspawnQmpContext *ctx, const char *verb) {
        assert(link);
        assert(ctx);

        if (ctx->runtime_scope == RUNTIME_SCOPE_USER)
                return 1; /* User scope: always authorized */

        return varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL, /* auto-opens system bus */
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("verb", verb),
                        ctx->owner_uid,
                        /* flags= */ 0,
                        &ctx->polkit_registry);
}

/* Translate a QMP async completion into a varlink error reply */
static void qmp_error_to_varlink(sd_varlink *link, const char *error_class, int error) {
        assert(link);

        if (ERRNO_IS_DISCONNECT(error))
                (void) sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
        else if (error == -EIO && streq_ptr(error_class, "CommandNotFound"))
                (void) sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
        else {
                if (error == -EIO)
                        log_warning("QMP command failed with error class '%s'", strna(error_class));
                (void) sd_varlink_error_errno(link, error);
        }
}

/* Shared async completion for simple QMP commands that return no data */
static void on_qmp_simple_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_class,
                int error,
                void *userdata) {

        sd_varlink *link = ASSERT_PTR(userdata);

        if (error == 0)
                (void) sd_varlink_reply(link, NULL);
        else
                qmp_error_to_varlink(link, error_class, error);

        sd_varlink_unref(link);
}

static const sd_json_dispatch_field polkit_dispatch_table[] = {
        VARLINK_DISPATCH_POLKIT_FIELD,
        {},
};

static int qmp_execute_simple_async(
                sd_varlink *link,
                sd_json_variant *parameters,
                VmspawnQmpContext *ctx,
                const char *polkit_verb,
                const char *qmp_command) {

        int r;

        assert(link);
        assert(ctx);
        assert(polkit_verb);
        assert(qmp_command);

        r = sd_varlink_dispatch(link, parameters, polkit_dispatch_table, NULL);
        if (r != 0)
                return r;

        r = vmspawn_verify_polkit(link, ctx, polkit_verb);
        if (r <= 0)
                return r;

        sd_varlink_ref(link);

        r = qmp_client_execute(ctx->qmp_client, qmp_command, /* arguments= */ NULL, on_qmp_simple_complete, link);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        return 0; /* Reply deferred to callback */
}

static int vl_method_terminate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "terminate", "quit");
}

static int vl_method_pause(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "pause", "stop");
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "resume", "cont");
}

static int vl_method_power_off(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "power_off", "system_powerdown");
}

static int vl_method_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "reboot", "system_reset");
}

/* Async completion for query-status: extract running/status from QMP result */
static void on_qmp_query_status_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_class,
                int error,
                void *userdata) {

        sd_varlink *link = ASSERT_PTR(userdata);

        if (error != 0) {
                qmp_error_to_varlink(link, error_class, error);
                sd_varlink_unref(link);
                return;
        }

        sd_json_variant *running = sd_json_variant_by_key(result, "running");
        sd_json_variant *status = sd_json_variant_by_key(result, "status");

        (void) sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", running ? sd_json_variant_boolean(running) : false),
                        SD_JSON_BUILD_PAIR_STRING("status", status && sd_json_variant_is_string(status) ? sd_json_variant_string(status) : "unknown"));

        sd_varlink_unref(link);
}

static int vl_method_query_status(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = sd_varlink_dispatch(link, parameters, polkit_dispatch_table, NULL);
        if (r != 0)
                return r;

        r = vmspawn_verify_polkit(link, ctx, "query_status");
        if (r <= 0)
                return r;

        sd_varlink_ref(link);

        r = qmp_client_execute(ctx->qmp_client, "query-status", /* arguments= */ NULL, on_qmp_query_status_complete, link);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        return 0;
}

static int vl_method_subscribe_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        struct {
                char **filter;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "filter", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv, 0, SD_JSON_NULLABLE },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = vmspawn_verify_polkit(link, ctx, "subscribe_events");
        if (r <= 0) {
                strv_free(p.filter);
                return r;
        }

        /* SD_VARLINK_REQUIRES_MORE in the IDL rejects non-streaming callers before we get here */

        _cleanup_strv_free_ char **filter = TAKE_PTR(p.filter);

        r = hashmap_ensure_put(&ctx->subscribed, &trivial_hash_ops, link, filter);
        if (r < 0)
                return r;

        TAKE_PTR(filter);

        sd_varlink_ref(link);

        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("ready", true));
        if (r < 0) {
                strv_free(hashmap_remove(ctx->subscribed, link));
                sd_varlink_unref(link);
                return r;
        }

        return 0;
}

static int vl_method_acquire_qmp(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = sd_varlink_dispatch(link, parameters, polkit_dispatch_table, NULL);
        if (r != 0)
                return r;

        r = vmspawn_verify_polkit(link, ctx, "acquire_qmp");
        if (r <= 0)
                return r;

        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        void *key = NULL;

        assert(server);
        assert(link);

        /* hashmap_remove2() returns the VALUE and sets *ret to the KEY */
        strv_free(hashmap_remove2(ctx->subscribed, link, &key));
        if (key)
                sd_varlink_unref(link);
}

static void on_qmp_event(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata) {

        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *notification = NULL;
        sd_varlink *link;
        char **filter;
        int r;

        assert(client);
        assert(event);

        if (hashmap_isempty(ctx->subscribed))
                return;

        r = sd_json_buildo(
                        &notification,
                        SD_JSON_BUILD_PAIR_STRING("event", event),
                        SD_JSON_BUILD_PAIR_CONDITION(!!data, "data", SD_JSON_BUILD_VARIANT(data)));
        if (r < 0) {
                log_warning_errno(r, "Failed to build event notification, ignoring: %m");
                return;
        }

        HASHMAP_FOREACH_KEY(filter, link, ctx->subscribed) {
                if (filter && !strv_contains(filter, event))
                        continue;

                r = sd_varlink_notify(link, notification);
                if (r < 0)
                        log_warning_errno(r, "Failed to notify event subscriber, ignoring: %m");
        }
}

static void on_qmp_disconnect(QmpClient *client, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        sd_varlink *link;
        void *v;

        assert(client);

        log_debug("QMP connection lost");

        /* Send terminal errors first while all links are still alive */
        HASHMAP_FOREACH_KEY(v, link, ctx->subscribed)
                (void) sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);

        /* Then drain the hashmap: steal entries one at a time so each is removed before
         * its value is freed. Use hashmap_isempty() as the loop guard because
         * hashmap_steal_first_key_and_value() returns the value which may be NULL
         * for unfiltered subscriptions. */
        while (!hashmap_isempty(ctx->subscribed)) {
                strv_free(hashmap_steal_first_key_and_value(ctx->subscribed, (void**) &link));
                sd_varlink_unref(link);
        }

        ctx->subscribed = hashmap_free(ctx->subscribed);
}

/* Detect QEMU features via schema introspection. query-qmp-schema returns all QAPI types;
 * conditionally compiled enum values (like io_uring in BlockdevAioOptions) are only present
 * if QEMU was built with support for them. */
static int qmp_detect_features(QmpClient *qmp, QemuFeatures *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;
        int r;

        assert(qmp);
        assert(ret);

        *ret = (QemuFeatures) { .io_uring = -1 };

        r = qmp_client_call(qmp, "query-qmp-schema", /* arguments= */ NULL, &schema, /* ret_error= */ NULL);
        if (r < 0)
                return r;

        ret->io_uring = 0; /* Schema probed successfully, assume unavailable until found */

        sd_json_variant *entry;
        JSON_VARIANT_ARRAY_FOREACH(entry, schema) {
                sd_json_variant *name = sd_json_variant_by_key(entry, "name");
                if (!streq_ptr(sd_json_variant_string(name), "BlockdevAioOptions"))
                        continue;

                sd_json_variant *meta = sd_json_variant_by_key(entry, "meta-type");
                if (!streq_ptr(sd_json_variant_string(meta), "enum"))
                        break;

                sd_json_variant *members = sd_json_variant_by_key(entry, "members");
                sd_json_variant *member;
                JSON_VARIANT_ARRAY_FOREACH(member, members) {
                        sd_json_variant *mname = sd_json_variant_by_key(member, "name");
                        if (streq_ptr(sd_json_variant_string(mname), "io_uring")) {
                                ret->io_uring = 1;
                                break;
                        }
                }
                break;
        }

        log_debug("QEMU feature detection: io_uring=%s", ret->io_uring > 0 ? "yes" : ret->io_uring < 0 ? "unprobed" : "no");
        return 0;
}

/* Build blockdev-add JSON for the protocol-level (file) node */
static int qmp_build_blockdev_add_file(
                const char *node_name,
                const char *filename,
                const char *driver,
                bool io_uring,
                bool read_only,
                sd_json_variant **ret) {

        assert(node_name);
        assert(filename);
        assert(driver);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", driver),
                        SD_JSON_BUILD_PAIR_STRING("filename", filename),
                        SD_JSON_BUILD_PAIR_CONDITION(read_only, "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(io_uring, "aio", SD_JSON_BUILD_STRING("io_uring")));
}

/* Build blockdev-add JSON for the format-level node */
static int qmp_build_blockdev_add_format(
                const char *node_name,
                const char *format,
                const char *file_node_name,
                bool read_only,
                bool discard,
                const char *backing,
                sd_json_variant **ret) {

        assert(node_name);
        assert(format);
        assert(file_node_name);
        assert(ret);

        /* When "file" is a string (not an object), QEMU interprets it as a reference to an
         * existing node-name. The "backing" field likewise references a format-level node. */
        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", format),
                        SD_JSON_BUILD_PAIR_STRING("file", file_node_name),
                        SD_JSON_BUILD_PAIR_CONDITION(read_only, "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(discard, "discard", SD_JSON_BUILD_STRING("unmap")),
                        SD_JSON_BUILD_PAIR_CONDITION(!!backing, "backing", SD_JSON_BUILD_STRING(backing)));
}

/* Build device_add JSON arguments for a drive */
static int qmp_build_device_add(const QmpDriveInfo *drive, sd_json_variant **ret) {
        assert(drive);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("driver", drive->disk_driver),
                        SD_JSON_BUILD_PAIR_STRING("drive", drive->node_name),
                        SD_JSON_BUILD_PAIR_STRING("id", drive->node_name),
                        SD_JSON_BUILD_PAIR_CONDITION(drive->boot, "bootindex", SD_JSON_BUILD_STRING("1")),
                        SD_JSON_BUILD_PAIR_CONDITION(!!drive->serial, "serial", SD_JSON_BUILD_STRING(drive->serial)),
                        SD_JSON_BUILD_PAIR_CONDITION(STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd"),
                                                    "bus", SD_JSON_BUILD_STRING("vmspawn_scsi.0")));
}

/* Issue blockdev-add for a file node, with io_uring fallback */
static int qmp_add_file_node(QmpClient *qmp, const char *node_name, const char *filename,
                             const char *driver, bool read_only, QemuFeatures *features) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        r = qmp_build_blockdev_add_file(node_name, filename, driver, features->io_uring != 0, read_only, &args);
        if (r < 0)
                return r;

        r = qmp_client_call(qmp, "blockdev-add", args, /* ret_result= */ NULL, &error_class);
        if (r == -EIO && features->io_uring != 0) {
                log_debug("blockdev-add with aio=io_uring failed for '%s' (%s), retrying without",
                          filename, strna(error_class));

                args = sd_json_variant_unref(args);
                error_class = mfree(error_class);

                r = qmp_build_blockdev_add_file(node_name, filename, driver, /* io_uring= */ false, read_only, &args);
                if (r < 0)
                        return r;

                r = qmp_client_call(qmp, "blockdev-add", args, /* ret_result= */ NULL, &error_class);
                features->io_uring = 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to add file node '%s': %s", filename, strna(error_class));

        return 0;
}

/* Get the virtual size of an image from the fd directly. For raw images the virtual size
 * equals the file/device size. For qcow2 the virtual size is a big-endian uint64 at header
 * offset 24 (the "size" field in the qcow2 header). */
static int get_image_virtual_size(int fd, const char *format, bool is_block_device, uint64_t *ret) {
        assert(fd >= 0);
        assert(format);
        assert(ret);

        if (streq(format, "raw")) {
                if (is_block_device)
                        return blockdev_get_device_size(fd, ret);

                struct stat st;
                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat image: %m");

                *ret = st.st_size;
                return 0;
        }

        if (streq(format, "qcow2")) {
                uint64_t size_be;
                ssize_t n = pread(fd, &size_be, sizeof(size_be), 24);
                if (n < 0)
                        return log_error_errno(errno, "Failed to read qcow2 header: %m");
                if (n != sizeof(size_be))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read on qcow2 header");

                *ret = be64toh(size_be);
                return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported image format '%s'", format);
}

/* Run blockdev-create synchronously: issue the command and wait for the job to conclude
 * via JOB_STATUS_CHANGE events. */
static int qmp_blockdev_create_and_wait(QmpClient *qmp, sd_json_variant *options, const char *job_id) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(options);
        assert(job_id);

        r = sd_json_buildo(&cmd_args,
                        SD_JSON_BUILD_PAIR_STRING("job-id", job_id),
                        SD_JSON_BUILD_PAIR_VARIANT("options", options));
        if (r < 0)
                return log_error_errno(r, "Failed to build blockdev-create JSON: %m");

        r = qmp_client_call(qmp, "blockdev-create", cmd_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to start blockdev-create job '%s': %s", job_id, strna(error_class));

        error_class = mfree(error_class);
        r = qmp_client_job_wait(qmp, job_id, &error_class);
        if (r < 0)
                return log_error_errno(r, "blockdev-create job '%s' failed: %s", job_id, strna(error_class));

        return 0;
}

/* Configure a single drive via QMP. Uses add-fd to pass pre-opened fds, split
 * file/format blockdev-add nodes, and blockdev-create for ephemeral overlays. */
static int qmp_setup_one_drive(QmpClient *qmp, const QmpDriveInfo *drive, QemuFeatures *features) {
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(drive);
        assert(drive->fd >= 0);

        bool ephemeral = drive->overlay_fd >= 0;

        if (ephemeral) {
                /* Ephemeral mode: base image (read-only) + anonymous qcow2 overlay (read-write).
                 * Node names: <name>-base-file, <name>-base-fmt, <name>-overlay-file, <name> */
                const char *base_file_node = strjoina(drive->node_name, "-base-file");
                const char *base_fmt_node = strjoina(drive->node_name, "-base-fmt");
                const char *overlay_file_node = strjoina(drive->node_name, "-overlay-file");

                /* Step 1-2: Pass both fds to QEMU */
                _cleanup_(qmp_fdset_done) QmpFdset base_fdset = {};
                r = qmp_client_fdset_new(qmp, drive->fd, &base_fdset);
                if (r < 0)
                        return r;

                _cleanup_(qmp_fdset_done) QmpFdset overlay_fdset = {};
                r = qmp_client_fdset_new(qmp, drive->overlay_fd, &overlay_fdset);
                if (r < 0)
                        return r;

                /* Step 3: Base image file node (read-only) */
                r = qmp_add_file_node(qmp, base_file_node, base_fdset.path,
                                      drive->is_block_device ? "host_device" : "file",
                                      /* read_only= */ true, features);
                if (r < 0)
                        return r;

                /* Step 4: Base image format node (read-only) */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *base_fmt_args = NULL;
                r = qmp_build_blockdev_add_format(base_fmt_node, drive->format, base_file_node,
                                                  /* read_only= */ true, /* discard= */ false, /* backing= */ NULL, &base_fmt_args);
                if (r < 0)
                        return r;

                r = qmp_client_call(qmp, "blockdev-add", base_fmt_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add base format node for '%s': %s",
                                               drive->path, strna(error_class));

                /* Step 5: Overlay file node (read-write) */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *overlay_file_args = NULL;
                r = qmp_build_blockdev_add_file(overlay_file_node, overlay_fdset.path, "file",
                                                /* io_uring= */ false, /* read_only= */ false, &overlay_file_args);
                if (r < 0)
                        return r;

                error_class = mfree(error_class);
                r = qmp_client_call(qmp, "blockdev-add", overlay_file_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add overlay file node for '%s': %s",
                                               drive->path, strna(error_class));

                /* Step 6: Get base image virtual size directly from the fd */
                uint64_t virtual_size;
                r = get_image_virtual_size(drive->fd, drive->format, drive->is_block_device, &virtual_size);
                if (r < 0)
                        return r;

                /* Step 7: Format overlay as qcow2 via blockdev-create */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *create_options = NULL;
                r = sd_json_buildo(&create_options,
                                SD_JSON_BUILD_PAIR_STRING("driver", "qcow2"),
                                SD_JSON_BUILD_PAIR_STRING("file", overlay_file_node),
                                SD_JSON_BUILD_PAIR_UNSIGNED("size", virtual_size),
                                SD_JSON_BUILD_PAIR_STRING("backing-file", base_fmt_node),
                                SD_JSON_BUILD_PAIR_STRING("backing-fmt", drive->format));
                if (r < 0)
                        return log_error_errno(r, "Failed to build blockdev-create options: %m");

                const char *job_id = strjoina("create-", drive->node_name);

                r = qmp_blockdev_create_and_wait(qmp, create_options, job_id);
                if (r < 0)
                        return r;

                /* Step 8: Open formatted overlay as qcow2 with backing reference */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *overlay_fmt_args = NULL;
                r = qmp_build_blockdev_add_format(drive->node_name, "qcow2", overlay_file_node,
                                                  /* read_only= */ false, drive->discard, base_fmt_node, &overlay_fmt_args);
                if (r < 0)
                        return r;

                error_class = mfree(error_class);
                r = qmp_client_call(qmp, "blockdev-add", overlay_fmt_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add overlay format node for '%s': %s",
                                               drive->path, strna(error_class));
        } else {
                /* Non-ephemeral: single file node + format node.
                 * Node names: <name>-file, <name> */
                const char *file_node_name = strjoina(drive->node_name, "-file");

                _cleanup_(qmp_fdset_done) QmpFdset fdset = {};
                r = qmp_client_fdset_new(qmp, drive->fd, &fdset);
                if (r < 0)
                        return r;

                r = qmp_add_file_node(qmp, file_node_name, fdset.path,
                                      drive->is_block_device ? "host_device" : "file",
                                      drive->read_only, features);
                if (r < 0)
                        return r;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fmt_args = NULL;
                r = qmp_build_blockdev_add_format(drive->node_name, drive->format, file_node_name,
                                                  drive->read_only, drive->discard, /* backing= */ NULL, &fmt_args);
                if (r < 0)
                        return r;

                error_class = mfree(error_class);
                r = qmp_client_call(qmp, "blockdev-add", fmt_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add format node for '%s': %s",
                                               drive->path, strna(error_class));
        }

        /* device_add: attach to virtual hardware */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *device_args = NULL;
        r = qmp_build_device_add(drive, &device_args);
        if (r < 0)
                return r;

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add device for '%s': %s", drive->path, strna(error_class));

        log_debug("Added drive '%s' via QMP (aio=%s%s)", drive->path,
                   features->io_uring != 0 ? "io_uring" : "default",
                   ephemeral ? ", ephemeral" : "");

        return 0;
}

int vmspawn_qmp_setup_network(QmpClient *qmp, const QmpNetworkInfo *network) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *netdev_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        bool tap_by_fd;
        int r;

        assert(qmp);
        assert(network);
        assert(network->type);

        tap_by_fd = streq(network->type, "tap") && network->fd >= 0;

        /* For TAP-by-fd: pass the TAP fd to QEMU via getfd + SCM_RIGHTS, then reference it by name
         * in netdev_add. QEMU stores the received fd under the given fdname and closes it on removal. */
        if (tap_by_fd) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *getfd_args = NULL;

                r = sd_json_buildo(
                                &getfd_args,
                                SD_JSON_BUILD_PAIR_STRING("fdname", "vmspawn_tap"));
                if (r < 0)
                        return log_error_errno(r, "Failed to build getfd JSON: %m");

                r = qmp_client_call_send_fd(qmp, "getfd", getfd_args, network->fd,
                                            /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to pass TAP fd to QEMU via getfd: %s", strna(error_class));

                error_class = mfree(error_class);
        }

        /* netdev_add: create the network backend */
        r = sd_json_buildo(
                        &netdev_args,
                        SD_JSON_BUILD_PAIR_STRING("type", network->type),
                        SD_JSON_BUILD_PAIR_STRING("id", "net0"),
                        SD_JSON_BUILD_PAIR_CONDITION(tap_by_fd,
                                                     "fd", SD_JSON_BUILD_STRING("vmspawn_tap")),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && !!network->ifname,
                                                     "ifname", SD_JSON_BUILD_STRING(network->ifname)),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && streq(network->type, "tap"),
                                                     "script", SD_JSON_BUILD_STRING("no")),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && streq(network->type, "tap"),
                                                     "downscript", SD_JSON_BUILD_STRING("no")));
        if (r < 0)
                return log_error_errno(r, "Failed to build netdev_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "netdev_add", netdev_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add network backend via QMP: %s", strna(error_class));

        /* device_add: attach NIC frontend */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-net-pci"),
                        SD_JSON_BUILD_PAIR_STRING("netdev", "net0"),
                        SD_JSON_BUILD_PAIR_STRING("id", "nic0"),
                        SD_JSON_BUILD_PAIR_CONDITION(!!network->mac,
                                                     "mac", SD_JSON_BUILD_STRING(network->mac ? ETHER_ADDR_TO_STR(network->mac) : NULL)));
        if (r < 0)
                return log_error_errno(r, "Failed to build NIC device_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add NIC device via QMP: %s", strna(error_class));

        log_debug("Added %s network via QMP%s", network->type, tap_by_fd ? " (fd via getfd)" : "");
        return 0;
}

static int vmspawn_qmp_setup_one_virtiofs(QmpClient *qmp, const QmpVirtiofsInfo *vfs) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *chardev_args = NULL, *device_args = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *addr = NULL, *backend_data = NULL, *backend = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(vfs);
        assert(vfs->id);
        assert(vfs->socket_path);
        assert(vfs->tag);

        /* chardev-add: connect to virtiofsd socket.
         * ChardevBackend and SocketAddressLegacy are QAPI legacy unions with explicit "data"
         * wrapper objects at each level — the nesting is mandatory on the wire. Build bottom-up
         * to keep each level readable. */
        r = sd_json_buildo(
                        &addr,
                        SD_JSON_BUILD_PAIR_STRING("type", "unix"),
                        SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("path", vfs->socket_path))));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev address JSON for '%s': %m", vfs->id);

        r = sd_json_buildo(
                        &backend_data,
                        SD_JSON_BUILD_PAIR_VARIANT("addr", addr),
                        SD_JSON_BUILD_PAIR_BOOLEAN("server", false));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev backend JSON for '%s': %m", vfs->id);

        r = sd_json_buildo(
                        &backend,
                        SD_JSON_BUILD_PAIR_STRING("type", "socket"),
                        SD_JSON_BUILD_PAIR_VARIANT("data", backend_data));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev backend wrapper JSON for '%s': %m", vfs->id);

        r = sd_json_buildo(
                        &chardev_args,
                        SD_JSON_BUILD_PAIR_STRING("id", vfs->id),
                        SD_JSON_BUILD_PAIR_VARIANT("backend", backend));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev-add JSON for '%s': %m", vfs->id);

        r = qmp_client_call(qmp, "chardev-add", chardev_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add chardev '%s' via QMP: %s", vfs->id, strna(error_class));

        /* device_add: create vhost-user-fs-pci device */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vhost-user-fs-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", vfs->id),
                        SD_JSON_BUILD_PAIR_STRING("chardev", vfs->id),
                        SD_JSON_BUILD_PAIR_STRING("tag", vfs->tag),
                        SD_JSON_BUILD_PAIR_UNSIGNED("queue-size", 1024));
        if (r < 0)
                return log_error_errno(r, "Failed to build virtiofs device_add JSON for '%s': %m", vfs->id);

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add virtiofs device '%s' via QMP: %s", vfs->id, strna(error_class));

        log_debug("Added virtiofs device '%s' (tag=%s) via QMP", vfs->id, vfs->tag);
        return 0;
}

int vmspawn_qmp_setup_virtiofs(QmpClient *qmp, const QmpVirtiofsInfo *virtiofs, size_t n_virtiofs) {
        int r;

        for (size_t i = 0; i < n_virtiofs; i++) {
                r = vmspawn_qmp_setup_one_virtiofs(qmp, &virtiofs[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vmspawn_qmp_setup_rng(QmpClient *qmp) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *object_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        /* object-add: create rng-random backend */
        r = sd_json_buildo(
                        &object_args,
                        SD_JSON_BUILD_PAIR_STRING("qom-type", "rng-random"),
                        SD_JSON_BUILD_PAIR_STRING("id", "rng0"),
                        SD_JSON_BUILD_PAIR_STRING("filename", "/dev/urandom"));
        if (r < 0)
                return log_error_errno(r, "Failed to build RNG object-add JSON: %m");

        r = qmp_client_call(qmp, "object-add", object_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add RNG backend via QMP: %s", strna(error_class));

        /* device_add: create virtio-rng-pci frontend */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-rng-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "rng-device0"),
                        SD_JSON_BUILD_PAIR_STRING("rng", "rng0"));
        if (r < 0)
                return log_error_errno(r, "Failed to build RNG device_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add RNG device via QMP: %s", strna(error_class));

        log_debug("Added virtio-rng-pci device via QMP");
        return 0;
}

int vmspawn_qmp_setup_vmgenid(QmpClient *qmp, sd_id128_t vmgenid) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vmgenid"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vmgenid0"),
                        SD_JSON_BUILD_PAIR_STRING("guid", SD_ID128_TO_UUID_STRING(vmgenid)));
        if (r < 0)
                return log_error_errno(r, "Failed to build vmgenid device_add JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add vmgenid device via QMP: %s", strna(error_class));

        log_debug("Added vmgenid device via QMP");
        return 0;
}

int vmspawn_qmp_setup_balloon(QmpClient *qmp) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-balloon"),
                        SD_JSON_BUILD_PAIR_STRING("id", "balloon0"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("free-page-reporting", true));
        if (r < 0)
                return log_error_errno(r, "Failed to build balloon device_add JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add balloon device via QMP: %s", strna(error_class));

        log_debug("Added virtio-balloon device via QMP");
        return 0;
}

int vmspawn_qmp_setup_vsock(QmpClient *qmp, const QmpVsockInfo *vsock) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *getfd_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(vsock);
        assert(vsock->fd >= 0);

        /* getfd: pass the vhost-vsock fd to QEMU via SCM_RIGHTS */
        r = sd_json_buildo(
                        &getfd_args,
                        SD_JSON_BUILD_PAIR_STRING("fdname", "vmspawn_vsock"));
        if (r < 0)
                return log_error_errno(r, "Failed to build getfd JSON for VSOCK: %m");

        r = qmp_client_call_send_fd(qmp, "getfd", getfd_args, vsock->fd,
                                    /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to pass VSOCK fd to QEMU via getfd: %s", strna(error_class));

        /* device_add: create vhost-vsock-pci device referencing the named fd */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vhost-vsock-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vsock0"),
                        SD_JSON_BUILD_PAIR_UNSIGNED("guest-cid", vsock->cid),
                        SD_JSON_BUILD_PAIR_STRING("vhostfd", "vmspawn_vsock"));
        if (r < 0)
                return log_error_errno(r, "Failed to build VSOCK device_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add VSOCK device via QMP: %s", strna(error_class));

        log_debug("Added vhost-vsock-pci device via QMP (cid=%u)", vsock->cid);
        return 0;
}

static bool drives_need_scsi_controller(const QmpDriveInfo *drives, size_t n_drives) {
        for (size_t i = 0; i < n_drives; i++)
                if (STR_IN_SET(drives[i].disk_driver, "scsi-hd", "scsi-cd"))
                        return true;

        return false;
}

static int qmp_setup_scsi_controller(QmpClient *qmp) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-scsi-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vmspawn_scsi"));
        if (r < 0)
                return log_error_errno(r, "Failed to build SCSI controller JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add SCSI controller via QMP: %s", strna(error_class));

        log_debug("Added virtio-scsi-pci controller via QMP");
        return 0;
}

int vmspawn_qmp_setup_drives(QmpClient *qmp, const QmpDriveInfo *drives, size_t n_drives) {
        int r;

        QemuFeatures features = { .io_uring = -1 };
        r = qmp_detect_features(qmp, &features);
        if (r < 0)
                log_warning_errno(r, "Failed to detect QEMU features, continuing with defaults: %m");

        if (drives_need_scsi_controller(drives, n_drives)) {
                r = qmp_setup_scsi_controller(qmp);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < n_drives; i++) {
                r = qmp_setup_one_drive(qmp, &drives[i], &features);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vmspawn_qmp_init(QmpClient **ret, int qmp_fd, sd_event *event) {
        _cleanup_(qmp_client_freep) QmpClient *qmp = NULL;
        _cleanup_close_ int fd = TAKE_FD(qmp_fd);
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(event, -EINVAL);

        r = qmp_client_connect_fd(&qmp, TAKE_FD(fd), event);
        if (r < 0)
                return log_error_errno(r, "Failed to perform QMP handshake: %m");

        *ret = TAKE_PTR(qmp);
        return 0;
}

int vmspawn_qmp_start(QmpClient *qmp) {
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert_return(qmp, -EINVAL);

        r = qmp_client_call(qmp, "cont", /* arguments= */ NULL, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to resume QEMU execution: %s", strna(error_class));

        r = qmp_client_start_async(qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to switch QMP client to async mode: %m");

        return 0;
}

int vmspawn_qmp_setup(
                VmspawnQmpContext **ret,
                QmpClient *qmp,
                const char *runtime_dir,
                RuntimeScope runtime_scope,
                uid_t owner_uid,
                char **ret_control_address) {

        _cleanup_(qmp_client_freep) QmpClient *qmp_owned = qmp;
        _cleanup_(vmspawn_qmp_context_freep) VmspawnQmpContext *ctx = NULL;
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(qmp_owned, -EINVAL);
        assert_return(runtime_dir, -EINVAL);

        sd_event *event = qmp_client_get_event(qmp_owned);
        assert(event);

        ctx = new(VmspawnQmpContext, 1);
        if (!ctx)
                return log_oom();

        *ctx = (VmspawnQmpContext) {
                .qmp_client = TAKE_PTR(qmp_owned),
                .runtime_scope = runtime_scope,
                .owner_uid = owner_uid,
        };

        /* Create varlink server for VM control */
        r = varlink_server_new(&ctx->varlink_server,
                               SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                               ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to create varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        ctx->varlink_server,
                        &vl_interface_io_systemd_MachineInstance,
                        &vl_interface_io_systemd_VirtualMachineInstance,
                        &vl_interface_io_systemd_QemuMachineInstance);
        if (r < 0)
                return log_error_errno(r, "Failed to add varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        ctx->varlink_server,
                        "io.systemd.MachineInstance.Terminate",         vl_method_terminate,
                        "io.systemd.MachineInstance.PowerOff",          vl_method_power_off,
                        "io.systemd.MachineInstance.Pause",             vl_method_pause,
                        "io.systemd.MachineInstance.Resume",            vl_method_resume,
                        "io.systemd.MachineInstance.Reboot",            vl_method_reboot,
                        "io.systemd.MachineInstance.QueryStatus",       vl_method_query_status,
                        "io.systemd.MachineInstance.SubscribeEvents",   vl_method_subscribe_events,
                        "io.systemd.QemuMachineInstance.AcquireQMP",    vl_method_acquire_qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to bind varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(ctx->varlink_server, vl_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind disconnect handler: %m");

        listen_address = path_join(runtime_dir, "io.systemd.MachineInstance");
        if (!listen_address)
                return log_oom();

        r = sd_varlink_server_listen_address(ctx->varlink_server, listen_address, 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on %s: %m", listen_address);

        r = sd_varlink_server_attach_event(ctx->varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink server to event loop: %m");

        qmp_client_set_event_callback(ctx->qmp_client, on_qmp_event, ctx);
        qmp_client_set_disconnect_callback(ctx->qmp_client, on_qmp_disconnect, ctx);

        log_debug("QMP varlink server listening on %s", listen_address);

        if (ret_control_address)
                *ret_control_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnQmpContext *vmspawn_qmp_context_free(VmspawnQmpContext *ctx) {
        sd_varlink *link;

        if (!ctx)
                return NULL;

        ctx->varlink_server = sd_varlink_server_unref(ctx->varlink_server);
        ctx->qmp_client = qmp_client_free(ctx->qmp_client);

        while (!hashmap_isempty(ctx->subscribed)) {
                strv_free(hashmap_steal_first_key_and_value(ctx->subscribed, (void**) &link));
                sd_varlink_unref(link);
        }
        hashmap_free(ctx->subscribed);

        hashmap_free(ctx->polkit_registry);

        return mfree(ctx);
}
