/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "discover-image.h"
#include "fd-util.h"
#include "format-table.h"
#include "import-common.h"
#include "import-util.h"
#include "log.h"
#include "main-func.h"
#include "oci-util.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "verbs.h"
#include "web-util.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static ImportFlags arg_import_flags = 0;
static ImportFlags arg_import_flags_mask = 0; /* Indicates which flags have been explicitly set to on or to off */
static bool arg_quiet = false;
static bool arg_ask_password = true;
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static const char* arg_format = NULL;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static ImageClass arg_image_class = _IMAGE_CLASS_INVALID;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;

#define PROGRESS_PREFIX "Total:"

static int settle_image_class(void) {
        int r;

        if (arg_image_class < 0) {
                _cleanup_free_ char *j = NULL;

                for (ImageClass class = 0; class < _IMAGE_CLASS_MAX; class++) {
                        _cleanup_free_ char *root = NULL;

                        r = image_root_pick(arg_runtime_scope, class, /* runtime= */ false, &root);
                        if (r < 0)
                                return log_error_errno(r, "Failed to pick image root: %m");

                        if (strextendf_with_separator(&j, ", ", "%s (downloads to %s/)",
                                                      image_class_to_string(class),
                                                      root) < 0)
                                return log_oom();
                }

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No image class specified, retry with --class= set to one of: %s.", j);
        }

        /* Keep the original pristine downloaded file as a copy only when dealing with machine images,
         * because unlike sysext/confext/portable they are typically modified during runtime. */
        if (!FLAGS_SET(arg_import_flags_mask, IMPORT_PULL_KEEP_DOWNLOAD))
                SET_FLAG(arg_import_flags, IMPORT_PULL_KEEP_DOWNLOAD, arg_image_class == IMAGE_MACHINE);

        return 0;
}

typedef struct Context {
        const char *object_path;
        double progress;
} Context;

static int match_log_message(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        const char *line;
        unsigned priority;
        int r;

        assert(m);

        if (!streq_ptr(c->object_path, sd_bus_message_get_path(m)))
                return 0;

        r = sd_bus_message_read(m, "us", &priority, &line);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (arg_quiet && LOG_PRI(priority) >= LOG_INFO)
                return 0;

        if (!arg_quiet)
                clear_progress_bar(PROGRESS_PREFIX);

        log_full(priority, "%s", line);

        if (!arg_quiet)
                draw_progress_bar(PROGRESS_PREFIX, c->progress * 100);

        return 0;
}

static int match_progress_update(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(m);

        if (!streq_ptr(c->object_path, sd_bus_message_get_path(m)))
                return 0;

        r = sd_bus_message_read(m, "d", &c->progress);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!arg_quiet)
                draw_progress_bar(PROGRESS_PREFIX, c->progress * 100);

        return 0;
}

static int match_transfer_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        const char *path, *result;
        uint32_t id;
        int r;

        assert(m);

        if (!arg_quiet)
                clear_progress_bar(PROGRESS_PREFIX);

        r = sd_bus_message_read(m, "uos", &id, &path, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq_ptr(c->object_path, path))
                return 0;

        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), !streq_ptr(result, "done"));
        return 0;
}

static int transfer_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        assert(s);
        assert(si);

        if (!arg_quiet)
                clear_progress_bar(PROGRESS_PREFIX);

        if (!arg_quiet)
                log_info("Continuing download in the background. Use \"%s cancel-transfer %" PRIu32 "\" to abort transfer.",
                         program_invocation_short_name,
                         PTR_TO_UINT32(userdata));

        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static int transfer_image_common(sd_bus *bus, sd_bus_message *m) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot_job_removed = NULL, *slot_log_message = NULL, *slot_progress_update = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_event_unrefp) sd_event* event = NULL;
        Context c = {};
        uint32_t id;
        int r;

        assert(bus);
        assert(m);

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = bus_match_signal_async(
                        bus,
                        &slot_job_removed,
                        bus_import_mgr,
                        "TransferRemoved",
                        match_transfer_removed,
                        /* install_callback= */ NULL,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_match_signal_async(
                        bus,
                        &slot_log_message,
                        "org.freedesktop.import1",
                        /* path= */ NULL,
                        "org.freedesktop.import1.Transfer",
                        "LogMessage",
                        match_log_message,
                        /* install_callback= */ NULL,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_match_signal_async(
                        bus,
                        &slot_progress_update,
                        "org.freedesktop.import1",
                        /* path= */ NULL,
                        "org.freedesktop.import1.Transfer",
                        "ProgressUpdate",
                        match_progress_update,
                        /* install_callback= */ NULL,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to transfer image: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "uo", &id, &c.object_path);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!arg_quiet) {
                clear_progress_bar(PROGRESS_PREFIX);
                log_info("Enqueued transfer job %u. Press C-c to continue download in background.", id);
                draw_progress_bar(PROGRESS_PREFIX, c.progress);
        }

        (void) sd_event_add_signal(event, NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK, transfer_signal_handler, UINT32_TO_PTR(id));
        (void) sd_event_add_signal(event, NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, transfer_signal_handler, UINT32_TO_PTR(id));

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return -r;
}

static int import_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *ll = NULL, *fn = NULL;
        const char *local = NULL, *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                r = path_extract_filename(path, &fn);
                if (r < 0)
                        return log_error_errno(r, "Cannot extract container name from filename: %m");
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                               "Path '%s' refers to directory, but we need a regular file.", path);

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        r = tar_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!image_name_is_valid(local))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable image name.",
                                       local);

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        if (arg_image_class == IMAGE_MACHINE && (arg_import_flags & ~(IMPORT_FORCE|IMPORT_READ_ONLY)) == 0) {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportTar");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "hsbb",
                                fd >= 0 ? fd : STDIN_FILENO,
                                local,
                                FLAGS_SET(arg_import_flags, IMPORT_FORCE),
                                FLAGS_SET(arg_import_flags, IMPORT_READ_ONLY));
        } else {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportTarEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "hsst",
                                fd >= 0 ? fd : STDIN_FILENO,
                                local,
                                image_class_to_string(arg_image_class),
                                (uint64_t) arg_import_flags & (IMPORT_FORCE|IMPORT_READ_ONLY));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int import_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *ll = NULL, *fn = NULL;
        const char *local = NULL, *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                r = path_extract_filename(path, &fn);
                if (r < 0)
                        return log_error_errno(r, "Cannot extract container name from filename: %m");
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                               "Path '%s' refers to directory, but we need a regular file.", path);

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        r = raw_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!image_name_is_valid(local))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable image name.",
                                       local);

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        if (arg_image_class == IMAGE_MACHINE && (arg_import_flags & ~(IMPORT_FORCE|IMPORT_READ_ONLY)) == 0) {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportRaw");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "hsbb",
                                fd >= 0 ? fd : STDIN_FILENO,
                                local,
                                FLAGS_SET(arg_import_flags, IMPORT_FORCE),
                                FLAGS_SET(arg_import_flags, IMPORT_READ_ONLY));
        } else {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportRawEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "hsst",
                                fd >= 0 ? fd : STDIN_FILENO,
                                local,
                                image_class_to_string(arg_image_class),
                                (uint64_t) arg_import_flags & (IMPORT_FORCE|IMPORT_READ_ONLY));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int import_fs(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const char *local = NULL, *path = NULL;
        _cleanup_free_ char *fn = NULL;
        _cleanup_close_ int fd = -EBADF;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                r = path_extract_filename(path, &fn);
                if (r < 0)
                        return log_error_errno(r, "Cannot extract container name from filename: %m");

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        if (!image_name_is_valid(local))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable image name.",
                                       local);

        if (path) {
                fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open directory '%s': %m", path);
        }

        if (arg_image_class == IMAGE_MACHINE && (arg_import_flags & ~(IMPORT_FORCE|IMPORT_READ_ONLY)) == 0) {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportFileSystem");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "hsbb",
                                fd >= 0 ? fd : STDIN_FILENO,
                                local,
                                FLAGS_SET(arg_import_flags, IMPORT_FORCE),
                                FLAGS_SET(arg_import_flags, IMPORT_READ_ONLY));
        } else {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportFileSystemEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "hsst",
                                fd >= 0 ? fd : STDIN_FILENO,
                                local,
                                image_class_to_string(arg_image_class),
                                (uint64_t) arg_import_flags & (IMPORT_FORCE|IMPORT_READ_ONLY));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static void determine_compression_from_filename(const char *p) {
        if (arg_format)
                return;

        if (!p)
                return;

        if (endswith(p, ".xz"))
                arg_format = "xz";
        else if (endswith(p, ".gz"))
                arg_format = "gzip";
        else if (endswith(p, ".bz2"))
                arg_format = "bzip2";
        else if (endswith(p, ".zst"))
                arg_format = "zstd";
}

static int export_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        local = argv[1];
        if (!image_name_is_valid(local))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Image name %s is not valid.", local);

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        if (arg_image_class == IMAGE_MACHINE && arg_import_flags == 0) {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportTar");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "shs",
                                local,
                                fd >= 0 ? fd : STDOUT_FILENO,
                                arg_format);
        } else {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportTarEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sshst",
                                local,
                                image_class_to_string(arg_image_class),
                                fd >= 0 ? fd : STDOUT_FILENO,
                                arg_format,
                                /* flags= */ UINT64_C(0));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int export_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        local = argv[1];
        if (!image_name_is_valid(local))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Image name %s is not valid.", local);

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        if (arg_image_class == IMAGE_MACHINE && arg_import_flags == 0) {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportRaw");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "shs",
                                local,
                                fd >= 0 ? fd : STDOUT_FILENO,
                                arg_format);
        } else {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportRawEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sshst",
                                local,
                                image_class_to_string(arg_image_class),
                                fd >= 0 ? fd : STDOUT_FILENO,
                                arg_format,
                                /* flags= */ UINT64_C(0));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        const char *local, *remote;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        remote = argv[1];
        if (!http_url_is_valid(remote) && !file_url_is_valid(remote))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "URL '%s' is not valid.", remote);

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(remote, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                local = l;
        }

        local = empty_or_dash_to_null(local);

        if (local) {
                r = tar_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!image_name_is_valid(local))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local name %s is not a suitable image name.",
                                               local);
        }

        if (arg_image_class == IMAGE_MACHINE && (arg_import_flags & ~IMPORT_FORCE) == 0) {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullTar");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sssb",
                                remote,
                                local,
                                import_verify_to_string(arg_verify),
                                FLAGS_SET(arg_import_flags, IMPORT_FORCE));
        } else {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullTarEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sssst",
                                remote,
                                local,
                                image_class_to_string(arg_image_class),
                                import_verify_to_string(arg_verify),
                                (uint64_t) arg_import_flags & (IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_PULL_KEEP_DOWNLOAD));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        const char *local, *remote;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        remote = argv[1];
        if (!http_url_is_valid(remote) && !file_url_is_valid(remote))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "URL '%s' is not valid.", remote);

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(remote, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                local = l;
        }

        local = empty_or_dash_to_null(local);

        if (local) {
                r = raw_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!image_name_is_valid(local))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local name %s is not a suitable image name.",
                                               local);
        }

        if (arg_image_class == IMAGE_MACHINE && (arg_import_flags & ~IMPORT_FORCE) == 0) {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullRaw");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sssb",
                                remote,
                                local,
                                import_verify_to_string(arg_verify),
                                FLAGS_SET(arg_import_flags, IMPORT_FORCE));
        } else {
                r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullRawEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sssst",
                                remote,
                                local,
                                image_class_to_string(arg_image_class),
                                import_verify_to_string(arg_verify),
                                (uint64_t) arg_import_flags & (IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_PULL_KEEP_DOWNLOAD));
        }
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_oci(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *l = NULL;
        const char *local, *remote;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = settle_image_class();
        if (r < 0)
                return r;

        remote = argv[1];
        _cleanup_free_ char *image = NULL;
        r = oci_ref_parse(remote, /* ret_registry= */ NULL, &image, /* ret_tag= */ NULL);
        if (r == -EINVAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Ref '%s' is not valid.", remote);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if ref '%s' is valid.", remote);

        if (argc >= 3)
                local = argv[2];
        else {
                r = path_extract_filename(image, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of reference: %m");

                local = l;
        }

        local = empty_or_dash_to_null(local);

        if (local) {
                if (!image_name_is_valid(local))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local name %s is not a suitable image name.",
                                               local);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullOci");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "ssst",
                        remote,
                        local,
                        image_class_to_string(arg_image_class),
                        (uint64_t) arg_import_flags & (IMPORT_FORCE|IMPORT_READ_ONLY));
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int list_transfers(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        pager_open(arg_pager_flags);

        bool ex;
        r = bus_call_method(bus, bus_import_mgr, "ListTransfersEx", &error, &reply, "st", image_class_to_string(arg_image_class), UINT64_C(0));
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
                        sd_bus_error_free(&error);

                        r = bus_call_method(bus, bus_import_mgr, "ListTransfers", &error, &reply, NULL);
                }
                if (r < 0)
                        return log_error_errno(r, "Could not get transfers: %s", bus_error_message(&error, r));

                ex = false;
                r = sd_bus_message_enter_container(reply, 'a', "(usssdo)");
        } else {
                ex = true;
                r = sd_bus_message_enter_container(reply, 'a', "(ussssdo)");
        }
        if (r < 0)
                return bus_log_parse_error(r);

        t = table_new("id", "progress", "type", "class", "local", "remote");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 4, (size_t) 0);
        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        for (;;) {
                const char *type, *remote, *local, *class = "machine";
                double progress;
                uint32_t id;

                if (ex)
                        r = sd_bus_message_read(reply, "(ussssdo)", &id, &type, &remote, &local, &class, &progress, NULL);
                else
                        r = sd_bus_message_read(reply, "(usssdo)", &id, &type, &remote, &local, &progress, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                /* Ideally we use server-side filtering. But if the server can't do it, we need to do it client side */
                if (arg_image_class >= 0 && image_class_from_string(class) != arg_image_class)
                        continue;

                r = table_add_many(
                                t,
                                TABLE_UINT32, id,
                                TABLE_SET_ALIGN_PERCENT, 100);
                if (r < 0)
                        return table_log_add_error(r);

                if (progress < 0)
                        r = table_add_many(
                                        t,
                                        TABLE_EMPTY,
                                        TABLE_SET_ALIGN_PERCENT, 100);
                else
                        r = table_add_many(
                                        t,
                                        TABLE_PERCENT, (int) (progress * 100),
                                        TABLE_SET_ALIGN_PERCENT, 100);
                if (r < 0)
                        return table_log_add_error(r);
                r = table_add_many(
                                t,
                                TABLE_STRING, type,
                                TABLE_STRING, class,
                                TABLE_STRING, local,
                                TABLE_STRING, remote,
                                TABLE_SET_URL, remote);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!table_isempty(t)) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend) {
                if (!table_isempty(t))
                        printf("\n%zu transfers listed.\n", table_get_rows(t) - 1);
                else
                        printf("No transfers.\n");
        }

        return 0;
}

static int cancel_transfer(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                uint32_t id;

                r = safe_atou32(argv[i], &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse transfer id: %s", argv[i]);

                r = bus_call_method(bus, bus_import_mgr, "CancelTransfer", &error, NULL, "u", id);
                if (r < 0)
                        return log_error_errno(r, "Could not cancel transfer: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int list_images(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        pager_open(arg_pager_flags);

        r = bus_call_method(bus, bus_import_mgr, "ListImages", &error, &reply, "st", image_class_to_string(arg_image_class), UINT64_C(0));
        if (r < 0)
                return log_error_errno(r, "Could not list images: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "(ssssbtttttt)");
        if (r < 0)
                return bus_log_parse_error(r);

        t = table_new("class", "name", "type", "path", "ro", "crtime", "mtime", "usage", "usage-exclusive", "limit", "limit-exclusive");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0, (size_t) 1);
        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        /* Hide the exclusive columns for now */
        (void) table_hide_column_from_display(t, 8);
        (void) table_hide_column_from_display(t, 10);

        /* Starting in v257, these fields would be automatically formatted with underscores. However, this
         * command was introduced in v256, so changing the field name would be a breaking change. */
        (void) table_set_json_field_name(t, 8, "usage-exclusive");
        (void) table_set_json_field_name(t, 10, "limit-exclusive");

        for (;;) {
                uint64_t crtime, mtime, usage, usage_exclusive, limit, limit_exclusive;
                const char *class, *name, *type, *path;
                int read_only;

                r = sd_bus_message_read(reply, "(ssssbtttttt)", &class, &name, &type, &path, &read_only, &crtime, &mtime, &usage, &usage_exclusive, &limit, &limit_exclusive);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = table_add_many(
                                t,
                                TABLE_STRING, class,
                                TABLE_STRING, name,
                                TABLE_STRING, type,
                                TABLE_PATH, path);
                if (r < 0)
                        return table_log_add_error(r);

                if (!sd_json_format_enabled(arg_json_format_flags))
                        r = table_add_many(
                                        t,
                                        TABLE_STRING, read_only ? "ro" : "rw",
                                        TABLE_SET_COLOR, read_only ? ANSI_HIGHLIGHT_RED : ANSI_HIGHLIGHT_GREEN);
                else
                        r = table_add_many(
                                        t,
                                        TABLE_BOOLEAN, read_only);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(
                                t,
                                TABLE_TIMESTAMP, crtime,
                                TABLE_TIMESTAMP, mtime,
                                TABLE_SIZE, usage,
                                TABLE_SIZE, usage_exclusive,
                                TABLE_SIZE, limit,
                                TABLE_SIZE, limit_exclusive);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!table_isempty(t)) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend) {
                if (!table_isempty(t))
                        printf("\n%zu images listed.\n", table_get_rows(t) - 1);
                else
                        printf("No images.\n");
        }

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("importctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sDownload, import or export disk images%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  pull-tar URL [NAME]         Download a TAR container image\n"
               "  pull-raw URL [NAME]         Download a RAW container or VM image\n"
               "  pull-oci REF [NAME]         Download an OCI container image\n"
               "  import-tar FILE [NAME]      Import a local TAR container image\n"
               "  import-raw FILE [NAME]      Import a local RAW container or VM image\n"
               "  import-fs DIRECTORY [NAME]  Import a local directory container image\n"
               "  export-tar NAME [FILE]      Export a TAR container image locally\n"
               "  export-raw NAME [FILE]      Export a RAW container or VM image locally\n"
               "  list-transfers              Show list of transfers in progress\n"
               "  cancel-transfer [ID...]     Cancel a transfer\n"
               "  list-images                 Show list of installed images\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not show the headers and footers\n"
               "     --no-ask-password        Do not ask for system passwords\n"
               "  -H --host=[USER@]HOST       Operate on remote host\n"
               "  -M --machine=CONTAINER      Operate on local container\n"
               "     --system                 Connect to system machine manager\n"
               "     --user                   Connect to user machine manager\n"
               "     --read-only              Create read-only image\n"
               "  -q --quiet                  Suppress output\n"
               "     --json=pretty|short|off  Generate JSON output\n"
               "  -j                          Equvilant to --json=pretty on TTY, --json=short\n"
               "                              otherwise\n"
               "     --verify=MODE            Verification mode for downloaded images (no,\n"
               "                               checksum, signature)\n"
               "     --format=xz|gzip|bzip2|zstd\n"
               "                              Desired output format for export\n"
               "     --force                  Install image even if already exists\n"
               "     --class=TYPE             Install as the specified TYPE\n"
               "  -m                          Install as --class=machine, machine image\n"
               "  -P                          Install as --class=portable,\n"
               "                              portable service image\n"
               "  -S                          Install as --class=sysext, system extension image\n"
               "  -C                          Install as --class=confext,\n"
               "                              configuration extension image\n"
               "     --keep-download=BOOL     Control whether to keep pristine copy of download\n"
               "  -N                          Same as --keep-download=no\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_NO_ASK_PASSWORD,
                ARG_READ_ONLY,
                ARG_JSON,
                ARG_VERIFY,
                ARG_FORCE,
                ARG_FORMAT,
                ARG_CLASS,
                ARG_KEEP_DOWNLOAD,
                ARG_SYSTEM,
                ARG_USER,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "no-legend",       no_argument,       NULL, ARG_NO_LEGEND       },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "host",            required_argument, NULL, 'H'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "read-only",       no_argument,       NULL, ARG_READ_ONLY       },
                { "json",            required_argument, NULL, ARG_JSON            },
                { "quiet",           no_argument,       NULL, 'q'                 },
                { "verify",          required_argument, NULL, ARG_VERIFY          },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "format",          required_argument, NULL, ARG_FORMAT          },
                { "class",           required_argument, NULL, ARG_CLASS           },
                { "keep-download",   required_argument, NULL, ARG_KEEP_DOWNLOAD   },
                { "system",          no_argument,       NULL, ARG_SYSTEM          },
                { "user",            no_argument,       NULL, ARG_USER            },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        for (;;) {
                c = getopt_long(argc, argv, "hH:M:jqmPSCN", options, NULL);
                if (c < 0)
                        break;

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        r = parse_machine_argument(optarg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                case ARG_READ_ONLY:
                        arg_import_flags |= IMPORT_READ_ONLY;
                        arg_import_flags_mask |= IMPORT_READ_ONLY;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERIFY:
                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(import_verify, ImportVerify, _IMPORT_VERIFY_MAX);

                        r = import_verify_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --verify= setting: %s", optarg);
                        arg_verify = r;
                        break;

                case ARG_FORCE:
                        arg_import_flags |= IMPORT_FORCE;
                        arg_import_flags_mask |= IMPORT_FORCE;
                        break;

                case ARG_FORMAT:
                        if (!STR_IN_SET(optarg, "uncompressed", "xz", "gzip", "bzip2", "zstd"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown format: %s", optarg);

                        arg_format = optarg;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        arg_legend = false;
                        break;

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        arg_legend = false;
                        break;

                case ARG_CLASS:
                        arg_image_class = image_class_from_string(optarg);
                        if (arg_image_class < 0)
                                return log_error_errno(arg_image_class, "Failed to parse --class= parameter: %s", optarg);
                        break;

                case 'm':
                        arg_image_class = IMAGE_MACHINE;
                        break;

                case 'P':
                        arg_image_class = IMAGE_PORTABLE;
                        break;

                case 'S':
                        arg_image_class = IMAGE_SYSEXT;
                        break;

                case 'C':
                        arg_image_class = IMAGE_CONFEXT;
                        break;

                case ARG_KEEP_DOWNLOAD:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --keep-download= value: %s", optarg);

                        SET_FLAG(arg_import_flags, IMPORT_PULL_KEEP_DOWNLOAD, r);
                        arg_import_flags_mask |= IMPORT_PULL_KEEP_DOWNLOAD;
                        break;

                case 'N':
                        arg_import_flags_mask &= ~IMPORT_PULL_KEEP_DOWNLOAD;
                        arg_import_flags_mask |= IMPORT_PULL_KEEP_DOWNLOAD;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        return 1;
}

static int importctl_main(int argc, char *argv[], sd_bus *bus) {

        static const Verb verbs[] = {
                { "help",            VERB_ANY, VERB_ANY, 0,            help              },
                { "import-tar",      2,        3,        0,            import_tar        },
                { "import-raw",      2,        3,        0,            import_raw        },
                { "import-fs",       2,        3,        0,            import_fs         },
                { "export-tar",      2,        3,        0,            export_tar        },
                { "export-raw",      2,        3,        0,            export_raw        },
                { "pull-tar",        2,        3,        0,            pull_tar          },
                { "pull-oci",        2,        3,        0,            pull_oci          },
                { "pull-raw",        2,        3,        0,            pull_raw          },
                { "list-transfers",  VERB_ANY, 1,        VERB_DEFAULT, list_transfers    },
                { "cancel-transfer", 2,        VERB_ANY, 0,            cancel_transfer   },
                { "list-images",     VERB_ANY, 1,        0,            list_images       },
                {}
        };

        return dispatch_verb(argc, argv, verbs, bus);
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, arg_runtime_scope, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        return importctl_main(argc, argv, bus);
}

DEFINE_MAIN_FUNCTION(run);
