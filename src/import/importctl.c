/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "options.h"
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

VERB(verb_pull_tar, "pull-tar", "URL [NAME]", 2, 3, 0, "Download a TAR container image");
static int verb_pull_tar(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_pull_raw, "pull-raw", "URL [NAME]", 2, 3, 0, "Download a RAW container or VM image");
static int verb_pull_raw(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_pull_oci, "pull-oci", "REF [NAME]", 2, 3, 0, "Download an OCI container image");
static int verb_pull_oci(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_import_tar, "import-tar", "FILE [NAME]", 2, 3, 0, "Import a local TAR container image");
static int verb_import_tar(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_import_raw, "import-raw", "FILE [NAME]", 2, 3, 0, "Import a local RAW container or VM image");
static int verb_import_raw(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_import_fs, "import-fs", "DIRECTORY [NAME]", 2, 3, 0, "Import a local directory container image");
static int verb_import_fs(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_export_tar, "export-tar", "NAME [FILE]", 2, 3, 0, "Export a TAR container image locally");
static int verb_export_tar(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_export_raw, "export-raw", "NAME [FILE]", 2, 3, 0, "Export a RAW container or VM image locally");
static int verb_export_raw(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB_DEFAULT_NOARG(verb_list_transfers, "list-transfers", "Show list of transfers in progress");
static int verb_list_transfers(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_cancel_transfer, "cancel-transfer", "[ID...]", 2, VERB_ANY, 0, "Cancel a transfer");
static int verb_cancel_transfer(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB_NOARG(verb_list_images, "list-images", "Show list of installed images");
static int verb_list_images(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("importctl", "1", &link);
        if (r < 0)
                return log_oom();

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sDownload, import or export disk images%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

VERB_COMMON_HELP(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION_COMMON_HOST:
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = opts.arg;
                        break;

                OPTION_COMMON_MACHINE:
                        r = parse_machine_argument(opts.arg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("system", NULL, "Connect to system machine manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Connect to user machine manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION_LONG("read-only", NULL, "Create read-only image"):
                        arg_import_flags |= IMPORT_READ_ONLY;
                        arg_import_flags_mask |= IMPORT_READ_ONLY;
                        break;

                OPTION('q', "quiet", NULL, "Suppress output"):
                        arg_quiet = true;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        arg_legend = false;
                        break;

                OPTION_COMMON_LOWERCASE_J:
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        arg_legend = false;
                        break;

                OPTION_LONG("verify", "MODE",
                            "Verification mode for downloaded images (no, checksum, signature)"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(import_verify, ImportVerify, _IMPORT_VERIFY_MAX);

                        r = import_verify_from_string(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --verify= setting: %s", opts.arg);
                        arg_verify = r;
                        break;

                OPTION_LONG("format", "FORMAT",
                            "Desired output format for export (zstd, xz, gzip, bzip2)"):
                        if (!STR_IN_SET(opts.arg, "uncompressed", "xz", "gzip", "bzip2", "zstd"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown format: %s", opts.arg);
                        arg_format = opts.arg;
                        break;

                OPTION_LONG("force", NULL, "Install image even if already exists"):
                        arg_import_flags |= IMPORT_FORCE;
                        arg_import_flags_mask |= IMPORT_FORCE;
                        break;

                OPTION_LONG("class", "TYPE", "Install as the specified TYPE"):
                        arg_image_class = image_class_from_string(opts.arg);
                        if (arg_image_class < 0)
                                return log_error_errno(arg_image_class, "Failed to parse --class= parameter: %s", opts.arg);
                        break;

                OPTION_SHORT('m', NULL, "Install as --class=machine, machine image"):
                        arg_image_class = IMAGE_MACHINE;
                        break;

                OPTION_SHORT('P', NULL, "Install as --class=portable, portable service image"):
                        arg_image_class = IMAGE_PORTABLE;
                        break;

                OPTION_SHORT('S', NULL, "Install as --class=sysext, system extension image"):
                        arg_image_class = IMAGE_SYSEXT;
                        break;

                OPTION_SHORT('C', NULL, "Install as --class=confext, configuration extension image"):
                        arg_image_class = IMAGE_CONFEXT;
                        break;

                OPTION_LONG("keep-download", "BOOL",
                            "Control whether to keep pristine copy of download"):
                        r = parse_boolean(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --keep-download= value: %s", opts.arg);

                        SET_FLAG(arg_import_flags, IMPORT_PULL_KEEP_DOWNLOAD, r);
                        arg_import_flags_mask |= IMPORT_PULL_KEEP_DOWNLOAD;
                        break;

                OPTION_SHORT('N', NULL, "Same as --keep-download=no"):
                        arg_import_flags &= ~IMPORT_PULL_KEEP_DOWNLOAD;
                        arg_import_flags_mask |= IMPORT_PULL_KEEP_DOWNLOAD;
                        break;
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, arg_runtime_scope, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        return dispatch_verb(args, bus);
}

DEFINE_MAIN_FUNCTION(run);
