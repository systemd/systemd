/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "hostname-util.h"
#include "import-util.h"
#include "locale-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "signal-util.h"
#include "sort-util.h"
#include "spawn-polkit-agent.h"
#include "string-table.h"
#include "verbs.h"
#include "web-util.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static bool arg_read_only = false;
static bool arg_quiet = false;
static bool arg_ask_password = true;
static bool arg_force = false;
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static const char* arg_format = NULL;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;

static int match_log_message(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char **our_path = userdata, *line;
        unsigned priority;
        int r;

        assert(m);
        assert(our_path);

        r = sd_bus_message_read(m, "us", &priority, &line);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq_ptr(*our_path, sd_bus_message_get_path(m)))
                return 0;

        if (arg_quiet && LOG_PRI(priority) >= LOG_INFO)
                return 0;

        log_full(priority, "%s", line);
        return 0;
}

static int match_transfer_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char **our_path = userdata, *path, *result;
        uint32_t id;
        int r;

        assert(m);
        assert(our_path);

        r = sd_bus_message_read(m, "uos", &id, &path, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq_ptr(*our_path, path))
                return 0;

        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), !streq_ptr(result, "done"));
        return 0;
}

static int transfer_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        assert(s);
        assert(si);

        if (!arg_quiet)
                log_info("Continuing download in the background. Use \"%s cancel-transfer %" PRIu32 "\" to abort transfer.",
                         program_invocation_short_name,
                         PTR_TO_UINT32(userdata));

        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static int transfer_image_common(sd_bus *bus, sd_bus_message *m) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot_job_removed = NULL, *slot_log_message = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_event_unrefp) sd_event* event = NULL;
        const char *path = NULL;
        uint32_t id;
        int r;

        assert(bus);
        assert(m);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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
                        match_transfer_removed, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_match_signal_async(
                        bus,
                        &slot_log_message,
                        "org.freedesktop.import1",
                        NULL,
                        "org.freedesktop.import1.Transfer",
                        "LogMessage",
                        match_log_message, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to transfer image: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "uo", &id, &path);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!arg_quiet)
                log_info("Enqueued transfer job %u. Press C-c to continue download in background.", id);

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
                                               "Path '%s' refers to directory, but we need a regular file: %m", path);

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        r = tar_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable machine name.",
                                       local);

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
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
                                               "Path '%s' refers to directory, but we need a regular file: %m", path);

                local = fn;
        }
        if (!local)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need either path or local name.");

        r = raw_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable machine name.",
                                       local);

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
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

        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Local name %s is not a suitable machine name.",
                                       local);

        if (path) {
                fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open directory '%s': %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ImportFileSystem");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
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
}

static int export_tar(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        local = argv[1];
        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Machine name %s is not valid.", local);

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "shs",
                        local,
                        fd >= 0 ? fd : STDOUT_FILENO,
                        arg_format);
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

        local = argv[1];
        if (!hostname_is_valid(local, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Machine name %s is not valid.", local);

        if (argc >= 3)
                path = argv[2];
        path = empty_or_dash_to_null(path);

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "ExportRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "shs",
                        local,
                        fd >= 0 ? fd : STDOUT_FILENO,
                        arg_format);
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

                if (!hostname_is_valid(local, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local name %s is not a suitable machine name.",
                                               local);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssb",
                        remote,
                        local,
                        import_verify_to_string(arg_verify),
                        arg_force);
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

                if (!hostname_is_valid(local, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local name %s is not a suitable machine name.",
                                               local);
        }

        r = bus_message_new_method_call(bus, &m, bus_import_mgr, "PullRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssb",
                        remote,
                        local,
                        import_verify_to_string(arg_verify),
                        arg_force);
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

        r = bus_call_method(bus, bus_import_mgr, "ListTransfers", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get transfers: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "(usssdo)");
        if (r < 0)
                return bus_log_parse_error(r);

        t = table_new("id", "progress", "type", "local", "remote");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 3, (size_t) 0);
        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        for (;;) {
                const char *type, *remote, *local;
                double progress;
                uint32_t id;

                r = sd_bus_message_read(reply, "(usssdo)", &id, &type, &remote, &local, &progress, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

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
                        return log_error_errno(r, "Failed to output table: %m");
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

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("importctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sDownload machine images%6$s\n"
               "\n%3$sImage Transfer Commands:%4$s\n"
               "  pull-tar URL [NAME]         Download a TAR container image\n"
               "  pull-raw URL [NAME]         Download a RAW container or VM image\n"
               "  import-tar FILE [NAME]      Import a local TAR container image\n"
               "  import-raw FILE [NAME]      Import a local RAW container or VM image\n"
               "  import-fs DIRECTORY [NAME]  Import a local directory container image\n"
               "  export-tar NAME [FILE]      Export a TAR container image locally\n"
               "  export-raw NAME [FILE]      Export a RAW container or VM image locally\n"
               "  list-transfers              Show list of downloads in progress\n"
               "  cancel-transfer             Cancel a download\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not show the headers and footers\n"
               "     --no-ask-password        Do not ask for system passwords\n"
               "  -H --host=[USER@]HOST       Operate on remote host\n"
               "  -M --machine=CONTAINER      Operate on local container\n"
               "     --read-only              Create read-only bind mount\n"
               "  -q --quiet                  Suppress output\n"
               "     --json=pretty|short|off  Generate JSON output\n"
               "  -j                          Equvilant to --json=pretty on TTY, --json=short\n"
               "                              otherwise\n"
               "     --verify=MODE            Verification mode for downloaded images (no,\n"
               "                               checksum, signature)\n"
               "     --format=xz|gzip|bzip2   Desired output format for export\n"
               "     --force                  Download image even if already exists\n"
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
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        for (;;) {
                c = getopt_long(argc, argv, "hH:M:jq", options, NULL);
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
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERIFY:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(import_verify, ImportVerify, _IMPORT_VERIFY_MAX);
                                return 0;
                        }

                        r = import_verify_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --verify= setting: %s", optarg);
                        arg_verify = r;
                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_FORMAT:
                        if (!STR_IN_SET(optarg, "uncompressed", "xz", "gzip", "bzip2"))
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
                        arg_json_format_flags = JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO;
                        arg_legend = false;
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
                { "pull-raw",        2,        3,        0,            pull_raw          },
                { "list-transfers",  VERB_ANY, 1,        VERB_DEFAULT, list_transfers    },
                { "cancel-transfer", 2,        VERB_ANY, 0,            cancel_transfer   },
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

        r = bus_connect_transport(arg_transport, arg_host, RUNTIME_SCOPE_SYSTEM, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        return importctl_main(argc, argv, bus);
}

DEFINE_MAIN_FUNCTION(run);
