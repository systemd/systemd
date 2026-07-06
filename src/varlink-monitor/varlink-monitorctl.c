/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-varlink.h"

#include "monitor-varlink-api.bpf.h"
#include "ringbuf.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "user-util.h"
#include "varlink-util.h"
#include "verbs.h"
#include "version.h"
#include "ansi-color.h"
#include "cleanup-util.h"
#include "alloc-util.h"
#include "pretty-print.h"
#include "options.h"
#include "build.h"

static uid_t arg_uid = UID_INVALID;

static int interrupt_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static int on_ringbuf_data(Ringbuf *rb, uint8_t *data, size_t size, void *userdata) {
        while (size >= sizeof(struct monitor_varlink_packet)) {
                struct monitor_varlink_packet *p = (struct monitor_varlink_packet *) data;

                if (p->path_len > 0)
                        printf("[%.*s%s] ", (int) p->path_len, p->path, p->accepted ? " (accepted)" : "");
                else if (p->accepted)
                        printf("[accepted] ");

                printf("pid=%"PRIu32" uid=%"PRIu32" -> peer_pid=%"PRIu32" peer_uid=%"PRIu32" %.*s\n",
                       p->pid, p->uid, p->peer_pid, p->peer_uid,
                       (int) p->data_len, (const char *) p->data);

                data += sizeof(struct monitor_varlink_packet);
                size -= sizeof(struct monitor_varlink_packet);
        }

        fflush(stdout);
        return 0;
}

static void on_ringbuf_shutdown(Ringbuf *rb, void *userdata) {
        log_error("Remote shut down, exiting");
        sd_event_exit(ringbuf_get_event(rb), EINTR);
}

typedef struct SetupData {
        unsigned read_eventfd_idx;
        unsigned write_eventfd_idx;
} SetupData;

VERB_DEFAULT_NOARG(verb_dump, "dump", "Dump varlink sockets");
static int verb_dump(int argc, char *argv[], uintptr_t _data, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "eventfdReadFileDescriptor",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, offsetof(SetupData, read_eventfd_idx),  SD_JSON_MANDATORY },
                { "eventfdWriteFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, offsetof(SetupData, write_eventfd_idx), SD_JSON_MANDATORY },
                {}
        };

        SetupData d = {
                .read_eventfd_idx = UINT_MAX,
                .write_eventfd_idx = UINT_MAX,
        };
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        _cleanup_(ringbuf_unrefp) Ringbuf *rb = NULL;
        _cleanup_close_ int read_eventfd = -EBADF, write_eventfd = -EBADF;
        sd_json_variant *reply;
        int r;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_add_signal(event, NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK, interrupt_signal_handler, NULL);

        r = sd_varlink_connect_address(&link, "/run/systemd/varlink/io.systemd.VarlinkMonitor");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to varlink monitoring service /run/systemd/varlink/io.systemd.VarlinkMonitor: %m");

        r = sd_varlink_set_allow_fd_passing_input(link, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable file descriptor passing: %m");

        r = sd_varlink_set_allow_fd_passing_output(link, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable file descriptor passing: %m");

        r = ringbuf_new(&rb, RINGBUF_SIDE_READER);
        assert(r >= 0);

        r = ringbuf_create_memfd(rb, page_size() * 8);
        assert(r >= 0);

        int memfd = ringbuf_get_memfd(rb);
        assert(memfd >= 0);

        int memfd_idx = sd_varlink_push_dup_fd(link, memfd);
        assert(memfd_idx >= 0);

        uid_t uid = arg_uid != UID_INVALID ? arg_uid : getuid();

        r = varlink_callbo_and_log(
                        link,
                        "io.systemd.VarlinkMonitor.Setup",
                        &reply,
                        SD_JSON_BUILD_PAIR_INTEGER("ringbufFileDescriptor", memfd_idx),
                        SD_JSON_BUILD_PAIR_INTEGER("uid", uid));
        if (r < 0)
                return r;

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &d);
        if (r < 0)
                return r;

        read_eventfd = sd_varlink_peek_dup_fd(link, d.read_eventfd_idx);
        if (read_eventfd < 0)
                return log_debug_errno(read_eventfd, "Failed to take reader eventfd from Varlink connection: %m");

        write_eventfd = sd_varlink_peek_dup_fd(link, d.write_eventfd_idx);
        if (write_eventfd < 0)
                return log_debug_errno(write_eventfd, "Failed to take writer eventfd from Varlink connection: %m");

        r = ringbuf_set_eventfds(rb, TAKE_FD(read_eventfd), TAKE_FD(write_eventfd));
        assert(r >= 0);

        r = ringbuf_bind_data(rb, on_ringbuf_data);
        assert(r >= 0);

        r = ringbuf_bind_shutdown(rb, on_ringbuf_shutdown);
        assert(r >= 0);

        r = ringbuf_attach_event(rb, event, 0);
        assert(r >= 0);

        r = varlink_call_and_log(link, "io.systemd.VarlinkMonitor.Start", /* parameters= */ NULL, /* ret_parameters= */ NULL);
        if (r < 0)
                return r;

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("varlink-monitorctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sMonitor Varlink Services.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  dump                   Dump varlink traffic\n"
               "  help                   Show this help\n"
               "\n%3$sOptions:%4$s\n"
               "  -u, --uid=UID          Monitor connections of the specified UID\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

VERB_COMMON_HELP(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('u', "uid", "UID", "Monitor connections of the specified UID"):
                        r = parse_uid(opts.arg, &arg_uid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse UID '%s': %m", opts.arg);
                        break;
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;  /* unnecessary initialization to appease gcc <= 13 */
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
