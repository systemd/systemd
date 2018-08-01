/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>

#include "rdtd.h"
#include "rdtd-group.h"
#include "def.h"
#include "sd-daemon.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "process-util.h"

static bool arg_debug = false;

static Manager* manager_unref(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_unref);

static int manager_new(Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->groups = hashmap_new(&string_hash_ops);
        if (!m->groups)
                return -ENOMEM;

        m->rdtinfo = NULL;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

        *ret = TAKE_PTR(m);
        return 0;
}

static Manager* manager_unref(Manager *m) {
        RdtGroup *g;

        while ((g = hashmap_first(m->groups))) {
                hashmap_remove(m->groups, g->name);
                group_free(g);
        }

        hashmap_free(m->groups);

        free(m->rdtinfo);
        m->rdtinfo = NULL;

        sd_event_unref(m->event);

        return mfree(m);
}

static int manager_dispatch_reload_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = userdata;
        int r;

        r = manager_enumerate_groups(m);
        if (r < 0)
                log_warning_errno(r, "Group enumeration failed: %m");
        else
                log_info("Group information refreshed.");

        return 0;
}

static int manager_startup(Manager *m) {
        int r;

        assert(m);

        r = sd_event_add_signal(m->event, NULL, SIGHUP, manager_dispatch_reload_signal, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register SIGHUP handler: %m");

        r = manager_get_rdtinfo(m);
        if (r < 0)
                log_warning_errno(r, "Get rdtinfo failed: %m");

        r = manager_enumerate_groups(m);
        if (r < 0)
                log_warning_errno(r, "Group enumeration failed: %m");

        return 0;
}

static int manager_run(Manager *m) {
        int r;

        assert(m);

        for (;;) {
                r = sd_event_get_state(m->event);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        return 0;

                r = sd_event_run(m->event, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Manages RDT groups.\n\n"
               "  -h --help                   Print this message\n"
               "  -V --version                Print version of the program\n"
               "  -D --debug                  Enable debug output\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "debug",              no_argument,            NULL, 'D' },
                { "help",               no_argument,            NULL, 'h' },
                { "version",            no_argument,            NULL, 'V' },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "DhV", options, NULL)) >= 0) {
                switch (c) {

                case 'D':
                        arg_debug = true;
                        break;
                case 'h':
                        help();
                        return 0;
                case 'V':
                        printf("%s\n", PACKAGE_VERSION);
                        return 0;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unhandled option");

                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_set_facility(LOG_AUTH);
        rdtd_parse_config();
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_debug)
                log_set_max_level(LOG_DEBUG);

        umask(0022);

        r = mac_selinux_init();
        if (r < 0) {
                log_error_errno(r, "Could not initialize labelling: %m");
                goto finish;
        }

        (void) mkdir_label(RDT_RUNTIME_DIR, 0755);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGHUP, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate manager object: %m");
                goto finish;
        }

        r = manager_startup(m);
        if (r < 0) {
                log_error_errno(r, "Failed to fully start up daemon: %m");
                goto finish;
        }

        log_debug("systemd-rdtd running as pid "PID_FMT, getpid_cached());

        (void) sd_notify(false,
                         "READY=1\n"
                         "STATUS=Processing requests...");

        r = manager_run(m);

        log_debug("systemd-rdtd stopped as pid "PID_FMT, getpid_cached());

        (void) sd_notify(false,
                         "STOPPING=1\n"
                         "STATUS=Shutting down...");

finish:
        mac_selinux_finish();
        log_close();
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
