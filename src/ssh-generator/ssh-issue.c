/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "fd-util.h"
#include "format-table.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "options.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "ssh-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "virt.h"

static enum {
        ACTION_MAKE_VSOCK,
        ACTION_RM_VSOCK,
} arg_action = ACTION_MAKE_VSOCK;

static char *arg_issue_path = NULL;
static bool arg_issue_stdout = false;

STATIC_DESTRUCTOR_REGISTER(arg_issue_path, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-ssh-issue", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%1$s [OPTIONS...] --make-vsock\n"
               "%1$s [OPTIONS...] --rm-vsock\n"
               "\n%2$sCreate ssh /run/issue.d/ file reporting VSOCK address.%3$s\n\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("make-vsock", NULL, "Generate the issue file (default)"):
                        arg_action = ACTION_MAKE_VSOCK;
                        break;

                OPTION_LONG("rm-vsock", NULL, "Remove the issue file"):
                        arg_action = ACTION_RM_VSOCK;
                        break;

                OPTION_LONG("issue-path", "PATH",
                            "Change path to /run/issue.d/50-ssh-vsock.issue"):
                        if (empty_or_dash(arg)) {
                                arg_issue_path = mfree(arg_issue_path);
                                arg_issue_stdout = true;
                                break;
                        }

                        r = parse_path_argument(arg, /* suppress_root= */ false, &arg_issue_path);
                        if (r < 0)
                                return r;

                        arg_issue_stdout = false;
                        break;
                }

        if (!arg_issue_path && !arg_issue_stdout) {
                arg_issue_path = strdup("/run/issue.d/50-ssh-vsock.issue");
                if (!arg_issue_path)
                        return log_oom();
        }

        return 1;
}

static int acquire_cid(unsigned *ret_cid) {
        int r;

        assert(ret_cid);

        Virtualization v = detect_virtualization();
        if (v < 0)
                return log_error_errno(v, "Failed to detect if we run in a VM: %m");
        if (!VIRTUALIZATION_IS_VM(v)) {
                /* NB: if we are running in a container inside a VM, then we'll *not* do AF_VSOCK stuff */
                log_debug("Not running in a VM, not creating issue file.");
                *ret_cid = 0;
                return 0;
        }

        r = vsock_open_or_warn(/* ret= */ NULL);
        if (r <= 0)
                return r;

        return vsock_get_local_cid_or_warn(ret_cid);
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        switch (arg_action) {
        case ACTION_MAKE_VSOCK: {
                unsigned cid;

                r = acquire_cid(&cid);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Not running in a VSOCK enabled VM, skipping.");
                        break;
                }

                _cleanup_(unlink_and_freep) char *t = NULL;
                _cleanup_(fclosep) FILE *f = NULL;
                FILE *out;

                if (arg_issue_path)  {
                        r = mkdir_parents(arg_issue_path, 0755);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create parent directories of '%s': %m", arg_issue_path);

                        r = fopen_tmpfile_linkable(arg_issue_path, O_WRONLY|O_CLOEXEC, &t, &f);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create '%s': %m", arg_issue_path);

                        out = f;
                } else
                        out = stdout;

                fprintf(out,
                        "Try contacting this VM's SSH server via 'ssh vsock%%%u' from host.\n"
                        "\n", cid);

                if (f) {
                        if (fchmod(fileno(f), 0644) < 0)
                                return log_error_errno(errno, "Failed to adjust access mode of '%s': %m", arg_issue_path);

                        r = flink_tmpfile(f, t, arg_issue_path, LINK_TMPFILE_REPLACE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to move '%s' into place: %m", arg_issue_path);
                }

                break;
        }

        case ACTION_RM_VSOCK:
                if (arg_issue_path) {
                        if (unlink(arg_issue_path) < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to remove '%s': %m", arg_issue_path);

                                log_debug_errno(errno, "File '%s' does not exist, no operation executed.", arg_issue_path);
                        } else
                                log_debug("Successfully removed '%s'.", arg_issue_path);
                } else
                        log_notice("STDOUT selected for issue file, not removing.");

                break;

        default:
                assert_not_reached();
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
