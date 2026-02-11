/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
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

#define DEFAULT_ISSUE_PATH "/run/issue.d/50-ssh-vsock.issue"
static char *arg_issue_path = NULL;
static bool arg_issue_stdout = false;

#include "ssh-issue.args.inc"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-ssh-issue", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] --make-vsock\n"
               "%s [OPTIONS...] --rm-vsock\n"
               "\n%sCreate ssh /run/issue.d/ file reporting VSOCK address.%s\n\n"
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
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

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        const char *path = arg_issue_stdout ? NULL : arg_issue_path ?: DEFAULT_ISSUE_PATH;

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

                if (path) {
                        r = mkdir_parents(path, 0755);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create parent directories of '%s': %m", path);

                        r = fopen_tmpfile_linkable(path, O_WRONLY|O_CLOEXEC, &t, &f);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create '%s': %m", path);

                        out = f;
                } else
                        out = stdout;

                fprintf(out,
                        "Try contacting this VM's SSH server via 'ssh vsock%%%u' from host.\n"
                        "\n", cid);

                if (f) {
                        if (fchmod(fileno(f), 0644) < 0)
                                return log_error_errno(errno, "Failed to adjust access mode of '%s': %m", path);

                        r = flink_tmpfile(f, t, path, LINK_TMPFILE_REPLACE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to move '%s' into place: %m", path);
                }

                break;
        }

        case ACTION_RM_VSOCK:
                if (path) {
                        if (unlink(path) < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to remove '%s': %m", path);

                                log_debug_errno(errno, "File '%s' does not exist, no operation executed.", path);
                        } else
                                log_debug("Successfully removed '%s'.", path);
                } else
                        log_notice("STDOUT selected for issue file, not removing.");

                break;

        default:
                assert_not_reached();
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
