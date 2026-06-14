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
#include "strv.h"
#include "tmpfile-util.h"
#include "verbs.h"
#include "virt.h"

static char *arg_issue_path = NULL;
static bool arg_issue_stdout = false;

STATIC_DESTRUCTOR_REGISTER(arg_issue_path, freep);

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

VERB_NOARG(verb_make_vsock, "make-vsock",
           "Generate the issue file");
static int verb_make_vsock(int argc, char *argv[], uintptr_t _data, void *_userdata) {
        unsigned cid;
        int r;

        r = acquire_cid(&cid);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("Not running in a VSOCK enabled VM, skipping.");
                return 0;
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

        return 0;
}

VERB_NOARG(verb_rm_vsock, "rm-vsock",
           "Remove the issue file");
static int verb_rm_vsock(int argc, char *argv[], uintptr_t _data, void *_userdata) {
        if (arg_issue_path) {
                if (unlink(arg_issue_path) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to remove '%s': %m", arg_issue_path);

                        log_debug_errno(errno, "File '%s' does not exist, no operation executed.", arg_issue_path);
                } else
                        log_debug("Successfully removed '%s'.", arg_issue_path);
        } else
                log_notice("STDOUT selected for issue file, not removing.");

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = terminal_urlify_man("systemd-ssh-issue", "1", &link);
        if (r < 0)
                return log_oom();

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s [OPTIONS...] COMMAND\n"
               "\n%sCreate/remove ssh /run/issue.d/ file reporting VSOCK address.%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(), ansi_normal(),
               ansi_underline(), ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(), ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };
        const char *verb = NULL;
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("make-vsock", NULL, /* help= */ NULL): {}
                OPTION_LONG("rm-vsock", NULL, /* help= */ NULL):
                        verb = opts.opt->long_code;
                        break;

                OPTION_LONG("issue-path", "PATH",
                            "Change path to /run/issue.d/50-ssh-vsock.issue"):
                        if (empty_or_dash(opts.arg)) {
                                arg_issue_path = mfree(arg_issue_path);
                                arg_issue_stdout = true;
                                break;
                        }

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_issue_path);
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

        char **args;
        if (verb) {
                if (option_parser_get_n_args(&opts) > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid use of compat option --make-vsock/--rm-vsock.");
                log_warning("Options --make-vsock/--rm-vsock have been replaced by make-vsock/rm-vsock verbs.");
                args = strv_new(verb);
        } else
                args = strv_copy(option_parser_get_args(&opts));
        if (!args)
                return log_oom();

        *ret_args = args;
        return 1;
}

static int run(int argc, char* argv[]) {
        _cleanup_strv_free_ char **args = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
