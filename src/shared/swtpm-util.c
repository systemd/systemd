/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "json-util.h"
#include "log.h"
#include "memfd-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "swtpm-util.h"

int manufacture_swtpm(const char *state_dir, const char *secret) {
        int r;

        assert(state_dir);

        _cleanup_free_ char *swtpm_setup = NULL;
        r = find_executable("swtpm_setup", &swtpm_setup);
        if (r < 0)
                return log_error_errno(r, "Failed to find 'swtpm_setup' binary: %m");

        _cleanup_strv_free_ char **args = strv_new(
                        swtpm_setup,
                         "--tpm2",
                         "--print-profiles");
        if (!args)
                return log_oom();

        _cleanup_close_ int mfd = memfd_new("swtpm-profiles");
        if (mfd < 0)
                return log_error_errno(mfd, "Failed to allocate memfd: %m");

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmdline = quote_command_line(args, SHELL_ESCAPE_EMPTY);
                log_debug("About to spawn: %s", strnull(cmdline));
        }

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        "(swtpm-lprof)",
                        (int[]) { -EBADF, mfd, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_REARRANGE_STDIO|FORK_LOG,
                        &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to run swtpm_setup: %m");
        if (r == 0) {
                /* Child */
                execvp(args[0], args);
                log_error_errno(errno, "Failed to execute '%s': %m", args[0]);
                _exit(EXIT_FAILURE);
        }

        r = pidref_wait_for_terminate_and_check("(swtpm-lprof)", &pidref, WAIT_LOG_ABNORMAL);
        if (r < 0)
                return r;

        /* NB: we ignore the exit status of --print-profiles, it's broken. Instead we check if we have
         * received a valid JSON object via STDOUT. */
        (void) r;

        _cleanup_free_ char *text = NULL;
        r = read_full_file_full(
                        mfd,
                        /* filename= */ NULL,
                        /* offset= */ 0,
                        /* size= */ SIZE_MAX,
                        /* flags= */ 0,
                        /* bind_name= */ NULL,
                        &text,
                        /* ret_size= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read memory fd: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        const char *best_profile = NULL;
        if (isempty(text))
                log_notice("No list of supported profiles could be acquired from swtpm, assuming the implementation is too old to know the concept of profiles.");
        else {
                r = sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT, &j, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse swtpm's --print-profiles output: %m");

                sd_json_variant *v = sd_json_variant_by_key(j, "builtin");
                if (v) {
                        if (!sd_json_variant_is_array(v))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'builtin' field is not an array: %m");

                        sd_json_variant *i;
                        JSON_VARIANT_ARRAY_FOREACH(i, v) {
                                if (!sd_json_variant_is_object(i))
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Profile object is not a JSON object.");

                                sd_json_variant *n = sd_json_variant_by_key(i, "Name");
                                if (!n) {
                                        log_debug("Object in profiles array does not have a 'Name', skipping.");
                                        continue;
                                }

                                if (!sd_json_variant_is_string(n))
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Profile's 'Name' field is not a string.");

                                const char *s = sd_json_variant_string(n);

                                /* Pick the best of the default-v1, default-v2, … profiles */
                                if (!startswith(s, "default-v"))
                                        continue;
                                if (!best_profile || strverscmp_improved(s, best_profile) > 0)
                                        best_profile = s;
                        }
                }
        }

        strv_free(args);
        args = strv_new(swtpm_setup,
                        "--tpm-state", state_dir,
                        "--tpm2",
                        "--pcr-banks", "sha256",
                        "--ecc",
                        "--createek",
                        "--create-ek-cert",
                        "--create-platform-cert",
                        "--not-overwrite");
        if (!args)
                return log_oom();

        if (secret && strv_extendf(&args, "--keyfile=%s", secret) < 0)
                return log_oom();

        if (best_profile && strv_extendf(&args, "--profile-name=%s", best_profile) < 0)
                return log_oom();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmdline = quote_command_line(args, SHELL_ESCAPE_EMPTY);
                log_debug("About to spawn: %s", strnull(cmdline));
        }

        r = pidref_safe_fork("(swtpm-setup)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT, /* ret= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run swtpm_setup: %m");
        if (r == 0) {
                /* Child */
                execvp(args[0], args);
                log_error_errno(errno, "Failed to execute '%s': %m", args[0]);
                _exit(EXIT_FAILURE);
        }

        return 0;
}
