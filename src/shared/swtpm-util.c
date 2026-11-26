/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "json-util.h"
#include "log.h"
#include "memfd-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "swtpm-util.h"
#include "sync-util.h"

static int swtpm_find_best_profile(const char *swtpm_setup, char **ret) {
        int r;

        assert(swtpm_setup);
        assert(ret);

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

        /* NB: the exit status of --print-profiles is broken — swtpm_setup also exits with a failure
         * status when it successfully printed its profiles. Hence we ignore it (including the -EPROTO
         * that FORK_WAIT turns it into), and instead try to parse the output as JSON. This is also why
         * FORK_LOG is not passed: it would log the routine non-zero exit status at LOG_ERR. */
        r = pidref_safe_fork_full(
                        "(swtpm-lprof)",
                        (int[]) { -EBADF, mfd, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_REARRANGE_STDIO|FORK_WAIT,
                        /* ret= */ NULL);
        if (r < 0 && r != -EPROTO)
                return log_error_errno(r, "Failed to run swtpm_setup: %m");
        if (r == 0) {
                /* Child */
                r = execvp_safe(args[0], args);
                log_error_errno(r, "Failed to execute '%s': %m", args[0]);
                _exit(EXIT_FAILURE);
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        r = sd_json_parse_fd(
                        "swtpm-profiles",
                        mfd,
                        SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_SEEK0,
                        &j,
                        /* reterr_line= */ NULL,
                        /* reterr_column= */ NULL);
        if (r < 0) {
                log_notice("Failed to parse swtpm's --print-profiles output as JSON, assuming the implementation is too old to know the concept of profiles.");
                *ret = NULL;
                return 0;
        }

        sd_json_variant *v = sd_json_variant_by_key(j, "builtin");
        if (!v) {
                *ret = NULL;
                return 0;
        }

        if (!sd_json_variant_is_array(v))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'builtin' field is not an array.");

        const char *best_profile = NULL;
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

        _cleanup_free_ char *copy = NULL;
        if (best_profile) {
                copy = strdup(best_profile);
                if (!copy)
                        return log_oom();
        }

        *ret = TAKE_PTR(copy);
        return 0;
}

/* Check whether swtpm advertises the given feature in the capabilities JSON printed by
 * "swtpm chardev --print-capabilities". Returns 1 if it does, 0 if it does not (in particular when swtpm
 * is too old to know --print-capabilities or the feature), or a negative errno on failure. */
int swtpm_has_feature(const char *swtpm, const char *feature) {
        int r;

        assert(swtpm);
        assert(feature);

        _cleanup_strv_free_ char **args = strv_new(
                        swtpm,
                        "chardev",
                        "--print-capabilities");
        if (!args)
                return log_oom();

        _cleanup_close_ int mfd = memfd_new("swtpm-capabilities");
        if (mfd < 0)
                return log_error_errno(mfd, "Failed to allocate memfd: %m");

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmdline = quote_command_line(args, SHELL_ESCAPE_EMPTY);
                log_debug("About to spawn: %s", strnull(cmdline));
        }

        r = pidref_safe_fork_full(
                        "(swtpm-caps)",
                        (int[]) { -EBADF, mfd, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_REARRANGE_STDIO|FORK_LOG|FORK_WAIT,
                        /* ret= */ NULL);
        if (r == 0) {
                /* Child */
                r = execvp_safe(args[0], args);
                log_error_errno(r, "Failed to execute '%s': %m", args[0]);
                _exit(EXIT_FAILURE);
        }
        if (r == -EPROTO) {
                /* swtpm exited with a failure or was killed by a signal, which WAIT_LOG logged already.
                 * This includes swtpm versions that do not know --print-capabilities. */
                log_debug("swtpm failed to report its capabilities, assuming the implementation is too old to know the feature '%s'.", feature);
                return 0;
        } else if (r < 0)
                return log_error_errno(r, "Failed to run swtpm: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        r = sd_json_parse_fd(
                        "swtpm-capabilities",
                        mfd,
                        SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_SEEK0,
                        &j,
                        /* reterr_line= */ NULL,
                        /* reterr_column= */ NULL);
        if (r < 0) {
                log_debug("Failed to parse swtpm's --print-capabilities output as JSON, assuming the implementation is too old to know the feature '%s'.", feature);
                return 0;
        }

        sd_json_variant *v = sd_json_variant_by_key(j, "features");
        if (!v) {
                log_debug("swtpm's capabilities JSON has no 'features' field, assuming the implementation is too old to know the feature '%s'.", feature);
                return 0;
        }

        if (!sd_json_variant_is_array(v)) {
                log_debug("'features' field is not an array, assuming the implementation is too old to know the feature '%s'.", feature);
                return 0;
        }

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, v) {
                if (!sd_json_variant_is_string(i)) {
                        log_debug("Entry in 'features' array is not a string, ignoring.");
                        continue;
                }

                if (streq(sd_json_variant_string(i), feature))
                        return 1;
        }

        return 0;
}

int manufacture_swtpm(const char *state_dir, const char *secret) {
        int r;

        assert(state_dir);

        _cleanup_close_ int state_dir_fd = xopenat(AT_FDCWD, state_dir, O_RDONLY|O_DIRECTORY);
        if (state_dir_fd < 0)
                return log_error_errno(state_dir_fd, "Failed to open TPM state directory '%s': %m", state_dir);

        _cleanup_free_ char *swtpm_setup = NULL;
        r = find_executable("swtpm_setup", &swtpm_setup);
        if (r < 0)
                return log_error_errno(r, "Failed to find 'swtpm_setup' binary: %m");

        _cleanup_free_ char *best_profile = NULL;
        r = swtpm_find_best_profile(swtpm_setup, &best_profile);
        if (r < 0)
                return r;

        /* Create custom swtpm config files so that swtpm_localca uses our state directory instead of
         * the system-wide /var/lib/swtpm-localca/ which may not be writable. */
        _cleanup_free_ char *localca_conf = path_join(state_dir, "swtpm-localca.conf");
        if (!localca_conf)
                return log_oom();

        r = write_string_filef_at(
                        state_dir_fd, "swtpm-localca.conf",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC,
                        "statedir = %1$s\n"
                        "signingkey = %1$s/signing-private-key.pem\n"
                        "issuercert = %1$s/issuer-certificate.pem\n"
                        "certserial = %1$s/certserial\n",
                        state_dir);
        if (r < 0)
                return log_error_errno(r, "Failed to write swtpm-localca.conf: %m");

        _cleanup_free_ char *localca_options = path_join(state_dir, "swtpm-localca.options");
        if (!localca_options)
                return log_oom();

        r = write_string_file_at(
                        state_dir_fd, "swtpm-localca.options",
                        "--platform-manufacturer systemd\n"
                        "--platform-version 2.1\n"
                        "--platform-model swtpm\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write swtpm-localca.options: %m");

        _cleanup_free_ char *swtpm_localca = NULL;
        r = find_executable("swtpm_localca", &swtpm_localca);
        if (r < 0)
                return log_error_errno(r, "Failed to find 'swtpm_localca' binary: %m");

        _cleanup_free_ char *setup_conf = path_join(state_dir, "swtpm_setup.conf");
        if (!setup_conf)
                return log_oom();

        r = write_string_filef_at(
                        state_dir_fd, "swtpm_setup.conf",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC,
                        "create_certs_tool = %1$s\n"
                        "create_certs_tool_config = %2$s\n"
                        "create_certs_tool_options = %3$s\n",
                        swtpm_localca,
                        localca_conf,
                        localca_options);
        if (r < 0)
                return log_error_errno(r, "Failed to write swtpm_setup.conf: %m");

        _cleanup_strv_free_ char **args = strv_new(
                        swtpm_setup,
                        "--tpm-state", state_dir,
                        "--tpm2",
                        "--pcr-banks", "sha256",
                        "--ecc",
                        "--createek",
                        "--create-ek-cert",
                        "--create-platform-cert",
                        "--not-overwrite",
                        "--config", setup_conf);
        if (!args)
                return log_oom();

        if (secret && strv_extendf(&args, "--keyfile=%s", secret) < 0)
                return log_oom();

        if (best_profile && strv_extendf(&args, "--profile-name=%s", best_profile) < 0)
                return log_oom();

        if (!DEBUG_LOGGING && strv_extend_many(&args, "--logfile", "/dev/null") < 0)
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
                r = execvp_safe(args[0], args);
                log_error_errno(r, "Failed to execute '%s': %m", args[0]);
                _exit(EXIT_FAILURE);
        }

        /* Persist swtpm_setup's freshly created TPM state before writing the completion marker. */
        r = syncfs_path(state_dir_fd, /* path= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to sync TPM state directory: %m");

        /* Marker, written last, signals that manufacturing completed successfully. */
        _cleanup_close_ int marker_fd = xopenat(state_dir_fd, SWTPM_MANUFACTURED_MARKER, O_WRONLY|O_CREAT|O_NOFOLLOW);
        if (marker_fd < 0)
                return log_error_errno(marker_fd, "Failed to write '%s' marker: %m", SWTPM_MANUFACTURED_MARKER);

        return 0;
}
