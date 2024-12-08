/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "ansi-color.h"
#include "chattr-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fsprg.h"
#include "hostname-util.h"
#include "io-util.h"
#include "journal-authenticate.h"
#include "journalctl.h"
#include "journalctl-authenticate.h"
#include "memstream-util.h"
#include "path-util.h"
#include "qrcode-util.h"
#include "random-util.h"
#include "stat-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"

static int format_key(
                const void *seed,
                size_t seed_size,
                uint64_t start,
                uint64_t interval,
                char **ret) {

        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        assert(seed);
        assert(seed_size > 0);
        assert(ret);

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        for (size_t i = 0; i < seed_size; i++) {
                if (i > 0 && i % 3 == 0)
                        fputc('-', f);
                fprintf(f, "%02x", ((uint8_t*) seed)[i]);
        }

        fprintf(f, "/%"PRIx64"-%"PRIx64, start, interval);

        return memstream_finalize(&m, ret, NULL);
}

int action_setup_keys(void) {
        _cleanup_(unlink_and_freep) char *tmpfile = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *path = NULL;
        size_t mpk_size, seed_size, state_size;
        uint8_t *mpk, *seed, *state;
        sd_id128_t machine, boot;
        uint64_t n;
        int r;

        assert(arg_action == ACTION_SETUP_KEYS);

        r = is_dir("/var/log/journal/", /* follow = */ false);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR),
                                       "/var/log/journal is not a directory, must be using persistent logging for FSS.");
        if (r == -ENOENT)
                return log_error_errno(r, "Directory /var/log/journal/ does not exist, must be using persistent logging for FSS.");
        if (r < 0)
                return log_error_errno(r, "Failed to check if /var/log/journal/ is a directory: %m");

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine ID: %m");

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID: %m");

        path = path_join("/var/log/journal/", SD_ID128_TO_STRING(machine), "/fss");
        if (!path)
                return log_oom();

        if (arg_force) {
                if (unlink(path) < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to remove \"%s\": %m", path);
        } else if (access(path, F_OK) >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Sealing key file %s exists already. Use --force to recreate.", path);

        mpk_size = FSPRG_mskinbytes(FSPRG_RECOMMENDED_SECPAR);
        mpk = alloca_safe(mpk_size);

        seed_size = FSPRG_RECOMMENDED_SEEDLEN;
        seed = alloca_safe(seed_size);

        state_size = FSPRG_stateinbytes(FSPRG_RECOMMENDED_SECPAR);
        state = alloca_safe(state_size);

        if (!arg_quiet)
                log_info("Generating seed...");
        r = crypto_random_bytes(seed, seed_size);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire random seed: %m");

        if (!arg_quiet)
                log_info("Generating key pair...");
        r = FSPRG_GenMK(NULL, mpk, seed, seed_size, FSPRG_RECOMMENDED_SECPAR);
        if (r < 0)
                return log_error_errno(r, "Failed to generate key pair: %m");

        if (!arg_quiet)
                log_info("Generating sealing key...");
        r = FSPRG_GenState0(state, mpk, seed, seed_size);
        if (r < 0)
                return log_error_errno(r, "Failed to generate sealing key: %m");

        assert(arg_interval > 0);
        n = now(CLOCK_REALTIME);
        n /= arg_interval;

        fd = open_tmpfile_linkable(path, O_WRONLY|O_CLOEXEC, &tmpfile);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open a temporary file for %s: %m", path);

        r = chattr_secret(fd, CHATTR_WARN_UNSUPPORTED_FLAGS);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || arg_quiet ? LOG_DEBUG : LOG_WARNING,
                               r, "Failed to set file attributes on a temporary file for '%s', ignoring: %m", path);

        struct FSSHeader h = {
                .signature = { 'K', 'S', 'H', 'H', 'R', 'H', 'L', 'P' },
                .machine_id = machine,
                .boot_id = boot,
                .header_size = htole64(sizeof(h)),
                .start_usec = htole64(n * arg_interval),
                .interval_usec = htole64(arg_interval),
                .fsprg_secpar = htole16(FSPRG_RECOMMENDED_SECPAR),
                .fsprg_state_size = htole64(state_size),
        };

        r = loop_write(fd, &h, sizeof(h));
        if (r < 0)
                return log_error_errno(r, "Failed to write header: %m");

        r = loop_write(fd, state, state_size);
        if (r < 0)
                return log_error_errno(r, "Failed to write state: %m");

        r = link_tmpfile(fd, tmpfile, path, /* flags = */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to link file: %m");

        tmpfile = mfree(tmpfile);

        _cleanup_free_ char *key = NULL;
        r = format_key(seed, seed_size, n, arg_interval, &key);
        if (r < 0)
                return r;

        if ((!on_tty() || arg_quiet) && !sd_json_format_enabled(arg_json_format_flags)) {
                /* If we are not on a TTY, show only the key. */
                puts(key);
                return 0;
        }

        _cleanup_free_ char *hn = NULL;
        hn = gethostname_malloc();
        if (hn)
                hostname_cleanup(hn);

        if (sd_json_format_enabled(arg_json_format_flags)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                if (arg_json_format_flags & (SD_JSON_FORMAT_SSE | SD_JSON_FORMAT_SEQ)) {
                        log_debug("Specified --output=%s with --setup-keys, migrating to --output=json.",
                                  FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_SSE) ? "json-sse" : "json-seq");
                        arg_json_format_flags &= ~(SD_JSON_FORMAT_SSE | SD_JSON_FORMAT_SEQ);
                        arg_json_format_flags |= SD_JSON_FORMAT_NEWLINE;
                }

                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR_ID128("machine", machine),
                                SD_JSON_BUILD_PAIR_STRING("hostname", hn),
                                SD_JSON_BUILD_PAIR_STRING("path", path),
                                SD_JSON_BUILD_PAIR_STRING("key", key));
                if (r < 0)
                        return log_error_errno(r, "Failed to build json object: %m");

                r = sd_json_variant_dump(v, arg_json_format_flags, /* f = */ NULL, /* prefix = */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to dump json object: %m");

                return 0;
        }

        fprintf(stderr,
                "\nNew keys have been generated for host %s%s" SD_ID128_FORMAT_STR ".\n"
                "\n"
                "The %ssecret sealing key%s has been written to the following local file.\n"
                "This key file is automatically updated when the sealing key is advanced.\n"
                "It should not be used on multiple hosts.\n"
                "\n"
                "\t%s\n"
                "\n"
                "The sealing key is automatically changed every %s.\n"
                "\n"
                "Please write down the following %ssecret verification key%s. It should be stored\n"
                "in a safe location and should not be saved locally on disk.\n"
                "\n\t%s",
                strempty(hn), hn ? "/" : "",
                SD_ID128_FORMAT_VAL(machine),
                ansi_highlight(), ansi_normal(),
                path,
                FORMAT_TIMESPAN(arg_interval, 0),
                ansi_highlight(), ansi_normal(),
                ansi_highlight_red());
        fflush(stderr);

        puts(key);

        fputs(ansi_normal(), stderr);

#if HAVE_QRENCODE
        _cleanup_free_ char *url = NULL;
        url = strjoin("fss://", key, "?machine=", SD_ID128_TO_STRING(machine), hn ? ";hostname=" : "", hn);
        if (!url)
                return log_oom();

        (void) print_qrcode(stderr, "Scan the verification key to transfer it to another device", url);
#endif

        return 0;
}
