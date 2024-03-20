/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "qrcode-util.h"
#include "random-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"

static int format_journal_url(
                const void *seed,
                size_t seed_size,
                uint64_t start,
                uint64_t interval,
                const char *hn,
                sd_id128_t machine,
                bool full,
                char **ret_url) {

        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        assert(seed);
        assert(seed_size > 0);

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        if (full)
                fputs("fss://", f);

        for (size_t i = 0; i < seed_size; i++) {
                if (i > 0 && i % 3 == 0)
                        fputc('-', f);
                fprintf(f, "%02x", ((uint8_t*) seed)[i]);
        }

        fprintf(f, "/%"PRIx64"-%"PRIx64, start, interval);

        if (full) {
                fprintf(f, "?machine=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(machine));
                if (hn)
                        fprintf(f, ";hostname=%s", hn);
        }

        return memstream_finalize(&m, ret_url, NULL);
}

int action_setup_keys(void) {
        size_t mpk_size, seed_size, state_size;
        _cleanup_(unlink_and_freep) char *k = NULL;
        _cleanup_free_ char *p = NULL;
        uint8_t *mpk, *seed, *state;
        _cleanup_close_ int fd = -EBADF;
        sd_id128_t machine, boot;
        struct stat st;
        uint64_t n;
        int r;

        assert(arg_action == ACTION_SETUP_KEYS);

        r = stat("/var/log/journal", &st);
        if (r < 0 && !IN_SET(errno, ENOENT, ENOTDIR))
                return log_error_errno(errno, "stat(\"%s\") failed: %m", "/var/log/journal");

        if (r < 0 || !S_ISDIR(st.st_mode)) {
                log_error("%s is not a directory, must be using persistent logging for FSS.",
                          "/var/log/journal");
                return r < 0 ? -errno : -ENOTDIR;
        }

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine ID: %m");

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID: %m");

        if (asprintf(&p, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return log_oom();

        if (arg_force) {
                r = unlink(p);
                if (r < 0 && errno != ENOENT)
                        return log_error_errno(errno, "unlink(\"%s\") failed: %m", p);
        } else if (access(p, F_OK) >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Sealing key file %s exists already. Use --force to recreate.", p);

        if (asprintf(&k, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss.tmp.XXXXXX",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return log_oom();

        mpk_size = FSPRG_mskinbytes(FSPRG_RECOMMENDED_SECPAR);
        mpk = alloca_safe(mpk_size);

        seed_size = FSPRG_RECOMMENDED_SEEDLEN;
        seed = alloca_safe(seed_size);

        state_size = FSPRG_stateinbytes(FSPRG_RECOMMENDED_SECPAR);
        state = alloca_safe(state_size);

        log_info("Generating seed...");
        r = crypto_random_bytes(seed, seed_size);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire random seed: %m");

        log_info("Generating key pair...");
        FSPRG_GenMK(NULL, mpk, seed, seed_size, FSPRG_RECOMMENDED_SECPAR);

        log_info("Generating sealing key...");
        FSPRG_GenState0(state, mpk, seed, seed_size);

        assert(arg_interval > 0);

        n = now(CLOCK_REALTIME);
        n /= arg_interval;

        safe_close(fd);
        fd = mkostemp_safe(k);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open %s: %m", k);

        r = chattr_secret(fd, CHATTR_WARN_UNSUPPORTED_FLAGS);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) ? LOG_DEBUG : LOG_WARNING,
                               r, "Failed to set file attributes on '%s', ignoring: %m", k);

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

        if (rename(k, p) < 0)
                return log_error_errno(errno, "Failed to link file: %m");

        k = mfree(k);

        _cleanup_free_ char *hn = NULL, *key = NULL;

        r = format_journal_url(seed, seed_size, n, arg_interval, hn, machine, false, &key);
        if (r < 0)
                return r;

        if (on_tty()) {
                hn = gethostname_malloc();
                if (hn)
                        hostname_cleanup(hn);

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
                        p,
                        FORMAT_TIMESPAN(arg_interval, 0),
                        ansi_highlight(), ansi_normal(),
                        ansi_highlight_red());
                fflush(stderr);
        }

        puts(key);

        if (on_tty()) {
                fprintf(stderr, "%s", ansi_normal());
#if HAVE_QRENCODE
                _cleanup_free_ char *url = NULL;
                r = format_journal_url(seed, seed_size, n, arg_interval, hn, machine, true, &url);
                if (r < 0)
                        return r;

                (void) print_qrcode(stderr,
                                    "To transfer the verification key to your phone scan the QR code below",
                                    url);
#endif
        }

        return 0;
}
