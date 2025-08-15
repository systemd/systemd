/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "creds-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "initrd-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"

static int sethostname_idempotent_full(const char *s, bool really) {
        struct utsname u;

        assert(s);

        if (uname(&u) < 0)
                return -errno;

        if (streq_ptr(s, u.nodename))
                return 0;

        if (really &&
            sethostname(s, strlen(s)) < 0)
                return -errno;

        return 1;
}

int sethostname_idempotent(const char *s) {
        return sethostname_idempotent_full(s, true);
}

int shorten_overlong(const char *s, char **ret) {
        _cleanup_free_ char *h = NULL;

        /* Shorten an overlong name to HOST_NAME_MAX or to the first dot,
         * whatever comes earlier. */

        assert(s);
        assert(ret);

        h = strdup(s);
        if (!h)
                return -ENOMEM;

        if (hostname_is_valid(h, 0)) {
                *ret = TAKE_PTR(h);
                return 0;
        }

        char *p = strchr(h, '.');
        if (p)
                *p = 0;

        strshorten(h, HOST_NAME_MAX);

        if (!hostname_is_valid(h, /* flags= */ 0))
                return -EDOM;

        *ret = TAKE_PTR(h);
        return 1;
}

static int acquire_hostname_from_credential(char **ret) {
        _cleanup_free_ char *cred = NULL;
        int r;

        assert(ret);

        r = read_credential_with_decryption("system.hostname", (void **) &cred, /* ret_size= */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to read system.hostname credential, ignoring: %m");
        if (r == 0) /* not found */
                return -ENXIO;

        if (!hostname_is_valid(cred, VALID_HOSTNAME_TRAILING_DOT)) /* check that the hostname we return is valid */
                return log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Hostname specified in system.hostname credential is invalid, ignoring: %s", cred);

        log_info("Initializing hostname from credential.");
        *ret = TAKE_PTR(cred);
        return 0;
}

int read_etc_hostname_stream(FILE *f, bool substitute_wildcards, char **ret) {
        int r;

        assert(f);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0) /* EOF without any hostname? the file is empty, let's treat that exactly like no file at all: ENOENT */
                        return -ENOENT;

                /* File may have empty lines or comments, ignore them */
                if (IN_SET(line[0], '\0', '#'))
                        continue;

                if (substitute_wildcards) {
                        r = hostname_substitute_wildcards(line);
                        if (r < 0)
                                return r;
                }

                hostname_cleanup(line); /* normalize the hostname */

                /* check that the hostname we return is valid */
                if (!hostname_is_valid(
                                    line,
                                    VALID_HOSTNAME_TRAILING_DOT|
                                    (substitute_wildcards ? 0 : VALID_HOSTNAME_QUESTION_MARK)))
                        return -EBADMSG;

                *ret = TAKE_PTR(line);
                return 0;
        }
}

int read_etc_hostname(const char *path, bool substitute_wildcards, char **ret) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(ret);

        if (!path)
                path = etc_hostname();

        f = fopen(path, "re");
        if (!f)
                return -errno;

        return read_etc_hostname_stream(f, substitute_wildcards, ret);
}

void hostname_update_source_hint(const char *hostname, HostnameSource source) {
        int r;

        assert(hostname);

        /* Why save the value and not just create a flag file? This way we will
         * notice if somebody sets the hostname directly (not going through hostnamed).
         */

        if (source == HOSTNAME_DEFAULT) {
                r = write_string_file("/run/systemd/default-hostname", hostname,
                                      WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_ATOMIC);
                if (r < 0)
                        log_warning_errno(r, "Failed to create \"/run/systemd/default-hostname\", ignoring: %m");
        } else
                (void) unlink_or_warn("/run/systemd/default-hostname");
}

int hostname_setup(bool really) {
        _cleanup_free_ char *hn = NULL;
        HostnameSource source;
        bool enoent = false;
        int r;

        r = proc_cmdline_get_key("systemd.hostname", 0, &hn);
        if (r < 0)
                log_warning_errno(r, "Failed to retrieve system hostname from kernel command line, ignoring: %m");
        else if (r > 0) {
                if (hostname_is_valid(hn, VALID_HOSTNAME_TRAILING_DOT))
                        source = HOSTNAME_TRANSIENT;
                else  {
                        log_warning("Hostname specified on kernel command line is invalid, ignoring: %s", hn);
                        hn = mfree(hn);
                }
        }

        if (!hn) {
                r = read_etc_hostname(/* path= */ NULL, /* substitute_wildcards= */ true, &hn);
                if (r == -ENOENT)
                        enoent = true;
                else if (r < 0)
                        log_warning_errno(r, "Failed to read configured hostname, ignoring: %m");
                else
                        source = HOSTNAME_STATIC;
        }

        if (!hn) {
                r = acquire_hostname_from_credential(&hn);
                if (r >= 0)
                        source = HOSTNAME_TRANSIENT;
        }

        if (!hn) {
                /* Don't override the hostname if it is already set and not explicitly configured */

                r = gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST, &hn);
                if (r == -ENOMEM)
                        return log_oom();
                if (r >= 0) {
                        log_debug("No hostname configured, leaving existing hostname <%s> in place.", hn);
                        goto finish;
                }

                if (enoent)
                        log_info("No hostname configured, using default hostname.");

                hn = get_default_hostname();
                if (!hn)
                        return log_oom();

                source = HOSTNAME_DEFAULT;
        }

        r = sethostname_idempotent_full(hn, really);
        if (r < 0)
                return log_warning_errno(r, "Failed to set hostname to <%s>: %m", hn);
        if (r == 0)
                log_debug("Hostname was already set to <%s>.", hn);
        else
                log_info("Hostname %s to <%s>.",
                         really ? "set" : "would have been set",
                         hn);

        if (really)
                hostname_update_source_hint(hn, source);

finish:
        if (!in_initrd())
                (void) sd_notifyf(/* unset_environment= */ false, "X_SYSTEMD_HOSTNAME=%s", hn);

        return 0;
}

static const char* const hostname_source_table[] = {
        [HOSTNAME_STATIC]    = "static",
        [HOSTNAME_TRANSIENT] = "transient",
        [HOSTNAME_DEFAULT]   = "default",
};

DEFINE_STRING_TABLE_LOOKUP(hostname_source, HostnameSource);

int hostname_substitute_wildcards(char *name) {
        static const sd_id128_t key = SD_ID128_MAKE(98,10,ad,df,8d,7d,4f,b5,89,1b,4b,56,ac,c2,26,8f);
        sd_id128_t mid = SD_ID128_NULL;
        size_t left_bits = 0, counter = 0;
        uint64_t h = 0;
        int r;

        assert(name);

        /* Replaces every occurrence of '?' in the specified string with a nibble hashed from
         * /etc/machine-id. This is supposed to be used on /etc/hostname files that want to automatically
         * configure a hostname derived from the machine ID in some form.
         *
         * Note that this does not directly use the machine ID, because that's not necessarily supposed to be
         * public information to be broadcast on the network, while the hostname certainly is. */

        for (char *n = name; ; n++) {
                n = strchr(n, '?');
                if (!n)
                        return 0;

                if (left_bits <= 0) {
                        if (sd_id128_is_null(mid)) {
                                r = sd_id128_get_machine(&mid);
                                if (r < 0)
                                        return r;
                        }

                        struct siphash state;
                        siphash24_init(&state, key.bytes);
                        siphash24_compress(&mid, sizeof(mid), &state);
                        siphash24_compress(&counter, sizeof(counter), &state); /* counter mode */
                        h = siphash24_finalize(&state);
                        left_bits = sizeof(h) * 8;
                        counter++;
                }

                assert(left_bits >= 4);
                *n = hexchar(h & 0xf);
                h >>= 4;
                left_bits -= 4;
        }
}

char* get_default_hostname(void) {
        int r;

        _cleanup_free_ char *h = get_default_hostname_raw();
        if (!h)
                return NULL;

        r = hostname_substitute_wildcards(h);
        if (r < 0) {
                log_debug_errno(r, "Failed to substitute wildcards in hostname, falling back to built-in name: %m");
                return strdup(FALLBACK_HOSTNAME);
        }

        return TAKE_PTR(h);
}

int gethostname_full(GetHostnameFlags flags, char **ret) {
        _cleanup_free_ char *buf = NULL, *fallback = NULL;
        struct utsname u;
        const char *s;

        assert(ret);

        if (uname(&u) < 0)
                return -errno;

        s = u.nodename;
        if (isempty(s) || streq(s, "(none)") ||
            (!FLAGS_SET(flags, GET_HOSTNAME_ALLOW_LOCALHOST) && is_localhost(s)) ||
            (FLAGS_SET(flags, GET_HOSTNAME_SHORT) && s[0] == '.')) {
                if (!FLAGS_SET(flags, GET_HOSTNAME_FALLBACK_DEFAULT))
                        return -ENXIO;

                s = fallback = get_default_hostname();
                if (!s)
                        return -ENOMEM;

                if (FLAGS_SET(flags, GET_HOSTNAME_SHORT) && s[0] == '.')
                        return -ENXIO;
        }

        if (FLAGS_SET(flags, GET_HOSTNAME_SHORT))
                buf = strdupcspn(s, ".");
        else
                buf = strdup(s);
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return 0;
}
