/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "constants.h"
#include "creds-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "initrd-util.h"
#include "io-util.h"
#include "log.h"
#include "namespace-util.h"
#include "pidref.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "siphash24.h"
#include "stat-util.h"
#include "stdio-util.h"
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

        /* Shorten an overlong name to LINUX_HOST_NAME_MAX or to the first dot,
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

        strshorten(h, LINUX_HOST_NAME_MAX);

        if (!hostname_is_valid(h, /* flags= */ 0))
                return -EDOM;

        *ret = TAKE_PTR(h);
        return 1;
}

static int validate_and_substitute_hostname_from_source(const char *raw, const char *source, char **ret) {
        int r;

        assert(raw);
        assert(source);
        assert(ret);

        /* Validate a raw hostname value that may carry '?'/'$' wildcards, expand the wildcards, then validate the
         * concrete result. Shared by the credential and kernel command line paths. */
        if (!hostname_is_valid(raw, VALID_HOSTNAME_TRAILING_DOT|VALID_HOSTNAME_QUESTION_MARK|VALID_HOSTNAME_WORD_TOKEN))
                return log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Hostname specified %s is invalid, ignoring: %s", source, raw);

        _cleanup_free_ char *substituted = NULL;
        r = hostname_substitute_wildcards(raw, &substituted);
        if (r < 0)
                return log_warning_errno(r, "Failed to substitute wildcards in hostname specified %s, ignoring: %m", source);

        if (!hostname_is_valid(substituted, VALID_HOSTNAME_TRAILING_DOT)) /* check that the expanded hostname is valid */
                return log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Hostname specified %s is invalid after expansion, ignoring: %s", source, substituted);

        *ret = TAKE_PTR(substituted);
        return 0;
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

        r = validate_and_substitute_hostname_from_source(cred, "in the system.hostname credential", ret);
        if (r < 0)
                return r;

        log_info("Initializing hostname from credential.");
        return 0;
}

static int acquire_hostname_from_cmdline(char **ret) {
        _cleanup_free_ char *hn = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key("systemd.hostname", 0, &hn);
        if (r < 0)
                return log_warning_errno(r, "Failed to retrieve system hostname from kernel command line, ignoring: %m");
        if (r == 0) /* not specified */
                return -ENXIO;

        /* The name may contain '?'/'$' wildcards (see hostname(5)). In the initrd the word lists (and
         * possibly the machine ID) are typically not available yet so returning here means the default
         * hostname will be used. Once the host file system is up the expansion succeeds and the intended
         * name is applied. */
        return validate_and_substitute_hostname_from_source(hn, "on the kernel command line", ret);
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
                        _cleanup_free_ char *substituted = NULL;

                        r = hostname_substitute_wildcards(line, &substituted);
                        if (r < 0)
                                return r;

                        free_and_replace(line, substituted);
                }

                hostname_cleanup(line); /* normalize the hostname */

                /* check that the hostname we return is valid */
                if (!hostname_is_valid(
                                    line,
                                    VALID_HOSTNAME_TRAILING_DOT|
                                    (substitute_wildcards ? 0 : VALID_HOSTNAME_QUESTION_MARK|VALID_HOSTNAME_WORD_TOKEN)))
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

        r = acquire_hostname_from_cmdline(&hn);
        if (r >= 0)
                source = HOSTNAME_TRANSIENT;

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

static int hostname_open_wordlist(const char *file, FILE **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(file);
        assert(ret);

        /* Opens one of the numbered hostname word list files ("1", "2", "3", ...) for the '$' wildcards. */
        const char *override = secure_getenv("SYSTEMD_HOSTNAME_WORDLIST_PATH");
        r = search_and_fopen(
                        file,
                        "re",
                        /* root= */ NULL,
                        override ? (const char**) STRV_MAKE(override) : (const char**) CONF_PATHS_STRV("systemd/hostname-wordlist"),
                        &f,
                        /* ret_path= */ NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

static bool normalize_and_validate_word(char *word) {
        assert(word);

        if (IN_SET(word[0], '\0', '#')) /* empty line or comment */
                return false;

        ascii_strlower(word);
        return hostname_is_valid(word, /* flags= */ 0);
}

static int pick_word_linear_scan(FILE *f, off_t offset, char **ret) {
        int r;

        assert(f);
        assert(ret);

        if (fseeko(f, offset, SEEK_SET) < 0)
                return -errno;

        bool wrapped = false;
        r = read_line(f, LONG_LINE_MAX, NULL); /* discard the partial line we landed in */
        if (r < 0)
                return r;
        if (r == 0) {
                wrapped = true;
                rewind(f);
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0) { /* hit EOF: we started at a random offset, wrap around to the beginning */
                        if (wrapped) /* already wrapped once, the file contains no usable word at all */
                                return -ENOENT;
                        wrapped = true;
                        rewind(f);
                        continue;
                }
                if (normalize_and_validate_word(line)) {
                        *ret = TAKE_PTR(line);
                        return 0;
                }
        }
}

static int hostname_pick_word(sd_id128_t mid, size_t pos, char **ret) {
        static const sd_id128_t word_key = SD_ID128_MAKE(2d,9f,1c,7a,4b,8e,43,11,9a,6d,5f,02,c8,77,e3,14);
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        int r;

        assert(pos >= 1);
        assert(ret);

        /* The n-th '$' in a template reads the word list file named after its position, i.e. "1", "2", ... */
        char file[DECIMAL_STR_MAX(size_t)];
        xsprintf(file, "%zu", pos);

        r = hostname_open_wordlist(file, &f);
        if (r < 0)
                return r;

        if (fstat(fileno(f), &st) < 0)
                return -errno;
        r = stat_verify_regular(&st);
        if (r < 0)
                return r;
        if (st.st_size == 0)
                return -ENOENT;

        /* Pick a word without reading the whole list into memory:
         * 1. pick a random offset in the file [0 … st.st_size-1]
         * 2. if offset is zero, read a full line from the beginning of the file, use that.
         * 3. otherwise, seek to offset minus 1 and read one character.
         * 4. if that character is newline, then read a full line after it, and use that as result
         * 5. otherwise, goto 1
         *
         * As a safety net terminate after a fixed number iterations (for pathological wordlists)
         * This stream is independent of the '?' nibble stream so pure-'?'  * templates keep producing
         * byte-identical output. Stable as long as the wordlist is stable. */
        off_t offset = 0;
        const unsigned int MAX_ITERATIONS = 64;
        for (unsigned i = 0; i < MAX_ITERATIONS; i++) {
                _cleanup_free_ char *line = NULL;

                struct siphash state;
                siphash24_init(&state, word_key.bytes);
                siphash24_compress_typesafe(mid, &state);
                siphash24_compress_typesafe(pos, &state);
                siphash24_compress_typesafe(i, &state); /* counter mode */
                offset = (off_t) (siphash24_finalize(&state) % (uint64_t) st.st_size);

                if (offset > 0) {
                        if (fseeko(f, offset - 1, SEEK_SET) < 0)
                                return -errno;
                        if (fgetc(f) != '\n')
                                continue; /* not a line start */
                } else if (fseeko(f, 0, SEEK_SET) < 0) /* offset 0 always begins the first line */
                        return -errno;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0) /* raced with truncation */
                        continue;
                if (normalize_and_validate_word(line)) {
                        *ret = TAKE_PTR(line);
                        return 0;
                }
                /* Comment/empty/invalid line: resample rather than advancing, to keep the pick uniform. */
        }

        /* We exhausted the uniform attempts, this should never happen but if it does fallback to picking the
        * next word after our last attempt. */
        log_warning("hostname_pick_word did not find a usable word after %u in wordlist %zu", MAX_ITERATIONS, pos);
        return pick_word_linear_scan(f, offset, ret);
}

int hostname_substitute_wildcards(const char *name, char **ret) {
        static const sd_id128_t key = SD_ID128_MAKE(98,10,ad,df,8d,7d,4f,b5,89,1b,4b,56,ac,c2,26,8f);
        sd_id128_t mid = SD_ID128_NULL;
        _cleanup_free_ char *result = NULL;
        size_t left_bits = 0, counter = 0;
        size_t word_pos = 0;
        size_t n_result = 0;
        uint64_t h = 0;
        int r;

        assert(name);
        assert(ret);

        if (isempty(name))
                return strdup_to(ret, "");

        /* Expands wildcards in the specified string, deriving the inserted values deterministically from
         * /etc/machine-id:
         *
         *   '?'  is replaced by a single hex nibble hashed from the machine ID.
         *   '$'  is replaced by a word picked from a word list; the n-th '$' in the string uses the list
         *        file named "n"
         *
         * This is supposed to be used on /etc/hostname files that want to automatically configure a hostname
         * derived from the machine ID in some form, e.g. "$-$-????".
         *
         * Note that this does not directly expose the machine ID, because that's not necessarily supposed to
         * be public information to be broadcast on the network, while the hostname certainly is. */

        for (const char *n = name; *n; n++) {
                if (IN_SET(*n, '?', '$') && sd_id128_is_null(mid)) {
                        r = sd_id128_get_machine(&mid);
                        if (r < 0)
                                return r;
                }

                if (*n == '?') {
                        if (left_bits <= 0) {
                                struct siphash state;
                                siphash24_init(&state, key.bytes);
                                siphash24_compress_typesafe(mid, &state);
                                siphash24_compress_typesafe(counter, &state); /* counter mode */
                                h = siphash24_finalize(&state);
                                left_bits = sizeof(h) * 8;
                                counter++;
                        }

                        assert(left_bits >= 4);
                        char c = hexchar(h & 0xf);
                        h >>= 4;
                        left_bits -= 4;

                        if (!GREEDY_REALLOC_APPEND(result, n_result, &c, 1))
                                return -ENOMEM;

                } else if (*n == '$') {
                        /* Each '$' is an independent word token; the n-th one picks from word list "n".
                         * There is no escape for a literal '$', as it is not a valid hostname character. */
                        _cleanup_free_ char *w = NULL;
                        r = hostname_pick_word(mid, ++word_pos, &w);
                        if (r < 0)
                                return r;

                        if (!GREEDY_REALLOC_APPEND(result, n_result, w, strlen(w)))
                                return -ENOMEM;

                } else if (!GREEDY_REALLOC_APPEND(result, n_result, n, 1))
                        return -ENOMEM;
        }

        if (!GREEDY_REALLOC(result, n_result + 1))
                return -ENOMEM;
        result[n_result] = 0;

        *ret = TAKE_PTR(result);
        return 0;
}

char* get_default_hostname(void) {
        int r;

        _cleanup_free_ char *h = get_default_hostname_raw();
        if (!h)
                return NULL;

        _cleanup_free_ char *substituted = NULL;
        r = hostname_substitute_wildcards(h, &substituted);
        if (r < 0) {
                log_debug_errno(r, "Failed to substitute wildcards in hostname, falling back to built-in name: %m");
                return strdup(FALLBACK_HOSTNAME);
        }

        /* Each token expands to a whole word, so the concrete name may exceed the length limit. */
        if (!hostname_is_valid(substituted, VALID_HOSTNAME_TRAILING_DOT)) {
                log_debug("Substituted hostname '%s' is invalid, falling back to built-in name.", substituted);
                return strdup(FALLBACK_HOSTNAME);
        }

        return TAKE_PTR(substituted);
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

int pidref_gethostname_full(PidRef *pidref, GetHostnameFlags flags, char **ret) {
        int r;

        assert(pidref);
        assert(ret);

        r = pidref_in_same_namespace(pidref, NULL, NAMESPACE_UTS);
        if (r < 0)
                return r;
        if (r > 0)
                return gethostname_full(flags, ret);

        _cleanup_close_ int utsns_fd = r = pidref_namespace_open_by_type(pidref, NAMESPACE_UTS);
        if (r < 0)
                return r;

        _cleanup_close_pair_ int errno_pipe[2] = EBADF_PAIR;
        r = pipe2(errno_pipe, O_CLOEXEC);
        if (r < 0)
                return -errno;

        _cleanup_close_pair_ int result_pipe[2] = EBADF_PAIR;
        r = pipe2(result_pipe, O_CLOEXEC);
        if (r < 0)
                return -errno;

        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        r = pidref_safe_fork("(sd-gethostname)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &child);
        if (r < 0)
                return r;
        if (r == 0) {
                errno_pipe[0] = safe_close(errno_pipe[0]);
                result_pipe[0] = safe_close(result_pipe[0]);

                if (setns(utsns_fd, CLONE_NEWUTS) < 0)
                        report_errno_and_exit(errno_pipe[1], -errno);

                char *t;
                r = gethostname_full(flags, &t);
                if (r < 0)
                        report_errno_and_exit(errno_pipe[1], r);

                r = loop_write(result_pipe[1], t, strlen(t) + 1);
                report_errno_and_exit(errno_pipe[1], r);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);
        result_pipe[1] = safe_close(result_pipe[1]);

        r = read_errno(errno_pipe[0]);
        if (r < 0)
                return r;

        char buf[LINUX_HOST_NAME_MAX+1];
        ssize_t n = loop_read(result_pipe[0], buf, sizeof(buf), /* do_poll= */ false);
        if (n < 0)
                return n;
        if (n == 0 || buf[n - 1] != '\0')
                return -EPROTO;

        return strdup_to(ret, buf);
}
