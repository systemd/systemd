/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "creds-util.h"
#include "env-file.h"
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
#include "path-util.h"
#include "pidref.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

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

static int hostname_wordlist_load(const char *class, char ***ret) {
        _cleanup_strv_free_ char **words = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(class);
        assert(ret);

        /* Loads the hostname word lists ("adverbs", "adjectives", "nouns") for '%v'/'%a'/'%n' wildcards.
         * Highest priority file wins */
        const char *override = secure_getenv("SYSTEMD_HOSTNAME_WORDS_PATH");
        if (override) {
                _cleanup_free_ char *p = path_join(override, class);
                if (!p)
                        return -ENOMEM;

                f = fopen(p, "re");
                if (!f)
                        return -errno;
        } else
                FOREACH_STRING(dir,
                               "/etc/systemd/hostname-words",
                               "/run/systemd/hostname-words",
                               "/usr/local/lib/systemd/hostname-words",
                               "/usr/lib/systemd/hostname-words") {
                        _cleanup_free_ char *p = path_join(dir, class);
                        if (!p)
                                return -ENOMEM;

                        f = fopen(p, "re");
                        if (f)
                                break;
                        if (errno != ENOENT)
                                return -errno;
                }

        if (!f)
                return -ENOENT;

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Skip empty lines and comments */
                if (IN_SET(line[0], '\0', '#'))
                        continue;

                /* Each word must be a valid single hostname label on its own; lowercase it and silently
                 * skip bogus entries rather than failing the whole list. */
                ascii_strlower(line);
                if (!hostname_is_valid(line, /* flags= */ 0))
                        continue;

                r = strv_extend(&words, line);
                if (r < 0)
                        return r;
        }

        if (strv_isempty(words))
                return -ENOENT;

        /* Canonicalize: sort so the file's line order doesn't affect the derived name, then drop
         * duplicates. Note the derived name still depends on the list *contents* and *length*. */
        strv_sort(words);
        strv_uniq(words);

        *ret = TAKE_PTR(words);
        return 0;
}

static const char* hostname_word_class_to_key(char class) {
        switch (class) {
        case 'v': return "adverb";
        case 'a': return "adjective";
        case 'n': return "noun";
        default:  return NULL;
        }
}

static int hostname_read_picked_word(char class, char **ret) {
        int r;

        assert(ret);

        /* Returns 1 and the word if one was picked once for this class (see hostname_persist_picked_words()),
         * 0 if none was picked yet (or the file/word is unusable). */

        const char *key = hostname_word_class_to_key(class);
        if (!key)
                return 0;

        _cleanup_free_ char *v = NULL;
        r = parse_env_file(NULL, HOSTNAME_PICKED_WORDS_PATH, key, &v);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read %s, ignoring: %m", HOSTNAME_PICKED_WORDS_PATH);
                return 0;
        }
        if (isempty(v))
                return 0;
        if (!hostname_is_valid(v, /* flags= */ 0)) {
                log_debug("Picked %s '%s' is not a valid hostname label, ignoring.", key, v);
                return 0;
        }

        *ret = TAKE_PTR(v);
        return 1;
}

static int hostname_derive_word(sd_id128_t mid, char class, char **ret) {
        static const sd_id128_t word_key = SD_ID128_MAKE(2d,9f,1c,7a,4b,8e,43,11,9a,6d,5f,02,c8,77,e3,14);
        _cleanup_strv_free_ char **words = NULL;
        const char *file;
        uint64_t h;
        int r;

        assert(ret);

        switch (class) {
        case 'v': file = "adverbs";    break;
        case 'a': file = "adjectives"; break;
        case 'n': file = "nouns";      break;
        default:
                return -EINVAL;
        }

        r = hostname_wordlist_load(file, &words);
        if (r < 0)
                return r;

        /* Derive an index into the list from the machine ID and the word class. This stream is independent of
         * the '?' nibble stream, so existing pure-'?' templates keep producing byte-identical output. */
        struct siphash state;
        siphash24_init(&state, word_key.bytes);
        siphash24_compress_typesafe(mid, &state);
        siphash24_compress_typesafe(class, &state);
        h = siphash24_finalize(&state);

        char *w = strdup(words[h % strv_length(words)]);
        if (!w)
                return -ENOMEM;

        *ret = w;
        return 0;
}

static int hostname_pick_word(sd_id128_t mid, char class, char **ret) {
        int r;

        assert(ret);

        /* Prefer the word picked once and persisted, so the name stays stable even if the word lists change */
        r = hostname_read_picked_word(class, ret);
        if (r > 0)
                return 0;

        return hostname_derive_word(mid, class, ret);
}

int hostname_persist_picked_words(void) {
        static const char classes[] = { 'v', 'a', 'n' };
        _cleanup_free_ char *content = NULL;
        sd_id128_t mid;
        int r;

        if (access(HOSTNAME_PICKED_WORDS_PATH, F_OK) >= 0)
                return 0; /* already picked, never re-pick */
        if (errno != ENOENT)
                return -errno;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        FOREACH_ARRAY(c, classes, ELEMENTSOF(classes)) {
                _cleanup_free_ char *w = NULL;

                r = hostname_derive_word(mid, *c, &w);
                if (r == -ENOENT)
                        continue; /* no word list for this class, skip */
                if (r < 0)
                        return r;

                if (!strextend(&content, hostname_word_class_to_key(*c), "=", w, "\n"))
                        return -ENOMEM;
        }

        if (!content)
                return 0; /* no word lists installed, nothing to pick */

        return write_string_file(HOSTNAME_PICKED_WORDS_PATH, content,
                                 WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
}

int hostname_substitute_wildcards(const char *name, char **ret) {
        static const sd_id128_t key = SD_ID128_MAKE(98,10,ad,df,8d,7d,4f,b5,89,1b,4b,56,ac,c2,26,8f);
        sd_id128_t mid = SD_ID128_NULL;
        _cleanup_free_ char *result = NULL;
        size_t left_bits = 0, counter = 0;
        uint64_t h = 0;
        int r;

        assert(name);
        assert(ret);

        /* Expands wildcards in the specified string, deriving the inserted values deterministically from
         * /etc/machine-id:
         *
         *   '?'  is replaced by a single hex nibble hashed from the machine ID.
         *   '%v' is replaced by a random adverb from the "adverbs" word list.
         *   '%a' is replaced by a random adjective from the "adjectives" word list.
         *   '%n' is replaced by a random noun from the "nouns" word list.
         *   '%%' is replaced by a literal '%'.
         *
         * This is supposed to be used on /etc/hostname files that want to automatically configure a hostname
         * derived from the machine ID in some form, e.g. "happy-octopus-????".
         *
         * Note that this does not directly expose the machine ID, because that's not necessarily supposed to
         * be public information to be broadcast on the network, while the hostname certainly is. */

        for (const char *n = name; *n; n++) {
                if (*n == '?') {
                        if (sd_id128_is_null(mid)) {
                                r = sd_id128_get_machine(&mid);
                                if (r < 0)
                                        return r;
                        }

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

                        if (!strextendn(&result, &c, 1))
                                return -ENOMEM;

                } else if (*n == '%') {
                        n++;

                        if (*n == '%') {
                                if (!strextend(&result, "%"))
                                        return -ENOMEM;
                        } else if (IN_SET(*n, 'v', 'a', 'n')) {
                                if (sd_id128_is_null(mid)) {
                                        r = sd_id128_get_machine(&mid);
                                        if (r < 0)
                                                return r;
                                }

                                _cleanup_free_ char *w = NULL;
                                r = hostname_pick_word(mid, *n, &w);
                                if (r < 0)
                                        return r;

                                if (!strextend(&result, w))
                                        return -ENOMEM;
                        } else
                                return -EINVAL; /* unknown specifier (or trailing '%') */

                } else if (!strextendn(&result, n, 1))
                        return -ENOMEM;
        }

        if (!result) {
                result = strdup(""); /* empty input → empty output, never NULL */
                if (!result)
                        return -ENOMEM;
        }

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
