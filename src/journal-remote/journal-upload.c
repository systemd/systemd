/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "build.h"
#include "conf-parser.h"
#include "curl-util.h"
#include "daemon-util.h"
#include "env-file.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "hashmap.h"
#include "help-util.h"
#include "journal-header-util.h"
#include "journal-upload.h"
#include "journal-util.h"
#include "log.h"
#include "logs-show.h"
#include "main-func.h"
#include "mkdir.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-helpers.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "version.h"

#define PRIV_KEY_FILE CERTIFICATE_ROOT "/private/journal-upload.pem"
#define CERT_FILE     CERTIFICATE_ROOT "/certs/journal-upload.pem"
#define TRUST_FILE    CERTIFICATE_ROOT "/ca/trusted.pem"
#define DEFAULT_PORT  19532

static char *arg_url = NULL;
static char *arg_key = NULL;
static char *arg_cert = NULL;
static char *arg_trust = NULL;
static char *arg_directory = NULL;
static char **arg_file = NULL;
static char *arg_cursor = NULL;
static bool arg_after_cursor = false;
static int arg_journal_type = 0;
static int arg_namespace_flags = 0;
static char *arg_machine = NULL;
static char *arg_namespace = NULL;
static bool arg_merge = false;
static int arg_follow = -1;
static char *arg_save_state = NULL;
static usec_t arg_network_timeout_usec = USEC_INFINITY;
static OrderedHashmap *arg_compression = NULL;
static OrderedHashmap *arg_headers = NULL;
static bool arg_force_compression = false;

STATIC_DESTRUCTOR_REGISTER(arg_url, freep);
STATIC_DESTRUCTOR_REGISTER(arg_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cert, freep);
STATIC_DESTRUCTOR_REGISTER(arg_trust, freep);
STATIC_DESTRUCTOR_REGISTER(arg_directory, freep);
STATIC_DESTRUCTOR_REGISTER(arg_file, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_cursor, freep);
STATIC_DESTRUCTOR_REGISTER(arg_machine, freep);
STATIC_DESTRUCTOR_REGISTER(arg_namespace, freep);
STATIC_DESTRUCTOR_REGISTER(arg_save_state, freep);
STATIC_DESTRUCTOR_REGISTER(arg_compression, ordered_hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(arg_headers, ordered_hashmap_freep);

static void close_fd_input(Uploader *u);

#define SERVER_ANSWER_KEEP 2048

#define STATE_FILE "/var/lib/systemd/journal-upload/state"

static size_t output_callback(char *buf,
                              size_t size,
                              size_t nmemb,
                              void *userp) {
        Uploader *u = ASSERT_PTR(userp);

        log_debug("The server answers (%zu bytes): %.*s",
                  size*nmemb, (int)(size*nmemb), buf);

        if (nmemb && !u->answer) {
                u->answer = strndup(buf, size*nmemb);
                if (!u->answer)
                        log_warning("Failed to store server answer (%zu bytes): out of memory", size*nmemb);
        }

        return size * nmemb;
}

static int check_cursor_updating(Uploader *u) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (!u->state_file)
                return 0;

        r = mkdir_parents(u->state_file, 0755);
        if (r < 0)
                return log_error_errno(r, "Cannot create parent directory of state file %s: %m",
                                       u->state_file);

        r = fopen_temporary(u->state_file, &f, &temp_path);
        if (r < 0)
                return log_error_errno(r, "Cannot save state to %s: %m",
                                       u->state_file);
        (void) unlink(temp_path);

        return 0;
}

static int update_cursor_state(Uploader *u) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (!u->state_file || !u->last_cursor)
                return 0;

        r = fopen_temporary(u->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "LAST_CURSOR=%s\n",
                u->last_cursor);

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, u->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        temp_path = mfree(temp_path);
        return 0;

fail:
        (void) unlink(u->state_file);

        return log_error_errno(r, "Failed to save state %s: %m", u->state_file);
}

static int load_cursor_state(Uploader *u) {
        int r;

        if (!u->state_file)
                return 0;

        r = parse_env_file(NULL, u->state_file, "LAST_CURSOR", &u->last_cursor);
        if (r == -ENOENT)
                log_debug("State file %s is not present.", u->state_file);
        else if (r < 0)
                return log_error_errno(r, "Failed to read state file %s: %m",
                                       u->state_file);
        else
                log_debug("Last cursor was %s", u->last_cursor);

        return 0;
}

int start_upload(Uploader *u,
                 size_t (*input_callback)(void *ptr,
                                          size_t size,
                                          size_t nmemb,
                                          void *userdata),
                 void *data) {
        assert(u);
        assert(input_callback);

        if (!u->header) {
                _cleanup_(curl_slist_free_allp) struct curl_slist *h = NULL;
                struct curl_slist *l;

                h = sym_curl_slist_append(NULL, "Content-Type: application/vnd.fdo.journal");
                if (!h)
                        return log_oom();

                l = sym_curl_slist_append(h, "Transfer-Encoding: chunked");
                if (!l)
                        return log_oom();
                h = l;

                l = sym_curl_slist_append(h, "Accept: text/plain");
                if (!l)
                        return log_oom();
                h = l;

                if (u->compression) {
                        _cleanup_free_ char *header = strjoin("Content-Encoding: ", compression_to_string(u->compression->algorithm));
                        if (!header)
                                return log_oom();

                        l = sym_curl_slist_append(h, header);
                        if (!l)
                                return log_oom();
                        h = l;
                }

                char **values;
                const char *name;
                ORDERED_HASHMAP_FOREACH_KEY(values, name, arg_headers) {
                        _cleanup_free_ char *joined = strv_join(values, ", ");
                        if (!joined)
                                return log_oom();

                        if (!header_value_is_valid(joined)) {
                                log_warning("Concatenated header value for %s is invalid, ignoring", name);
                                continue;
                        }

                        _cleanup_free_ char *header = strjoin(name, ": ", joined);
                        if (!header)
                                return log_oom();

                        l = sym_curl_slist_append(h, header);
                        if (!l)
                                return log_oom();
                        h = l;
                }

                u->header = TAKE_PTR(h);
        }

        if (!u->easy) {
                _cleanup_(curl_easy_cleanupp) CURL *curl = NULL;

                curl = sym_curl_easy_init();
                if (!curl)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOSR),
                                               "Call to curl_easy_init failed.");

                /* If configured, set a timeout for the curl operation. */
                if (arg_network_timeout_usec != USEC_INFINITY &&
                    !easy_setopt(curl, LOG_ERR, CURLOPT_TIMEOUT,
                                 (long) DIV_ROUND_UP(arg_network_timeout_usec, USEC_PER_SEC)))
                        return -EXFULL;

                /* tell it to POST to the URL */
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_POST, 1L))
                        return -EXFULL;

                if (!easy_setopt(curl, LOG_ERR, CURLOPT_ERRORBUFFER, u->error))
                        return -EXFULL;

                /* set where to write to */
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_WRITEFUNCTION, output_callback))
                        return -EXFULL;

                if (!easy_setopt(curl, LOG_ERR, CURLOPT_WRITEDATA, data))
                        return -EXFULL;

                /* set where to read from */
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_READFUNCTION, input_callback))
                        return -EXFULL;

                if (!easy_setopt(curl, LOG_ERR, CURLOPT_READDATA, data))
                        return -EXFULL;

                /* use our special own mime type and chunked transfer */
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_HTTPHEADER, u->header))
                        return -EXFULL;

                if (DEBUG_LOGGING)
                        /* enable verbose for easier tracing */
                        (void) easy_setopt(curl, LOG_WARNING, CURLOPT_VERBOSE, 1L);

                (void) easy_setopt(curl, LOG_WARNING,
                                   CURLOPT_USERAGENT, "systemd-journal-upload " GIT_VERSION);

                if (!streq_ptr(arg_key, "-") && (arg_key || startswith(u->url, "https://"))) {
                        if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSLKEY, arg_key ?: PRIV_KEY_FILE))
                                return -EXFULL;
                        if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSLCERT, arg_cert ?: CERT_FILE))
                                return -EXFULL;
                }

                if (STRPTR_IN_SET(arg_trust, "-", "all")) {
                        log_info("Server certificate verification disabled.");
                        if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSL_VERIFYPEER, 0L))
                                return -EUCLEAN;
                        if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSL_VERIFYHOST, 0L))
                                return -EUCLEAN;
                } else if (arg_trust || startswith(u->url, "https://")) {
                        if (!easy_setopt(curl, LOG_ERR, CURLOPT_CAINFO, arg_trust ?: TRUST_FILE))
                                return -EXFULL;
                }

                if (startswith(u->url, "https://"))
                        (void) easy_setopt(curl, LOG_WARNING, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

                u->easy = TAKE_PTR(curl);
        } else {
                /* truncate the potential old error message */
                u->error[0] = '\0';

                u->answer = mfree(u->answer);
        }

        /* upload to this place */
        if (!easy_setopt(u->easy, LOG_ERR, CURLOPT_URL, u->url))
                return -EXFULL;

        u->uploading = true;

        return 0;
}

static size_t fd_input_callback(void *buf, size_t size, size_t nmemb, void *userp) {
        _cleanup_free_ char *compression_buffer = NULL;
        Uploader *u = ASSERT_PTR(userp);
        ssize_t n;
        int r;

        assert(nmemb < SSIZE_MAX / size);

        if (u->input < 0)
                return 0;

        assert(!size_multiply_overflow(size, nmemb));

        if (u->compression) {
                compression_buffer = malloc_multiply(nmemb, size);
                if (!compression_buffer) {
                        log_oom();
                        return CURL_READFUNC_ABORT;
                }
        }

        n = read(u->input, compression_buffer ?: buf, size * nmemb);
        if (n > 0) {
                log_debug("%s: allowed %zu, read %zd", __func__, size * nmemb, n);
                if (!u->compression)
                        return n;

                size_t compressed_size;
                r = compress_blob(u->compression->algorithm, compression_buffer, n, buf, size * nmemb, &compressed_size, u->compression->level);
                if (r < 0) {
                        log_error_errno(r, "Failed to compress %zd bytes by %s with level %i: %m",
                                        n, compression_to_string(u->compression->algorithm), u->compression->level);
                        return CURL_READFUNC_ABORT;
                }
                assert(compressed_size <= size * nmemb);
                return compressed_size;
        } else if (n < 0) {
                log_error_errno(errno, "Aborting transfer after read error on input: %m.");
                return CURL_READFUNC_ABORT;
        }

        u->uploading = false;
        log_debug("Reached EOF");
        close_fd_input(u);
        return 0;
}

static void close_fd_input(Uploader *u) {
        assert(u);

        u->input = safe_close(u->input);
        u->timeout = 0;
}

static int dispatch_fd_input(sd_event_source *event,
                             int fd,
                             uint32_t revents,
                             void *userp) {
        Uploader *u = ASSERT_PTR(userp);

        assert(fd >= 0);

        if (revents & EPOLLHUP) {
                log_debug("Received HUP");
                close_fd_input(u);
                return 0;
        }

        if (!(revents & EPOLLIN)) {
                log_warning("Unexpected poll event %"PRIu32".", revents);
                return -EINVAL;
        }

        if (u->uploading) {
                log_warning("dispatch_fd_input called when uploading, ignoring.");
                return 0;
        }

        return start_upload(u, fd_input_callback, u);
}

static int open_file_for_upload(Uploader *u, const char *filename) {
        int fd, r = 0;

        if (streq(filename, "-"))
                fd = STDIN_FILENO;
        else {
                fd = open(filename, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", filename);
        }

        u->input = fd;

        if (arg_follow != 0) {
                r = sd_event_add_io(u->event, &u->input_event,
                                    fd, EPOLLIN, dispatch_fd_input, u);
                if (r < 0) {
                        if (r != -EPERM || arg_follow > 0)
                                return log_error_errno(r, "Failed to register input event: %m");

                        /* Normal files should just be consumed without polling. */
                        r = start_upload(u, fd_input_callback, u);
                }
        }

        return r;
}

static int setup_uploader(Uploader *u, const char *url, const char *state_file) {
        int r;
        const char *host, *proto = "";

        assert(u);
        assert(url);

        *u = (Uploader) {
                .input = -1,
        };

        if (arg_force_compression)
                u->compression = ordered_hashmap_first(arg_compression);

        host = STARTSWITH_SET(url, "http://", "https://");
        if (!host) {
                host = url;
                proto = "https://";
        }

        if (strchr(host, ':'))
                u->url = strjoin(proto, url, "/upload");
        else {
                char *t;
                size_t x;

                t = strdupa_safe(url);
                x = strlen(t);
                while (x > 0 && t[x - 1] == '/')
                        t[x - 1] = '\0';

                u->url = strjoin(proto, t, ":" STRINGIFY(DEFAULT_PORT), "/upload");
        }
        if (!u->url)
                return log_oom();

        u->state_file = state_file;

        r = sd_event_default(&u->event);
        if (r < 0)
                return log_error_errno(r, "sd_event_default failed: %m");

        r = sd_event_set_signal_exit(u->event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        (void) sd_watchdog_enabled(false, &u->watchdog_usec);

        return load_cursor_state(u);
}

static void destroy_uploader(Uploader *u) {
        assert(u);

        if (sym_curl_easy_cleanup)
                sym_curl_easy_cleanup(u->easy);
        if (sym_curl_slist_free_all)
                sym_curl_slist_free_all(u->header);
        free(u->answer);

        free(u->last_cursor);
        free(u->current_cursor);

        free(u->url);

        u->input_event = sd_event_source_unref(u->input_event);

        close_fd_input(u);
        close_journal_input(u);

        sd_event_unref(u->event);
}

#if LIBCURL_VERSION_NUM >= 0x075300
static int update_content_encoding_header(Uploader *u, const CompressionConfig *cc) {
        bool update_header = false;

        assert(u);

        if (cc == u->compression)
                return 0; /* Already picked the algorithm. Let's shortcut. */

        if (cc) {
                _cleanup_free_ char *header = strjoin("Content-Encoding: ", compression_to_string(cc->algorithm));
                if (!header)
                        return log_oom();

                /* First, try to update existing Content-Encoding header. */
                bool found = false;
                for (struct curl_slist *l = u->header; l; l = l->next)
                        if (startswith(l->data, "Content-Encoding:")) {
                                free_and_replace(l->data, header);
                                found = true;
                                break;
                        }

                /* If Content-Encoding header is not found, append new one. */
                if (!found) {
                        struct curl_slist *l = sym_curl_slist_append(u->header, header);
                        if (!l)
                                return log_oom();
                        u->header = l;
                }

                update_header = true;
        } else
                /* Remove Content-Encoding header. */
                for (struct curl_slist *l = u->header, *prev = NULL; l; prev = l, l = l->next)
                        if (startswith(l->data, "Content-Encoding:")) {
                                if (prev)
                                        prev->next = TAKE_PTR(l->next);
                                else
                                        u->header = TAKE_PTR(l->next);

                                sym_curl_slist_free_all(l);
                                update_header = true;
                                break;
                        }

        if (update_header &&
            !easy_setopt(u->easy, LOG_WARNING, CURLOPT_HTTPHEADER, u->header))
                return -EXFULL;

        u->compression = cc;

        if (cc)
                log_debug("Using compression algorithm %s with compression level %i.",
                          compression_to_string(cc->algorithm), cc->level);
        else
                log_debug("Disabled compression algorithm.");
        return 0;
}
#endif

static int parse_accept_encoding_header(Uploader *u) {
#if LIBCURL_VERSION_NUM >= 0x075300
        int r;

        assert(u);

        if (ordered_hashmap_isempty(arg_compression))
                return update_content_encoding_header(u, NULL);

        struct curl_header *header;
        CURLHcode hcode = sym_curl_easy_header(u->easy, "Accept-Encoding", 0, CURLH_HEADER, -1, &header);
        if (hcode != CURLHE_OK)
                goto not_found;

        for (const char *p = header->value;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", 0);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse Accept-Encoding header value, ignoring: %m");
                if (r == 0)
                        break;

                /* Cut the quality value waiting. */
                char *q = strchr(word, ';');
                if (q)
                        *q = '\0';

                if (streq(word, "*"))
                        return update_content_encoding_header(u, ordered_hashmap_first(arg_compression));

                Compression c = compression_from_string_harder(word);
                if (c <= 0 || !compression_supported(c))
                        continue; /* unsupported or invalid algorithm. */

                const CompressionConfig *cc = ordered_hashmap_get(arg_compression, INT_TO_PTR(c));
                if (!cc)
                        continue; /* The specified algorithm is not enabled. */

                return update_content_encoding_header(u, cc);
        }

not_found:
        if (arg_force_compression)
                return update_content_encoding_header(u, ordered_hashmap_first(arg_compression));

        return update_content_encoding_header(u, NULL);
#else
        return 0;
#endif
}

static int perform_upload(Uploader *u) {
        CURLcode code;
        long status;

        assert(u);

        u->watchdog_timestamp = now(CLOCK_MONOTONIC);
        code = sym_curl_easy_perform(u->easy);
        if (code) {
                if (u->error[0])
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Upload to %s failed: %.*s",
                                               u->url, (int) sizeof(u->error), u->error);
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Upload to %s failed: %s",
                                               u->url, sym_curl_easy_strerror(code));
        }

        code = sym_curl_easy_getinfo(u->easy, CURLINFO_RESPONSE_CODE, &status);
        if (code)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Failed to retrieve response code: %s",
                                       sym_curl_easy_strerror(code));

        if (status >= 300)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Upload to %s failed with code %ld: %s",
                                       u->url, status, strna(u->answer));
        if (status < 200)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Upload to %s finished with unexpected code %ld: %s",
                                       u->url, status, strna(u->answer));

        (void) parse_accept_encoding_header(u);

        log_debug("Upload finished successfully with code %ld: %s",
                  status, strna(u->answer));

        free_and_replace(u->last_cursor, u->current_cursor);

        return update_cursor_state(u);
}

static int parse_config(void) {
        const ConfigTableItem items[] = {
                { "Upload",  "URL",                    config_parse_string,         CONFIG_PARSE_STRING_SAFE, &arg_url                  },
                { "Upload",  "ServerKeyFile",          config_parse_path_or_ignore, 0,                        &arg_key                  },
                { "Upload",  "ServerCertificateFile",  config_parse_path_or_ignore, 0,                        &arg_cert                 },
                { "Upload",  "TrustedCertificateFile", config_parse_path_or_ignore, 0,                        &arg_trust                },
                { "Upload",  "NetworkTimeoutSec",      config_parse_sec,            0,                        &arg_network_timeout_usec },
                { "Upload",  "Header",                 config_parse_header,         0,                        &arg_headers              },
                { "Upload",  "Compression",            config_parse_compression,    /* with_level= */ true,   &arg_compression          },
                { "Upload",  "ForceCompression",       config_parse_bool,           0,                        &arg_force_compression    },
                {}
        };

        return config_parse_standard_file_with_dropins(
                        "systemd/journal-upload.conf",
                        "Upload\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("-u URL {FILE|-}...");
        help_abstract("Upload journal events to a remote server.");

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-journal-upload.service", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('u', "url", "URL",
                       "Upload to this address (default port " STRINGIFY(DEFAULT_PORT) ")"):
                        r = free_and_strdup_warn(&arg_url, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("key", "FILENAME",
                            "Specify key in PEM format (default: \"" PRIV_KEY_FILE "\")"):
                        r = free_and_strdup_warn(&arg_key, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("cert", "FILENAME",
                            "Specify certificate in PEM format (default: \"" CERT_FILE "\")"):
                        r = free_and_strdup_warn(&arg_cert, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("trust", "FILENAME|all",
                            "Specify CA certificate or disable checking (default: \"" TRUST_FILE "\")"):
                        r = free_and_strdup_warn(&arg_trust, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("system", NULL, "Use the system journal"):
                        arg_journal_type |= SD_JOURNAL_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Use the user journal for the current user"):
                        arg_journal_type |= SD_JOURNAL_CURRENT_USER;
                        break;

                OPTION('m', "merge", NULL, "Use all available journals"):
                        arg_merge = true;
                        break;

                OPTION_COMMON_MACHINE:
                        r = free_and_strdup_warn(&arg_machine, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("namespace", "NAMESPACE", "Use journal files from namespace"):
                        if (streq(opts.arg, "*")) {
                                arg_namespace_flags = SD_JOURNAL_ALL_NAMESPACES;
                                arg_namespace = mfree(arg_namespace);
                                r = 0;
                        } else if (startswith(opts.arg, "+")) {
                                arg_namespace_flags = SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE;
                                r = free_and_strdup_warn(&arg_namespace, opts.arg + 1);
                        } else if (isempty(opts.arg)) {
                                arg_namespace_flags = 0;
                                arg_namespace = mfree(arg_namespace);
                                r = 0;
                        } else {
                                arg_namespace_flags = 0;
                                r = free_and_strdup_warn(&arg_namespace, opts.arg);
                        }
                        if (r < 0)
                                return r;
                        break;

                OPTION('D', "directory", "PATH", "Use journal files from this directory"):
                        r = free_and_strdup_warn(&arg_directory, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("file", "PATH", "Use this journal file"):
                        r = glob_extend(&arg_file, opts.arg, GLOB_NOCHECK);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add paths: %m");
                        break;

                OPTION_LONG_DATA("after-cursor", "CURSOR", /* data= */ true,
                                 "Start after the specified cursor"): {}
                OPTION_LONG_DATA("cursor", "CURSOR", /* data= */ false,
                                 "Start at the specified cursor"):
                        r = free_and_strdup_warn(&arg_cursor, opts.arg);
                        if (r < 0)
                                return r;
                        arg_after_cursor = opts.opt->data;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "follow", "BOOL",
                                  "Whether to wait for input"):
                        r = parse_boolean_argument("--follow", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        arg_follow = r;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "save-state", "FILE",
                                  "Save uploaded cursors (default " STATE_FILE ")"):
                        r = free_and_strdup_warn(&arg_save_state, opts.arg ?: STATE_FILE);
                        if (r < 0)
                                return r;
                        break;
                }

        if (!arg_url)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Required --url=/-u option missing.");

        if (!!arg_key != !!arg_cert)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --key= and --cert= must be used together.");

        char **args = option_parser_get_args(&opts);
        if (!strv_isempty(args) && (arg_directory || arg_file || arg_machine || arg_journal_type))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Input arguments make no sense with journal input.");

        *ret_args = args;
        return 1;
}

static int open_journal(sd_journal **j) {
        int r;

        assert(j);

        if (arg_directory)
                r = sd_journal_open_directory(j, arg_directory, arg_journal_type);
        else if (arg_file)
                r = sd_journal_open_files(j, (const char**) arg_file, 0);
        else if (arg_machine)
                r = journal_open_machine(j, arg_machine, 0);
        else
                r = sd_journal_open_namespace(j, arg_namespace,
                                              (arg_merge ? 0 : SD_JOURNAL_LOCAL_ONLY) | arg_namespace_flags | arg_journal_type);
        if (r < 0)
                log_error_errno(r, "Failed to open %s: %m",
                                arg_directory ?: (arg_file ? "files" : "journal"));
        return r;
}

static int run(int argc, char **argv) {
        _cleanup_(destroy_uploader) Uploader u = {};
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        char **args = NULL;
        bool use_journal;
        int r;

        log_setup();

        r = parse_config();
        if (r < 0)
                return r;

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        r = dlopen_curl(LOG_DEBUG);
        if (r < 0)
                return r;

        r = compression_configs_mangle(&arg_compression);
        if (r < 0)
                return r;

        journal_browse_prepare();

        r = setup_uploader(&u, arg_url, arg_save_state);
        if (r < 0)
                return r;

        sd_event_set_watchdog(u.event, true);

        r = check_cursor_updating(&u);
        if (r < 0)
                return r;

        log_debug("%s running as pid "PID_FMT,
                  program_invocation_short_name, getpid_cached());

        use_journal = strv_isempty(args);
        if (use_journal) {
                sd_journal *j;
                r = open_journal(&j);
                if (r < 0)
                        return r;
                r = open_journal_for_upload(&u, j,
                                            arg_cursor ?: u.last_cursor,
                                            arg_cursor ? arg_after_cursor : true,
                                            arg_follow != 0);
                if (r < 0)
                        return r;
        }

        notify_message = notify_start("READY=1\n"
                                      "STATUS=Processing input...",
                                      NOTIFY_STOPPING_MESSAGE);

        for (size_t i = 0;;) {
                r = sd_event_get_state(u.event);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        return 0;

                if (use_journal) {
                        if (!u.journal)
                                return 0;

                        r = check_journal_input(&u);
                } else if (u.input < 0 && !use_journal) {
                        if (!args[i])
                                return 0;

                        log_debug("Using %s as input.", args[i]);
                        r = open_file_for_upload(&u, args[i++]);
                }
                if (r < 0)
                        return r;

                if (u.uploading) {
                        r = perform_upload(&u);
                        if (r < 0)
                                return r;
                }

                r = sd_event_run(u.event, u.timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");
        }
}

DEFINE_MAIN_FUNCTION(run);
