/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

#include "sd-daemon.h"
#include "log.h"
#include "util.h"
#include "build.h"
#include "fileio.h"
#include "mkdir.h"
#include "conf-parser.h"
#include "sigbus.h"
#include "formats-util.h"
#include "signal-util.h"
#include "journal-upload.h"

#define PRIV_KEY_FILE CERTIFICATE_ROOT "/private/journal-upload.pem"
#define CERT_FILE     CERTIFICATE_ROOT "/certs/journal-upload.pem"
#define TRUST_FILE    CERTIFICATE_ROOT "/ca/trusted.pem"
#define DEFAULT_PORT  19532

static const char* arg_url = NULL;
static const char *arg_key = NULL;
static const char *arg_cert = NULL;
static const char *arg_trust = NULL;
static const char *arg_directory = NULL;
static char **arg_file = NULL;
static const char *arg_cursor = NULL;
static bool arg_after_cursor = false;
static int arg_journal_type = 0;
static const char *arg_machine = NULL;
static bool arg_merge = false;
static int arg_follow = -1;
static const char *arg_save_state = NULL;

static void close_fd_input(Uploader *u);

#define SERVER_ANSWER_KEEP 2048

#define STATE_FILE "/var/lib/systemd/journal-upload/state"

#define easy_setopt(curl, opt, value, level, cmd)                       \
        do {                                                            \
                code = curl_easy_setopt(curl, opt, value);              \
                if (code) {                                             \
                        log_full(level,                                 \
                                 "curl_easy_setopt " #opt " failed: %s", \
                                  curl_easy_strerror(code));            \
                        cmd;                                            \
                }                                                       \
        } while(0)

static size_t output_callback(char *buf,
                              size_t size,
                              size_t nmemb,
                              void *userp) {
        Uploader *u = userp;

        assert(u);

        log_debug("The server answers (%zu bytes): %.*s",
                  size*nmemb, (int)(size*nmemb), buf);

        if (nmemb && !u->answer) {
                u->answer = strndup(buf, size*nmemb);
                if (!u->answer)
                        log_warning_errno(ENOMEM, "Failed to store server answer (%zu bytes): %m",
                                          size*nmemb);
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
        unlink(temp_path);

        return 0;
}

static int update_cursor_state(Uploader *u) {
        _cleanup_free_ char *temp_path = NULL;
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

        return 0;

fail:
        if (temp_path)
                (void) unlink(temp_path);

        (void) unlink(u->state_file);

        return log_error_errno(r, "Failed to save state %s: %m", u->state_file);
}

static int load_cursor_state(Uploader *u) {
        int r;

        if (!u->state_file)
                return 0;

        r = parse_env_file(u->state_file, NEWLINE,
                           "LAST_CURSOR",  &u->last_cursor,
                           NULL);

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
        CURLcode code;

        assert(u);
        assert(input_callback);

        if (!u->header) {
                struct curl_slist *h;

                h = curl_slist_append(NULL, "Content-Type: application/vnd.fdo.journal");
                if (!h)
                        return log_oom();

                h = curl_slist_append(h, "Transfer-Encoding: chunked");
                if (!h) {
                        curl_slist_free_all(h);
                        return log_oom();
                }

                h = curl_slist_append(h, "Accept: text/plain");
                if (!h) {
                        curl_slist_free_all(h);
                        return log_oom();
                }

                u->header = h;
        }

        if (!u->easy) {
                CURL *curl;

                curl = curl_easy_init();
                if (!curl) {
                        log_error("Call to curl_easy_init failed.");
                        return -ENOSR;
                }

                /* tell it to POST to the URL */
                easy_setopt(curl, CURLOPT_POST, 1L,
                            LOG_ERR, return -EXFULL);

                easy_setopt(curl, CURLOPT_ERRORBUFFER, u->error,
                            LOG_ERR, return -EXFULL);

                /* set where to write to */
                easy_setopt(curl, CURLOPT_WRITEFUNCTION, output_callback,
                            LOG_ERR, return -EXFULL);

                easy_setopt(curl, CURLOPT_WRITEDATA, data,
                            LOG_ERR, return -EXFULL);

                /* set where to read from */
                easy_setopt(curl, CURLOPT_READFUNCTION, input_callback,
                            LOG_ERR, return -EXFULL);

                easy_setopt(curl, CURLOPT_READDATA, data,
                            LOG_ERR, return -EXFULL);

                /* use our special own mime type and chunked transfer */
                easy_setopt(curl, CURLOPT_HTTPHEADER, u->header,
                            LOG_ERR, return -EXFULL);

                if (_unlikely_(log_get_max_level() >= LOG_DEBUG))
                        /* enable verbose for easier tracing */
                        easy_setopt(curl, CURLOPT_VERBOSE, 1L, LOG_WARNING, );

                easy_setopt(curl, CURLOPT_USERAGENT,
                            "systemd-journal-upload " PACKAGE_STRING,
                            LOG_WARNING, );

                if (arg_key || startswith(u->url, "https://")) {
                        easy_setopt(curl, CURLOPT_SSLKEY, arg_key ?: PRIV_KEY_FILE,
                                    LOG_ERR, return -EXFULL);
                        easy_setopt(curl, CURLOPT_SSLCERT, arg_cert ?: CERT_FILE,
                                    LOG_ERR, return -EXFULL);
                }

                if (streq_ptr(arg_trust, "all"))
                        easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0,
                                    LOG_ERR, return -EUCLEAN);
                else if (arg_trust || startswith(u->url, "https://"))
                        easy_setopt(curl, CURLOPT_CAINFO, arg_trust ?: TRUST_FILE,
                                    LOG_ERR, return -EXFULL);

                if (arg_key || arg_trust)
                        easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1,
                                    LOG_WARNING, );

                u->easy = curl;
        } else {
                /* truncate the potential old error message */
                u->error[0] = '\0';

                free(u->answer);
                u->answer = 0;
        }

        /* upload to this place */
        code = curl_easy_setopt(u->easy, CURLOPT_URL, u->url);
        if (code) {
                log_error("curl_easy_setopt CURLOPT_URL failed: %s",
                          curl_easy_strerror(code));
                return -EXFULL;
        }

        u->uploading = true;

        return 0;
}

static size_t fd_input_callback(void *buf, size_t size, size_t nmemb, void *userp) {
        Uploader *u = userp;

        ssize_t r;

        assert(u);
        assert(nmemb <= SSIZE_MAX / size);

        if (u->input < 0)
                return 0;

        r = read(u->input, buf, size * nmemb);
        log_debug("%s: allowed %zu, read %zd", __func__, size*nmemb, r);

        if (r > 0)
                return r;

        u->uploading = false;
        if (r == 0) {
                log_debug("Reached EOF");
                close_fd_input(u);
                return 0;
        } else {
                log_error_errno(errno, "Aborting transfer after read error on input: %m.");
                return CURL_READFUNC_ABORT;
        }
}

static void close_fd_input(Uploader *u) {
        assert(u);

        if (u->input >= 0)
                close_nointr(u->input);
        u->input = -1;
        u->timeout = 0;
}

static int dispatch_fd_input(sd_event_source *event,
                             int fd,
                             uint32_t revents,
                             void *userp) {
        Uploader *u = userp;

        assert(u);
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

        if (arg_follow) {
                r = sd_event_add_io(u->events, &u->input_event,
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

static int dispatch_sigterm(sd_event_source *event,
                            const struct signalfd_siginfo *si,
                            void *userdata) {
        Uploader *u = userdata;

        assert(u);

        log_received_signal(LOG_INFO, si);

        close_fd_input(u);
        close_journal_input(u);

        sd_event_exit(u->events, 0);
        return 0;
}

static int setup_signals(Uploader *u) {
        int r;

        assert(u);

        assert_se(sigprocmask_many(SIG_SETMASK, NULL, SIGINT, SIGTERM, -1) >= 0);

        r = sd_event_add_signal(u->events, &u->sigterm_event, SIGTERM, dispatch_sigterm, u);
        if (r < 0)
                return r;

        r = sd_event_add_signal(u->events, &u->sigint_event, SIGINT, dispatch_sigterm, u);
        if (r < 0)
                return r;

        return 0;
}

static int setup_uploader(Uploader *u, const char *url, const char *state_file) {
        int r;
        const char *host, *proto = "";

        assert(u);
        assert(url);

        memzero(u, sizeof(Uploader));
        u->input = -1;

        if (!(host = startswith(url, "http://")) && !(host = startswith(url, "https://"))) {
                host = url;
                proto = "https://";
        }

        if (strchr(host, ':'))
                u->url = strjoin(proto, url, "/upload", NULL);
        else {
                char *t;
                size_t x;

                t = strdupa(url);
                x = strlen(t);
                while (x > 0 && t[x - 1] == '/')
                        t[x - 1] = '\0';

                u->url = strjoin(proto, t, ":" STRINGIFY(DEFAULT_PORT), "/upload", NULL);
        }
        if (!u->url)
                return log_oom();

        u->state_file = state_file;

        r = sd_event_default(&u->events);
        if (r < 0)
                return log_error_errno(r, "sd_event_default failed: %m");

        r = setup_signals(u);
        if (r < 0)
                return log_error_errno(r, "Failed to set up signals: %m");

        return load_cursor_state(u);
}

static void destroy_uploader(Uploader *u) {
        assert(u);

        curl_easy_cleanup(u->easy);
        curl_slist_free_all(u->header);
        free(u->answer);

        free(u->last_cursor);
        free(u->current_cursor);

        free(u->url);

        u->input_event = sd_event_source_unref(u->input_event);

        close_fd_input(u);
        close_journal_input(u);

        sd_event_source_unref(u->sigterm_event);
        sd_event_source_unref(u->sigint_event);
        sd_event_unref(u->events);
}

static int perform_upload(Uploader *u) {
        CURLcode code;
        long status;

        assert(u);

        code = curl_easy_perform(u->easy);
        if (code) {
                if (u->error[0])
                        log_error("Upload to %s failed: %.*s",
                                  u->url, (int) sizeof(u->error), u->error);
                else
                        log_error("Upload to %s failed: %s",
                                  u->url, curl_easy_strerror(code));
                return -EIO;
        }

        code = curl_easy_getinfo(u->easy, CURLINFO_RESPONSE_CODE, &status);
        if (code) {
                log_error("Failed to retrieve response code: %s",
                          curl_easy_strerror(code));
                return -EUCLEAN;
        }

        if (status >= 300) {
                log_error("Upload to %s failed with code %ld: %s",
                          u->url, status, strna(u->answer));
                return -EIO;
        } else if (status < 200) {
                log_error("Upload to %s finished with unexpected code %ld: %s",
                          u->url, status, strna(u->answer));
                return -EIO;
        } else
                log_debug("Upload finished successfully with code %ld: %s",
                          status, strna(u->answer));

        free(u->last_cursor);
        u->last_cursor = u->current_cursor;
        u->current_cursor = NULL;

        return update_cursor_state(u);
}

static int parse_config(void) {
        const ConfigTableItem items[] = {
                { "Upload",  "URL",                    config_parse_string, 0, &arg_url    },
                { "Upload",  "ServerKeyFile",          config_parse_path,   0, &arg_key    },
                { "Upload",  "ServerCertificateFile",  config_parse_path,   0, &arg_cert   },
                { "Upload",  "TrustedCertificateFile", config_parse_path,   0, &arg_trust  },
                {}};

        return config_parse_many(PKGSYSCONFDIR "/journal-upload.conf",
                                 CONF_DIRS_NULSTR("systemd/journal-upload.conf"),
                                 "Upload\0", config_item_table_lookup, items,
                                 false, NULL);
}

static void help(void) {
        printf("%s -u URL {FILE|-}...\n\n"
               "Upload journal events to a remote server.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "  -u --url=URL              Upload to this address (default port "
                                            STRINGIFY(DEFAULT_PORT) ")\n"
               "     --key=FILENAME         Specify key in PEM format (default:\n"
               "                            \"" PRIV_KEY_FILE "\")\n"
               "     --cert=FILENAME        Specify certificate in PEM format (default:\n"
               "                            \"" CERT_FILE "\")\n"
               "     --trust=FILENAME|all   Specify CA certificate or disable checking (default:\n"
               "                            \"" TRUST_FILE "\")\n"
               "     --system               Use the system journal\n"
               "     --user                 Use the user journal for the current user\n"
               "  -m --merge                Use  all available journals\n"
               "  -M --machine=CONTAINER    Operate on local container\n"
               "  -D --directory=PATH       Use journal files from directory\n"
               "     --file=PATH            Use this journal file\n"
               "     --cursor=CURSOR        Start at the specified cursor\n"
               "     --after-cursor=CURSOR  Start after the specified cursor\n"
               "     --follow[=BOOL]        Do [not] wait for input\n"
               "     --save-state[=FILE]    Save uploaded cursors (default \n"
               "                            " STATE_FILE ")\n"
               "  -h --help                 Show this help and exit\n"
               "     --version              Print version string and exit\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_KEY,
                ARG_CERT,
                ARG_TRUST,
                ARG_USER,
                ARG_SYSTEM,
                ARG_FILE,
                ARG_CURSOR,
                ARG_AFTER_CURSOR,
                ARG_FOLLOW,
                ARG_SAVE_STATE,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'                },
                { "version",      no_argument,       NULL, ARG_VERSION        },
                { "url",          required_argument, NULL, 'u'                },
                { "key",          required_argument, NULL, ARG_KEY            },
                { "cert",         required_argument, NULL, ARG_CERT           },
                { "trust",        required_argument, NULL, ARG_TRUST          },
                { "system",       no_argument,       NULL, ARG_SYSTEM         },
                { "user",         no_argument,       NULL, ARG_USER           },
                { "merge",        no_argument,       NULL, 'm'                },
                { "machine",      required_argument, NULL, 'M'                },
                { "directory",    required_argument, NULL, 'D'                },
                { "file",         required_argument, NULL, ARG_FILE           },
                { "cursor",       required_argument, NULL, ARG_CURSOR         },
                { "after-cursor", required_argument, NULL, ARG_AFTER_CURSOR   },
                { "follow",       optional_argument, NULL, ARG_FOLLOW         },
                { "save-state",   optional_argument, NULL, ARG_SAVE_STATE     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        opterr = 0;

        while ((c = getopt_long(argc, argv, "hu:mM:D:", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        return 0 /* done */;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0 /* done */;

                case 'u':
                        if (arg_url) {
                                log_error("cannot use more than one --url");
                                return -EINVAL;
                        }

                        arg_url = optarg;
                        break;

                case ARG_KEY:
                        if (arg_key) {
                                log_error("cannot use more than one --key");
                                return -EINVAL;
                        }

                        arg_key = optarg;
                        break;

                case ARG_CERT:
                        if (arg_cert) {
                                log_error("cannot use more than one --cert");
                                return -EINVAL;
                        }

                        arg_cert = optarg;
                        break;

                case ARG_TRUST:
                        if (arg_trust) {
                                log_error("cannot use more than one --trust");
                                return -EINVAL;
                        }

                        arg_trust = optarg;
                        break;

                case ARG_SYSTEM:
                        arg_journal_type |= SD_JOURNAL_SYSTEM;
                        break;

                case ARG_USER:
                        arg_journal_type |= SD_JOURNAL_CURRENT_USER;
                        break;

                case 'm':
                        arg_merge = true;
                        break;

                case 'M':
                        if (arg_machine) {
                                log_error("cannot use more than one --machine/-M");
                                return -EINVAL;
                        }

                        arg_machine = optarg;
                        break;

                case 'D':
                        if (arg_directory) {
                                log_error("cannot use more than one --directory/-D");
                                return -EINVAL;
                        }

                        arg_directory = optarg;
                        break;

                case ARG_FILE:
                        r = glob_extend(&arg_file, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add paths: %m");
                        break;

                case ARG_CURSOR:
                        if (arg_cursor) {
                                log_error("cannot use more than one --cursor/--after-cursor");
                                return -EINVAL;
                        }

                        arg_cursor = optarg;
                        break;

                case ARG_AFTER_CURSOR:
                        if (arg_cursor) {
                                log_error("cannot use more than one --cursor/--after-cursor");
                                return -EINVAL;
                        }

                        arg_cursor = optarg;
                        arg_after_cursor = true;
                        break;

                case ARG_FOLLOW:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0) {
                                        log_error("Failed to parse --follow= parameter.");
                                        return -EINVAL;
                                }

                                arg_follow = !!r;
                        } else
                                arg_follow = true;

                        break;

                case ARG_SAVE_STATE:
                        arg_save_state = optarg ?: STATE_FILE;
                        break;

                case '?':
                        log_error("Unknown option %s.", argv[optind-1]);
                        return -EINVAL;

                case ':':
                        log_error("Missing argument to %s.", argv[optind-1]);
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        if (!arg_url) {
                log_error("Required --url/-u option missing.");
                return -EINVAL;
        }

        if (!!arg_key != !!arg_cert) {
                log_error("Options --key and --cert must be used together.");
                return -EINVAL;
        }

        if (optind < argc && (arg_directory || arg_file || arg_machine || arg_journal_type)) {
                log_error("Input arguments make no sense with journal input.");
                return -EINVAL;
        }

        return 1;
}

static int open_journal(sd_journal **j) {
        int r;

        if (arg_directory)
                r = sd_journal_open_directory(j, arg_directory, arg_journal_type);
        else if (arg_file)
                r = sd_journal_open_files(j, (const char**) arg_file, 0);
        else if (arg_machine)
                r = sd_journal_open_container(j, arg_machine, 0);
        else
                r = sd_journal_open(j, !arg_merge*SD_JOURNAL_LOCAL_ONLY + arg_journal_type);
        if (r < 0)
                log_error_errno(r, "Failed to open %s: %m",
                                arg_directory ? arg_directory : arg_file ? "files" : "journal");
        return r;
}

int main(int argc, char **argv) {
        Uploader u;
        int r;
        bool use_journal;

        log_show_color(true);
        log_parse_environment();

        r = parse_config();
        if (r < 0)
                goto finish;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        sigbus_install();

        r = setup_uploader(&u, arg_url, arg_save_state);
        if (r < 0)
                goto cleanup;

        sd_event_set_watchdog(u.events, true);

        r = check_cursor_updating(&u);
        if (r < 0)
                goto cleanup;

        log_debug("%s running as pid "PID_FMT,
                  program_invocation_short_name, getpid());

        use_journal = optind >= argc;
        if (use_journal) {
                sd_journal *j;
                r = open_journal(&j);
                if (r < 0)
                        goto finish;
                r = open_journal_for_upload(&u, j,
                                            arg_cursor ?: u.last_cursor,
                                            arg_cursor ? arg_after_cursor : true,
                                            !!arg_follow);
                if (r < 0)
                        goto finish;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing input...");

        while (true) {
                r = sd_event_get_state(u.events);
                if (r < 0)
                        break;
                if (r == SD_EVENT_FINISHED)
                        break;

                if (use_journal) {
                        if (!u.journal)
                                break;

                        r = check_journal_input(&u);
                } else if (u.input < 0 && !use_journal) {
                        if (optind >= argc)
                                break;

                        log_debug("Using %s as input.", argv[optind]);
                        r = open_file_for_upload(&u, argv[optind++]);
                }
                if (r < 0)
                        goto cleanup;

                if (u.uploading) {
                        r = perform_upload(&u);
                        if (r < 0)
                                break;
                }

                r = sd_event_run(u.events, u.timeout);
                if (r < 0) {
                        log_error_errno(r, "Failed to run event loop: %m");
                        break;
                }
        }

cleanup:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

        destroy_uploader(&u);

finish:
        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
