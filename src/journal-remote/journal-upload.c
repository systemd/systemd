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
#include "journal-upload.h"

static const char* arg_url;

static void close_fd_input(Uploader *u);

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

#define SERVER_ANSWER_KEEP 2048

#define easy_setopt(curl, opt, value, level, cmd)                       \
        {                                                               \
                code = curl_easy_setopt(curl, opt, value);              \
                if (code) {                                             \
                        log_full(level,                                 \
                                 "curl_easy_setopt " #opt " failed: %s", \
                                  curl_easy_strerror(code));            \
                        cmd;                                            \
                }                                                       \
        }

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
                        log_warning("Failed to store server answer (%zu bytes): %s",
                                    size*nmemb, strerror(ENOMEM));
        }

        return size * nmemb;
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

                easy_setopt(curl, CURLOPT_ERRORBUFFER, &u->error,
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

                /* enable verbose for easier tracing */
                easy_setopt(curl, CURLOPT_VERBOSE, 1L, LOG_WARNING, );

                easy_setopt(curl, CURLOPT_USERAGENT,
                            "systemd-journal-upload " PACKAGE_STRING,
                            LOG_WARNING, );

                if (arg_key) {
                        assert(arg_cert);

                        easy_setopt(curl, CURLOPT_SSLKEY, arg_key,
                                    LOG_ERR, return -EXFULL);
                        easy_setopt(curl, CURLOPT_SSLCERT, arg_cert,
                                    LOG_ERR, return -EXFULL);
                }

                if (arg_trust)
                        easy_setopt(curl, CURLOPT_CAINFO, arg_trust,
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
        log_debug("%s: allowed %zu, read %zu", __func__, size*nmemb, r);

        if (r > 0)
                return r;

        u->uploading = false;
        if (r == 0) {
                log_debug("Reached EOF");
                close_fd_input(u);
                return 0;
        } else {
                log_error("Aborting transfer after read error on input: %m.");
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
        assert(revents & EPOLLIN);
        assert(fd >= 0);

        if (u->uploading) {
                log_warning("dispatch_fd_input called when uploading, ignoring.");
                return 0;
        }

        return start_upload(u, fd_input_callback, u);
}

static int open_file_for_upload(Uploader *u, const char *filename) {
        int fd, r;

        if (streq(filename, "-"))
                fd = STDIN_FILENO;
        else {
                fd = open(filename, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        log_error("Failed to open %s: %m", filename);
                        return -errno;
                }
        }

        u->input = fd;

        if (arg_follow) {
                r = sd_event_add_io(u->events, &u->input_event,
                                    fd, EPOLLIN, dispatch_fd_input, u);
                if (r < 0) {
                        if (r != -EPERM || arg_follow > 0) {
                                log_error("Failed to register input event: %s", strerror(-r));
                                return r;
                        }

                        /* Normal files should just be consumed without polling. */
                        r = start_upload(u, fd_input_callback, u);
                }
        }

        return r;
}

static int setup_uploader(Uploader *u, const char *url) {
        int r;

        assert(u);
        assert(url);

        memzero(u, sizeof(Uploader));
        u->input = -1;

        u->url = url;

        r = sd_event_default(&u->events);
        if (r < 0) {
                log_error("sd_event_default failed: %s", strerror(-r));
                return r;
        }

        return 0;
}

static void destroy_uploader(Uploader *u) {
        assert(u);

        curl_easy_cleanup(u->easy);
        curl_slist_free_all(u->header);
        free(u->answer);

        free(u->last_cursor);

        u->input_event = sd_event_source_unref(u->input_event);

        close_fd_input(u);
        close_journal_input(u);

        sd_event_unref(u->events);
}

static int perform_upload(Uploader *u) {
        CURLcode code;
        long status;

        assert(u);

        code = curl_easy_perform(u->easy);
        if (code) {
                log_error("Upload to %s failed: %.*s",
                          u->url,
                          u->error[0] ? (int) sizeof(u->error) : INT_MAX,
                          u->error[0] ? u->error : curl_easy_strerror(code));
                return -EIO;
        }

        code = curl_easy_getinfo(u->easy, CURLINFO_RESPONSE_CODE, &status);
        if (code) {
                log_error("Failed to retrieve response code: %s",
                          curl_easy_strerror(code));
                return -EUCLEAN;
        }

        if (status >= 300) {
                log_error("Upload to %s failed with code %lu: %s",
                          u->url, status, strna(u->answer));
                return -EIO;
        } else if (status < 200) {
                log_error("Upload to %s finished with unexpected code %lu: %s",
                          u->url, status, strna(u->answer));
                return -EIO;
        } else
                log_debug("Upload finished successfully with code %lu: %s",
                          status, strna(u->answer));
        return 0;
}

static void help(void) {
        printf("%s -u URL {FILE|-}...\n\n"
               "Upload journal events to a remote server.\n\n"
               "Options:\n"
               "  --url=URL                Upload to this address\n"
               "  --key=FILENAME           Specify key in PEM format\n"
               "  --cert=FILENAME          Specify certificate in PEM format\n"
               "  --trust=FILENAME         Specify CA certificate in PEM format\n"
               "     --system              Use the system journal\n"
               "     --user                Use the user journal for the current user\n"
               "  -m --merge               Use  all available journals\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "  -D --directory=PATH      Use journal files from directory\n"
               "     --file=PATH           Use this journal file\n"
               "  --cursor=CURSOR          Start at the specified cursor\n"
               "  --after-cursor=CURSOR    Start after the specified cursor\n"
               "  --[no-]follow            Do [not] wait for input\n"
               "  -h --help                Show this help and exit\n"
               "  --version                Print version string and exit\n"
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
                ARG_NO_FOLLOW,
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
                { "follow",       no_argument,       NULL, ARG_FOLLOW         },
                { "no-follow",    no_argument,       NULL, ARG_NO_FOLLOW      },
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
                        if (r < 0) {
                                log_error("Failed to add paths: %s", strerror(-r));
                                return r;
                        };
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
                        arg_follow = true;
                        break;

                case ARG_NO_FOLLOW:
                        arg_follow = false;
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
                log_error("Failed to open %s: %s",
                          arg_directory ? arg_directory : arg_file ? "files" : "journal",
                          strerror(-r));
        return r;
}

int main(int argc, char **argv) {
        Uploader u;
        int r;
        bool use_journal;

        log_show_color(true);
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = setup_uploader(&u, arg_url);
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
                                            arg_cursor, arg_after_cursor,
                                            !!arg_follow);
                if (r < 0)
                        goto finish;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing input...");

        while (true) {
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

                r = sd_event_get_state(u.events);
                if (r < 0)
                        break;
                if (r == SD_EVENT_FINISHED)
                        break;

                if (u.uploading) {
                        r = perform_upload(&u);
                        if (r < 0)
                                break;
                }

                r = sd_event_run(u.events, u.timeout);
                if (r < 0) {
                        log_error("Failed to run event loop: %s", strerror(-r));
                        break;
                }
        }

cleanup:
        sd_notify(false, "STATUS=Shutting down...");
        destroy_uploader(&u);

finish:
        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
