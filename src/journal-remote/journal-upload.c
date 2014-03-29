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

        r = sd_event_add_io(u->events, &u->input_event,
                            fd, EPOLLIN, dispatch_fd_input, u);
        if (r < 0) {
                if (r != -EPERM) {
                        log_error("Failed to register input event: %s", strerror(-r));
                        return r;
                }

                /* Normal files should just be consumed without polling. */
                r = start_upload(u, fd_input_callback, u);
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

        u->input_event = sd_event_source_unref(u->input_event);

        close_fd_input(u);

        sd_event_unref(u->events);
}

static void help(void) {
        printf("%s -u URL {FILE|-}...\n\n"
               "Upload journal events to a remote server.\n\n"
               "Options:\n"
               "  --url=URL                Upload to this address\n"
               "  --key=FILENAME           Specify key in PEM format\n"
               "  --cert=FILENAME          Specify certificate in PEM format\n"
               "  --trust=FILENAME         Specify CA certificate in PEM format\n"
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
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'                },
                { "version",      no_argument,       NULL, ARG_VERSION        },
                { "url",          required_argument, NULL, 'u'                },
                { "key",          required_argument, NULL, ARG_KEY            },
                { "cert",         required_argument, NULL, ARG_CERT           },
                { "trust",        required_argument, NULL, ARG_TRUST          },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        opterr = 0;

        while ((c = getopt_long(argc, argv, "hu:", options, NULL)) >= 0)
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

        if (optind >= argc) {
                log_error("Input argument missing.");
                return -EINVAL;
        }

        return 1;
}


int main(int argc, char **argv) {
        Uploader u;
        int r;

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
        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing input...");

        while (true) {
                if (u.input < 0) {
                        if (optind >= argc)
                                break;

                        log_debug("Using %s as input.", argv[optind]);

                        r = open_file_for_upload(&u, argv[optind++]);
                        if (r < 0)
                                goto cleanup;

                }

                r = sd_event_get_state(u.events);
                if (r < 0)
                        break;
                if (r == SD_EVENT_FINISHED)
                        break;

                if (u.uploading) {
                        CURLcode code;

                        assert(u.easy);

                        code = curl_easy_perform(u.easy);
                        if (code) {
                                log_error("Upload to %s failed: %s",
                                          u.url, curl_easy_strerror(code));
                                r = -EIO;
                                break;
                        } else
                                log_debug("Upload finished successfully.");
                }

                r = sd_event_run(u.events, u.input >= 0 ? -1 : 0);
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
