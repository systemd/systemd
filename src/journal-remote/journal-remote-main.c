/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "build.h"
#include "conf-parser.h"
#include "daemon-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "journal-compression-util.h"
#include "journal-remote.h"
#include "journal-remote-write.h"
#include "logs-show.h"
#include "main-func.h"
#include "microhttpd-util.h"
#include "parse-argument.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

#define PRIV_KEY_FILE CERTIFICATE_ROOT "/private/journal-remote.pem"
#define CERT_FILE     CERTIFICATE_ROOT "/certs/journal-remote.pem"
#define TRUST_FILE    CERTIFICATE_ROOT "/ca/trusted.pem"

static char *arg_url = NULL;
static char *arg_getter = NULL;
static char *arg_listen_raw = NULL;
static char *arg_listen_http = NULL;
static char *arg_listen_https = NULL;
static char **arg_files = NULL;
static bool arg_compress = true;
static bool arg_seal = false;
static int http_socket = -1, https_socket = -1;
static char **arg_gnutls_log = NULL;

static JournalWriteSplitMode arg_split_mode = _JOURNAL_WRITE_SPLIT_INVALID;
static char *arg_output = NULL;

static char *arg_key = NULL;
static char *arg_cert = NULL;
static char *arg_trust = NULL;
#if HAVE_GNUTLS
static bool arg_trust_all = false;
#else
static bool arg_trust_all = true;
#endif

static uint64_t arg_max_use = UINT64_MAX;
static uint64_t arg_max_size = UINT64_MAX;
static uint64_t arg_n_max_files = UINT64_MAX;
static uint64_t arg_keep_free = UINT64_MAX;

static OrderedHashmap *arg_compression = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_url, freep);
STATIC_DESTRUCTOR_REGISTER(arg_getter, freep);
STATIC_DESTRUCTOR_REGISTER(arg_listen_raw, freep);
STATIC_DESTRUCTOR_REGISTER(arg_listen_http, freep);
STATIC_DESTRUCTOR_REGISTER(arg_listen_https, freep);
STATIC_DESTRUCTOR_REGISTER(arg_files, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_gnutls_log, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cert, freep);
STATIC_DESTRUCTOR_REGISTER(arg_trust, freep);
STATIC_DESTRUCTOR_REGISTER(arg_output, freep);
STATIC_DESTRUCTOR_REGISTER(arg_compression, ordered_hashmap_freep);

static const char* const journal_write_split_mode_table[_JOURNAL_WRITE_SPLIT_MAX] = {
        [JOURNAL_WRITE_SPLIT_NONE] = "none",
        [JOURNAL_WRITE_SPLIT_HOST] = "host",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(journal_write_split_mode, JournalWriteSplitMode);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_write_split_mode, journal_write_split_mode, JournalWriteSplitMode);

#if HAVE_MICROHTTPD

typedef struct MHDDaemonWrapper {
        uint64_t fd;
        struct MHD_Daemon *daemon;

        sd_event_source *io_event;
        sd_event_source *timer_event;
} MHDDaemonWrapper;

static MHDDaemonWrapper* MHDDaemonWrapper_free(MHDDaemonWrapper *d) {
        if (!d)
                return NULL;

        d->io_event = sd_event_source_unref(d->io_event);
        d->timer_event = sd_event_source_unref(d->timer_event);

        if (d->daemon)
                MHD_stop_daemon(d->daemon);

        return mfree(d);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(MHDDaemonWrapper*, MHDDaemonWrapper_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                mhd_daemon_hash_ops,
                uint64_t, uint64_hash_func, uint64_compare_func,
                MHDDaemonWrapper, MHDDaemonWrapper_free);

#endif

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int spawn_child(const char *child, char **argv) {
        pid_t child_pid;
        int fd[2], r;

        if (pipe(fd) < 0)
                return log_error_errno(errno, "Failed to create pager pipe: %m");

        r = safe_fork_full("(remote)",
                           (int[]) {STDIN_FILENO, fd[1], STDERR_FILENO },
                           NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE, &child_pid);
        if (r < 0) {
                safe_close_pair(fd);
                return r;
        }

        /* In the child */
        if (r == 0) {
                execvp(child, argv);
                log_error_errno(errno, "Failed to exec child %s: %m", child);
                _exit(EXIT_FAILURE);
        }

        safe_close(fd[1]);

        r = fd_nonblock(fd[0], true);
        if (r < 0)
                log_warning_errno(r, "Failed to set child pipe to non-blocking: %m");

        return fd[0];
}

static int spawn_curl(const char *url) {
        char **argv = STRV_MAKE("curl",
                                "-HAccept: application/vnd.fdo.journal",
                                "--silent",
                                "--show-error",
                                url);
        int r;

        r = spawn_child("curl", argv);
        if (r < 0)
                log_error_errno(r, "Failed to spawn curl: %m");
        return r;
}

static int spawn_getter(const char *getter) {
        int r;
        _cleanup_strv_free_ char **words = NULL;

        assert(getter);
        r = strv_split_full(&words, getter, WHITESPACE, EXTRACT_UNQUOTE);
        if (r < 0)
                return log_error_errno(r, "Failed to split getter option: %m");

        r = spawn_child(words[0], words);
        if (r < 0)
                log_error_errno(r, "Failed to spawn getter %s: %m", getter);

        return r;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

#if HAVE_MICROHTTPD

static int null_timer_event_handler(sd_event_source *s,
                                uint64_t usec,
                                void *userdata);
static int dispatch_http_event(sd_event_source *event,
                               int fd,
                               uint32_t revents,
                               void *userdata);

static int build_accept_encoding(char **ret) {
        assert(ret);

        if (ordered_hashmap_isempty(arg_compression)) {
                *ret = NULL;
                return 0;
        }

        _cleanup_free_ char *buf = NULL;
        float q = 1.0, step = 1.0 / ordered_hashmap_size(arg_compression);

        const CompressionConfig *cc;
        ORDERED_HASHMAP_FOREACH(cc, arg_compression) {
                const char *c = compression_lowercase_to_string(cc->algorithm);
                if (strextendf_with_separator(&buf, ",", "%s;q=%.1f", c, q) < 0)
                        return -ENOMEM;
                q -= step;
        }

        *ret = TAKE_PTR(buf);
        return 0;
}

static int request_meta(void **connection_cls, int fd, char *hostname) {
        int r;

        assert(connection_cls);

        if (*connection_cls)
                return 0; /* already assigned. */

        Writer *writer;
        r = journal_remote_get_writer(journal_remote_server_global, hostname, &writer);
        if (r < 0)
                return log_warning_errno(r, "Failed to get writer for source %s: %m",
                                         hostname);

        _cleanup_(source_freep) RemoteSource *source = source_new(fd, true, hostname, writer);
        if (!source)
                return log_oom();

        log_debug("Added RemoteSource as connection metadata %p", source);

        r = build_accept_encoding(&source->encoding);
        if (r < 0)
                return log_oom();

        source->compression = COMPRESSION_NONE;
        *connection_cls = TAKE_PTR(source);
        return 0;
}

static void request_meta_free(void *cls,
                              struct MHD_Connection *connection,
                              void **connection_cls,
                              enum MHD_RequestTerminationCode toe) {
        RemoteSource *s;

        assert(connection_cls);
        s = *connection_cls;

        if (s) {
                log_debug("Cleaning up connection metadata %p", s);
                source_free(s);
                *connection_cls = NULL;
        }
}

static int process_http_upload(
                struct MHD_Connection *connection,
                const char *upload_data,
                size_t *upload_data_size,
                RemoteSource *source) {

        bool finished = false;
        size_t remaining;
        int r;

        assert(source);

        log_trace("%s: connection %p, %zu bytes",
                  __func__, connection, *upload_data_size);

        if (*upload_data_size) {
                log_trace("Received %zu bytes", *upload_data_size);

                if (source->compression != COMPRESSION_NONE) {
                        _cleanup_free_ char *buf = NULL;
                        size_t buf_size;

                        r = decompress_blob(source->compression, upload_data, *upload_data_size, (void **) &buf, &buf_size, 0);
                        if (r < 0)
                                return mhd_respondf(connection, r, MHD_HTTP_BAD_REQUEST, "Decompression of received blob failed.");

                        r = journal_importer_push_data(&source->importer, buf, buf_size);
                } else
                        r = journal_importer_push_data(&source->importer, upload_data, *upload_data_size);
                if (r < 0)
                        return mhd_respond_oom(connection);

                *upload_data_size = 0;
        } else
                finished = true;

        for (;;) {
                r = process_source(source, journal_remote_server_global->file_flags);
                if (r == -EAGAIN)
                        break;
                if (r < 0) {
                        if (r == -ENOBUFS)
                                log_warning_errno(r, "Entry is above the maximum of %u, aborting connection %p.",
                                                  DATA_SIZE_MAX, connection);
                        else if (r == -E2BIG)
                                log_warning_errno(r, "Entry with more fields than the maximum of %u, aborting connection %p.",
                                                  ENTRY_FIELD_COUNT_MAX, connection);
                        else
                                log_warning_errno(r, "Failed to process data, aborting connection %p: %m",
                                                  connection);
                        return MHD_NO;
                }
        }

        if (!finished)
                return MHD_YES;

        /* The upload is finished */

        remaining = journal_importer_bytes_remaining(&source->importer);
        if (remaining > 0) {
                log_warning("Premature EOF byte. %zu bytes lost.", remaining);
                return mhd_respondf(connection,
                                    0, MHD_HTTP_EXPECTATION_FAILED,
                                    "Premature EOF. %zu bytes of trailing data not processed.",
                                    remaining);
        }

        return mhd_respond_with_encoding(connection, MHD_HTTP_ACCEPTED, source->encoding, "OK.");
};

static mhd_result request_handler(
                void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **connection_cls) {

        const char *header;
        int r, code, fd;
        _cleanup_free_ char *hostname = NULL;
        bool chunked = false;

        assert(connection);
        assert(connection_cls);
        assert(url);
        assert(method);

        log_trace("Handling a connection %s %s %s", method, url, version);

        if (*connection_cls) {
                RemoteSource *source = *connection_cls;
                header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Content-Encoding");
                if (header) {
                        Compression c = compression_lowercase_from_string(header);
                        if (c <= 0 || !compression_supported(c))
                                return mhd_respondf(connection, 0, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE,
                                                    "Unsupported Content-Encoding type: %s", header);
                        source->compression = c;
                } else
                        source->compression = COMPRESSION_NONE;

                return process_http_upload(connection,
                                           upload_data, upload_data_size,
                                           source);
        }

        if (!streq(method, "POST"))
                return mhd_respond(connection, MHD_HTTP_NOT_ACCEPTABLE, "Unsupported method.");

        if (!streq(url, "/upload"))
                return mhd_respond(connection, MHD_HTTP_NOT_FOUND, "Not found.");

        header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Content-Type");
        if (!header || !streq(header, "application/vnd.fdo.journal"))
                return mhd_respond(connection, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE,
                                   "Content-Type: application/vnd.fdo.journal is required.");

        header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Transfer-Encoding");
        if (header) {
                if (!strcaseeq(header, "chunked"))
                        return mhd_respondf(connection, 0, MHD_HTTP_BAD_REQUEST,
                                            "Unsupported Transfer-Encoding type: %s", header);

                chunked = true;
        }

        header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Content-Length");
        if (header) {
                size_t len;

                if (chunked)
                        return mhd_respond(connection, MHD_HTTP_BAD_REQUEST,
                                           "Content-Length not allowed when Transfer-Encoding type is 'chunked'");

                r = safe_atozu(header, &len);
                if (r < 0)
                        return mhd_respondf(connection, r, MHD_HTTP_LENGTH_REQUIRED,
                                            "Content-Length: %s cannot be parsed: %m", header);

                if (len > ENTRY_SIZE_MAX)
                        /* When serialized, an entry of maximum size might be slightly larger,
                         * so this does not correspond exactly to the limit in journald. Oh well.
                         */
                        return mhd_respondf(connection, 0, MHD_HTTP_CONTENT_TOO_LARGE,
                                            "Payload larger than maximum size of %u bytes", ENTRY_SIZE_MAX);
        }

        {
                const union MHD_ConnectionInfo *ci;

                ci = MHD_get_connection_info(connection,
                                             MHD_CONNECTION_INFO_CONNECTION_FD);
                if (!ci) {
                        log_error("MHD_get_connection_info failed: cannot get remote fd");
                        return mhd_respond(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                           "Cannot check remote address.");
                }

                fd = ci->connect_fd;
                assert(fd >= 0);
        }

        if (journal_remote_server_global->check_trust) {
                r = check_permissions(connection, &code, &hostname);
                if (r < 0)
                        return code;
        } else {
                r = getpeername_pretty(fd, false, &hostname);
                if (r < 0)
                        return mhd_respond(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                           "Cannot check remote hostname.");
        }

        assert(hostname);

        r = request_meta(connection_cls, fd, hostname);
        if (r == -ENOMEM)
                return respond_oom(connection);
        else if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "%m");

        hostname = NULL;
        return MHD_YES;
}

#endif

static int setup_microhttpd_server(RemoteServer *s,
                                   int fd,
                                   const char *key,
                                   const char *cert,
                                   const char *trust) {

#if HAVE_MICROHTTPD
        struct MHD_OptionItem opts[] = {
                { MHD_OPTION_EXTERNAL_LOGGER, (intptr_t) microhttpd_logger},
                { MHD_OPTION_NOTIFY_COMPLETED, (intptr_t) request_meta_free},
                { MHD_OPTION_LISTEN_SOCKET, fd},
                { MHD_OPTION_CONNECTION_MEMORY_LIMIT, JOURNAL_SERVER_MEMORY_MAX},
                { MHD_OPTION_END},
                { MHD_OPTION_END},
                { MHD_OPTION_END},
                { MHD_OPTION_END},
                { MHD_OPTION_END}};
        int opts_pos = 4;
        int flags =
                MHD_USE_DEBUG |
                MHD_USE_DUAL_STACK |
                MHD_USE_EPOLL |
                MHD_USE_ITC;

        _cleanup_(MHDDaemonWrapper_freep) MHDDaemonWrapper *d = NULL;
        const union MHD_DaemonInfo *info;
        int r, epoll_fd;

        assert(fd >= 0);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return log_error_errno(r, "Failed to make fd:%d nonblocking: %m", fd);

/* MHD_OPTION_STRICT_FOR_CLIENT is introduced in microhttpd 0.9.54,
 * and MHD_USE_PEDANTIC_CHECKS will be deprecated in future.
 * If MHD_USE_PEDANTIC_CHECKS is '#define'd, then it is deprecated
 * and we should use MHD_OPTION_STRICT_FOR_CLIENT. On the other hand,
 * if MHD_USE_PEDANTIC_CHECKS is not '#define'd, then it is not
 * deprecated yet and there exists an enum element with the same name.
 * So we can safely use it. */
#ifdef MHD_USE_PEDANTIC_CHECKS
        opts[opts_pos++] = (struct MHD_OptionItem)
                {MHD_OPTION_STRICT_FOR_CLIENT, 1};
#else
        flags |= MHD_USE_PEDANTIC_CHECKS;
#endif

        if (key) {
                assert(cert);

                opts[opts_pos++] = (struct MHD_OptionItem)
                        {MHD_OPTION_HTTPS_MEM_KEY, 0, (char*) key};
                opts[opts_pos++] = (struct MHD_OptionItem)
                        {MHD_OPTION_HTTPS_MEM_CERT, 0, (char*) cert};

                flags |= MHD_USE_TLS;

                if (trust)
                        opts[opts_pos++] = (struct MHD_OptionItem)
                                {MHD_OPTION_HTTPS_MEM_TRUST, 0, (char*) trust};
        }

        d = new(MHDDaemonWrapper, 1);
        if (!d)
                return log_oom();

        d->fd = (uint64_t) fd;

        d->daemon = MHD_start_daemon(flags, 0,
                                     NULL, NULL,
                                     request_handler, NULL,
                                     MHD_OPTION_ARRAY, opts,
                                     MHD_OPTION_END);
        if (!d->daemon)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to start μhttp daemon");

        log_debug("Started MHD %s daemon on fd:%d (wrapper @ %p)",
                  key ? "HTTPS" : "HTTP", fd, d);

        info = MHD_get_daemon_info(d->daemon, MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY);
        if (!info)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "μhttp returned NULL daemon info");

        epoll_fd = info->listen_fd;
        if (epoll_fd < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "μhttp epoll fd is invalid");

        r = sd_event_add_io(s->event, &d->io_event,
                            epoll_fd, EPOLLIN,
                            dispatch_http_event, d);
        if (r < 0)
                return log_error_errno(r, "Failed to add event callback: %m");

        r = sd_event_source_set_description(d->io_event, "io_event");
        if (r < 0)
                return log_error_errno(r, "Failed to set source name: %m");

        r = sd_event_add_time(s->event, &d->timer_event,
                              CLOCK_MONOTONIC, UINT64_MAX, 0,
                              null_timer_event_handler, d);
        if (r < 0)
                return log_error_errno(r, "Failed to add timer_event: %m");

        r = sd_event_source_set_description(d->timer_event, "timer_event");
        if (r < 0)
                return log_error_errno(r, "Failed to set source name: %m");

        r = hashmap_ensure_put(&s->daemons, &mhd_daemon_hash_ops, &d->fd, d);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to add daemon to hashmap: %m");

        TAKE_PTR(d);
        s->active++;
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "microhttpd support not compiled in");
#endif
}

static int setup_microhttpd_socket(RemoteServer *s,
                                   const char *address,
                                   const char *key,
                                   const char *cert,
                                   const char *trust) {
        int fd;

        fd = make_socket_fd(LOG_DEBUG, address, SOCK_STREAM, SOCK_CLOEXEC);
        if (fd < 0)
                return fd;

        return setup_microhttpd_server(s, fd, key, cert, trust);
}

#if HAVE_MICROHTTPD

static int null_timer_event_handler(sd_event_source *timer_event,
                                    uint64_t usec,
                                    void *userdata) {
        return dispatch_http_event(timer_event, 0, 0, userdata);
}

static int dispatch_http_event(sd_event_source *event,
                               int fd,
                               uint32_t revents,
                               void *userdata) {
        MHDDaemonWrapper *d = ASSERT_PTR(userdata);
        int r;
        MHD_UNSIGNED_LONG_LONG timeout = ULLONG_MAX;

        r = MHD_run(d->daemon);
        if (r == MHD_NO)
                // FIXME: unregister daemon
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "MHD_run failed!");
        if (MHD_get_timeout(d->daemon, &timeout) == MHD_NO)
                timeout = ULLONG_MAX;

        r = sd_event_source_set_time(d->timer_event, timeout);
        if (r < 0) {
                log_warning_errno(r, "Unable to set event loop timeout: %m, this may result in indefinite blocking!");
                return 1;
        }

        r = sd_event_source_set_enabled(d->timer_event, SD_EVENT_ON);
        if (r < 0)
                log_warning_errno(r, "Unable to enable timer_event: %m, this may result in indefinite blocking!");

        return 1; /* work to do */
}

#endif

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int setup_raw_socket(RemoteServer *s, const char *address) {
        int fd;

        fd = make_socket_fd(LOG_INFO, address, SOCK_STREAM, SOCK_CLOEXEC);
        if (fd < 0)
                return fd;

        return journal_remote_add_raw_socket(s, fd);
}

static int create_remoteserver(
                RemoteServer *s,
                const char *key,
                const char *cert,
                const char *trust) {

        int r, n, fd;

        r = journal_remote_server_init(
                        s,
                        arg_output,
                        arg_split_mode,
                        (arg_compress ? JOURNAL_COMPRESS : 0) |
                        (arg_seal ? JOURNAL_SEAL : 0));
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(s->event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        n = sd_listen_fds(true);
        if (n < 0)
                return log_error_errno(n, "Failed to read listening file descriptors from environment: %m");
        else
                log_debug("Received %d descriptors", n);

        if (MAX(http_socket, https_socket) >= SD_LISTEN_FDS_START + n)
                return log_error_errno(SYNTHETIC_ERRNO(EBADFD),
                                       "Received fewer sockets than expected");

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                if (sd_is_socket(fd, AF_UNSPEC, 0, true)) {
                        log_debug("Received a listening socket (fd:%d)", fd);

                        if (fd == http_socket)
                                r = setup_microhttpd_server(s, fd, NULL, NULL, NULL);
                        else if (fd == https_socket)
                                r = setup_microhttpd_server(s, fd, key, cert, trust);
                        else
                                r = journal_remote_add_raw_socket(s, fd);
                } else if (sd_is_socket(fd, AF_UNSPEC, 0, false)) {
                        char *hostname;

                        r = getpeername_pretty(fd, false, &hostname);
                        if (r < 0)
                                return log_error_errno(r, "Failed to retrieve remote name: %m");

                        log_debug("Received a connection socket (fd:%d) from %s", fd, hostname);

                        r = journal_remote_add_source(s, fd, hostname, true);
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Unknown socket passed on fd:%d", fd);

                if (r < 0)
                        return log_error_errno(r, "Failed to register socket (fd:%d): %m", fd);
        }

        if (arg_getter) {
                log_info("Spawning getter %s...", arg_getter);
                fd = spawn_getter(arg_getter);
                if (fd < 0)
                        return fd;

                r = journal_remote_add_source(s, fd, (char*) arg_output, false);
                if (r < 0)
                        return r;
        }

        if (arg_url) {
                const char *url, *hostname;

                if (!strstr(arg_url, "/entries")) {
                        if (endswith(arg_url, "/"))
                                url = strjoina(arg_url, "entries");
                        else
                                url = strjoina(arg_url, "/entries");
                } else
                        url = strdupa_safe(arg_url);

                log_info("Spawning curl %s...", url);
                fd = spawn_curl(url);
                if (fd < 0)
                        return fd;

                hostname = STARTSWITH_SET(arg_url, "https://", "http://");
                if (!hostname)
                        hostname = arg_url;

                hostname = strndupa_safe(hostname, strcspn(hostname, "/:"));

                r = journal_remote_add_source(s, fd, (char *) hostname, false);
                if (r < 0)
                        return r;
        }

        if (arg_listen_raw) {
                log_debug("Listening on a socket...");
                r = setup_raw_socket(s, arg_listen_raw);
                if (r < 0)
                        return r;
        }

        if (arg_listen_http) {
                r = setup_microhttpd_socket(s, arg_listen_http, NULL, NULL, NULL);
                if (r < 0)
                        return r;
        }

        if (arg_listen_https) {
                r = setup_microhttpd_socket(s, arg_listen_https, key, cert, trust);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(file, arg_files) {
                const char *output_name;

                if (streq(*file, "-")) {
                        log_debug("Using standard input as source.");

                        fd = STDIN_FILENO;
                        output_name = "stdin";
                } else {
                        log_debug("Reading file %s...", *file);

                        fd = open(*file, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to open %s: %m", *file);
                        output_name = *file;
                }

                r = journal_remote_add_source(s, fd, (char*) output_name, false);
                if (r < 0)
                        return r;
        }

        if (s->active == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Zero sources specified");

        if (arg_split_mode == JOURNAL_WRITE_SPLIT_NONE) {
                /* In this case we know what the writer will be
                   called, so we can create it and verify that we can
                   create output as expected. */
                r = journal_remote_get_writer(s, NULL, &s->_single_writer);
                if (r < 0)
                        return log_warning_errno(r, "Failed to get writer: %m");
        }

        return 0;
}

static int negative_fd(const char *spec) {
        /* Return a non-positive number as its inverse, -EINVAL otherwise. */

        int fd, r;

        r = safe_atoi(spec, &fd);
        if (r < 0)
                return r;

        if (fd > 0)
                return -EINVAL;
        else
                return -fd;
}

static int parse_config(void) {
        const ConfigTableItem items[] = {
                { "Remote",  "Seal",                   config_parse_bool,             0, &arg_seal        },
                { "Remote",  "SplitMode",              config_parse_write_split_mode, 0, &arg_split_mode  },
                { "Remote",  "ServerKeyFile",          config_parse_path,             0, &arg_key         },
                { "Remote",  "ServerCertificateFile",  config_parse_path,             0, &arg_cert        },
                { "Remote",  "TrustedCertificateFile", config_parse_path_or_ignore,   0, &arg_trust       },
                { "Remote",  "MaxUse",                 config_parse_iec_uint64,       0, &arg_max_use     },
                { "Remote",  "MaxFileSize",            config_parse_iec_uint64,       0, &arg_max_size    },
                { "Remote",  "MaxFiles",               config_parse_uint64,           0, &arg_n_max_files },
                { "Remote",  "KeepFree",               config_parse_iec_uint64,       0, &arg_keep_free   },
                { "Remote",  "Compression",            config_parse_compression,      0, &arg_compression },
                {}
        };

        return config_parse_standard_file_with_dropins(
                        "systemd/journal-remote.conf",
                        "Remote\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-journal-remote.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] {FILE|-}...\n\n"
               "Write external journal events to journal file(s).\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --url=URL              Read events from systemd-journal-gatewayd at URL\n"
               "     --getter=COMMAND       Read events from the output of COMMAND\n"
               "     --listen-raw=ADDR      Listen for connections at ADDR\n"
               "     --listen-http=ADDR     Listen for HTTP connections at ADDR\n"
               "     --listen-https=ADDR    Listen for HTTPS connections at ADDR\n"
               "  -o --output=FILE|DIR      Write output to FILE or DIR/external-*.journal\n"
               "     --compress[=BOOL]      Use compression in the output journal (default: yes)\n"
               "     --seal[=BOOL]          Use event sealing (default: no)\n"
               "     --key=FILENAME         SSL key in PEM format (default:\n"
               "                            \"" PRIV_KEY_FILE "\")\n"
               "     --cert=FILENAME        SSL certificate in PEM format (default:\n"
               "                            \"" CERT_FILE "\")\n"
               "     --trust=FILENAME|all   SSL CA certificate or disable checking (default:\n"
               "                            \"" TRUST_FILE "\")\n"
               "     --gnutls-log=CATEGORY...\n"
               "                            Specify a list of gnutls logging categories\n"
               "     --split-mode=none|host How many output files to create\n"
               "\nNote: file descriptors from sd_listen_fds() will be consumed, too.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_URL,
                ARG_LISTEN_RAW,
                ARG_LISTEN_HTTP,
                ARG_LISTEN_HTTPS,
                ARG_GETTER,
                ARG_SPLIT_MODE,
                ARG_COMPRESS,
                ARG_SEAL,
                ARG_KEY,
                ARG_CERT,
                ARG_TRUST,
                ARG_GNUTLS_LOG,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "url",          required_argument, NULL, ARG_URL          },
                { "getter",       required_argument, NULL, ARG_GETTER       },
                { "listen-raw",   required_argument, NULL, ARG_LISTEN_RAW   },
                { "listen-http",  required_argument, NULL, ARG_LISTEN_HTTP  },
                { "listen-https", required_argument, NULL, ARG_LISTEN_HTTPS },
                { "output",       required_argument, NULL, 'o'              },
                { "split-mode",   required_argument, NULL, ARG_SPLIT_MODE   },
                { "compress",     optional_argument, NULL, ARG_COMPRESS     },
                { "seal",         optional_argument, NULL, ARG_SEAL         },
                { "key",          required_argument, NULL, ARG_KEY          },
                { "cert",         required_argument, NULL, ARG_CERT         },
                { "trust",        required_argument, NULL, ARG_TRUST        },
                { "gnutls-log",   required_argument, NULL, ARG_GNUTLS_LOG   },
                {}
        };

        int c, r;
        bool type_a, type_b;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ho:", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_URL:
                        r = free_and_strdup_warn(&arg_url, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_GETTER:
                        r = free_and_strdup_warn(&arg_getter, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_LISTEN_RAW:
                        r = free_and_strdup_warn(&arg_listen_raw, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_LISTEN_HTTP:
                        if (arg_listen_http || http_socket >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot currently use --listen-http= more than once");

                        r = negative_fd(optarg);
                        if (r >= 0)
                                http_socket = r;
                        else {
                                r = free_and_strdup_warn(&arg_listen_http, optarg);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case ARG_LISTEN_HTTPS:
                        if (arg_listen_https || https_socket >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot currently use --listen-https= more than once");

                        r = negative_fd(optarg);
                        if (r >= 0)
                                https_socket = r;
                        else {
                                r = free_and_strdup_warn(&arg_listen_https, optarg);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case ARG_KEY:
                        r = free_and_strdup_warn(&arg_key, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CERT:
                        r = free_and_strdup_warn(&arg_cert, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_TRUST:
#if HAVE_GNUTLS
                        r = free_and_strdup_warn(&arg_trust, optarg);
                        if (r < 0)
                                return r;
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --trust= is not available.");
#endif
                        break;

                case 'o':
                        r = parse_path_argument(optarg, /* suppress_root = */ false, &arg_output);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SPLIT_MODE:
                        arg_split_mode = journal_write_split_mode_from_string(optarg);
                        if (arg_split_mode == _JOURNAL_WRITE_SPLIT_INVALID)
                                return log_error_errno(arg_split_mode, "Invalid split mode: %s", optarg);
                        break;

                case ARG_COMPRESS:
                        r = parse_boolean_argument("--compress", optarg, &arg_compress);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SEAL:
                        r = parse_boolean_argument("--seal", optarg, &arg_seal);
                        if (r < 0)
                                return r;
                        break;

                case ARG_GNUTLS_LOG:
#if HAVE_GNUTLS
                        for (const char *p = optarg;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&p, &word, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --gnutls-log= argument: %m");
                                if (r == 0)
                                        break;

                                if (strv_consume(&arg_gnutls_log, TAKE_PTR(word)) < 0)
                                        return log_oom();
                        }
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --gnutls-log= is not available.");
#endif
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        arg_files = strv_copy(strv_skip(argv, optind));
        if (!arg_files)
                return log_oom();

        type_a = arg_getter || !strv_isempty(arg_files);
        type_b = arg_url
                || arg_listen_raw
                || arg_listen_http || arg_listen_https
                || sd_listen_fds(false) > 0;
        if (type_a && type_b)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot use file input or --getter= with "
                                       "--listen-...= or socket activation.");
        if (type_a) {
                if (!arg_output)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Option --output= must be specified with file input or --getter=.");

                if (!IN_SET(arg_split_mode, JOURNAL_WRITE_SPLIT_NONE, _JOURNAL_WRITE_SPLIT_INVALID))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "For active sources, only --split-mode=none is allowed.");

                arg_split_mode = JOURNAL_WRITE_SPLIT_NONE;
        }

        if (arg_split_mode == _JOURNAL_WRITE_SPLIT_INVALID)
                arg_split_mode = JOURNAL_WRITE_SPLIT_HOST;

        if (arg_split_mode == JOURNAL_WRITE_SPLIT_NONE && arg_output) {
                if (is_dir(arg_output, true) > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "For SplitMode=none, output must be a file.");
                if (!endswith(arg_output, ".journal"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "For SplitMode=none, output file name must end with .journal.");
        }

        if (arg_split_mode == JOURNAL_WRITE_SPLIT_HOST
            && arg_output && is_dir(arg_output, true) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "For SplitMode=host, output must be a directory.");

        if (STRPTR_IN_SET(arg_trust, "-", "all")) {
                arg_trust_all = true;
                arg_trust = mfree(arg_trust);
        }

        log_debug("Full config: SplitMode=%s Key=%s Cert=%s Trust=%s",
                  journal_write_split_mode_to_string(arg_split_mode),
                  strna(arg_key),
                  strna(arg_cert),
                  strna(arg_trust));

        return 1 /* work to do */;
}

static int load_certificates(char **key, char **cert, char **trust) {
        int r;

        r = read_full_file_full(
                        AT_FDCWD, arg_key ?: PRIV_KEY_FILE, UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                        NULL,
                        key, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read key from file '%s': %m",
                                       arg_key ?: PRIV_KEY_FILE);

        r = read_full_file_full(
                        AT_FDCWD, arg_cert ?: CERT_FILE, UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_CONNECT_SOCKET,
                        NULL,
                        cert, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read certificate from file '%s': %m",
                                       arg_cert ?: CERT_FILE);

        if (arg_trust_all)
                log_info("Certificate checking disabled.");
        else {
                r = read_full_file_full(
                                AT_FDCWD, arg_trust ?: TRUST_FILE, UINT64_MAX, SIZE_MAX,
                                READ_FULL_FILE_CONNECT_SOCKET,
                                NULL,
                                trust, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to read CA certificate file '%s': %m",
                                               arg_trust ?: TRUST_FILE);
        }

        if ((arg_listen_raw || arg_listen_http) && *trust)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --trust= makes all non-HTTPS connections untrusted.");

        return 0;
}

static int run(int argc, char **argv) {
        _cleanup_(journal_remote_server_destroy) RemoteServer s = {};
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        _cleanup_(erase_and_freep) char *key = NULL;
        _cleanup_free_ char *cert = NULL, *trust = NULL;
        int r;

        log_setup();

        r = parse_config();
        if (r < 0)
                return r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = compression_configs_mangle(&arg_compression);
        if (r < 0)
                return r;

        journal_browse_prepare();

#if HAVE_MICROHTTPD
        if (arg_listen_http || arg_listen_https) {
                r = setup_gnutls_logger(arg_gnutls_log);
                if (r < 0)
                        return r;
        }
#endif

        if (arg_listen_https || https_socket >= 0) {
                r = load_certificates(&key, &cert, &trust);
                if (r < 0)
                        return r;

                s.check_trust = !arg_trust_all;
        }

        journal_reset_metrics(&s.metrics);
        s.metrics.max_use = arg_max_use;
        s.metrics.max_size = arg_max_size;
        s.metrics.keep_free = arg_keep_free;
        s.metrics.n_max_files = arg_n_max_files;

        r = create_remoteserver(&s, key, cert, trust);
        if (r < 0)
                return r;

        r = sd_event_set_watchdog(s.event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable watchdog: %m");

        log_debug("Watchdog is %sd.", enable_disable(r > 0));

        log_debug("%s running as pid "PID_FMT,
                  program_invocation_short_name, getpid_cached());

        notify_message = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        while (s.active) {
                r = sd_event_get_state(s.event);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        break;

                r = sd_event_run(s.event, -1);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");
        }

        notify_message = NULL;
        (void) sd_notifyf(false,
                          "STOPPING=1\n"
                          "STATUS=Shutting down after writing %" PRIu64 " entries...", s.event_count);

        log_info("Finishing after writing %" PRIu64 " entries", s.event_count);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
