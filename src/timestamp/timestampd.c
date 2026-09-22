/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-json.h"
#include "sd-resolve.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "constants.h"
#include "curl-util.h"
#include "daemon-util.h"
#include "dlopen-note.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "main-func.h"
#include "service-util.h"
#include "set.h"
#include "stat-util.h"
#include "time-util.h"
#include "timestampd.h"
#include "timestampd-request.h"
#include "timestampd-tsp.h"
#include "varlink-io.systemd.Timestamp.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

#define DEFAULT_CONNECTION_TIMEOUT_USEC (90 * USEC_PER_SEC)

/* How much data we are willing to digest on behalf of a client by default. */
#define DEFAULT_DATA_SIZE_MAX U64_GB

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        manager_cancel_all_requests(m);
        set_free(m->requests);

#if HAVE_LIBCURL
        m->curl_glue = curl_glue_unref(m->curl_glue);
#endif
        m->resolve = sd_resolve_unref(m->resolve);
        m->varlink_server = sd_varlink_server_unref(m->varlink_server);
        m->event = sd_event_unref(m->event);

        free(m->authority);

        return mfree(m);
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .connection_timeout_usec = DEFAULT_CONNECTION_TIMEOUT_USEC,
                .data_size_max = DEFAULT_DATA_SIZE_MAX,
        };

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        (void) sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);

        *ret = TAKE_PTR(m);
        return 0;
}

int manager_parse_config(Manager *m) {
        int r;

        assert(m);

        r = config_parse_standard_file_with_dropins(
                        "systemd/timestampd.conf",
                        "Timestamp\0",
                        config_item_perf_lookup, timestampd_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ m);
        if (r < 0)
                return r;

        if (m->authority) {
                r = timestamp_authority_validate(m->authority);
                if (r == -EOPNOTSUPP) {
                        log_warning("Configured Authority=%s uses an unsupported scheme, ignoring.", m->authority);
                        m->authority = mfree(m->authority);
                } else if (r < 0) {
                        log_warning("Configured Authority=%s is malformed, ignoring.", m->authority);
                        m->authority = mfree(m->authority);
                }
        }

        return 0;
}

typedef struct MethodParameters {
        const char *digest;
        unsigned data_fd_idx;
        const char *hash_algorithm;
        const char *authority;
        bool no_nonce;            /* the nonce is included unless this is set */
        int request_certificate;  /* tristate: <0 means default (enabled) */
} MethodParameters;

static int vl_method_request(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",             SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, offsetof(MethodParameters, digest),              SD_JSON_NULLABLE },
                { "dataFileDescriptor", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,         offsetof(MethodParameters, data_fd_idx),         SD_JSON_NULLABLE },
                { "hashAlgorithm",      SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(MethodParameters, hash_algorithm),      SD_JSON_NULLABLE },
                { "authority",          SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(MethodParameters, authority),           SD_JSON_NULLABLE },
                { "noNonce",            SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(MethodParameters, no_nonce),            SD_JSON_NULLABLE },
                { "requestCertificate", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     offsetof(MethodParameters, request_certificate), SD_JSON_NULLABLE },
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        MethodParameters p = {
                .data_fd_idx = UINT_MAX,
                .request_certificate = -1,
        };
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        int nid;
        size_t expected_size;
        r = tsp_hash_algorithm_from_string(p.hash_algorithm, &nid, &expected_size);
        if (r == -EOPNOTSUPP)
                return sd_varlink_error(link, TIMESTAMP_ERROR("UnsupportedHashAlgorithm"), NULL);
        if (r < 0)
                return r;

        bool have_digest = p.digest, have_fd = p.data_fd_idx != UINT_MAX;
        if (have_digest == have_fd)
                return sd_varlink_error_invalid_parameter_name(link, have_digest ? "dataFileDescriptor" : "digest");

        _cleanup_free_ void *digest = NULL;
        size_t digest_size;
        if (p.digest) {
                r = unhexmem(p.digest, &digest, &digest_size);
                if (r < 0)
                        return sd_varlink_errorbo(link, TIMESTAMP_ERROR("InvalidDigest"),
                                                  SD_JSON_BUILD_PAIR_STRING("reason", "Digest is not valid hexadecimal"));
                if (digest_size != expected_size)
                        return sd_varlink_errorbo(link, TIMESTAMP_ERROR("InvalidDigest"),
                                                  SD_JSON_BUILD_PAIR_STRING("reason", "Digest length does not match the hash algorithm"));
        } else {
                _cleanup_close_ int fd = sd_varlink_peek_dup_fd(link, p.data_fd_idx);
                if (fd == -ENXIO)
                        return sd_varlink_error_invalid_parameter_name(link, "dataFileDescriptor");
                if (fd < 0)
                        return log_error_errno(fd, "Failed to peek data file descriptor from client: %m");

                r = fd_verify_safe_flags(fd);
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "dataFileDescriptor");
                if (r == O_WRONLY)
                        return sd_varlink_error_invalid_parameter_name(link, "dataFileDescriptor");

                /* Make sure this fd is a regular file, so that we can safely digest it without blocking indefinitely. */
                struct stat st;
                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat supplied file descriptor: %m");
                r = stat_verify_regular(&st);
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "dataFileDescriptor");

                /* Digesting is synchronous, so limit the size of the file we are willing to digest on behalf of a client. */
                if (m->data_size_max != UINT64_MAX && (uint64_t) st.st_size > m->data_size_max)
                        return sd_varlink_errorb(link, TIMESTAMP_ERROR("DataTooLarge"));

                r = tsp_digest_fd(nid, fd, &digest, &digest_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to digest supplied file descriptor: %m");

                assert(digest_size == expected_size);
        }

        const char *authority = p.authority ?: m->authority;
        if (!authority)
                return sd_varlink_error(link, TIMESTAMP_ERROR("NoAuthorityConfigured"), NULL);
        r = timestamp_authority_validate(authority);
        if (r < 0)
                return sd_varlink_errorbo(link, TIMESTAMP_ERROR("InvalidAuthority"),
                                          SD_JSON_BUILD_PAIR_STRING("reason",
                                                                    r == -EOPNOTSUPP ? "Authority URL uses an unsupported scheme" :
                                                                                       "Authority URL is malformed"));

        _cleanup_free_ void *der = NULL;
        size_t der_size;
        r = tsp_build_request(nid, digest, digest_size, !p.no_nonce, p.request_certificate != 0, &der, &der_size);
        if (r < 0)
                return log_error_errno(r, "Failed to build timestamp request: %m");

        r = timestamp_request_start(m, link, authority, TAKE_PTR(der), der_size);
        if (r < 0)
                return log_error_errno(r, "Failed to start timestamp request against '%s': %m", authority);

        return 1; /* The reply is sent asynchronously once the authority responds. */
}

static int connect_varlink(Manager *m) {
        int r;

        assert(m);
        assert(m->event);
        assert(!m->varlink_server);

        r = varlink_server_new(&m->varlink_server,
                               SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT,
                               m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_Timestamp,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Timestamp interface to Varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.Timestamp.Request",      vl_method_request,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method calls: %m");

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        r = sd_varlink_server_listen_auto(m->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink sockets: %m");
        if (r == 0) {
                r = sd_varlink_server_listen_address(m->varlink_server, "/run/systemd/io.systemd.Timestamp", 0666);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind to Varlink socket: %m");
        }

        return 0;
}

static bool manager_is_idle(Manager *m) {
        assert(m);

        /* Idle when nobody is connected and we have no outstanding requests to an authority. */
        return sd_varlink_server_current_connections(m->varlink_server) == 0 && set_isempty(m->requests);
}

static int manager_run(Manager *m) {
        int r;

        assert(m);

        /* Run the event loop until we have been idle for DEFAULT_EXIT_USEC, so that the service can be
         * socket-activated on demand. We are idle when there are no outstanding requests to an authority,
         * and there are no open varlink connections. */
        for (;;) {
                r = sd_event_get_state(m->event);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        return 0;

                bool idle = manager_is_idle(m);

                r = sd_event_run(m->event, idle ? DEFAULT_EXIT_USEC : UINT64_MAX);
                if (r < 0)
                        return r;

                if (r == 0 && idle) {
                        (void) sd_notify(/* unset_environment= */ false, NOTIFY_STOPPING_MESSAGE);
                        return 0;
                }
        }
}

COMMAND(
        "systemd-timestampd\0",
        "Acquire RFC 3161 time-stamp tokens from a Time-Stamp Authority.",
        .man_pages = "systemd-timestampd.service(8)\0",
        .option_namespace = "service",
        .option_groups =
                "Options\0",
);

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        LIBCRYPTO_NOTE(required);
        LIBCURL_NOTE(recommended);

        log_setup();

        r = service_parse_argv(/* bus_objects= */ NULL,
                               /* runtime_scope= */ NULL,
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager: %m");

        r = manager_parse_config(m);
        if (r < 0)
                return r;

        r = connect_varlink(m);
        if (r < 0)
                return r;

        r = sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        if (r < 0)
                return log_error_errno(r, "Failed to send readiness notification: %m");

        return manager_run(m);
}

DEFINE_MAIN_FUNCTION(run);
