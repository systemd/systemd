/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <net/if.h>
#include <sched.h>
#include <sys/xattr.h>

#include "sd-device.h"
#include "sd-event.h"
#include "sd-json.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "build-path.h"
#include "build.h"
#include "bus-polkit.h"
#include "chase.h"
#include "copy.h"
#include "device-private.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-ifname.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "imds-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "netlink-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "utf8.h"
#include "varlink-io.systemd.InstanceMetadata.h"
#include "varlink-util.h"
#include "web-util.h"
#include "xattr-util.h"

#include "../import/curl-util.h"

/* This implements a client to the AWS' and Azure's "Instance Metadata Service", as well as GCPs "VM
 * Metadata", i.e.:
 *
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
 * https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
 * https://docs.cloud.google.com/compute/docs/metadata/overview
 *
 * Some notes:
 *   - IMDS service are heavily rate limited, and hence we want to centralize requests in one place and cache
 *   - Because of this we want to serialize requests
 *   - This implements a Varlink service, that processes requests serially (not concurrently).
 *   - In order to isolate IMDS access this expects that traffic to the IMDS address 169.254.169.254 is
 *     generally blackholed, but our service uses fwmark 0x7FFF0815, which (via source routing) can bypass
 *     this blackhole.
 *   - To be robust to situations with multiple interfaces, if we have no hint which interface we shall use,
 *     we'll fork our own binary off, once for each interface, and communicate to it via Varlink.
 *   - This is supposed to run under its own UID, but with CAP_NET_ADMIN held (since we want to use
 *     SO_BINDTODEVICE + SO_MARK)
 */

/* TODO:
 *    - set up routing table/rule
 *    - drop privs
 *    - deal with special HTTP errors
 *    - retry limit
 *    - api version handling (?)
 *    - polkit
 *    - negative caching
 *    - ssh keys
 */

#define TOKEN_SIZE_MAX (4096U)
#define DATA_SIZE_MAX (4*1024*1024U)
#define FWMARK_DEFAULT UINT32_C(0x7FFF0815)
#define REFRESH_USEC_DEFAULT (15 * USEC_PER_MINUTE)
#define REFRESH_USEC_MIN (1 * USEC_PER_SEC)

typedef enum EndpointSource {
        ENDPOINT_USER,
        ENDPOINT_UDEV,
        _ENDPOINT_SOURCE_MAX,
        _ENDPOINT_SOURCE_INVALID = -EINVAL,
} EndpointSource;

static char *arg_ifname = NULL;
static usec_t arg_refresh_usec = REFRESH_USEC_DEFAULT;
static uint32_t arg_fwmark = FWMARK_DEFAULT;
static bool arg_fwmark_set = true;
static ImdsWellKnown arg_well_known = _IMDS_WELL_KNOWN_INVALID;
static char* arg_key = NULL;
static bool arg_cache = true;
static bool arg_wait = false;
static bool arg_varlink = false;

/* The follow configure the IMDS service endpoint details */
static EndpointSource arg_endpoint_source = _ENDPOINT_SOURCE_INVALID;
static char *arg_vendor = NULL;
static char *arg_token_url = NULL;
static char *arg_refresh_header_name = NULL;
static char *arg_data_url = NULL;
static char *arg_data_url_suffix = NULL;
static char *arg_token_header_name = NULL;
static char **arg_extra_header = NULL;
static struct in_addr arg_address_ipv4 = {};
static struct in6_addr arg_address_ipv6 = {};
static char *arg_well_known_property[_IMDS_WELL_KNOWN_MAX] = {};

static void imds_well_known_property_free(typeof(arg_well_known_property) *array) {
        FOREACH_ARRAY(i, *array, _IMDS_WELL_KNOWN_MAX)
                free(*i);
}

STATIC_DESTRUCTOR_REGISTER(arg_ifname, freep);
STATIC_DESTRUCTOR_REGISTER(arg_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_vendor, freep);
STATIC_DESTRUCTOR_REGISTER(arg_token_url, freep);
STATIC_DESTRUCTOR_REGISTER(arg_refresh_header_name, freep);
STATIC_DESTRUCTOR_REGISTER(arg_data_url, freep);
STATIC_DESTRUCTOR_REGISTER(arg_data_url_suffix, freep);
STATIC_DESTRUCTOR_REGISTER(arg_token_header_name, freep);
STATIC_DESTRUCTOR_REGISTER(arg_extra_header, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_well_known_property, imds_well_known_property_free);

typedef struct Context Context;

typedef struct ChildData {
        /* If there are multiple network interfaces, and we are not sure where to look for things, we'll fork
         * additional instances of ourselves, one for each interface. */
        Context *context;
        int ifindex;
        sd_varlink *link;  /* outing varlink connection towards the child */
        bool retry;        /* If true then new information came to light and we should restart the request */
} ChildData;

struct Context {
        /* Fields shared between requests (these remain allocated between Varlink requests) */
        sd_event *event;
        sd_netlink *rtnl;
        CurlGlue *glue;
        struct iovec token;  /* token in binary */
        char *token_string;  /* token as string, once complete and validated */
        int cache_dir_fd;

        /* Request-specific fields (these get reset whenever we start processing a new Varlink call) */
        int ifindex;
        usec_t timestamp; /* CLOCK_BOOTTIME */
        int cache_fd;
        char *cache_filename, *cache_temporary_filename;
        uint64_t data_size;
        usec_t refresh_usec;
        char *key;
        ImdsWellKnown well_known;
        bool write_stdout;
        struct iovec write_iovec;
        bool cache;
        bool wait;
        sd_varlink *current_link; /* incoming varlink connection we are processing */

        /* Mode 1: we go directly to the network */
        CURL *curl_token;
        CURL *curl_data;
        struct curl_slist *request_header_token, *request_header_data;

        /* Mode 2: we fork off a number of children which go to the network on behalf of us, because we have
         * multiple network interfaces. */
        Hashmap *child_data;
};

#define CONTEXT_NULL                                    \
        (Context) {                                     \
                .cache_dir_fd = -EBADF,                 \
                .cache_fd = -EBADF,                     \
                .well_known = _IMDS_WELL_KNOWN_INVALID, \
        }

/* Log helpers that cap at debug logging if we are are operating on behalf of a Varlink client */
#define context_log_errno(c, level, r, fmt, ...)                        \
        log_full_errno((c)->current_link ? LOG_DEBUG : (level), r, fmt, ##__VA_ARGS__)
#define context_log(c, level, fmt, ...)                                 \
        log_full((c)->current_link ? LOG_DEBUG : (level), fmt, ##__VA_ARGS__)
#define context_log_oom(c)                                              \
        (c)->current_link ? log_oom_debug() : log_oom()

static int context_acquire_data(Context *c);
static int context_acquire_token(Context *c);
static int context_spawn_child(Context *c, int ifindex, sd_varlink **ret);

static ChildData* child_data_free(ChildData *cd) {
        if (!cd)
                return NULL;

        if (cd->context)
                hashmap_remove(cd->context->child_data, INT_TO_PTR(cd->ifindex));

        sd_varlink_close_unref(cd->link);
        return mfree(cd);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ChildData*, child_data_free);

static void context_reset_token(Context *c) {
        assert(c);

        iovec_done(&c->token);
        c->token_string = mfree(c->token_string);
        c->cache_dir_fd = safe_close(c->cache_dir_fd);
}

static void context_flush_token(Context *c) {

        if (c->cache_dir_fd >= 0)
                (void) unlinkat(c->cache_dir_fd, "token", /* flags= */ 0);

        context_reset_token(c);
}

static void context_reset_for_refresh(Context *c) {
        assert(c);

        /* Flush out all fields, up to the point we can restart the current request */

        if (c->curl_token) {
                curl_glue_remove_and_free(c->glue, c->curl_token);
                c->curl_token = NULL;
        }

        if (c->curl_data) {
                curl_glue_remove_and_free(c->glue, c->curl_data);
                c->curl_data = NULL;
        }

        curl_slist_free_all(c->request_header_token);
        c->request_header_token = NULL;
        curl_slist_free_all(c->request_header_data);
        c->request_header_data = NULL;

        c->cache_fd = safe_close(c->cache_fd);
        c->cache_filename = mfree(c->cache_filename);

        if (c->cache_temporary_filename && c->cache_dir_fd >= 0)
                (void) unlinkat(c->cache_dir_fd, c->cache_temporary_filename, /* flags= */ 0);

        c->cache_temporary_filename = mfree(c->cache_temporary_filename);

        iovec_done(&c->write_iovec);

        c->child_data = hashmap_free(c->child_data);
        c->data_size = 0;
}

static void context_reset_full(Context *c) {
        assert(c);

        /* Flush out all fields relevant to the current request, comprehensively */

        context_reset_for_refresh(c);
        c->key = mfree(c->key);
        c->well_known = _IMDS_WELL_KNOWN_INVALID;
        c->current_link = sd_varlink_unref(c->current_link);
}

static void context_new_request(Context *c) {
        assert(c);

        /* Flush everything out from the previous request */
        context_reset_full(c);

        /* Reinitialize settings from defaults. */
        c->ifindex = 0;
        c->timestamp = now(CLOCK_BOOTTIME);
        c->refresh_usec = arg_refresh_usec;
        c->cache = arg_cache;
        c->wait = arg_wait;
}

static void context_done(Context *c) {
        assert(c);

        /* Flush out everything specific to the current request first */
        context_reset_full(c);
        context_reset_token(c);

        /* And then also flush out everything shared between requests */
        c->glue = curl_glue_unref(c->glue);
        c->rtnl = sd_netlink_unref(c->rtnl);
        c->event = sd_event_unref(c->event);
}

static void context_fail_full(Context *c, int r, const char *varlink_error) {
        assert(c);
        assert(r != 0);

        if (varlink_error)
                context_log_errno(c, LOG_ERR, r, "Operation failed (%s).", varlink_error);
        else
                context_log_errno(c, LOG_ERR, r, "Operation failed (%m).");
        r = -abs(r);

        /* If we are running in Varlink mode, return the error on the connection */
        if (c->current_link) {
                if (varlink_error)
                        (void) sd_varlink_error(c->current_link, varlink_error, NULL);
                else
                        (void) sd_varlink_error_errno(c->current_link, r);
                c->current_link = sd_varlink_unref(c->current_link);
                return;
        }

        /* Otherwise terminate the whole process. */
        sd_event_exit(c->event, r);
}

static void context_fail(Context *c, int r) {
        context_fail_full(c, r, /* varlink_error= */ NULL);
}

static void context_success(Context *c) {
        int r;

        assert(c);

        context_log(c, LOG_DEBUG, "Operation succeeded.");

        if (c->current_link) {
                r = sd_varlink_replybo(
                                c->current_link,
                                JSON_BUILD_PAIR_IOVEC_BASE64("data", &c->write_iovec),
                                SD_JSON_BUILD_PAIR_CONDITION(c->ifindex > 0, "interface", SD_JSON_BUILD_INTEGER(c->ifindex)));
                if (r < 0)
                        context_log_errno(c, LOG_WARNING, r, "Failed to reply to Varlink call, ignoring: %m");

                c->current_link = sd_varlink_unref(c->current_link);
                return;
        }

        sd_event_exit(c->event, 0);
}

static int setsockopt_callback(void *userdata, curl_socket_t curlfd, curlsocktype purpose) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(curlfd >= 0);

        if (purpose != CURLSOCKTYPE_IPCXN)
                return CURL_SOCKOPT_OK;

        r = setsockopt_int(curlfd, SOL_SOCKET, SO_BINDTOIFINDEX, c->ifindex);
        if (r < 0) {
                context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to bind HTTP socket to interface: %m"));
                return CURL_SOCKOPT_ERROR;
        }

        if (arg_fwmark_set &&
            setsockopt(curlfd, SOL_SOCKET, SO_MARK, &arg_fwmark, sizeof(arg_fwmark)) < 0) {
                context_fail(c, context_log_errno(c, LOG_ERR, errno, "Failed to set firewall mark on HTTP socket: %m"));
                return CURL_SOCKOPT_ERROR;
        }

        return CURL_SOCKOPT_OK;
}

static int context_combine_key(Context *c, char **ret) {
        assert(ret);

        char *s;
        if (c->well_known < 0 || c->well_known == IMDS_BASE) {
                if (!c->key)
                        return -ENODATA;

                s = strdup(c->key);
        } else {
                const char *wk = arg_well_known_property[c->well_known];
                if (!wk)
                        return -ENODATA;
                if (c->key)
                        s = strjoin(wk, c->key);
                else
                        s = strdup(wk);
        }
        if (!s)
                return -ENOMEM;

        *ret = TAKE_PTR(s);
        return 0;
}

static void curl_glue_on_finished(CurlGlue *g, CURL *curl, CURLcode result) {
        int r;

        assert(g);

        Context *c = NULL;
        if (curl_easy_getinfo(curl, CURLINFO_PRIVATE, (char **)&c) != CURLE_OK)
                return;

        if (result != CURLE_OK)
                return context_fail_full(
                                c,
                                context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EHOSTDOWN), "Transfer failed: %s", curl_easy_strerror(result)),
                                "io.systemd.InstanceMetadata.CommunicationFailure");

        /* Error handling as per:
           https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#instance-metadata-returns
           https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#rate-limiting
        */

        long status;
        CURLcode code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (code != CURLE_OK)
                return context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to retrieve response code: %s", curl_easy_strerror(code)));
        if (status < 200)
                return context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "HTTP request finished with unexpected code %li.", status));
        if (status == 403)
                return context_fail_full(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EADDRNOTAVAIL), "IMDS is not available"), "io.systemd.InstanceMetadata.NotAvailable");
        if (IN_SET(status,
                   503, /* AWS + GCP */
                   429  /* Azure + GCP */)) {
                /* retry */
                //FIXME
        }

        if (curl == c->curl_token) {
                if (status >= 300)
                        return context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "HTTP request for token finished with unexpected code %li.", status));

                r = make_cstring(
                                c->token.iov_base,
                                c->token.iov_len,
                                MAKE_CSTRING_REFUSE_TRAILING_NUL,
                                &c->token_string);
                if (r < 0)
                        return context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to convert token into C string: %m"));

                if (string_has_cc(c->token_string, NULL) ||
                    !utf8_is_valid(c->token_string))
                        return context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EINVAL), "Token not valid UTF-8 or contains control characters, refusing."));

                context_log(c, LOG_DEBUG, "Token is: %s", c->token_string);

                if (c->cache_dir_fd >= 0) {
                        /* Only store half the valid time, to make sure we have ample time to use it */
                        usec_t until = usec_add(c->timestamp, c->refresh_usec/2);

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
                        r = sd_json_buildo(
                                        &j,
                                        SD_JSON_BUILD_PAIR_STRING("token", c->token_string),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("validUntilUSec", until));
                        if (r < 0)
                                return context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to build token JSON: %m"));

                        _cleanup_free_ char *t = NULL;
                        r = sd_json_variant_format(j, SD_JSON_FORMAT_NEWLINE, &t);
                        if (r < 0)
                                return context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to format JSON: %m"));

                        r = write_string_file_at(c->cache_dir_fd, "token", t, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MODE_0600);
                        if (r < 0)
                                return context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to write token cache file: %m"));
                }

                r = context_acquire_data(c);
                if (r < 0)
                        return context_fail(c, r);

                return;

        } else if (curl == c->curl_data) {

                if (status == 401) {
                        /* We need a new a new token */
                        context_flush_token(c);
                        context_reset_for_refresh(c);

                        r = context_acquire_token(c);
                        if (r < 0)
                                return context_fail(c, r);

                        r = context_acquire_data(c);
                        if (r < 0)
                                return context_fail(c, r);

                        return;
                }
                if (status == 404) {
                        _cleanup_free_ char *key = NULL;
                        (void) context_combine_key(c, &key);
                        return context_fail_full(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(ENOENT), "Key '%s' not found.", strna(key)), "io.systemd.InstanceMetadata.KeyNotFound");
                }
                if (status >= 300)
                        return context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "HTTP request for token finished with unexpected code %li.", status));

                if (c->cache_fd >= 0) {
                        r = link_tmpfile_at(c->cache_fd, c->cache_dir_fd, c->cache_temporary_filename, c->cache_filename, LINK_TMPFILE_REPLACE);
                        if (r < 0)
                                return context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to move cache file into place: %m"));

                        c->cache_fd = safe_close(c->cache_fd);
                        c->cache_temporary_filename = mfree(c->cache_temporary_filename);

                        context_log(c, LOG_DEBUG, "Cached data.");
                }

                context_success(c);
        } else
                assert_not_reached();
}

static int context_acquire_glue(Context *c) {
        int r;

        assert(c);

        if (c->glue)
                return 0;

        r = curl_glue_new(&c->glue, c->event);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to allocate curl glue: %m");

        c->glue->on_finished = curl_glue_on_finished;
        c->glue->userdata = c;

        return 0;
}

static size_t data_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        size_t sz = size * nmemb;
        int r;

        assert(contents);

        if (size > UINT64_MAX - c->data_size ||
            c->data_size + size > DATA_SIZE_MAX) {
                context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(E2BIG), "Data too large, refusing."));
                return 0;
        }

        if (c->write_stdout)
                fwrite(contents, size, nmemb, stdout);
        else if (!iovec_append(&c->write_iovec, &IOVEC_MAKE(contents, sz))) {
                context_fail(c, context_log_oom(c));
                return 0;
        }

        if (c->cache_fd >= 0) {
                r = loop_write(c->cache_fd, contents, sz);
                if (r < 0) {
                        context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to write data to cache: %m"));
                        return 0;
                }
        }

        return sz;
}

static int context_acquire_data(Context *c) {
        int r;

        assert(c);
        assert(c->key || c->well_known >= 0);

        if (arg_token_url && !c->token_string)
                return 0;

        _cleanup_free_ char *k = NULL;
        r = context_combine_key(c, &k);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to combine key: %m");

        context_log(c, LOG_INFO, "Requesting data for key '%s'.", k);

        if (c->cache_dir_fd >= 0 &&
            c->cache_filename &&
            c->cache_fd < 0) {
                c->cache_fd = open_tmpfile_linkable_at(c->cache_dir_fd, c->cache_filename, O_WRONLY|O_CLOEXEC, &c->cache_temporary_filename);
                if (c->cache_fd < 0)
                        return context_log_errno(c, LOG_ERR, c->cache_fd, "Failed to create cache file '%s': %m", c->cache_filename);

                if (fsetxattr(c->cache_fd, "user.imds-timestamp", &c->timestamp, sizeof(c->timestamp), /* flags= */ 0) < 0)
                        return context_log_errno(c, LOG_ERR, errno, "Failed to set timestamp xattr on '%s': %m", c->cache_filename);
        }

        r = context_acquire_glue(c);
        if (r < 0)
                return r;

        _cleanup_free_ char *url = strjoin(arg_data_url, k, arg_data_url_suffix);
        if (!url)
                return context_log_oom(c);

        r = curl_glue_make(&c->curl_data, url, c);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to create CURL request for data: %m");

        if (c->token_string) {
                _cleanup_free_ char *token_header = strjoin(arg_token_header_name, ": ", c->token_string);
                if (!token_header)
                        return context_log_oom(c);

                struct curl_slist *n = curl_slist_append(c->request_header_data, token_header);
                if (!n)
                        return context_log_oom(c);

                c->request_header_data = n;
        }

        STRV_FOREACH(i, arg_extra_header) {
                struct curl_slist *n = curl_slist_append(c->request_header_data, *i);
                if (!n)
                        return context_log_oom(c);

                c->request_header_data = n;
        }

        if (c->request_header_data)
                if (curl_easy_setopt(c->curl_data, CURLOPT_HTTPHEADER, c->request_header_data) != CURLE_OK)
                        return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set HTTP request header.");

        if (curl_easy_setopt(c->curl_data, CURLOPT_WRITEFUNCTION, data_write_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function.");

        if (curl_easy_setopt(c->curl_data, CURLOPT_WRITEDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function userdata.");

        if (curl_easy_setopt(c->curl_data, CURLOPT_SOCKOPTFUNCTION, setsockopt_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt funcion.");

        if (curl_easy_setopt(c->curl_data, CURLOPT_SOCKOPTDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt funcion userdata.");

        r = curl_glue_add(c->glue, c->curl_data);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to add CURL request to glue: %m");

        return 0;
}

static size_t token_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        size_t sz = size * nmemb;

        assert(contents);

        if (sz > SIZE_MAX - c->token.iov_len ||
            c->token.iov_len + sz > TOKEN_SIZE_MAX) {
                context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(E2BIG), "IMDS token too large."));
                return 0;
        }

        if (!iovec_append(&c->token, &IOVEC_MAKE(contents, sz))) {
                context_fail(c, context_log_oom(c));
                return 0;
        }

        return sz;
}

static int context_acquire_token(Context *c) {
        int r;

        assert(c);

        if (c->token_string || !arg_token_url)
                return 0;

        context_log(c, LOG_INFO, "Requesting token.");

        r = context_acquire_glue(c);
        if (r < 0)
                return r;

        _cleanup_free_ char *url = strjoin(arg_token_url, "/api/token");
        if (!url)
                return context_log_oom(c);

        r = curl_glue_make(&c->curl_token, url, c);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to create CURL request for API token: %m");

        if (arg_refresh_header_name) {
                _cleanup_free_ char *ttl_header = NULL;
                if (asprintf(&ttl_header,
                             "%s: %" PRIu64,
                             arg_refresh_header_name,
                             DIV_ROUND_UP(c->refresh_usec, USEC_PER_SEC)) < 0)
                        return context_log_oom(c);

                c->request_header_token = curl_slist_new(ttl_header, NULL);
                if (!c->request_header_token)
                        return context_log_oom(c);
        }

        if (curl_easy_setopt(c->curl_token, CURLOPT_HTTPHEADER, c->request_header_token) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set HTTP request header.");

        if (curl_easy_setopt(c->curl_token, CURLOPT_CUSTOMREQUEST, "PUT") != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set HTTP request method.");

        if (curl_easy_setopt(c->curl_token, CURLOPT_WRITEFUNCTION, token_write_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function.");

        if (curl_easy_setopt(c->curl_token, CURLOPT_WRITEDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function userdata.");

        if (curl_easy_setopt(c->curl_token, CURLOPT_SOCKOPTFUNCTION, setsockopt_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt funcion.");

        if (curl_easy_setopt(c->curl_token, CURLOPT_SOCKOPTDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt funcion userdata.");

        r = curl_glue_add(c->glue, c->curl_token);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to add CURL request to glue: %m");

        return 0;
}

static const char *runtime_directory(Context *c) {
        assert(c);

        if (!c->cache) {
                context_log(c, LOG_DEBUG, "Cache disabled.");
                return NULL;
        }

        const char *e = secure_getenv("RUNTIME_DIRECTORY");
        if (!e) {
                context_log(c, LOG_DEBUG, "Not using cache as $RUNTIME_DIRECTORY is not set.");
                return NULL;
        }

        return e;
}

static int context_process_cache(Context *c) {
        int r;

        assert(c);

        assert(c->key || c->well_known >= 0);
        assert(c->cache_fd < 0);
        assert(c->cache_dir_fd < 0);
        assert(!c->cache_filename);
        assert(!c->cache_temporary_filename);

        const char *e = runtime_directory(c);
        if (!e)
                return 0;

        char ifname[IF_NAMESIZE];
        r = format_ifname(c->ifindex, ifname);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to format interface name: %m");

        if (!filename_is_valid(ifname))
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EINVAL), "Network interface name '%s' is not a valid filename, refusing.", ifname);

        _cleanup_free_ char *cache_dir = path_join("cache", ifname);
        if (!cache_dir)
                return context_log_oom(c);

        r = chase(cache_dir,
                  e,
                  CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY|CHASE_PREFIX_ROOT,
                  /* ret_path= */ NULL,
                  &c->cache_dir_fd);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to open cache directory: %m");

        _cleanup_free_ char *k = NULL;
        r = context_combine_key(c, &k);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to combine IMDS key: %m");

        _cleanup_free_ char *escaped = xescape(k, "/.");
        if (!escaped)
                return context_log_oom(c);

        _cleanup_free_ char *fn = strjoin("key-", escaped);
        if (!fn)
                return context_log_oom(c);

        if (!filename_is_valid(fn)) {
                context_log(c, LOG_WARNING, "Cache filename for '%s' is not valid, not caching.", fn);
                return 0;
        }

        c->cache_filename = TAKE_PTR(fn);

        _cleanup_close_ int fd = openat(c->cache_dir_fd, c->cache_filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                if (errno != ENOENT)
                        return context_log_errno(c, LOG_ERR, errno, "Failed to open cache file '%s': %m", c->cache_filename);
        } else {
                _cleanup_free_ char *d = NULL;
                size_t l;

                r = fgetxattr_malloc(fd, "user.imds-timestamp", &d, &l);
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to read timestamp from cache file: %m");
                if (l != sizeof(usec_t))
                        return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EBADMSG), "Invalid timestamp xattr on cache file '%s': %m", c->cache_filename);

                usec_t *u = (usec_t*) d;
                if (usec_add(*u, c->refresh_usec) > c->timestamp) {

                        if (c->write_stdout) {
                                r = copy_bytes(fd, STDOUT_FILENO, /* max_bytes= */ UINT64_MAX, /* flags= */ 0);
                                if (r < 0)
                                        return context_log_errno(c, LOG_ERR, r, "Failed to write cached data to standard output: %m");
                        } else {
                                assert(!iovec_is_set(&c->write_iovec));
                                r = read_full_file_at(fd, /* filename= */ NULL, (char**) &c->write_iovec.iov_base, &c->write_iovec.iov_len);
                                if (r < 0)
                                        return context_log_errno(c, LOG_ERR, r, "Failed to read cache data: %m");
                        }

                        return 1; /* cached data is already valid */
                }

                context_log(c, LOG_DEBUG, "Cached data is older than '%s', ignoring.", FORMAT_TIMESPAN(c->refresh_usec, 0));
                (void) unlinkat(c->cache_dir_fd, c->cache_filename, /* flags= */ 0);
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        r = sd_json_parse_file_at(/* f= */ NULL, c->cache_dir_fd, "token", /* flags= */ 0, &j, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r == -ENOENT) {
                context_log_errno(c, LOG_DEBUG, r, "No cached token");
                return 0;
        }
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to read cached token: %m");

        struct {
                const char *token;
                uint64_t until;
        } d = {};

        static const sd_json_dispatch_field table[] = {
                { "token",          SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(d, token), SD_JSON_MANDATORY },
                { "validUntilUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(d, until), SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(j, table, SD_JSON_ALLOW_EXTENSIONS, &d);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to decode cached token data: %m");

        if (d.until > c->timestamp) {
                c->token_string = strdup(d.token);
                if (!c->token_string)
                        return context_log_oom(c);

                context_log(c, LOG_INFO, "Reusing cached token.");
        } else
                context_log(c, LOG_DEBUG, "Cached token is stale, not using.");

        return 0;
}

static int vl_on_reply(sd_varlink *link, sd_json_variant *m, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        ChildData *cd = ASSERT_PTR(userdata);
        Context *c = ASSERT_PTR(cd->context);
        int r;

        assert(link);
        assert(m);

        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, m);
                if (r == -EBADR)
                        context_log_errno(c, LOG_WARNING, r, "Varlink error from interface %i: %s", cd->ifindex, error_id);
                else
                        context_log_errno(c, LOG_WARNING, r, "Varlink error from interface %i: %m", cd->ifindex);

                if (streq(error_id, "io.systemd.InstanceMetadata.KeyNotFound")) {
                        context_fail_full(c, -ENOENT, error_id);
                        return 0;
                }
                if (streq(error_id, "io.systemd.InstanceMetadata.WellKnownKeyUnset")) {
                        context_fail_full(c, -ENODATA, error_id);
                        return 0;
                }
                if (streq(error_id, "io.systemd.InstanceMetadata.NotAvailable")) {
                        context_fail_full(c, -EADDRNOTAVAIL, error_id);
                        return 0;
                }
                if (streq(error_id, "io.systemd.InstanceMetadata.CommunicationFailure")) {
                        context_fail_full(c, -EHOSTDOWN, error_id);
                        return 0;
                }

                if (cd->retry) {
                        cd->link = sd_varlink_close_unref(cd->link);
                        cd->retry = false;

                        r = context_spawn_child(c, cd->ifindex, &cd->link);
                        if (r < 0) {
                                context_fail(c, r);
                                return 0;
                        }

                        sd_varlink_set_userdata(cd->link, cd);
                        return 0;
                }

                cd = child_data_free(cd);

                if (hashmap_isempty(c->child_data) && !c->wait)
                        context_fail(c, r);

                return 0;
        }

        assert(!iovec_is_set(&c->write_iovec));

        static const sd_json_dispatch_field table[] = {
                { "data",    SD_JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec, offsetof(Context, write_iovec), SD_JSON_MANDATORY },
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,        offsetof(Context, ifindex),     0                 },
                {}
        };

        r = sd_json_dispatch(m, table, SD_JSON_ALLOW_EXTENSIONS, c);
        if (r < 0) {
                context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to decode reply data: %m"));
                return 0;
        }

        if (c->write_stdout) {
                r = loop_write(STDOUT_FILENO, c->write_iovec.iov_base, c->write_iovec.iov_len);
                if (r < 0) {
                        context_fail(c, context_log_errno(c, LOG_ERR, r, "Failed to output data: %m"));
                        return 0;
                }
        }

        context_success(c);
        return 0;
}

static int context_find_if(Context *c) {
        int r;

        assert(c);

        const char *e = runtime_directory(c);
        if (!e)
                return 0;

        _cleanup_close_ int dirfd = open(e, O_PATH|O_CLOEXEC);
        if (dirfd < 0)
                return context_log_errno(c, LOG_ERR, errno, "Failed to open runtime directory: %m");

        _cleanup_free_ char *ifname = NULL;
        r = read_one_line_file_at(dirfd, "ifname", &ifname);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to load 'ifname' file from runtime directory: %m");

        if (!ifname_valid(ifname))
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EINVAL), "Loaded interface name not valid, refusing: %s", ifname);

        c->ifindex = rtnl_resolve_interface_or_warn(/* rtnl= */ NULL, ifname);
        if (c->ifindex < 0)
                return c->ifindex;

        return 1;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                child_data_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                ChildData,
                child_data_free);

static int context_spawn_child(Context *c, int ifindex, sd_varlink **ret) {
        int r;

        assert(c);
        assert(ifindex > 0);
        assert(ret);

        context_log(c, LOG_DEBUG, "Spawning child for interface '%i'.", ifindex);

        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = pin_callout_binary(LIBEXECDIR "/systemd-imdsd", &p);
        if (fd < 0)
                return context_log_errno(c, LOG_ERR, fd, "Failed to find imdsd binary: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_exec(&vl, p, /* argv= */ NULL);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to fork off imdsd binary for interface %i: %m", ifindex);

        r = sd_varlink_attach_event(
                        vl,
                        c->event,
                        SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to attach Varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, vl_on_reply);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to bind reply callback: %m");

        r = sd_varlink_invokebo(
                        vl,
                        "io.systemd.InstanceMetadata.Get",
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("key", c->key),
                        SD_JSON_BUILD_PAIR_CONDITION(c->well_known >= 0, "wellKnown", JSON_BUILD_STRING_UNDERSCORIFY(imds_well_known_to_string(c->well_known))),
                        SD_JSON_BUILD_PAIR_INTEGER("interface", ifindex),
                        SD_JSON_BUILD_PAIR_INTEGER("refreshUSec", c->refresh_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("cache", c->cache));
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to issue Get() command to Varlink child: %m");

        *ret = TAKE_PTR(vl);
        return 0;
}

static int context_spawn_new_child(Context *c, int ifindex) {
        int r;

        assert(c);

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = context_spawn_child(c, ifindex, &vl);
        if (r < 0)
                return r;

        _cleanup_(child_data_freep) ChildData *cd = new(ChildData, 1);
        if (!cd)
                return context_log_oom(c);

        *cd = (ChildData) {
                .ifindex = ifindex,
                .link = sd_varlink_ref(vl),
        };

        sd_varlink_set_userdata(vl, cd);

        if (hashmap_ensure_put(&c->child_data, &child_data_hash_ops, INT_TO_PTR(ifindex), cd) < 0)
                return context_log_oom(c);

        cd->context = c;
        TAKE_PTR(cd);

        return 0;
}

static int on_address_change(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int ifindex, r;

        assert(rtnl);
        assert(m);

        /* Called whenever an address appears on the network stack. We use that as hint that it is worth to
         * invoke a child processing that interface (either for the first time, or again) */

        r = sd_rtnl_message_addr_get_ifindex(m, &ifindex);
        if (r < 0) {
                context_log_errno(c, LOG_WARNING, r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        }
        if (ifindex <= 0) {
                context_log(c, LOG_WARNING, "rtnl: received address message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        if (ifindex == LOOPBACK_IFINDEX) {
                context_log(c, LOG_DEBUG, "Ignoring loopback device.");
                return 0;
        }

        if (!c->key && c->well_known < 0)
                return 0;

        ChildData *existing = hashmap_get(c->child_data, INT_TO_PTR(ifindex));
        if (existing) {
                /* We already have an attempt ongoing for this one? Remember there's a reason now to retry
                 * this, because new connectivity appeared. */
                existing->retry = true;
                return 0;
        }

        return context_spawn_new_child(c, ifindex);
}

static int context_spawn_children(Context *c) {
        int r;

        assert(c);
        assert(c->key || c->well_known >= 0);

        if (!c->rtnl) {
                r = sd_netlink_open(&c->rtnl);
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to connect to netlink: %m");

                r = sd_netlink_attach_event(c->rtnl, c->event, SD_EVENT_PRIORITY_NORMAL);
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to attach netlink socket to event loop: %m");

                r = sd_netlink_add_match(c->rtnl, /* ret_slot= */ NULL, RTM_NEWADDR, on_address_change, /* destroy_callback= */ NULL, c, "newaddr");
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to subscribe to RTM_NEWADDR events: %m");
        }

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        r = sd_rtnl_message_new_addr(c->rtnl, &req, RTM_GETADDR, /* ifindex= */ 0, AF_INET);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL;
        r = sd_netlink_call(c->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *i = reply; i; i = sd_netlink_message_next(i)) {
                r = on_address_change(c->rtnl, i, c);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int cmdline_run(void) {
        int r;

        assert(arg_key);

        /* When invoked via the command line (i.e. not via Varlink) */

        _cleanup_(context_done) Context c = CONTEXT_NULL;
        c.write_stdout = true;

        context_new_request(&c);

        c.key = strdup(arg_key);
        if (!c.key)
                return context_log_oom(&c);

        if (arg_ifname) {
                c.ifindex = rtnl_resolve_interface_or_warn(&c.rtnl, arg_ifname);
                if (c.ifindex < 0)
                        return c.ifindex;
        } else {
                r = context_find_if(&c);
                if (r < 0)
                        return r;
        }

        r = sd_event_default(&c.event);
        if (r < 0)
                return context_log_errno(&c, LOG_ERR, r, "Failed to allocate event loop: %m");

        if (c.ifindex > 0) {
                r = context_process_cache(&c);
                if (r < 0)
                        return r;
                if (r > 0) /* Key was cached already */
                        return 0;

                r = context_acquire_token(&c);
                if (r < 0)
                        return r;

                r = context_acquire_data(&c);
                if (r < 0)
                        return r;
        } else {
                /* Couldn't find anything, let's spawn off parallel clients for all interfaces */
                r = context_spawn_children(&c);
                if (r < 0)
                        return r;
        }

        r = sd_event_loop(c.event);
        if (r < 0)
                return r;

        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_well_known, ImdsWellKnown, imds_well_known_from_string);

static int vl_method_get(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);

        if (!c->event)
                c->event = sd_event_ref(sd_varlink_get_event(link));

        context_new_request(c);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "wellKnown",   SD_JSON_VARIANT_STRING,        dispatch_well_known,      offsetof(Context, well_known),   0 },
                { "key",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,  offsetof(Context, key),          0 },
                { "interface",   _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,    offsetof(Context, ifindex),      0 },
                { "refreshUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,  offsetof(Context, refresh_usec), 0 },
                { "cache",       SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(Context, cache),        0 },
                { "wait",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(Context, wait),         0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, c);
        if (r != 0)
                return r;

        if (c->key) {
                if (!imds_key_is_valid(c->key))
                        return sd_varlink_error_invalid_parameter_name(link, "key");

                if (c->well_known < 0)
                        c->well_known = IMDS_BASE;
                else if (!imds_well_known_can_suffix(c->well_known))
                        return sd_varlink_error_invalid_parameter_name(link, "key");
        } else if (c->well_known < 0)
                return sd_varlink_error_invalid_parameter_name(link, "key");

        if (c->refresh_usec < REFRESH_USEC_MIN)
                c->refresh_usec = REFRESH_USEC_MIN;

        assert(!c->current_link);
        c->current_link = sd_varlink_ref(link);

        if (c->ifindex <= 0) {
                r = context_find_if(c);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ char *k = NULL;
        r = context_combine_key(c, &k);
        if (r == -ENODATA)
                return sd_varlink_error(link, "io.systemd.InstanceMetadata.WellKnownKeyUnset", NULL);
        if (r < 0)
                return r;

        context_log(c, LOG_DEBUG, "Will request '%s' now.", k);

        if (c->ifindex > 0) {
                r = context_process_cache(c);
                if (r < 0)
                        return r;
                if (r > 0) { /* Key was cached already */
                        context_success(c);
                        return 0;
                }

                r = context_acquire_token(c);
                if (r < 0)
                        return r;

                r = context_acquire_data(c);
                if (r < 0)
                        return r;
        } else {
                r = context_spawn_children(c);
                if (r < 0)
                        return r;
        }

        context_log(c, LOG_DEBUG, "Method call is pending");
        return 1;
}

static int vl_method_get_vendor_info(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, c);
        if (r != 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *wkj = NULL;
        for (ImdsWellKnown i = 0; i < _IMDS_WELL_KNOWN_MAX; i++) {
                if (!arg_well_known_property[i])
                        continue;

                r = sd_json_variant_set_field_string(&wkj, imds_well_known_to_string(i), arg_well_known_property[i]);
                if (r < 0)
                        return r;
        }

        return sd_varlink_replybo(
                        link,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("vendor", arg_vendor),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("tokenUrl", arg_token_url),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("refreshHeaderName", arg_refresh_header_name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("dataUrl", arg_data_url),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("dataUrlSuffix", arg_data_url_suffix),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("tokenHeaderName", arg_token_header_name),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("extraHeader", arg_extra_header),
                        JSON_BUILD_PAIR_IN4_ADDR_NON_NULL("addressIPv4", &arg_address_ipv4),
                        JSON_BUILD_PAIR_IN6_ADDR_NON_NULL("addressIPv6", &arg_address_ipv6),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("wellKnownProperty", wkj));
}

static int vl_server(void) {
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        int r;

        /* Invocation as Varlink service */

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_InstanceMetadata);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.InstanceMetadata.Get", vl_method_get,
                        "io.systemd.InstanceMetadata.GetVendorInfo", vl_method_get_vendor_info);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-imdsd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [KEY]\n"
               "\n%5$sLow-level IMDS data acquisition.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "  -i --interface=INTERFACE\n"
               "                       Use the specified interface\n"
               "     --refresh=SEC     Set token refresh time\n"
               "     --fwmark=INTEGER  Choose firewall mark for HTTP traffic\n"
               "     --cache=no        Disable cache use\n"
               "  -w --wait=yes        Wait for connectivity\n"
               "  -K --well-known=     Select well-known key\n"
               "\n%3$sManual Endpoint Configuration:%4$s\n"
               "     --vendor=VENDOR   Specify IMDS vendor literally\n"
               "     --token-url=URL   URL for acquiring token\n"
               "     --refresh-header-name=NAME\n"
               "                       Header name for passing refresh time\n"
               "     --data-url=URL    Base URL for acquiring data\n"
               "     --data-url-suffix=STRING\n"
               "                       Suffix to append to data URL\n"
               "     --token-header-name=NAME\n"
               "                       Header name for passing token string\n"
               "     --extra-header='NAME: VALUE'\n"
               "                       Additional header to pass to data transfer\n"
               "     --address-ipv4=ADDRESS\n"
               "     --address-ipv6=ADDRESS\n"
               "                       Configure the IPv4 and IPv6 address of the IMDS server\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static bool http_header_name_valid(const char *a) {
        return a && ascii_is_valid(a) && !string_has_cc(a, /* ok= */ NULL) && !strchr(a, ':');
}

static bool http_header_valid(const char *a) {
        return a && ascii_is_valid(a) && !string_has_cc(a, /* ok= */ NULL) && strchr(a, ':');
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_REFRESH,
                ARG_FWMARK,
                ARG_CACHE,
                ARG_WAIT,
                ARG_WELL_KNOWN,
                ARG_VENDOR,
                ARG_TOKEN_URL,
                ARG_REFRESH_HEADER_NAME,
                ARG_DATA_URL,
                ARG_DATA_URL_SUFFIX,
                ARG_TOKEN_HEADER_NAME,
                ARG_EXTRA_HEADER,
                ARG_ADDRESS_IPV4,
                ARG_ADDRESS_IPV6,
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "version",             no_argument,       NULL, ARG_VERSION             },
                { "interface",           required_argument, NULL, 'i'                     },
                { "refresh",             required_argument, NULL, ARG_REFRESH             },
                { "fwmark",              required_argument, NULL, ARG_FWMARK              },
                { "cache",               required_argument, NULL, ARG_CACHE               },
                { "wait",                required_argument, NULL, ARG_WAIT                },
                { "well-known",          required_argument, NULL, ARG_WELL_KNOWN          },
                { "token-url",           required_argument, NULL, ARG_TOKEN_URL           },
                { "refresh-header-name", required_argument, NULL, ARG_REFRESH_HEADER_NAME },
                { "data-url",            required_argument, NULL, ARG_DATA_URL            },
                { "data-url-suffix",     required_argument, NULL, ARG_DATA_URL_SUFFIX     },
                { "token-header-name",   required_argument, NULL, ARG_TOKEN_HEADER_NAME   },
                { "extra-header",        required_argument, NULL, ARG_EXTRA_HEADER        },
                { "address-ipv4",        required_argument, NULL, ARG_ADDRESS_IPV4        },
                { "address-ipv6",        required_argument, NULL, ARG_ADDRESS_IPV6        },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hi:wK:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'i':
                        if (isempty(optarg)) {
                                arg_ifname = mfree(arg_ifname);
                                break;
                        }

                        if (!ifname_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Interface name '%s' is not valid.", optarg);

                        r = free_and_strdup_warn(&arg_ifname, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_REFRESH: {
                        if (isempty(optarg)) {
                                arg_refresh_usec = REFRESH_USEC_DEFAULT;
                                break;
                        }

                        usec_t t;
                        r = parse_sec(optarg, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse refresh timeout: %s", optarg);
                        if (t < REFRESH_USEC_MIN) {
                                log_warning("Increasing specified refresh time to %s, lower values are not supported.", FORMAT_TIMESPAN(REFRESH_USEC_MIN, 0));
                                arg_refresh_usec = REFRESH_USEC_MIN;
                        } else
                                arg_refresh_usec = t;
                        break;
                }

                case ARG_FWMARK:
                        if (isempty(optarg)) {
                                arg_fwmark_set = false;
                                break;
                        }

                        if (streq(optarg, "default")) {
                                arg_fwmark = FWMARK_DEFAULT;
                                arg_fwmark_set = true;
                                break;
                        }

                        r = safe_atou32(optarg, &arg_fwmark);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse --fwmark= parameter: %s", optarg);

                        arg_fwmark_set = true;
                        break;

                case ARG_CACHE:
                        r = parse_boolean_argument("--cache", optarg, &arg_cache);
                        if (r < 0)
                                return r;

                        break;

                case ARG_WAIT:
                        r = parse_boolean_argument("--wait", optarg, &arg_wait);
                        if (r < 0)
                                return r;

                        break;

                case 'w':
                        arg_wait = true;
                        break;

                case ARG_WELL_KNOWN: {
                        if (isempty(optarg)) {
                                arg_well_known = _IMDS_WELL_KNOWN_INVALID;
                                break;
                        }

                        ImdsWellKnown wk = imds_well_known_from_string(optarg);
                        if (wk < 0)
                                return log_error_errno(wk, "Failed to parse --well-known= parameter: %m");

                        arg_well_known = wk;
                        break;
                }

                case ARG_VENDOR:
                        if (isempty(optarg)) {
                                arg_vendor = mfree(arg_vendor);
                                break;
                        }

                        r = free_and_strdup_warn(&arg_vendor, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_TOKEN_URL:
                        if (isempty(optarg)) {
                                arg_token_url = mfree(arg_token_url);
                                break;
                        }

                        if (!http_url_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid URL: %s", optarg);

                        r = free_and_strdup_warn(&arg_token_url, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_REFRESH_HEADER_NAME:
                        if (isempty(optarg)) {
                                arg_refresh_header_name = mfree(arg_refresh_header_name);
                                break;
                        }

                        if (!http_header_name_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP header name: %s", optarg);

                        r = free_and_strdup_warn(&arg_refresh_header_name, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_DATA_URL:
                        if (isempty(optarg)) {
                                arg_data_url = mfree(arg_data_url);
                                break;
                        }

                        if (!http_url_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid URL: %s", optarg);

                        r = free_and_strdup_warn(&arg_data_url, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_DATA_URL_SUFFIX:
                        if (isempty(optarg)) {
                                arg_data_url_suffix = mfree(arg_data_url_suffix);
                                break;
                        }

                        if (!ascii_is_valid(optarg) || string_has_cc(optarg, /* ok= */ NULL))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid URL suffix: %s", optarg);

                        r = free_and_strdup_warn(&arg_data_url_suffix, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TOKEN_HEADER_NAME:
                        if (isempty(optarg)) {
                                arg_token_header_name = mfree(arg_token_header_name);
                                break;
                        }

                        if (!http_header_name_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP header name: %s", optarg);

                        r = free_and_strdup_warn(&arg_token_header_name, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_EXTRA_HEADER:
                        if (isempty(optarg)) {
                                arg_extra_header = strv_free(arg_extra_header);
                                break;
                        }

                        if (!http_header_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP header: %s", optarg);

                        if (strv_extend(&arg_extra_header, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_ADDRESS_IPV4: {
                        if (isempty(optarg)) {
                                arg_address_ipv4 = (struct in_addr) {};
                                break;
                        }

                        union in_addr_union u;
                        r = in_addr_from_string(AF_INET, optarg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse IPv4 address: %s", optarg);
                        arg_address_ipv4 = u.in;
                        break;
                }

                case ARG_ADDRESS_IPV6: {
                        if (isempty(optarg)) {
                                arg_address_ipv6 = (struct in6_addr) {};
                                break;
                        }

                        union in_addr_union u;
                        r = in_addr_from_string(AF_INET6, optarg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse IPv6 address: %s", optarg);
                        arg_address_ipv6 = u.in6;
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (arg_vendor || arg_token_url || arg_refresh_header_name || arg_data_url || arg_data_url_suffix || arg_token_header_name || arg_extra_header)
                arg_endpoint_source = ENDPOINT_USER;

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");

        arg_varlink = r;

        if (!arg_varlink) {
                if (optind+1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "A single argument expected.");

                if (!imds_key_is_valid(argv[optind]))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified IMDS key is not valid, refusing: %s", argv[optind]);

                r = free_and_strdup_warn(&arg_key, argv[optind]);
                if (r < 0)
                        return r;
        }

        return 1;
}

static const char *imds_well_known_udev_table[] = {
        [IMDS_HOSTNAME]        = "IMDS_KEY_HOSTNAME",
        [IMDS_REGION]          = "IMDS_KEY_REGION",
        [IMDS_ZONE]            = "IMDS_KEY_ZONE",
        [IMDS_IPV4_PUBLIC]     = "IMDS_KEY_IPV4_PUBLIC",
        [IMDS_IPV6_PUBLIC]     = "IMDS_KEY_IPV6_PUBLIC",
        [IMDS_SSH_KEY]         = "IMDS_KEY_SSH_KEY",
        [IMDS_USERDATA]        = "IMDS_KEY_USERDATA",
        [IMDS_USERDATA_BASE]   = "IMDS_KEY_USERDATA_BASE",
        [IMDS_USERDATA_BASE64] = "IMDS_KEY_USERDATA_BASE64",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(imds_well_known_udev, ImdsWellKnown);

static int smbios_server_info(void) {
        int r;

        if (arg_endpoint_source >= 0)
                return 0;

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        r = sd_device_new_from_syspath(&d, "/sys/class/dmi/id/");
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_debug_errno(r, "Failed to open /sys/class/dmi/id/ device, ignoring: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open /sys/class/dmi/id/ device: %m");

        const char *vendor;
        r = sd_device_get_property_value(d, "IMDS_VENDOR", &vendor);
        if (r == -ENOENT) {
                log_debug_errno(r, "IMDS_VENDOR= property not set on DMI device, skipping.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read IMDS_SUPPORTED= property of DMI device: %m");

        log_debug("Detected IMDS vendor support '%s'.", vendor);

        r = free_and_strdup_warn(&arg_vendor, vendor);
        if (r < 0)
                return r;

        struct {
                const char *property;
                char **variable;
        } table[] = {
                { "IMDS_TOKEN_URL",           &arg_token_url           },
                { "IMDS_REFRESH_HEADER_NAME", &arg_refresh_header_name },
                { "IMDS_DATA_URL",            &arg_data_url            },
                { "IMDS_DATA_URL_SUFFIX",     &arg_data_url_suffix     },
                { "IMDS_TOKEN_HEADER_NAME",   &arg_token_header_name   },
        };

        FOREACH_ELEMENT(i, table) {
                const char *v = NULL;

                r = sd_device_get_property_value(d, i->property, &v);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read property '%s' of DMI: %m", i->property);

                r = free_and_strdup_warn(i->variable, v);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < 64U; i++) {
                _cleanup_free_ char *property = NULL;
                const char *p = NULL;
                if (i > 0) {
                        if (asprintf(&property, "IMDS_EXTRA_HEADER%zu", i + 1) < 0)
                                return log_oom();
                        p = property;
                } else
                        p = "IMDS_EXTRA_HEADER";

                const char *v = NULL;
                r = sd_device_get_property_value(d, p, &v);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read property '%s' of DMI: %m", p);

                if (v)
                        if (strv_extend(&arg_extra_header, v) < 0)
                                return log_oom();
        }

        const char *v = NULL;
        r = sd_device_get_property_value(d, "IMDS_ADDRESS_IPV4", &v);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read property 'IMDS_ADDRESS_IPV4' of DMI: %m");
        if (v) {
                union in_addr_union u;
                r = in_addr_from_string(AF_INET, v, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse IP address: %s", v);

                arg_address_ipv4 = u.in;
        }

        v = NULL;
        r = sd_device_get_property_value(d, "IMDS_ADDRESS_IPV6", &v);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read property 'IMDS_ADDRESS_IPV6' of DMI: %m");
        if (v) {
                union in_addr_union u;
                r = in_addr_from_string(AF_INET6, v, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse IP address: %s", v);

                arg_address_ipv6 = u.in6;
        }

        for (ImdsWellKnown k = 0; k < _IMDS_WELL_KNOWN_MAX; k++) {
                const char *p = imds_well_known_udev_to_string(k);
                if (!p)
                        continue;

                v = NULL;
                r = sd_device_get_property_value(d, p, &v);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read property '%s' of DMI: %m", p);

                r = free_and_strdup_warn(arg_well_known_property + k, v);
                if (r < 0)
                        return r;
        }

        log_debug("IMDS endpoint data set from SMBIOS device.");
        arg_endpoint_source = ENDPOINT_UDEV;
        return 0;
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = smbios_server_info();
        if (r < 0)
                return r;

        if (arg_endpoint_source < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "No IMDS endpoint information provided or detected, cannot operate.");

        if (!arg_data_url)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No data base URL provided.");

        if (!!arg_token_url != !!arg_token_header_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Incomplete token parameters configured for endpoint.");

        if (arg_varlink)
                return vl_server();

        return cmdline_run();
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
