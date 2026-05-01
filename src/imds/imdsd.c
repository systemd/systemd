/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <net/if.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-bus.h"
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
#include "creds-util.h"
#include "curl-util.h"
#include "device-private.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "escape.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-ifname.h"
#include "format-table.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "imds-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "netlink-util.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
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

/* This implements a client to the AWS' and Azure's "Instance Metadata Service", as well as GCP's "VM
 * Metadata", i.e.:
 *
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
 * https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
 * https://docs.cloud.google.com/compute/docs/metadata/overview
 * https://docs.hetzner.cloud/reference/cloud#description/server-metadata
 *
 * Some notes:
 *   - IMDS service are heavily rate limited, and hence we want to centralize requests in one place and cache
 *   - In order to isolate IMDS access this expects that traffic to the IMDS address 169.254.169.254 is
 *     generally prohibited (via a prohibit route), but our service uses fwmark 0x7FFF0815, which (via source
 *     routing) can bypass this route.
 *   - To be robust to situations with multiple interfaces, if we have no hint which interface we shall use,
 *     we'll fork our own binary off, once for each interface, and communicate to it via Varlink.
 *   - This is supposed to run under its own UID, but with CAP_NET_ADMIN held (since we want to use
 *     IP_UNICAST_IF + SO_MARK)
 *   - This daemon either be invoked manually from the command line, to do a single request, mostly for
 *     debugging purposes. Or it can be invoked as a Varlink service, which is the primary intended mode of
 *     operation.
 */

#define TOKEN_SIZE_MAX (4096U)
#define DATA_SIZE_MAX (4*1024*1024U)
#define FWMARK_DEFAULT UINT32_C(0x7FFF0815)
#define REFRESH_USEC_DEFAULT (15U * USEC_PER_MINUTE)
#define REFRESH_USEC_MIN (1U * USEC_PER_SEC)
#define DIRECT_OVERALL_TIMEOUT_USEC (40U * USEC_PER_SEC) /* a bit shorter than the default D-Bus/Varlink method call time-out) */
#define INDIRECT_OVERALL_TIMEOUT_USEC (DIRECT_OVERALL_TIMEOUT_USEC + 5U * USEC_PER_SEC)
#define RETRY_MIN_USEC (20U * USEC_PER_MSEC)
#define RETRY_MAX_USEC (3U * USEC_PER_SEC)
#define RETRY_MAX 10U

/* Which endpoint configuration source has been used, in order of preference */
typedef enum EndpointSource {
        ENDPOINT_USER,           /* Explicit command line options */
        ENDPOINT_ENVIRONMENT,    /* Fallback environment variables */
        ENDPOINT_PROC_CMDLINE,   /* Acquired via kernel command line */
        ENDPOINT_CREDENTIALS,    /* Acquired via system credentials */
        ENDPOINT_UDEV,           /* Acquired via udev SMBIOS object */
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
static ImdsNetworkMode arg_network_mode = _IMDS_NETWORK_MODE_INVALID;
static bool arg_setup_network = false;

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
static char *arg_well_known_key[_IMDS_WELL_KNOWN_MAX] = {};

static void imds_well_known_key_free(typeof(arg_well_known_key) *array) {
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
STATIC_DESTRUCTOR_REGISTER(arg_well_known_key, imds_well_known_key_free);

typedef struct Context Context;

typedef struct ChildData {
        /* If there are multiple network interfaces, and we are not sure where to look for things, we'll fork
         * additional instances of ourselves, one for each interface. */
        Context *context;
        int ifindex;
        sd_varlink *link;  /* outgoing varlink connection towards the child */
        bool retry;        /* If true then new information came to light and we should restart the request */
} ChildData;

struct Context {
        /* Fields shared between requests (these remain allocated between Varlink requests) */
        sd_event *event;
        sd_netlink *rtnl;
        bool rtnl_attached;
        sd_bus *system_bus;  /* for polkit */
        CurlGlue *glue;
        struct iovec token;  /* token in binary */
        char *token_string;  /* token as string, once complete and validated */
        int cache_dir_fd;
        Hashmap *polkit_registry;

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
        uint32_t fwmark;
        bool fwmark_set;
        sd_event_source *overall_timeout_source;

        /* Mode 1 "direct": we go directly to the network (this is done if we know the interface index to
         * use) */
        CurlSlot *slot_token;
        CurlSlot *slot_data;
        struct curl_slist *request_header_token, *request_header_data;
        sd_event_source *retry_source;
        unsigned n_retry;
        usec_t retry_interval_usec;

        /* Mode 2 "indirect": we fork off a number of children which go to the network on behalf of us,
         * because we have multiple network interfaces to deal with. */
        Hashmap *child_data;
        sd_netlink_slot *address_change_slot;
};

#define CONTEXT_NULL                                    \
        (Context) {                                     \
                .cache_dir_fd = -EBADF,                 \
                .cache_fd = -EBADF,                     \
                .well_known = _IMDS_WELL_KNOWN_INVALID, \
        }

/* Log helpers that cap at debug logging if we are operating on behalf of a Varlink client */
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
}

static void context_flush_token(Context *c) {

        if (c->cache_dir_fd >= 0)
                (void) unlinkat(c->cache_dir_fd, "token", /* flags= */ 0);

        context_reset_token(c);
}

static void context_reset_for_refresh(Context *c) {
        assert(c);

        /* Flush out all fields, up to the point we can restart the current request */

        c->slot_token = curl_slot_unref(c->slot_token);
        c->slot_data = curl_slot_unref(c->slot_data);

        sym_curl_slist_free_all(c->request_header_token);
        c->request_header_token = NULL;
        sym_curl_slist_free_all(c->request_header_data);
        c->request_header_data = NULL;

        c->cache_fd = safe_close(c->cache_fd);
        c->cache_filename = mfree(c->cache_filename);

        if (c->cache_temporary_filename && c->cache_dir_fd >= 0)
                (void) unlinkat(c->cache_dir_fd, c->cache_temporary_filename, /* flags= */ 0);

        c->cache_temporary_filename = mfree(c->cache_temporary_filename);

        iovec_done(&c->write_iovec);

        c->child_data = hashmap_free(c->child_data);
        c->data_size = 0;

        (void) sd_event_source_set_enabled(c->retry_source, SD_EVENT_OFF);
}

static void context_reset_full(Context *c) {
        assert(c);

        /* Flush out all fields relevant to the current request, comprehensively */

        context_reset_for_refresh(c);
        c->key = mfree(c->key);
        c->well_known = _IMDS_WELL_KNOWN_INVALID;
        c->current_link = sd_varlink_unref(c->current_link);
        c->address_change_slot = sd_netlink_slot_unref(c->address_change_slot);
        c->retry_source = sd_event_source_unref(c->retry_source);
        c->overall_timeout_source = sd_event_source_unref(c->overall_timeout_source);
        c->cache_dir_fd = safe_close(c->cache_dir_fd);
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
        c->fwmark = arg_fwmark;
        c->fwmark_set = arg_fwmark_set;
        c->n_retry = 0;
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
        c->polkit_registry = hashmap_free(c->polkit_registry);
        c->system_bus = sd_bus_flush_close_unref(c->system_bus);
}

static int context_fail_full(Context *c, int r, const char *varlink_error) {
        assert(c);
        assert(r != 0);

        /* Called whenever the current retrieval fails asynchronously. Returns 0 so callers in
         * int-returning paths can `return context_fail_full(...)` directly. */

        r = -abs(r);

        if (varlink_error)
                context_log_errno(c, LOG_ERR, r, "Operation failed (%s).", varlink_error);
        else
                context_log_errno(c, LOG_ERR, r, "Operation failed (%m).");

        /* If we are running in Varlink mode, return the error on the connection */
        if (c->current_link) {
                if (varlink_error)
                        (void) sd_varlink_error(c->current_link, varlink_error, NULL);
                else
                        (void) sd_varlink_error_errno(c->current_link, r);
        } else
                /* Otherwise terminate the whole process. */
                sd_event_exit(c->event, r);

        context_reset_full(c);
        return 0;
}

static int context_fail(Context *c, int r) {
        return context_fail_full(c, r, /* varlink_error= */ NULL);
}

static void context_success(Context *c) {
        int r;

        assert(c);

        /* Called whenever the current retrieval succeeds asynchronously */

        context_log(c, LOG_DEBUG, "Operation succeeded.");

        if (c->current_link) {
                r = sd_varlink_replybo(
                                c->current_link,
                                JSON_BUILD_PAIR_IOVEC_BASE64("data", &c->write_iovec),
                                SD_JSON_BUILD_PAIR_CONDITION(c->ifindex > 0, "interface", SD_JSON_BUILD_INTEGER(c->ifindex)));
                if (r < 0)
                        context_log_errno(c, LOG_WARNING, r, "Failed to reply to Varlink call, ignoring: %m");
        } else
                sd_event_exit(c->event, 0);

        context_reset_full(c);
}

static int setsockopt_callback(void *userdata, curl_socket_t curlfd, curlsocktype purpose) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(curlfd >= 0);

        if (purpose != CURLSOCKTYPE_IPCXN)
                return CURL_SOCKOPT_OK;

        r = socket_set_unicast_if(curlfd, AF_UNSPEC, c->ifindex);
        if (r < 0) {
                context_log_errno(c, LOG_ERR, r, "Failed to bind HTTP socket to interface: %m");
                return CURL_SOCKOPT_ERROR;
        }

        if (c->fwmark_set &&
            setsockopt(curlfd, SOL_SOCKET, SO_MARK, &c->fwmark, sizeof(c->fwmark)) < 0) {
                context_log_errno(c, LOG_ERR, errno, "Failed to set firewall mark on HTTP socket: %m");
                return CURL_SOCKOPT_ERROR;
        }

        return CURL_SOCKOPT_OK;
}

static int context_combine_key(Context *c, char **ret) {
        assert(ret);

        /* Combines the well known key with the explicitly configured key */

        char *s;
        if (c->well_known < 0 || c->well_known == IMDS_BASE) {
                if (!c->key)
                        return -ENODATA;

                s = strdup(c->key);
        } else {
                const char *wk = arg_well_known_key[c->well_known];
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

static const char *context_get_runtime_directory(Context *c) {
        assert(c);

        /* Returns the discovered runtime directory, but only if caching is enabled. */

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

static int context_save_ifname(Context *c) {
        int r;

        assert(c);

        /* Saves the used interface name for later retrievals, so that we don't have to wildcard search on
         * all interfaces anymore. */

        if (c->ifindex <= 0)
                return 0;

        const char *d = context_get_runtime_directory(c);
        if (!d)
                return 0;

        _cleanup_close_ int dirfd = open(d, O_PATH|O_CLOEXEC);
        if (dirfd < 0)
                return context_log_errno(c, LOG_ERR, errno, "Failed to open runtime directory: %m");

        _cleanup_free_ char *ifname = NULL;
        r = rtnl_get_ifname_full(&c->rtnl, c->ifindex, &ifname, /* ret_altnames= */ NULL);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to resolve interface index %i: %m", c->ifindex);

        r = write_string_file_at(dirfd, "ifname", ifname, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to write 'ifname' file: %m");

        return 1;
}

typedef enum CacheResult {
        CACHE_RESULT_DISABLED,             /* caching is disabled */
        CACHE_RESULT_HIT,                  /* found a positive entry */
        CACHE_RESULT_MISS,                 /* did not find an entry */
        CACHE_RESULT_KEY_NOT_FOUND,        /* found a negative entry */
        CACHE_RESULT_NOT_CACHEABLE,        /* not suitable for caching */
        _CACHE_RESULT_MAX,
        _CACHE_RESULT_INVALID = -EINVAL,
        _CACHE_RESULT_ERRNO_MAX = -ERRNO_MAX,
} CacheResult;

static CacheResult context_process_cache(Context *c) {
        int r;

        assert(c);

        assert(c->key || c->well_known >= 0);
        assert(c->cache_fd < 0);
        assert(!c->cache_filename);
        assert(!c->cache_temporary_filename);

        /* Checks the local cache – if we have one – for the current request */

        if (c->cache_dir_fd < 0) {
                const char *e = context_get_runtime_directory(c);
                if (!e)
                        return CACHE_RESULT_DISABLED;

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
        }

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
                return CACHE_RESULT_NOT_CACHEABLE;
        }

        c->cache_filename = TAKE_PTR(fn);

        _cleanup_close_ int fd = openat(c->cache_dir_fd, c->cache_filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                if (errno != ENOENT)
                        return context_log_errno(c, LOG_ERR, errno, "Failed to open cache file '%s': %m", c->cache_filename);
        } else {
                _cleanup_free_ char *d = NULL;
                size_t l;

                context_log(c, LOG_DEBUG, "Found cached file '%s'.", c->cache_filename);

                r = fgetxattr_malloc(fd, "user.imds.timestamp", &d, &l);
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to read timestamp from cache file: %m");
                if (l != sizeof(usec_t))
                        return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EBADMSG), "Invalid timestamp xattr on cache file '%s': %m", c->cache_filename);

                usec_t *u = (usec_t*) d;
                if (usec_add(*u, c->refresh_usec) > c->timestamp) {
                        _cleanup_free_ char *result = NULL;
                        r = fgetxattr_malloc(fd, "user.imds.result", &result, /* ret_size= */ NULL);
                        if (r == -ENODATA) {
                                /* No user.imds.result xattr means: hit! */
                                if (c->write_stdout) {
                                        r = copy_bytes(fd, STDOUT_FILENO, /* max_bytes= */ UINT64_MAX, /* copy_flags= */ 0);
                                        if (r < 0)
                                                return context_log_errno(c, LOG_ERR, r, "Failed to write cached data to standard output: %m");
                                } else {
                                        assert(!iovec_is_set(&c->write_iovec));
                                        r = read_full_file_at(fd, /* filename= */ NULL, (char**) &c->write_iovec.iov_base, &c->write_iovec.iov_len);
                                        if (r < 0)
                                                return context_log_errno(c, LOG_ERR, r, "Failed to read cache data: %m");
                                }

                                return CACHE_RESULT_HIT;
                        }
                        if (r < 0)
                                return context_log_errno(c, LOG_ERR, r, "Failed to read 'user.imds.result' extended attribute: %m");

                        if (streq(result, "key-not-found"))
                                return CACHE_RESULT_KEY_NOT_FOUND;

                        context_log(c, LOG_WARNING, "Unexpected 'user.imds.result' extended attribute value, ignoring: %s", result);
                        (void) unlinkat(c->cache_dir_fd, c->cache_filename, /* flags= */ 0);
                } else {
                        context_log(c, LOG_DEBUG, "Cached data is older than '%s', ignoring.", FORMAT_TIMESPAN(c->refresh_usec, 0));
                        (void) unlinkat(c->cache_dir_fd, c->cache_filename, /* flags= */ 0);
                }
        }

        /* So the above was not conclusive, let's then at least try to reuse the token */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        r = sd_json_parse_file_at(/* f= */ NULL, c->cache_dir_fd, "token", /* flags= */ 0, &j, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r == -ENOENT) {
                context_log_errno(c, LOG_DEBUG, r, "No cached token");
                return CACHE_RESULT_MISS;
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

        return CACHE_RESULT_MISS;
}

static int on_retry(sd_event_source *s, uint64_t usec, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(s);

        /* Invoked whenever the retry timer event elapses and we need to retry again */

        context_log(c, LOG_DEBUG, "Retrying...");

        /* Maybe some other instance was successful in the meantime and already found something? */
        CacheResult cr = context_process_cache(c);
        if (cr < 0) {
                context_fail(c, cr);
                return 0;
        }
        if (cr == CACHE_RESULT_HIT) {
                context_success(c);
                return 0;
        }
        if (cr == CACHE_RESULT_KEY_NOT_FOUND) {
                context_fail(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(ENOENT), "Cache reports: key not found"));
                return 0;
        }

        r = context_acquire_token(c);
        if (r < 0) {
                context_fail(c, r);
                return 0;
        }

        r = context_acquire_data(c);
        if (r < 0)
                context_fail(c, r);

        return 0;
}

static int context_schedule_retry(Context *c) {
        int r;

        assert(c);

        /* Schedules a new retry via a timer event */

        if (c->n_retry >= RETRY_MAX)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EUCLEAN), "Retry limits reached, refusing.");

        if (c->n_retry == 0)
                c->retry_interval_usec = RETRY_MIN_USEC;
        else if (c->retry_interval_usec < RETRY_MAX_USEC / 2)
                c->retry_interval_usec *= 2;
        else
                c->retry_interval_usec = RETRY_MAX_USEC;

        c->n_retry++;
        context_log(c, LOG_DEBUG, "Retry attempt #%u in %s...", c->n_retry, FORMAT_TIMESPAN(c->retry_interval_usec, USEC_PER_MSEC));

        context_reset_for_refresh(c);

        r = event_reset_time_relative(
                        c->event,
                        &c->retry_source,
                        CLOCK_BOOTTIME,
                        c->retry_interval_usec,
                        /* accuracy= */ 0,
                        on_retry,
                        c,
                        /* priority= */ 0,
                        "imds-retry",
                        /* force_reset= */ true);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to reset retry timer event source: %m");

        return 0;
}

static int context_acquire_http_status(Context *c, CURL *curl, long *ret_status) {
        assert(c);
        assert(ret_status);

        /* Acquires the HTTP status code, and does some generic validation that applies to both the token and
         * the data transfer.
         *
         * Error handling as per:
         *     https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#instance-metadata-returns
         *     https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#rate-limiting
         */

        long status;
        CURLcode code = sym_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (code != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to retrieve response code: %s", sym_curl_easy_strerror(code));

        context_log(c, LOG_DEBUG, "Got HTTP error code %li.", status);

        if (status == 403)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EADDRNOTAVAIL), "IMDS is not available");

        /* Automatically retry on some transient errors from HTTP */
        if (IN_SET(status,
                   503, /* AWS + GCP */
                   429  /* Azure + GCP */)) {
                *ret_status = 0;
                return 0; /* no immediate answer, please schedule retry */
        }

        if (status < 200 || status > 600)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "HTTP request finished with unexpected code %li.", status);

        *ret_status = status;
        return 1; /* valid answer */
}

static int context_validate_token_http_status(Context *c, long status) {
        assert(c);

        /* Specific HTTP status checks for the token transfer */

        if (status >= 300)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "HTTP request for token finished with unexpected code %li.", status);

        return 1; /* all good */
}

static int context_validate_data_http_status(Context *c, long status) {
        int r;

        assert(c);

        /* Specific HTTP status checks for the data transfer */

        if (status == 401 && arg_token_url) {
                /* We need a new token */
                context_log(c, LOG_DEBUG, "Server requested a new token...");

                /* Count token requests as a retry */
                if (c->n_retry >= RETRY_MAX)
                        return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EUCLEAN), "Retry limits reached, refusing.");
                c->n_retry++;

                context_flush_token(c);
                context_reset_for_refresh(c);

                r = context_acquire_token(c);
                if (r < 0)
                        return r;

                r = context_acquire_data(c);
                if (r < 0)
                        return r;

                return 0; /* restarted right-away */
        }

        if (status == 404) {
                _cleanup_free_ char *key = NULL;
                r = context_combine_key(c, &key);
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to combine IMDS key: %m");

                /* Do negative caching for not found */
                if (c->cache_fd >= 0) {
                        if (fsetxattr(c->cache_fd, "user.imds.result", "key-not-found", STRLEN("key-not-found"), /* flags= */ 0) < 0)
                                context_log_errno(c, LOG_DEBUG, errno, "Failed to set result xattr on '%s', ignoring: %m", c->cache_filename);
                        else {
                                r = link_tmpfile_at(c->cache_fd, c->cache_dir_fd, c->cache_temporary_filename, c->cache_filename, LINK_TMPFILE_REPLACE);
                                if (r < 0)
                                        return context_log_errno(c, LOG_ERR, r, "Failed to move cache file into place: %m");

                                c->cache_fd = safe_close(c->cache_fd);
                                c->cache_temporary_filename = mfree(c->cache_temporary_filename);

                                context_log(c, LOG_DEBUG, "Cached negative entry for '%s'.", key);
                        }
                }

                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(ENOENT), "Key '%s' not found.", key);
        }

        if (status >= 300)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "HTTP request for data finished with unexpected code %li.", status);

        return 1; /* all good */
}

static int context_validate_token(Context *c) {
        int r;

        assert(c);

        /* Validates that the downloaded token data actually forms a valid string */

        _cleanup_free_ char *t = NULL;
        r = make_cstring(
                        c->token.iov_base,
                        c->token.iov_len,
                        MAKE_CSTRING_REFUSE_TRAILING_NUL,
                        &t);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to convert token into C string: %m");

        if (string_has_cc(t, NULL) ||
            !utf8_is_valid(t))
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EINVAL), "Token not valid UTF-8 or contains control characters, refusing.");

        free_and_replace(c->token_string, t);
        return 1; /* all good */
}

static int context_save_token(Context *c) {
        int r;

        assert(c);
        assert(c->token_string);

        /* Save the acquired token in the cache, so that we can reuse it later */

        if (c->cache_dir_fd < 0)
                return 0;

        /* Only store half the valid time, to make sure we have ample time to use it */
        usec_t until = usec_add(c->timestamp, c->refresh_usec/2);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        r = sd_json_buildo(
                        &j,
                        SD_JSON_BUILD_PAIR_STRING("token", c->token_string),
                        SD_JSON_BUILD_PAIR_UNSIGNED("validUntilUSec", until));
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to build token JSON: %m");

        _cleanup_free_ char *t = NULL;
        r = sd_json_variant_format(j, SD_JSON_FORMAT_NEWLINE, &t);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to format JSON: %m");

        r = write_string_file_at(c->cache_dir_fd, "token", t, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MODE_0600);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to write token cache file: %m");

        return 0;
}

static int context_save_data(Context *c) {
        int r;

        assert(c);

        /* Finalize saving of the acquired data in the cache */

        if (c->cache_fd < 0)
                return 0;

        r = link_tmpfile_at(c->cache_fd, c->cache_dir_fd, c->cache_temporary_filename, c->cache_filename, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to move cache file into place: %m");

        c->cache_fd = safe_close(c->cache_fd);
        c->cache_temporary_filename = mfree(c->cache_temporary_filename);

        context_log(c, LOG_DEBUG, "Cached data.");
        return 0;
}

static int curl_on_finished(CurlSlot *slot, CURL *curl, CURLcode result, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        /* Called whenever libcurl did its thing and reports a download being complete or having failed */

        switch (result) {

        case CURLE_OK: /* yay! */
                /* If we managed to get a HTTP reply, this is good enough, let's pin the interface now for
                 * later calls */
                (void) context_save_ifname(c);
                break;

        case CURLE_WRITE_ERROR:
                /* CURLE_WRITE_ERROR we'll see if the data callbacks failed already. We'll try to look at the
                 * HTTP status below, and use that ideally. */
                break;

        case CURLE_COULDNT_CONNECT:
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_GOT_NOTHING:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
                context_log(c, LOG_INFO, "Connection error from curl: %s", sym_curl_easy_strerror(result));

                /* Automatically retry on some transient errors from curl itself */
                r = context_schedule_retry(c);
                if (r < 0)
                        return context_fail(c, r);

                return 0;

        default:
                return context_fail_full(
                                c,
                                context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EHOSTDOWN), "Transfer failed: %s", sym_curl_easy_strerror(result)),
                                "io.systemd.InstanceMetadata.CommunicationFailure");
        }

        long status;
        r = context_acquire_http_status(c, curl, &status);
        if (r == -EADDRNOTAVAIL)
                return context_fail_full(c, r, "io.systemd.InstanceMetadata.NotAvailable");
        if (r < 0)
                return context_fail(c, r);
        if (r == 0) { /* We shall retry */
                (void) context_schedule_retry(c);
                return 0;
        }
        if (result != CURLE_OK) /* if getting the HTTP status didn't work, propagate a generic error */
                return context_fail(c, SYNTHETIC_ERRNO(ENOTRECOVERABLE));

        if (slot == c->slot_token) {
                r = context_validate_token_http_status(c, status);
                if (r < 0)
                        return context_fail(c, r);

                r = context_validate_token(c);
                if (r < 0)
                        return context_fail(c, r);

                context_log(c, LOG_DEBUG, "Token successfully acquired.");

                r = context_save_token(c);
                if (r < 0)
                        return context_fail(c, r);

                r = context_acquire_data(c);
                if (r < 0)
                        return context_fail(c, r);

        } else if (slot == c->slot_data) {

                r = context_validate_data_http_status(c, status);
                if (r == -ENOENT)
                        return context_fail_full(c, r, "io.systemd.InstanceMetadata.KeyNotFound");
                if (r < 0)
                        return context_fail(c, r);
                if (r == 0) /* Immediately restarted */
                        return 0;

                context_log(c, LOG_DEBUG, "Data download successful.");

                r = context_save_data(c);
                if (r < 0)
                        return context_fail(c, r);

                context_success(c);
        } else
                assert_not_reached();

        return 0;
}

static int context_acquire_glue(Context *c) {
        int r;

        assert(c);

        /* Allocates a curl object if we don't have one yet */

        if (c->glue)
                return 0;

        r = curl_glue_new(&c->glue, c->event);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to allocate curl glue: %m");

        return 0;
}

static size_t data_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        size_t sz = size * nmemb;
        int r;

        /* Called whenever we receive new payload from the server */
        assert(contents);

        /* If we managed to get a HTTP reply, this is good enough, let's pin the interface now for later calls */
        (void) context_save_ifname(c);

        /* Before we use the acquired data, let's verify the HTTP status, if there's a failure or we need to
         * restart, abort the write here. Note that the curl_on_finished() call will then check the HTTP
         * status again and act on it. */
        long status;
        r = context_acquire_http_status(c, curl_slot_get_easy(c->slot_data), &status);
        if (r <= 0)
                return 0; /* fail the thing, so that curl_on_finished() can handle this failure or retry request */
        if (status >= 300) /* any status equal or above 300 needs to be handled by curl_on_finished() too */
                return 0;

        if (sz > UINT64_MAX - c->data_size ||
            c->data_size + sz > DATA_SIZE_MAX) {
                context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(E2BIG), "Data too large, refusing.");
                return 0;
        }

        c->data_size += sz;

        if (c->write_stdout)
                (void) fwrite(contents, 1, sz, stdout);
        else if (!iovec_append(&c->write_iovec, &IOVEC_MAKE(contents, sz))) {
                context_log_oom(c);
                return 0;
        }

        if (c->cache_fd >= 0) {
                r = loop_write(c->cache_fd, contents, sz);
                if (r < 0) {
                        context_log_errno(c, LOG_ERR, r, "Failed to write data to cache: %m");
                        return 0;
                }
        }

        return sz;
}

static int context_acquire_data(Context *c) {
        int r;

        assert(c);
        assert(c->key || c->well_known >= 0);

        /* Called to initiate getting the actual IMDS key payload */

        if (arg_token_url && !c->token_string)
                return 0; /* If we need a token first, let's not do anything */

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

                if (fchmod(c->cache_fd, 0600) < 0)
                        return context_log_errno(c, LOG_ERR, errno, "Failed to adjust cache node access mode: %m");

                if (fsetxattr(c->cache_fd, "user.imds.timestamp", &c->timestamp, sizeof(c->timestamp), /* flags= */ 0) < 0)
                        return context_log_errno(c, LOG_ERR, errno, "Failed to set timestamp xattr on '%s': %m", c->cache_filename);
        }

        r = context_acquire_glue(c);
        if (r < 0)
                return r;

        _cleanup_free_ char *url = strjoin(arg_data_url, k, arg_data_url_suffix);
        if (!url)
                return context_log_oom(c);

        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        r = curl_glue_make(&easy, url);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to create CURL request for data: %m");

        if (c->token_string) {
                _cleanup_free_ char *token_header = strjoin(arg_token_header_name, ": ", c->token_string);
                if (!token_header)
                        return context_log_oom(c);

                r = curl_append_to_header(&c->request_header_data, STRV_MAKE(token_header));
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to create curl header: %m");
        }

        r = curl_append_to_header(&c->request_header_data, arg_extra_header);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to create curl header: %m");

        if (c->request_header_data)
                if (sym_curl_easy_setopt(easy, CURLOPT_HTTPHEADER, c->request_header_data) != CURLE_OK)
                        return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set HTTP request header.");

        if (sym_curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, data_write_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function.");

        if (sym_curl_easy_setopt(easy, CURLOPT_WRITEDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function userdata.");

        if (sym_curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, setsockopt_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt function.");

        if (sym_curl_easy_setopt(easy, CURLOPT_SOCKOPTDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt function userdata.");

        if (sym_curl_easy_setopt(easy, CURLOPT_LOCALPORT, 1L) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt local port");

        if (sym_curl_easy_setopt(easy, CURLOPT_LOCALPORTRANGE, 1023L) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt local port range");

        r = curl_glue_perform_async(c->glue, easy, curl_on_finished, c, &c->slot_data);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to add CURL request to glue: %m");
        TAKE_PTR(easy);

        return 0;
}

static size_t token_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        size_t sz = size * nmemb;
        int r;

        /* Called whenever we get data from the token download */
        assert(contents);

        /* If we managed to get a HTTP reply, this is good enough, let's pin the interface now for later calls */
        (void) context_save_ifname(c);

        /* Before we use acquired data, let's verify the HTTP status */
        long status;
        r = context_acquire_http_status(c, curl_slot_get_easy(c->slot_token), &status);
        if (r <= 0)
                return 0; /* fail the thing, so that curl_on_finished() can handle this failure or retry request */
        if (status >= 300) /* any status equal or above 300 needs to be handled by curl_on_finished() */
                return 0;

        if (sz > SIZE_MAX - c->token.iov_len ||
            c->token.iov_len + sz > TOKEN_SIZE_MAX) {
                context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(E2BIG), "IMDS token too large.");
                return 0;
        }

        if (!iovec_append(&c->token, &IOVEC_MAKE(contents, sz))) {
                context_log_oom(c);
                return 0;
        }

        return sz;
}

static int context_acquire_token(Context *c) {
        int r;

        assert(c);

        /* Called to initiate getting the token if we need one. */

        if (c->token_string || !arg_token_url)
                return 0;

        context_log(c, LOG_INFO, "Requesting token.");

        r = context_acquire_glue(c);
        if (r < 0)
                return r;

        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        r = curl_glue_make(&easy, arg_token_url);
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

        if (sym_curl_easy_setopt(easy, CURLOPT_HTTPHEADER, c->request_header_token) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set HTTP request header.");

        if (sym_curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "PUT") != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set HTTP request method.");

        if (sym_curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, token_write_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function.");

        if (sym_curl_easy_setopt(easy, CURLOPT_WRITEDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL write function userdata.");

        if (sym_curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, setsockopt_callback) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt function.");

        if (sym_curl_easy_setopt(easy, CURLOPT_SOCKOPTDATA, c) != CURLE_OK)
                return context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(EIO), "Failed to set CURL setsockopt function userdata.");

        r = curl_glue_perform_async(c->glue, easy, curl_on_finished, c, &c->slot_token);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to add CURL request to glue: %m");
        TAKE_PTR(easy);

        return 0;
}

static int vl_on_reply(sd_varlink *link, sd_json_variant *m, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        ChildData *cd = ASSERT_PTR(userdata);
        Context *c = ASSERT_PTR(cd->context);
        int r;

        assert(link);
        assert(m);

        /* When we spawned off worker instances of ourselves (one for each local network interface), then
         * we'll get a response from them via a Varlink reply. Handle it. */

        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, m);
                if (r == -EBADR)
                        context_log_errno(c, LOG_WARNING, r, "Varlink error from interface %i: %s", cd->ifindex, error_id);
                else
                        context_log_errno(c, LOG_WARNING, r, "Varlink error from interface %i: %m", cd->ifindex);

                /* Propagate these errors immediately */
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

                /* The other errors we consider transient. Let's see if we shall immediately restart the request. */
                if (cd->retry) {
                        context_log(c, LOG_DEBUG, "Child for network interface %i was scheduled for immediate retry, executing now.", cd->ifindex);
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

                /* We shall not retry immediately. In that case, we give up on the child, and propagate the
                 * error if it was the last child, otherwise we continue until the last one dies too. */
                cd = child_data_free(cd);

                if (hashmap_isempty(c->child_data) && !c->wait) {
                        /* This is the last child, propagate the error */
                        context_log(c, LOG_DEBUG, "Last child failed, propagating error.");

                        if (streq(error_id, "io.systemd.InstanceMetadata.CommunicationFailure"))
                                context_fail_full(c, -EHOSTDOWN, error_id);
                        else if (streq(error_id, "io.systemd.InstanceMetadata.Timeout"))
                                context_fail_full(c, -ETIMEDOUT, error_id);
                        else
                                context_fail_full(c, r, error_id);

                        return 0;
                }

                context_log(c, LOG_DEBUG, "Pending children remaining, continuing to wait.");
                return 0;
        }

        assert(!iovec_is_set(&c->write_iovec));

        static const sd_json_dispatch_field table[] = {
                { "data",      SD_JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec, offsetof(Context, write_iovec), SD_JSON_MANDATORY },
                { "interface", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,        offsetof(Context, ifindex),     0                 },
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

static int context_load_ifname(Context *c) {
        int r;

        assert(c);

        /* Tries to load the previously used interface name, so that we don't have to wildcard search on all
         * interfaces. */

        const char *e = context_get_runtime_directory(c);
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

        c->ifindex = rtnl_resolve_interface(&c->rtnl, ifname);
        if (c->ifindex < 0) {
                (void) unlinkat(dirfd, "ifname", /* flags= */ 0);
                context_log_errno(c, LOG_ERR, c->ifindex, "Failed to resolve saved interface name '%s', assuming interface disappeared, ignoring: %m", ifname);
                c->ifindex = 0;
                return 0;
        }

        log_debug("Using previously pinned interface '%s' (ifindex: %i).", ifname, c->ifindex);
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

        /* If we don't know yet on which network interface the IMDS server can be found, let's spawn separate
         * instances of ourselves, one for each interface, and collect the results. We communicate with
         * each one via Varlink, the same way as clients talk to us. */

        context_log(c, LOG_DEBUG, "Spawning child for interface '%i'.", ifindex);

        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = pin_callout_binary(LIBEXECDIR "/systemd-imdsd", &p);
        if (fd < 0)
                return context_log_errno(c, LOG_ERR, fd, "Failed to find imdsd binary: %m");

        _cleanup_strv_free_ char **argv = strv_new(
                        p,
                        "--vendor", strempty(arg_vendor),
                        "--token-url", strempty(arg_token_url),
                        "--refresh-header-name", strempty(arg_refresh_header_name),
                        "--data-url", strempty(arg_data_url),
                        "--data-url-suffix", strempty(arg_data_url_suffix),
                        "--token-header-name", strempty(arg_token_header_name),
                        "--address-ipv4", in4_addr_is_null(&arg_address_ipv4) ? "" : IN4_ADDR_TO_STRING(&arg_address_ipv4),
                        "--address-ipv6", in6_addr_is_null(&arg_address_ipv6) ? "" : IN6_ADDR_TO_STRING(&arg_address_ipv6));
        if (!argv)
                return log_oom();

        STRV_FOREACH(i, arg_extra_header)
                if (strv_extend_strv(&argv, STRV_MAKE("--extra-header", *i), /* filter_duplicates= */ false) < 0)
                        return log_oom();

        for (ImdsWellKnown wk = 0; wk < _IMDS_WELL_KNOWN_MAX; wk++) {
                if (!arg_well_known_key[wk])
                        continue;

                if (strv_extendf(&argv, "--well-known-key=%s:%s", imds_well_known_to_string(wk), arg_well_known_key[wk]) < 0)
                        return log_oom();
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmdline = quote_command_line(argv, SHELL_ESCAPE_EMPTY);
                log_debug("About to fork off: %s", strnull(cmdline));
        }

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_exec(&vl, p, argv);
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
                        SD_JSON_BUILD_PAIR_BOOLEAN("cache", c->cache),
                        SD_JSON_BUILD_PAIR_CONDITION(c->fwmark_set, "firewallMark", SD_JSON_BUILD_UNSIGNED(c->fwmark)),
                        SD_JSON_BUILD_PAIR_CONDITION(!c->fwmark_set, "firewallMark", SD_JSON_BUILD_NULL)); /* explicitly turn off fwmark, if not set */
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to issue Get() command to Varlink child: %m");

        *ret = TAKE_PTR(vl);
        return 0;
}

static int context_spawn_new_child(Context *c, int ifindex) {
        int r;

        assert(c);

        /* Spawn a child, and keep track of it */

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
                context_log(c, LOG_DEBUG, "Child for network interface %i already spawned off, scheduling for immediate retry.", ifindex);
                existing->retry = true;
                return 0;
        }

        return context_spawn_new_child(c, ifindex);
}

static int context_acquire_rtnl_with_match(Context *c) {
        int r;

        assert(c);
        assert(c->event);

        /* Acquire a netlink connection and a match if we don't have one yet */

        if (!c->rtnl) {
                r = sd_netlink_open(&c->rtnl);
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to connect to netlink: %m");
        }

        if (!c->rtnl_attached) {
                /* The netlink connection might have created previously via rtnl_resolve_interface() – which
                 * however didn't attach it to our event loop. Do so now. */
                r = sd_netlink_attach_event(c->rtnl, c->event, SD_EVENT_PRIORITY_NORMAL);
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to attach netlink socket to event loop: %m");

                c->rtnl_attached = true;
        }

        if (!c->address_change_slot) {
                r = sd_netlink_add_match(c->rtnl, &c->address_change_slot, RTM_NEWADDR, on_address_change, /* destroy_callback= */ NULL, c, "newaddr");
                if (r < 0)
                        return context_log_errno(c, LOG_ERR, r, "Failed to subscribe to RTM_NEWADDR events: %m");
        }

        return 0;
}

static int context_spawn_children(Context *c) {
        int r;

        assert(c);
        assert(c->key || c->well_known >= 0);

        /* If we don't know yet on which interface to query, let's see which interfaces there are and spawn
         * ourselves, once on each */

        r = context_acquire_rtnl_with_match(c);
        if (r < 0)
                return r;

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        r = sd_rtnl_message_new_addr(c->rtnl, &req, RTM_GETADDR, /* ifindex= */ 0, AF_UNSPEC);
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

static int imds_configured(int level) {
        /* Checks if we have enough endpoint information to operate */

        if (arg_endpoint_source < 0)
                return log_full_errno(level, SYNTHETIC_ERRNO(EOPNOTSUPP), "No IMDS endpoint information provided or detected, cannot operate.");

        if (!arg_data_url)
                return log_full_errno(level, SYNTHETIC_ERRNO(EOPNOTSUPP), "No data base URL provided.");

        if (!!arg_token_url != !!arg_token_header_name)
                return log_full_errno(level, SYNTHETIC_ERRNO(EOPNOTSUPP), "Incomplete token parameters configured for endpoint.");

        return 0;
}

static int setup_network(void) {
        int r;

        /* Generates a .network file based on the IMDS endpoint information we have */

        if (arg_network_mode == IMDS_NETWORK_OFF) {
                log_debug("IMDS networking turned off, not generating .network file.");
                return 0;
        }

        _cleanup_close_ int network_dir_fd = -EBADF;
        r = chase("/run/systemd/network",
                  /* root= */ NULL,
                  CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                  /* ret_path= */ NULL,
                  &network_dir_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open .network directory: %m");

        _cleanup_free_ char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable_at(network_dir_fd, "85-imds-early.network", O_WRONLY|O_CLOEXEC, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create 85-imds-early.network file: %m");

        CLEANUP_TMPFILE_AT(network_dir_fd, t);

        fputs("# Generated by systemd-imdsd, do not edit.\n"
              "#\n"
              "# This configures Ethernet devices on cloud hosts that support IMDS, given that\n"
              "# before doing IMDS we need to activate the network.\n", f);

        if (arg_network_mode != IMDS_NETWORK_UNLOCKED &&
            (in4_addr_is_set(&arg_address_ipv4) || in6_addr_is_set(&arg_address_ipv6)))
                fputs("#\n"
                      "# Note: this will create a 'prohibit' route to the IMDS endpoint,\n"
                      "# blocking direct access to IMDS. Direct IMDS access is then only\n"
                      "# available to traffic marked with fwmark 0x7FFF0815, which can be\n"
                      "# set via SO_MARK and various other methods, which require\n"
                      "# privileges.\n",
                      f);

        fputs("\n"
              "[Match]\n"
              "Type=ether\n"
              "Kind=!*\n"
              "\n"
              "[Network]\n"
              "DHCP=yes\n"
              "LinkLocalAddressing=ipv6\n"
              "\n"
              "[DHCP]\n"
              "UseTimezone=yes\n"
              "UseHostname=yes\n"
              "UseMTU=yes\n", f);

        if (in4_addr_is_set(&arg_address_ipv4))
                fputs("\n"
                      "[Link]\n"
                      "RequiredFamilyForOnline=ipv4\n", f);
        else if (in6_addr_is_set(&arg_address_ipv6))
                fputs("\n"
                      "[Link]\n"
                      "RequiredFamilyForOnline=ipv6\n", f);

        if (arg_network_mode != IMDS_NETWORK_UNLOCKED) {
                if (in4_addr_is_set(&arg_address_ipv4))
                        fprintf(f,
                                "\n"
                                "# Prohibit regular access to IMDS (IPv4)\n"
                                "[Route]\n"
                                "Destination=%s\n"
                                "Type=prohibit\n",
                                IN4_ADDR_TO_STRING(&arg_address_ipv4));

                if (in6_addr_is_set(&arg_address_ipv6))
                        fprintf(f,
                                "\n"
                                "# Prohibit regular access to IMDS (IPv6)\n"
                                "[Route]\n"
                                "Destination=%s\n"
                                "Type=prohibit\n",
                                IN6_ADDR_TO_STRING(&arg_address_ipv6));
        }

        if (in4_addr_is_set(&arg_address_ipv4))
                fprintf(f,
                        "\n"
                        "# Always allow IMDS access via a special routing table (IPv4)\n"
                        "[Route]\n"
                        "Destination=%s\n"
                        "Scope=link\n"
                        "Table=0x7FFF0815\n"
                        "\n"
                        "# Sockets marked with firewall mark 0x7FFF0815 get access to the IMDS route by\n"
                        "# using the 0x7FFF0815 table populated above.\n"
                        "[RoutingPolicyRule]\n"
                        "Family=ipv4\n"
                        "FirewallMark=0x7FFF0815\n"
                        "Table=0x7FFF0815\n",
                        IN4_ADDR_TO_STRING(&arg_address_ipv4));

        if (in6_addr_is_set(&arg_address_ipv6))
                fprintf(f,
                        "\n"
                        "# Always allow IMDS access via a special routing table (IPv6)\n"
                        "[Route]\n"
                        "Destination=%s\n"
                        "Table=0x7FFF0815\n"
                        "\n"
                        "# Sockets marked with firewall mark 0x7FFF0815 get access to the IMDS route by\n"
                        "# using the 0x7FFF0815 table populated above.\n"
                        "[RoutingPolicyRule]\n"
                        "Family=ipv6\n"
                        "FirewallMark=0x7FFF0815\n"
                        "Table=0x7FFF0815\n",
                        IN6_ADDR_TO_STRING(&arg_address_ipv6));

        if (fchmod(fileno(f), 0644) < 0)
                return log_error_errno(errno, "Failed to set access mode for 85-imds-early.network: %m");

        r = flink_tmpfile_at(f, network_dir_fd, t, "85-imds-early.network", LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move 85-imds-early.network into place: %m");

        t = mfree(t); /* disarm auto-cleanup */

        log_info("Created 85-imds-early.network.");
        return 0;
}

static int add_address_to_json_array(sd_json_variant **array, int family, const union in_addr_union *addr) {
        int r;

        assert(array);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(addr);

        /* Appends the specified IP address, turned into A/AAAA RRs to the specified JSON array */

        if (in_addr_is_null(family, addr))
                return 0;

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        if (dns_resource_record_new_address(&rr, family, addr, "_imds") < 0)
                return log_oom();

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *rrj = NULL;
        r = dns_resource_record_to_json(rr, &rrj);
        if (r < 0)
                return log_error_errno(r, "Failed to convert A RR to JSON: %m");

        r = sd_json_variant_append_array(array, rrj);
        if (r < 0)
                return log_error_errno(r, "Failed to append A RR to JSON array: %m");

        log_debug("Writing IMDS RR for: %s", dns_resource_record_to_string(rr));
        return 1;
}

static int setup_address_rrs(void) {
        int r;

        /* Creates local RRs (honoured by systemd-resolved) for the IMDS endpoint addresses. */

        if (arg_network_mode == IMDS_NETWORK_OFF) {
                log_debug("IMDS networking turned off, not generating .rr file.");
                return 0;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *aj = NULL;

        union in_addr_union u = { .in = arg_address_ipv4 };
        r = add_address_to_json_array(&aj, AF_INET, &u);
        if (r < 0)
                return r;

        u = (union in_addr_union) { .in6 = arg_address_ipv6 };
        r = add_address_to_json_array(&aj, AF_INET6, &u);
        if (r < 0)
                return r;

        if (sd_json_variant_elements(aj) == 0) {
                log_debug("No IMDS endpoint addresses known, not writing out RRs.");
                return 0;
        }

        _cleanup_free_ char *text = NULL;
        r = sd_json_variant_format(aj, SD_JSON_FORMAT_NEWLINE, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON text: %m");

        r = write_string_file("/run/systemd/resolve/static.d/imds-endpoint.rr", text, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write IMDS RR data: %m");

        log_info("Created imds-endpoint.rr.");
        return 0;
}

static int on_overall_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        assert(s);

        /* Invoked whenever the overall time-out event elapses, and we just give up */

        context_fail_full(c, context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(ETIMEDOUT), "Overall timeout reached."), "io.systemd.InstanceMetadata.Timeout");
        return 0;
}

static int context_start_overall_timeout(Context *c, usec_t usec) {
        int r;

        assert(c);

        r = event_reset_time_relative(
                        c->event,
                        &c->overall_timeout_source,
                        CLOCK_BOOTTIME,
                        usec,
                        /* accuracy= */ 0,
                        on_overall_timeout,
                        c,
                        /* priority= */ 0,
                        "imds-overall-timeout",
                        /* force_reset= */ true);
        if (r < 0)
                return context_log_errno(c, LOG_ERR, r, "Failed to reset retry timer event source: %m");

        return 0;
}

static int cmdline_run(void) {
        int r;

        /* Process the request when invoked via the command line (i.e. not via Varlink) */

        r = imds_configured(LOG_ERR);
        if (r < 0)
                return r;

        if (arg_setup_network) {
                r = setup_network();
                return RET_GATHER(r, setup_address_rrs());
        }

        assert(arg_key || arg_well_known >= 0);

        _cleanup_(context_done) Context c = CONTEXT_NULL;
        c.write_stdout = true;
        context_new_request(&c);

        c.well_known = arg_well_known;
        if (arg_key) {
                c.key = strdup(arg_key);
                if (!c.key)
                        return context_log_oom(&c);
        }

        if (arg_ifname) {
                c.ifindex = rtnl_resolve_interface_or_warn(&c.rtnl, arg_ifname);
                if (c.ifindex < 0)
                        return c.ifindex;
        } else {
                /* Try to load the previously cached interface */
                r = context_load_ifname(&c);
                if (r < 0)
                        return r;
        }

        r = sd_event_default(&c.event);
        if (r < 0)
                return context_log_errno(&c, LOG_ERR, r, "Failed to allocate event loop: %m");

        if (c.ifindex > 0) {
                CacheResult cr = context_process_cache(&c);
                if (cr < 0)
                        return cr;
                if (cr == CACHE_RESULT_HIT)
                        return 0;
                if (cr == CACHE_RESULT_KEY_NOT_FOUND)
                        return context_log_errno(&c, LOG_ERR, SYNTHETIC_ERRNO(ENOENT), "Cache reports: key not found");

                r = context_acquire_token(&c);
                if (r < 0)
                        return r;

                r = context_acquire_data(&c);
                if (r < 0)
                        return r;

                r = context_start_overall_timeout(&c, DIRECT_OVERALL_TIMEOUT_USEC);
                if (r < 0)
                        return r;
        } else {
                /* Couldn't find anything, let's spawn off parallel clients for all interfaces */
                r = context_spawn_children(&c);
                if (r < 0)
                        return r;

                r = context_start_overall_timeout(&c, INDIRECT_OVERALL_TIMEOUT_USEC);
                if (r < 0)
                        return r;
        }

        r = sd_event_loop(c.event);
        if (r < 0)
                return r;

        return 0;
}

static int context_acquire_system_bus(Context *c) {
        int r;

        assert(c);

        /* Connect to the bus if we haven't yet */

        if (c->system_bus)
                return 0;

        r = sd_bus_default_system(&c->system_bus);
        if (r < 0)
                return r;

        r = sd_bus_attach_event(c->system_bus, c->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_well_known, ImdsWellKnown, imds_well_known_from_string);

static int dispatch_fwmark(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        /* Parses a firewall mark passed via Varlink/JSON. Note that any 32bit fwmark is valid, hence we keep
         * track if it is set or not in a separate boolean. */

        if (sd_json_variant_is_null(variant)) {
                c->fwmark_set = false;
                return 0;
        }

        r = sd_json_dispatch_uint32(name, variant, flags, &c->fwmark);
        if (r < 0)
                return r;

        c->fwmark_set = true;
        return 0;
}

static int vl_method_get(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);

        if (!c->event)
                c->event = sd_event_ref(sd_varlink_get_event(link));

        context_new_request(c);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "wellKnown",    SD_JSON_VARIANT_STRING,        dispatch_well_known,      offsetof(Context, well_known),   0 },
                { "key",          SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,  offsetof(Context, key),          0 },
                { "interface",    _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,    offsetof(Context, ifindex),      0 },
                { "refreshUSec",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,  offsetof(Context, refresh_usec), 0 },
                { "firewallMark", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_fwmark,          0,                               0 },
                { "cache",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(Context, cache),        0 },
                { "wait",         SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(Context, wait),         0 },
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

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        if (peer_uid != 0 && peer_uid != getuid()) {
                /* Ask polkit if client is not privileged */

                r = context_acquire_system_bus(c);
                if (r < 0)
                        return r;

                const char* l[5];
                size_t k = 0;
                if (c->well_known >= 0) {
                        l[k++] = "wellKnown";
                        l[k++] = imds_well_known_to_string(c->well_known);
                }
                if (c->key) {
                        l[k++] = "key";
                        l[k++] = c->key;
                }
                l[k] = NULL;

                r = varlink_verify_polkit_async(
                                link,
                                c->system_bus,
                                "io.systemd.imds.get",
                                l,
                                &c->polkit_registry);
                if (r <= 0)
                        return r;
        }

        if (imds_configured(LOG_DEBUG) < 0)
                return sd_varlink_error(link, "io.systemd.InstanceMetadata.NotSupported", NULL);

        /* Up to this point we only validated/parsed stuff. Now we actually execute stuff, hence from now on
         * we need to go through context_fail() when failing (context_success() if we succeed early), to
         * release resources we might have allocated. */
        assert(!c->current_link);
        c->current_link = sd_varlink_ref(link);

        _cleanup_free_ char *k = NULL; /* initialize here, to avoid that this remains uninitialized due to the gotos below */

        if (c->ifindex <= 0) {
                /* Try to load the previously used network interface */
                r = context_load_ifname(c);
                if (r < 0)
                        goto fail;
        }

        r = context_combine_key(c, &k);
        if (r == -ENODATA) {
                context_fail_full(c, r, "io.systemd.InstanceMetadata.WellKnownKeyUnset");
                return r;
        }
        if (r < 0)
                goto fail;

        context_log(c, LOG_DEBUG, "Will request '%s' now.", k);

        if (c->ifindex > 0) {
                CacheResult cr = context_process_cache(c);
                if (cr < 0) {
                        r = cr;
                        goto fail;
                }
                if (cr == CACHE_RESULT_HIT) {
                        context_success(c);
                        return 0;
                }
                if (cr == CACHE_RESULT_KEY_NOT_FOUND) {
                        r = context_log_errno(c, LOG_ERR, SYNTHETIC_ERRNO(ENOENT), "Cache reports: key not found");
                        context_fail_full(c, r, "io.systemd.InstanceMetadata.KeyNotFound");
                        return r;
                }

                r = context_acquire_token(c);
                if (r < 0)
                        goto fail;

                r = context_acquire_data(c);
                if (r < 0)
                        goto fail;

                r = context_start_overall_timeout(c, DIRECT_OVERALL_TIMEOUT_USEC);
                if (r < 0)
                        goto fail;
        } else {
                r = context_spawn_children(c);
                if (r < 0)
                        goto fail;

                r = context_start_overall_timeout(c, INDIRECT_OVERALL_TIMEOUT_USEC);
                if (r < 0)
                        goto fail;
        }

        context_log(c, LOG_DEBUG, "Incoming method call is now pending");
        return 1;

fail:
        context_fail(c, r);
        return r;
}

static int vl_method_get_vendor_info(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, c);
        if (r != 0)
                return r;

        /* NB! We allow access to this call without Polkit */

        if (imds_configured(LOG_DEBUG) < 0)
                return sd_varlink_error(link, "io.systemd.InstanceMetadata.NotSupported", NULL);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *wkj = NULL;
        for (ImdsWellKnown i = 0; i < _IMDS_WELL_KNOWN_MAX; i++) {
                if (!arg_well_known_key[i])
                        continue;

                r = sd_json_variant_set_field_string(&wkj, imds_well_known_to_string(i), arg_well_known_key[i]);
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
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("wellKnown", wkj));
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
        _cleanup_(table_unrefp) Table *options = NULL, *endpoint_options = NULL;
        int r;

        r = terminal_urlify_man("systemd-imdsd@.service", "8", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_group("Manual Endpoint Configuration", &endpoint_options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, options, endpoint_options);

        printf("%1$s [OPTIONS...] KEY\n"
               "\n%2$sLow-level IMDS data acquisition.%3$s\n"
               "\n%4$sOptions:%5$s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\n%sManual Endpoint Configuration:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(endpoint_options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static bool http_header_name_valid(const char *a) {
        return a && ascii_is_valid(a) && !string_has_cc(a, /* ok= */ NULL) && !strchr(a, ':');
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('i', "interface", "INTERFACE", "Use the specified interface"):
                        if (isempty(opts.arg)) {
                                arg_ifname = mfree(arg_ifname);
                                break;
                        }

                        if (!ifname_valid_full(opts.arg, IFNAME_VALID_ALTERNATIVE|IFNAME_VALID_NUMERIC))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Interface name '%s' is not valid.", opts.arg);

                        r = free_and_strdup_warn(&arg_ifname, opts.arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("refresh", "SEC", "Set token refresh time"): {
                        if (isempty(opts.arg)) {
                                arg_refresh_usec = REFRESH_USEC_DEFAULT;
                                break;
                        }

                        usec_t t;
                        r = parse_sec(opts.arg, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse refresh timeout: %s", opts.arg);
                        if (t < REFRESH_USEC_MIN) {
                                log_warning("Increasing specified refresh time to %s, lower values are not supported.", FORMAT_TIMESPAN(REFRESH_USEC_MIN, 0));
                                arg_refresh_usec = REFRESH_USEC_MIN;
                        } else
                                arg_refresh_usec = t;
                        break;
                }

                OPTION_LONG("fwmark", "INTEGER", "Choose firewall mark for HTTP traffic"):
                        if (isempty(opts.arg)) {
                                arg_fwmark_set = false;
                                break;
                        }

                        if (streq(opts.arg, "default")) {
                                arg_fwmark = FWMARK_DEFAULT;
                                arg_fwmark_set = true;
                                break;
                        }

                        r = safe_atou32(opts.arg, &arg_fwmark);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse --fwmark= parameter: %s", opts.arg);

                        arg_fwmark_set = true;
                        break;

                OPTION_LONG("cache", "BOOL", "Enable/disable cache use"):
                        r = parse_boolean_argument("--cache", opts.arg, &arg_cache);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("wait", "BOOL", "Whether to wait for connectivity"):
                        r = parse_boolean_argument("--wait", opts.arg, &arg_wait);
                        if (r < 0)
                                return r;
                        break;

                OPTION_SHORT('w', NULL, "Same as --wait=yes"):
                        arg_wait = true;
                        break;

                OPTION('K', "well-known", "KEY", "Select well-known key"): {
                        if (isempty(opts.arg)) {
                                arg_well_known = _IMDS_WELL_KNOWN_INVALID;
                                break;
                        }

                        ImdsWellKnown wk = imds_well_known_from_string(opts.arg);
                        if (wk < 0)
                                return log_error_errno(wk, "Failed to parse --well-known= parameter: %m");

                        arg_well_known = wk;
                        break;
                }

                OPTION_LONG("setup-network", NULL, "Generate .network and .rr files"):
                        arg_setup_network = true;
                        break;

                /* The following all configure endpoint information explicitly */
                OPTION_GROUP("Manual Endpoint Configuration"): {}

                OPTION_LONG("vendor", "VENDOR", "Specify IMDS vendor literally"):
                        if (isempty(opts.arg)) {
                                arg_vendor = mfree(arg_vendor);
                                break;
                        }

                        r = free_and_strdup_warn(&arg_vendor, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("token-url", "URL", "URL for acquiring token"):
                        if (isempty(opts.arg)) {
                                arg_token_url = mfree(arg_token_url);
                                break;
                        }

                        if (!http_url_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid URL: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_token_url, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("refresh-header-name", "NAME", "Header name for passing refresh time"):
                        if (isempty(opts.arg)) {
                                arg_refresh_header_name = mfree(arg_refresh_header_name);
                                break;
                        }

                        if (!http_header_name_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP header name: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_refresh_header_name, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("data-url", "URL", "Base URL for acquiring data"):
                        if (isempty(opts.arg)) {
                                arg_data_url = mfree(arg_data_url);
                                break;
                        }

                        if (!http_url_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid URL: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_data_url, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("data-url-suffix", "STRING", "Suffix to append to data URL"):
                        if (isempty(opts.arg)) {
                                arg_data_url_suffix = mfree(arg_data_url_suffix);
                                break;
                        }

                        if (!ascii_is_valid(opts.arg) || string_has_cc(opts.arg, /* ok= */ NULL))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid URL suffix: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_data_url_suffix, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("token-header-name", "NAME", "Header name for passing token string"):
                        if (isempty(opts.arg)) {
                                arg_token_header_name = mfree(arg_token_header_name);
                                break;
                        }

                        if (!http_header_name_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP header name: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_token_header_name, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("extra-header", "NAME: VALUE", "Additional header to pass to data transfer"):
                        if (isempty(opts.arg)) {
                                arg_extra_header = strv_free(arg_extra_header);
                                break;
                        }

                        if (!http_header_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP header: %s", opts.arg);

                        if (strv_extend(&arg_extra_header, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("address-ipv4", "ADDRESS", "Configure IPv4 address of the IMDS server"): {
                        if (isempty(opts.arg)) {
                                arg_address_ipv4 = (struct in_addr) {};
                                break;
                        }

                        union in_addr_union u;
                        r = in_addr_from_string(AF_INET, opts.arg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse IPv4 address: %s", opts.arg);
                        arg_address_ipv4 = u.in;
                        break;
                }

                OPTION_LONG("address-ipv6", "ADDRESS", "Configure IPv6 address of the IMDS server"): {
                        if (isempty(opts.arg)) {
                                arg_address_ipv6 = (struct in6_addr) {};
                                break;
                        }

                        union in_addr_union u;
                        r = in_addr_from_string(AF_INET6, opts.arg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse IPv6 address: %s", opts.arg);
                        arg_address_ipv6 = u.in6;
                        break;
                }

                OPTION_LONG("well-known-key", "NAME:KEY", "Configure the location of well-known keys"): {
                        if (isempty(opts.arg)) {
                                for (ImdsWellKnown wk = 0; wk < _IMDS_WELL_KNOWN_MAX; wk++)
                                        arg_well_known_key[wk] = mfree(arg_well_known_key[wk]);
                                break;
                        }

                        const char *e = strchr(opts.arg, ':');
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--well-known-key= expects colon separated name and key pairs.");

                        _cleanup_free_ char *name = strndup(opts.arg, e - opts.arg);
                        if (!name)
                                return log_oom();

                        ImdsWellKnown wk = imds_well_known_from_string(name);
                        if (wk < 0)
                                return log_error_errno(wk, "Failed to parse --well-known-key= argument: %m");

                        e++;
                        if (!imds_key_is_valid(e))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Well known key '%s' is not valid.", e);

                        r = free_and_strdup_warn(arg_well_known_key + wk, e);
                        if (r < 0)
                                return r;
                        break;
                }
                }

        if (arg_vendor || arg_token_url || arg_refresh_header_name || arg_data_url || arg_data_url_suffix || arg_token_header_name || arg_extra_header)
                arg_endpoint_source = ENDPOINT_USER;

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");

        arg_varlink = r;

        if (!arg_varlink) {
                char **args = option_parser_get_args(&opts);
                size_t n_args = option_parser_get_n_args(&opts);

                if (arg_setup_network) {
                        if (n_args != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No argument expected.");
                } else {
                        if (arg_well_known < 0) {
                                /* if no --well-known= parameter was specified we require an argument */
                                if (n_args != 1)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "A single argument expected.");
                        } else if (n_args > 1) /* if not, then the additional parameter is optional */
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "At most a single argument expected.");

                        if (n_args > 0) {
                                if (!imds_key_is_valid(args[0]))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified IMDS key is not valid, refusing: %s", args[0]);

                                r = free_and_strdup_warn(&arg_key, args[0]);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 1;
}

static int device_get_property_ip_address(
                sd_device *d,
                const char *name,
                int family,
                union in_addr_union *ret) {

        int r;

        /* Parses an IP address stored in the udev database for a device */

        assert(d);
        assert(name);
        assert(IN_SET(family, AF_INET, AF_INET6));

        const char *v = NULL;
        r = sd_device_get_property_value(d, name, &v);
        if (r < 0)
                return r;

        return in_addr_from_string(family, v, ret);
}

static const char * const imds_well_known_udev_table[_IMDS_WELL_KNOWN_MAX] = {
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

        /* Acquires IMDS server information from udev/hwdb */

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
                return log_error_errno(r, "Failed to read IMDS_VENDOR= property of DMI device: %m");

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

        union in_addr_union u;
        r = device_get_property_ip_address(d, "IMDS_ADDRESS_IPV4", AF_INET, &u);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read property 'IMDS_ADDRESS_IPV4' of DMI: %m");
        else if (r >= 0)
                arg_address_ipv4 = u.in;

        r = device_get_property_ip_address(d, "IMDS_ADDRESS_IPV6", AF_INET6, &u);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read property 'IMDS_ADDRESS_IPV6' of DMI: %m");
        else if (r >= 0)
                arg_address_ipv6 = u.in6;

        for (ImdsWellKnown k = 0; k < _IMDS_WELL_KNOWN_MAX; k++) {
                const char *p = imds_well_known_udev_to_string(k);
                if (!p)
                        continue;

                const char *v = NULL;
                r = sd_device_get_property_value(d, p, &v);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read property '%s' of DMI: %m", p);

                r = free_and_strdup_warn(arg_well_known_key + k, v);
                if (r < 0)
                        return r;
        }

        log_debug("IMDS endpoint data set from SMBIOS device.");
        arg_endpoint_source = ENDPOINT_UDEV;
        return 0;
}

static int secure_getenv_ip_address(
                const char *name,
                int family,
                union in_addr_union *ret) {

        assert(name);
        assert(IN_SET(family, AF_INET, AF_INET6));

        /* Parses an IP address specified in an environment variable */

        const char *e = secure_getenv(name);
        if (!e)
                return -ENXIO;

        return in_addr_from_string(family, e, ret);
}

static const char * const imds_well_known_environment_table[_IMDS_WELL_KNOWN_MAX] = {
        [IMDS_HOSTNAME]        = "SYSTEMD_IMDS_KEY_HOSTNAME",
        [IMDS_REGION]          = "SYSTEMD_IMDS_KEY_REGION",
        [IMDS_ZONE]            = "SYSTEMD_IMDS_KEY_ZONE",
        [IMDS_IPV4_PUBLIC]     = "SYSTEMD_IMDS_KEY_IPV4_PUBLIC",
        [IMDS_IPV6_PUBLIC]     = "SYSTEMD_IMDS_KEY_IPV6_PUBLIC",
        [IMDS_SSH_KEY]         = "SYSTEMD_IMDS_KEY_SSH_KEY",
        [IMDS_USERDATA]        = "SYSTEMD_IMDS_KEY_USERDATA",
        [IMDS_USERDATA_BASE]   = "SYSTEMD_IMDS_KEY_USERDATA_BASE",
        [IMDS_USERDATA_BASE64] = "SYSTEMD_IMDS_KEY_USERDATA_BASE64",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(imds_well_known_environment, ImdsWellKnown);

static int environment_server_info(void) {
        int r;

        /* Acquires IMDS endpoint info from environment variables */

        if (arg_endpoint_source >= 0)
                return 0;

        static const struct {
                const char *name;
                char **variable;
        } table[] = {
                { "SYSTEMD_IMDS_VENDOR",              &arg_vendor              },
                { "SYSTEMD_IMDS_TOKEN_URL",           &arg_token_url           },
                { "SYSTEMD_IMDS_REFRESH_HEADER_NAME", &arg_refresh_header_name },
                { "SYSTEMD_IMDS_DATA_URL",            &arg_data_url            },
                { "SYSTEMD_IMDS_DATA_URL_SUFFIX",     &arg_data_url_suffix     },
                { "SYSTEMD_IMDS_TOKEN_HEADER_NAME",   &arg_token_header_name   },
        };

        FOREACH_ELEMENT(i, table) {
                const char *e = secure_getenv(i->name);
                if (!e)
                        continue;

                r = free_and_strdup_warn(i->variable, e);
                if (r < 0)
                        return r;

                arg_endpoint_source = ENDPOINT_ENVIRONMENT;
        }

        for (unsigned u = 1; u < 64; u++) {
                _cleanup_free_ char *name = NULL;

                if (u > 1 && asprintf(&name, "SYSTEMD_IMDS_EXTRA_HEADER%u", u) < 0)
                        return log_oom();

                const char *e = secure_getenv(name ?: "SYSTEMD_IMDS_EXTRA_HEADER");
                if (!e)
                        break;

                if (strv_extend(&arg_extra_header, e) < 0)
                        return log_oom();

                arg_endpoint_source = ENDPOINT_ENVIRONMENT;
        }

        union in_addr_union u;
        r = secure_getenv_ip_address("SYSTEMD_IMDS_ADDRESS_IPV4", AF_INET, &u);
        if (r < 0 && r != -ENXIO)
                return log_error_errno(r, "Failed read IPv4 address from environment variable 'SYSTEMD_IMDS_ADDRESS_IPV4': %m");
        if (r >= 0) {
                arg_address_ipv4 = u.in;
                arg_endpoint_source = ENDPOINT_ENVIRONMENT;
        }

        r = secure_getenv_ip_address("SYSTEMD_IMDS_ADDRESS_IPV6", AF_INET6, &u);
        if (r < 0 && r != -ENXIO)
                return log_error_errno(r, "Failed read IPv6 address from environment variable 'SYSTEMD_IMDS_ADDRESS_IPV6': %m");
        if (r >= 0) {
                arg_address_ipv6 = u.in6;
                arg_endpoint_source = ENDPOINT_ENVIRONMENT;
        }

        for (ImdsWellKnown k = 0; k < _IMDS_WELL_KNOWN_MAX; k++) {
                const char *n = imds_well_known_environment_to_string(k);
                if (!n)
                        continue;

                const char *e = secure_getenv(n);
                if (!e)
                        continue;

                r = free_and_strdup_warn(arg_well_known_key + k, e);
                if (r < 0)
                        return r;

                arg_endpoint_source = ENDPOINT_ENVIRONMENT;
        }

        if (arg_endpoint_source >= 0)
                log_debug("IMDS endpoint data set from environment.");

        return 0;
}

static int read_credential_ip_address(
                const char *name,
                int family,
                union in_addr_union *ret) {

        int r;

        assert(name);
        assert(IN_SET(family, AF_INET, AF_INET6));

        /* Parses an IP address specified in a credential */

        _cleanup_free_ char *s = NULL;
        r = read_credential(name, (void**) &s, /* ret_size= */ NULL);
        if (r < 0)
                return r;

        return in_addr_from_string(family, s, ret);
}

static const char * const imds_well_known_credential_table[_IMDS_WELL_KNOWN_MAX] = {
        [IMDS_HOSTNAME]        = "imds.key_hostname",
        [IMDS_REGION]          = "imds.key_region",
        [IMDS_ZONE]            = "imds.key_zone",
        [IMDS_IPV4_PUBLIC]     = "imds.key_ipv4_public",
        [IMDS_IPV6_PUBLIC]     = "imds.key_ipv6_public",
        [IMDS_SSH_KEY]         = "imds.key_ssh_key",
        [IMDS_USERDATA]        = "imds.key_userdata",
        [IMDS_USERDATA_BASE]   = "imds.key_userdata_base",
        [IMDS_USERDATA_BASE64] = "imds.key_userdata_base64",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(imds_well_known_credential, ImdsWellKnown);

static int credential_server_info(void) {
        int r;

        /* Acquires IMDS endpoint info from credentials */

        if (arg_endpoint_source >= 0)
                return 0;

        static const struct {
                const char *name;
                char **variable;
        } table[] = {
                { "imds.vendor",              &arg_vendor              },
                { "imds.vendor_token",        &arg_token_url           },
                { "imds.refresh_header_name", &arg_refresh_header_name },
                { "imds.data_url",            &arg_data_url            },
                { "imds.data_url_suffix",     &arg_data_url_suffix     },
                { "imds.token_header_name",   &arg_token_header_name   },
        };

        FOREACH_ELEMENT(i, table) {
                _cleanup_free_ char *s = NULL;

                r = read_credential(i->name, (void**) &s, /* ret_size= */ NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read credential '%s', ignoring: %m", i->name);
                        continue;
                }

                r = free_and_strdup_warn(i->variable, s);
                if (r < 0)
                        return r;

                arg_endpoint_source = ENDPOINT_CREDENTIALS;
        }

        for (unsigned u = 1; u < 64; u++) {
                _cleanup_free_ char *name = NULL;
                if (u > 1 && asprintf(&name, "imds.extra_header%u", u) < 0)
                        return log_oom();

                const char *n = name ?: "imds.extra_header";

                _cleanup_free_ char *s = NULL;
                r = read_credential(n, (void**) &s, /* ret_size= */ NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read credential '%s', ignoring: %m", n);
                        continue;
                }

                if (strv_extend(&arg_extra_header, s) < 0)
                        return log_oom();

                arg_endpoint_source = ENDPOINT_CREDENTIALS;
        }

        union in_addr_union u;
        r = read_credential_ip_address("imds.address_ipv4", AF_INET, &u);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed read IPv4 address from credential 'imds.address_ipv4', ignoring: %m");
        if (r >= 0) {
                arg_address_ipv4 = u.in;
                arg_endpoint_source = ENDPOINT_CREDENTIALS;
        }

        r = read_credential_ip_address("imds.address_ipv6", AF_INET6, &u);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed read IPv6 address from credential 'imds.address_ipv6', ignoring: %m");
        if (r >= 0) {
                arg_address_ipv6 = u.in6;
                arg_endpoint_source = ENDPOINT_CREDENTIALS;
        }

        for (ImdsWellKnown k = 0; k < _IMDS_WELL_KNOWN_MAX; k++) {
                const char *n = imds_well_known_credential_to_string(k);
                if (!n)
                        continue;

                _cleanup_free_ char *s = NULL;
                r = read_credential(n, (void**) &s, /* ret_size= */ NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read credential '%s', ignoring: %m", n);
                        continue;
                }

                free_and_replace(arg_well_known_key[k], s);
                arg_endpoint_source = ENDPOINT_CREDENTIALS;
        }

        if (arg_endpoint_source >= 0)
                log_debug("IMDS endpoint data set from credentials.");

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        /* Called for each kernel command line option. */

        if (proc_cmdline_key_streq(key, "systemd.imds.network")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                ImdsNetworkMode m = imds_network_mode_from_string(value);
                if (m < 0)
                        return log_warning_errno(m, "Failed to parse systemd.imds.network= value: %m");

                arg_network_mode = m;
                return 0;
        }

        /* The other kernel command line options configured IMDS endpoint data. We'll only check it if no
         * other configuration source for it has been used */
        if (arg_endpoint_source >= 0 && arg_endpoint_source != ENDPOINT_PROC_CMDLINE)
                return 0;

        static const struct {
                const char *key;
                char **variable;
        } table[] = {
                { "systemd.imds.vendor",              &arg_vendor              },
                { "systemd.imds.token_url",           &arg_token_url           },
                { "systemd.imds.refresh_header_name", &arg_refresh_header_name },
                { "systemd.imds.data_url",            &arg_data_url            },
                { "systemd.imds.data_url_suffix",     &arg_data_url_suffix     },
                { "systemd.imds.token_header_name",   &arg_token_header_name   },
        };

        FOREACH_ELEMENT(i, table) {
                if (!proc_cmdline_key_streq(key, i->key))
                        continue;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup_warn(i->variable, value);
                if (r < 0)
                        return r;

                arg_endpoint_source = ENDPOINT_PROC_CMDLINE;
                return 0;
        }

        if (proc_cmdline_key_streq(key, "systemd.imds.extra_header")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (isempty(value))
                        arg_extra_header = strv_free(arg_extra_header);
                else if (strv_extend(&arg_extra_header, value) < 0)
                        return log_oom();

                arg_endpoint_source = ENDPOINT_PROC_CMDLINE;
                return 0;
        }

        if (proc_cmdline_key_streq(key, "systemd.imds.address_ipv4")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                union in_addr_union u;
                r = in_addr_from_string(AF_INET, value, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse 'systemd.imds.address_ipv4=' parameter: %s", value);

                arg_address_ipv4 = u.in;
                arg_endpoint_source = ENDPOINT_PROC_CMDLINE;
                return 0;
        }

        if (proc_cmdline_key_streq(key, "systemd.imds.address_ipv6")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                union in_addr_union u;
                r = in_addr_from_string(AF_INET6, value, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse 'systemd.imds.address_ipv6=' parameter: %s", value);

                arg_address_ipv6 = u.in6;
                arg_endpoint_source = ENDPOINT_PROC_CMDLINE;
                return 0;
        }

        static const char * const well_known_table[_IMDS_WELL_KNOWN_MAX] = {
                [IMDS_HOSTNAME]        = "systemd.imds.key.hostname",
                [IMDS_REGION]          = "systemd.imds.key.region",
                [IMDS_ZONE]            = "systemd.imds.key.zone",
                [IMDS_IPV4_PUBLIC]     = "systemd.imds.key.ipv4_public",
                [IMDS_IPV6_PUBLIC]     = "systemd.imds.key.ipv6_public",
                [IMDS_SSH_KEY]         = "systemd.imds.key.ssh_key",
                [IMDS_USERDATA]        = "systemd.imds.key.userdata",
                [IMDS_USERDATA_BASE]   = "systemd.imds.key.userdata_base",
                [IMDS_USERDATA_BASE64] = "systemd.imds.key.userdata_base64",
        };

        for (ImdsWellKnown wk = 0; wk < _IMDS_WELL_KNOWN_MAX; wk++) {
                const char *k = well_known_table[wk];
                if (!k)
                        continue;

                if (!proc_cmdline_key_streq(key, k))
                        continue;

                r = free_and_strdup_warn(arg_well_known_key + wk, value);
                if (r < 0)
                        return r;

                arg_endpoint_source = ENDPOINT_PROC_CMDLINE;
                return 0;
        }

        return 0;
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = dlopen_curl(LOG_DEBUG);
        if (r < 0)
                return r;

        r = environment_server_info();
        if (r < 0)
                return r;

        r = proc_cmdline_parse(parse_proc_cmdline_item, /* userdata= */ NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        r = credential_server_info();
        if (r < 0)
                return r;

        r = smbios_server_info();
        if (r < 0)
                return r;

        if (arg_varlink)
                return vl_server();

        return cmdline_run();
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
