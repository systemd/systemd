/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>
#include <sys/stat.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "curl-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "lock-util.h"
#include "log.h"
#include "metrics.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "path-util.h"
#include "report-geoip.h"
#include "stat-util.h"
#include "string-util.h"
#include "time-util.h"
#include "version.h"
#include "web-util.h"

#define METRIC_IO_SYSTEMD_GEOIP_PREFIX "io.systemd.GeoIP."

/* The cache lives below the service's StateDirectory= (as passed via $STATE_DIRECTORY), so that it survives
 * reboots, falling back to this path below /var/lib/ when started directly from the command line. All
 * instances of the socket activated service share it, hence access is serialized via a lock file next to it. */
#define REPORT_GEOIP_STATE_DIR_SUFFIX "systemd/report-geoip"
#define REPORT_GEOIP_CACHE_FILE_NAME "cache.json"

/* Upper bound on the size of the answer we accept from the server, and of the cache file we are willing to
 * read back. The actual answer is a couple of hundred bytes. */
#define REPORT_GEOIP_ANSWER_MAX (64U * 1024U)

/* The overall Varlink call is bounded by the client's timeout (30s for systemd-report), hence keep the
 * network timeout well below that, so that we can still fall back to the cache in time. */
#define REPORT_GEOIP_NETWORK_TIMEOUT_USEC (10 * USEC_PER_SEC)

/* Follow HTTP redirects, but only a few of them. */
#define REPORT_GEOIP_MAX_REDIRECTS 5L

typedef enum GeoIPField {
        GEOIP_FIELD_IP,
        GEOIP_FIELD_COUNTRY_CODE,
        GEOIP_FIELD_COUNTRY_NAME,
        GEOIP_FIELD_REGION_CODE,
        GEOIP_FIELD_REGION_NAME,
        GEOIP_FIELD_CITY,
        GEOIP_FIELD_ZIP_CODE,
        GEOIP_FIELD_TIME_ZONE,
        GEOIP_FIELD_LATITUDE,
        GEOIP_FIELD_LONGITUDE,
        GEOIP_FIELD_TIMESTAMP,
        _GEOIP_FIELD_MAX,
        _GEOIP_FIELD_INVALID = -EINVAL,
} GeoIPField;

typedef enum GeoIPValueType {
        GEOIP_VALUE_STRING,    /* A free-form string, reported as is */
        GEOIP_VALUE_ADDRESS,   /* An IP address, stored in parsed form and reported in normalized form */
        GEOIP_VALUE_DOUBLE,    /* A floating point number */
        GEOIP_VALUE_TIMESTAMP, /* A CLOCK_REALTIME timestamp in µs */
        _GEOIP_VALUE_TYPE_MAX,
        _GEOIP_VALUE_TYPE_INVALID = -EINVAL,
} GeoIPValueType;

/* The data we pick out of the server's JSON answer, plus when we acquired it. */
typedef struct GeoIPData {
        struct in_addr_data ip;
        char *country_code;
        char *country_name;
        char *region_code;
        char *region_name;
        char *city;
        char *zip_code;
        char *time_zone;
        double latitude;
        double longitude;
        usec_t timestamp; /* CLOCK_REALTIME, when the data was downloaded (i.e. the mtime of the cache file) */
} GeoIPData;

#define GEOIP_DATA_INIT (GeoIPData) { .ip.family = AF_UNSPEC, .latitude = NAN, .longitude = NAN, .timestamp = USEC_INFINITY }

static void geoip_data_done(GeoIPData *d) {
        assert(d);

        d->country_code = mfree(d->country_code);
        d->country_name = mfree(d->country_name);
        d->region_code = mfree(d->region_code);
        d->region_name = mfree(d->region_name);
        d->city = mfree(d->city);
        d->zip_code = mfree(d->zip_code);
        d->time_zone = mfree(d->time_zone);
}

static int geoip_data_parse(const char *text, GeoIPData *ret) {
        /* The address is parsed right here, so that only well-formed IPv4/IPv6 addresses are ever stored; a
         * malformed one is skipped rather than failing the whole answer. The coordinates are dispatched
         * without a type constraint, so that both integer and real JSON numbers are accepted. Additional
         * fields the server might return are ignored. */
        static const sd_json_dispatch_field dispatch_table[] = {
                { "ip",           _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, offsetof(GeoIPData, ip),           SD_JSON_NULLABLE },
                { "country_code", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,    offsetof(GeoIPData, country_code), SD_JSON_NULLABLE },
                { "country_name", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,    offsetof(GeoIPData, country_name), SD_JSON_NULLABLE },
                { "region_code",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,    offsetof(GeoIPData, region_code),  SD_JSON_NULLABLE },
                { "region_name",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,    offsetof(GeoIPData, region_name),  SD_JSON_NULLABLE },
                { "city",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,    offsetof(GeoIPData, city),         SD_JSON_NULLABLE },
                { "zip_code",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,    offsetof(GeoIPData, zip_code),     SD_JSON_NULLABLE },
                { "time_zone",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,    offsetof(GeoIPData, time_zone),    SD_JSON_NULLABLE },
                { "latitude",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double,    offsetof(GeoIPData, latitude),     SD_JSON_NULLABLE },
                { "longitude",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double,    offsetof(GeoIPData, longitude),    SD_JSON_NULLABLE },
                {},
        };

        int r;

        assert(text);
        assert(ret);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return r;

        _cleanup_(geoip_data_done) GeoIPData d = GEOIP_DATA_INIT;
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_PERMISSIVE|SD_JSON_LOG, &d);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(d);
        return 0;
}

static size_t write_callback(char *buf, size_t size, size_t nmemb, void *userdata) {
        struct iovec *answer = ASSERT_PTR(userdata);

        assert(size == 1); /* The docs say that this is always true. */

        if (nmemb == 0)
                return 0;

        /* The answer is accumulated in a single contiguous buffer, so that the number of chunks the server
         * delivers it in doesn't matter, only the total size does. */
        size_t new_size = size_add(answer->iov_len, nmemb);
        if (new_size > REPORT_GEOIP_ANSWER_MAX) {
                log_debug("Server answer too long (%zu > %u), refusing.", new_size, REPORT_GEOIP_ANSWER_MAX);
                return 0;
        }

        if (memchr(buf, 0, nmemb)) {
                log_debug("Server answer contains an embedded NUL, refusing.");
                return 0;
        }

        if (!iovec_append(answer, &IOVEC_MAKE(buf, nmemb))) {
                log_oom_debug();
                return 0; /* Returning < nmemb signals failure */
        }

        return nmemb;
}

static int geoip_fetch(const char *endpoint, char **ret) {
        _cleanup_(iovec_done) struct iovec answer = {};
        _cleanup_(curl_slist_free_allp) struct curl_slist *header = NULL;
        char error[CURL_ERROR_SIZE] = {};
        int r;

        assert(endpoint);
        assert(ret);

        /* Downloads the JSON answer from the configured endpoint, and returns it as NUL-terminated string. */

        /* The endpoint from the configuration file is validated when parsed, but the compile-time default is
         * not, hence check here, so that both take the same path. */
        if (!http_url_is_valid(endpoint))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Endpoint URL '%s' is not valid, refusing.", endpoint);

        r = dlopen_curl(LOG_DEBUG);
        if (r < 0)
                return r;

        r = curl_append_to_header(&header, STRV_MAKE("Accept: application/json"));
        if (r < 0)
                return r;

        _cleanup_(curl_easy_cleanupp) CURL *curl = sym_curl_easy_init();
        if (!curl)
                return -ENOSR;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_URL, endpoint))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_HTTPGET, 1L))
                return -EXFULL;

        /* Only ever talk HTTP(S), for the initial request as well as for any redirects we follow. */
#if LIBCURL_VERSION_NUM >= 0x075500 /* libcurl 7.85.0 */
        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_PROTOCOLS_STR, "HTTP,HTTPS"))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_REDIR_PROTOCOLS_STR, "HTTP,HTTPS"))
                return -EXFULL;
#else
        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS))
                return -EXFULL;
#endif

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_FOLLOWLOCATION, 1L))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_MAXREDIRS, REPORT_GEOIP_MAX_REDIRECTS))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_TIMEOUT_MS,
                         (long) DIV_ROUND_UP(REPORT_GEOIP_NETWORK_TIMEOUT_USEC, USEC_PER_MSEC)))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_NOSIGNAL, 1L))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_ERRORBUFFER, error))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_WRITEFUNCTION, write_callback))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_WRITEDATA, &answer))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_DEBUG, CURLOPT_HTTPHEADER, header))
                return -EXFULL;

        (void) easy_setopt(curl, LOG_DEBUG, CURLOPT_USERAGENT, "systemd-report-geoip " GIT_VERSION);

        if (DEBUG_LOGGING)
                (void) easy_setopt(curl, LOG_DEBUG, CURLOPT_VERBOSE, 1L);

        CURLcode code = sym_curl_easy_perform(curl);
        if (code != CURLE_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Download from '%s' failed: %s", endpoint,
                                       empty_to_null(&error[0]) ?: sym_curl_easy_strerror(code));

        long status;
        code = sym_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (code != CURLE_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Failed to retrieve response code: %s", sym_curl_easy_strerror(code));

        if (status < 200 || status >= 300)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Download from '%s' failed with HTTP status %ld.", endpoint, status);

        r = make_cstring(answer.iov_base, answer.iov_len, MAKE_CSTRING_REFUSE_TRAILING_NUL, ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to turn acquired data into C string: %m");

        return 0;
}

static int geoip_cache_path(char **ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *dir = NULL;
        r = state_directory(RUNTIME_SCOPE_SYSTEM, REPORT_GEOIP_STATE_DIR_SUFFIX, &dir);
        if (r < 0)
                return r;

        _cleanup_free_ char *path = path_join(dir, REPORT_GEOIP_CACHE_FILE_NAME);
        if (!path)
                return -ENOMEM;

        *ret = TAKE_PTR(path);
        return 0;
}

static int geoip_cache_load(const char *path, char **ret_text, usec_t *ret_mtime) {
        int r;

        assert(path);
        assert(ret_text);
        assert(ret_mtime);

        /* Reads the cache file, and returns its modification time, i.e. when the data was downloaded. */

        _cleanup_close_ int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        struct stat st;
        if (fstat(fd, &st) < 0)
                return -errno;

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        _cleanup_free_ char *text = NULL;
        r = read_full_file_full(
                        fd,
                        /* filename= */ NULL,
                        /* offset= */ UINT64_MAX,
                        REPORT_GEOIP_ANSWER_MAX,
                        READ_FULL_FILE_FAIL_WHEN_LARGER,
                        /* bind_name= */ NULL,
                        &text,
                        /* ret_size= */ NULL);
        if (r < 0)
                return r;

        *ret_text = TAKE_PTR(text);
        *ret_mtime = timespec_load(&st.st_mtim);
        return 0;
}

static int geoip_data_acquire(GeoIPData *ret) {
        int r;

        assert(ret);

        /* Acquires the geolocation data, preferably from the cache if it is recent enough, otherwise from
         * the network. A stale cache is used as fallback if the network is unavailable. Note that we
         * consider the cache optional, hence any failure of the cache is handled gracefully. */

        const char *endpoint = arg_endpoint ?: GEOIP_ENDPOINT; /* compile-time default, see -Dgeoip-endpoint= */

        _cleanup_(release_lock_file) LockFile lock = LOCK_FILE_INIT;

        _cleanup_free_ char *cache_path = NULL, *cached = NULL;
        usec_t mtime = USEC_INFINITY, age = USEC_INFINITY;
        r = geoip_cache_path(&cache_path);
        if (r < 0)
                log_warning_errno(r, "Failed to determine cache file path, ignoring: %m");
        else {
                /* Create the parent directory before we try to create the lock file. Ignore failures. */
                r = mkdir_parents(cache_path, 0755);
                if (r < 0)
                        log_warning_errno(r, "Failed to create parent directory of '%s', ignoring: %m", cache_path);

                /* Serialize concurrent instances, so that only one of them talks to the network and the others pick
                 * up the cache it leaves behind. */
                r = make_lock_file_for(cache_path, LOCK_EX, &lock);
                if (r < 0)
                        log_warning_errno(r, "Failed to take lock on '%s', ignoring: %m", cache_path);

                r = geoip_cache_load(cache_path, &cached, &mtime);
                if (r < 0)
                        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to read cache file '%s', ignoring: %m", cache_path);
                else
                        age = usec_sub_unsigned(now(CLOCK_REALTIME), mtime); /* A cache from the future counts as brand new. */

                if (age < arg_refresh_usec) {
                        assert(cached);

                        _cleanup_(geoip_data_done) GeoIPData d = GEOIP_DATA_INIT;
                        r = geoip_data_parse(cached, &d);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse cache file '%s', ignoring: %m", cache_path);
                        else {
                                log_debug("Using cached geolocation data (age: %s).", FORMAT_TIMESPAN(age, USEC_PER_SEC));
                                d.timestamp = mtime;
                                *ret = TAKE_STRUCT(d);
                                return 0;
                        }

                        /* The cache is unusable, don't fall back to it below either. */
                        cached = mfree(cached);
                }
        }

        _cleanup_free_ char *fresh = NULL;
        r = geoip_fetch(endpoint, &fresh);
        if (r < 0)
                log_warning_errno(r, "Failed to download geolocation data from '%s', ignoring: %m", endpoint);
        else {
                _cleanup_(geoip_data_done) GeoIPData d = GEOIP_DATA_INIT;

                r = geoip_data_parse(fresh, &d);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse geolocation data from '%s', ignoring: %m", endpoint);
                else {
                        /* Sample the timestamp only now, i.e. after the (potentially slow) download completed,
                         * and stamp the cache file with precisely this value, so that the mtime we report on
                         * later requests matches the timestamp we report right now. */
                        usec_t n = now(CLOCK_REALTIME);

                        /* Only cache what we managed to parse, so that we never fall back to garbage. */
                        if (cache_path) {
                                r = write_string_file_full(AT_FDCWD, cache_path, fresh,
                                                           WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755,
                                                           TIMESPEC_STORE(n), /* label_fn= */ NULL);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to write cache file '%s', ignoring: %m", cache_path);
                        }

                        d.timestamp = n;
                        *ret = TAKE_STRUCT(d);
                        return 0;
                }
        }

        if (cached) {
                _cleanup_(geoip_data_done) GeoIPData d = GEOIP_DATA_INIT;

                r = geoip_data_parse(cached, &d);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse cache file '%s', ignoring: %m", cache_path);
                else {
                        log_notice("Using stale cached geolocation data (age: %s).", FORMAT_TIMESPAN(age, USEC_PER_SEC));
                        d.timestamp = mtime;
                        *ret = TAKE_STRUCT(d);
                        return 0;
                }
        }

        log_debug("No geolocation data available, reporting nothing.");
        *ret = GEOIP_DATA_INIT;
        return 0;
}

static int geoip_generate(const MetricFamily mf[static _GEOIP_FIELD_MAX], sd_varlink *link, void *userdata) {
        /* Describes how each member of GeoIPData is turned into a metric. The order must match the metric
         * family table below. */
        static const struct {
                GeoIPValueType value_type;
                size_t offset; /* Offset of the corresponding member in GeoIPData */
        } field_table[_GEOIP_FIELD_MAX] = {
                [GEOIP_FIELD_IP]           = { GEOIP_VALUE_ADDRESS,   offsetof(GeoIPData, ip)           },
                [GEOIP_FIELD_COUNTRY_CODE] = { GEOIP_VALUE_STRING,    offsetof(GeoIPData, country_code) },
                [GEOIP_FIELD_COUNTRY_NAME] = { GEOIP_VALUE_STRING,    offsetof(GeoIPData, country_name) },
                [GEOIP_FIELD_REGION_CODE]  = { GEOIP_VALUE_STRING,    offsetof(GeoIPData, region_code)  },
                [GEOIP_FIELD_REGION_NAME]  = { GEOIP_VALUE_STRING,    offsetof(GeoIPData, region_name)  },
                [GEOIP_FIELD_CITY]         = { GEOIP_VALUE_STRING,    offsetof(GeoIPData, city)         },
                [GEOIP_FIELD_ZIP_CODE]     = { GEOIP_VALUE_STRING,    offsetof(GeoIPData, zip_code)     },
                [GEOIP_FIELD_TIME_ZONE]    = { GEOIP_VALUE_STRING,    offsetof(GeoIPData, time_zone)    },
                [GEOIP_FIELD_LATITUDE]     = { GEOIP_VALUE_DOUBLE,    offsetof(GeoIPData, latitude)     },
                [GEOIP_FIELD_LONGITUDE]    = { GEOIP_VALUE_DOUBLE,    offsetof(GeoIPData, longitude)    },
                [GEOIP_FIELD_TIMESTAMP]    = { GEOIP_VALUE_TIMESTAMP, offsetof(GeoIPData, timestamp)    },
        };

        int r;

        assert(mf && mf[0].name);
        assert(link);

        _cleanup_(geoip_data_done) GeoIPData d = GEOIP_DATA_INIT;
        r = geoip_data_acquire(&d);
        if (r < 0)
                return r;

        for (GeoIPField f = 0; f < _GEOIP_FIELD_MAX; f++) {
                const void *member = (const uint8_t*) &d + field_table[f].offset;

                switch (field_table[f].value_type) {

                case GEOIP_VALUE_STRING: {
                        const char *v = *(const char* const*) member;
                        if (isempty(v))
                                continue;

                        if (!string_is_safe(v, STRING_ALLOW_BACKSLASHES|STRING_ALLOW_QUOTES|STRING_ALLOW_GLOBS)) {
                                log_debug("Value of metric '%s' contains unsafe characters, ignoring.", mf[f].name);
                                continue;
                        }

                        r = metric_build_send_string(mf + f, link, /* object= */ NULL, v, /* fields= */ NULL);
                        if (r < 0)
                                return r;
                        break;
                }

                case GEOIP_VALUE_ADDRESS: {
                        const struct in_addr_data *a = member;
                        if (!IN_SET(a->family, AF_INET, AF_INET6))
                                continue;

                        /* Report the canonical formatting of the parsed address, never the string as we got it. */
                        r = metric_build_send_string(mf + f, link, /* object= */ NULL, IN_ADDR_TO_STRING(a->family, &a->address), /* fields= */ NULL);
                        if (r < 0)
                                return r;
                        break;
                }

                case GEOIP_VALUE_DOUBLE: {
                        double v = *(const double*) member;
                        if (!isfinite(v))
                                continue;

                        r = metric_build_send_double(mf + f, link, /* object= */ NULL, v, /* fields= */ NULL);
                        if (r < 0)
                                return r;
                        break;
                }

                case GEOIP_VALUE_TIMESTAMP: {
                        usec_t v = *(const usec_t*) member;
                        if (v == USEC_INFINITY)
                                continue;

                        r = metric_build_send_unsigned(mf + f, link, /* object= */ NULL, v, /* fields= */ NULL);
                        if (r < 0)
                                return r;
                        break;
                }

                default:
                        assert_not_reached();
                }
        }

        return 0;
}

/* The metrics we report. Only the first entry carries the generating function, which reports all of them in
 * one go. The order must match the field table in geoip_generate() above. */
static const MetricFamily metric_family_table[_GEOIP_FIELD_MAX + 1] = {
        [GEOIP_FIELD_IP] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "PublicAddress",
                "Public IP address of the system as seen by the geolocation service, in normalized form",
                METRIC_FAMILY_TYPE_STRING,
                .generate = geoip_generate,
        },
        [GEOIP_FIELD_COUNTRY_CODE] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "CountryCode",
                "ISO 3166-1 alpha-2 code of the country the system is located in",
                METRIC_FAMILY_TYPE_STRING,
        },
        [GEOIP_FIELD_COUNTRY_NAME] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "CountryName",
                "Name of the country the system is located in",
                METRIC_FAMILY_TYPE_STRING,
        },
        [GEOIP_FIELD_REGION_CODE] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "RegionCode",
                "Code of the region (state, province, …) the system is located in",
                METRIC_FAMILY_TYPE_STRING,
        },
        [GEOIP_FIELD_REGION_NAME] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "RegionName",
                "Name of the region (state, province, …) the system is located in",
                METRIC_FAMILY_TYPE_STRING,
        },
        [GEOIP_FIELD_CITY] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "City",
                "Name of the city the system is located in",
                METRIC_FAMILY_TYPE_STRING,
        },
        [GEOIP_FIELD_ZIP_CODE] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "ZipCode",
                "Postal code of the area the system is located in",
                METRIC_FAMILY_TYPE_STRING,
        },
        [GEOIP_FIELD_TIME_ZONE] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "Timezone",
                "IANA time zone name of the area the system is located in",
                METRIC_FAMILY_TYPE_STRING,
        },
        [GEOIP_FIELD_LATITUDE] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "Latitude",
                "Latitude of the system's location in decimal degrees",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        [GEOIP_FIELD_LONGITUDE] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "Longitude",
                "Longitude of the system's location in decimal degrees",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        [GEOIP_FIELD_TIMESTAMP] = {
                METRIC_IO_SYSTEMD_GEOIP_PREFIX "Timestamp",
                "CLOCK_REALTIME microseconds at which the geolocation data was acquired from the service",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        [_GEOIP_FIELD_MAX] = {}, /* terminator */
};

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, /* userdata= */ NULL);
}

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, /* userdata= */ NULL);
}
