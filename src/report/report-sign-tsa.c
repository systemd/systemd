#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "assert-util.h"
#include "build.h"
#include "cleanup-util.h"
#include "conf-parser.h"
#include "crypto-util.h"
#include "dlopen-note.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
//#include "report.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "time.h"
#include "varlink-io.systemd.Report.Signer.h"
#include "varlink-util.h"
#include "verbs.h"
#include "version.h"

#define TSA_ENDPOINT_URL_DEFAULT "http://timestamp.digicert.com"
/*Sanity cap, real TSA responses are only a few KB, if too big then refuse to buffer it because the behavior isn't normal.*/
#define TSA_RESPONSE_MAX_SIZE (64U * 1024U)
#define TSA_NETWORK_TIMEOUT_USEC_DEFAULT (30 * USEC_PER_SEC)


COMMAND("systemd-report-sign-tsa\0",
        "Sign a report with a timestamp from the TSA server.",
        .man_pages = "systemd-report-sign-tsa@.service(8)\0", );
static char *arg_tsa_url = NULL;
static usec_t arg_network_timeout_usec = TSA_NETWORK_TIMEOUT_USEC_DEFAULT;
static char *arg_certificate_authority = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_tsa_url, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_authority, freep);

typedef struct SignParameters {
        struct iovec digest;
        const char *algorithm;
} SignParameters;

static void sign_parameters_done(SignParameters *p) {
        iovec_done(&p->digest);
}

static int build_nonce(ASN1_INTEGER **ret_nonce) {
        int r;
        assert(ret_nonce);

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_(ASN1_INTEGER_freep) ASN1_INTEGER *nonce = NULL;

        uint64_t nonce_val;

        if (sym_RAND_bytes((unsigned char *) &nonce_val, sizeof(nonce_val)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate random nonce.");

        nonce = sym_ASN1_INTEGER_new();
        if (!nonce)
                return log_oom();

        if (sym_ASN1_INTEGER_set_uint64(nonce, nonce_val) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set nonce in ASN1_INTEGER.");

        *ret_nonce = TAKE_PTR(nonce);
        return 0;
}

static int build_timestamp_request(const struct iovec *digest, const char *algorithm, TS_REQ **ret_ts_req) {
        int r;
        assert(digest);
        assert(algorithm);
        assert(ret_ts_req);

        _cleanup_(TS_REQ_freep) TS_REQ *ts_req = NULL;
        _cleanup_(TS_MSG_IMPRINT_freep) TS_MSG_IMPRINT *ts_imprint = NULL;
        _cleanup_(X509_ALGOR_freep) X509_ALGOR *algo = NULL;
        _cleanup_(ASN1_INTEGER_freep) ASN1_INTEGER *nonce = NULL;

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        int nid = sym_OBJ_txt2nid(algorithm);
        if (nid == NID_undef)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported digest algorithm: %s.", algorithm);

        /* Possibly implement a check digest size is equal to the size expected by the algorithm*/

        ts_req = sym_TS_REQ_new();
        if (!ts_req)
                return log_oom();

        /* version defaults to 1, RFC3161 only defines 1 */
        ts_imprint = sym_TS_MSG_IMPRINT_new();
        if (!ts_imprint)
                return log_oom();

        algo = sym_X509_ALGOR_new();
        if (!algo)
                return log_oom();

        /* redundant given RFC3161 only has one value (1) */
        if (sym_TS_REQ_set_version(ts_req, 1) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set version.");

        if (sym_X509_ALGOR_set0(algo, sym_OBJ_nid2obj(nid), V_ASN1_NULL, /*pval=*/NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set digest algorithm.");

        if (sym_TS_MSG_IMPRINT_set_algo(ts_imprint, algo) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set message imprint algorithm.");

        if (sym_TS_MSG_IMPRINT_set_msg(ts_imprint, digest->iov_base, digest->iov_len) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set message imprint digest.");

        if (sym_TS_REQ_set_msg_imprint(ts_req, ts_imprint) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to attach message imprint.");

        if (sym_TS_REQ_set_cert_req(ts_req, 1) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set certReq flag.");

        r = build_nonce(&nonce);
        if (r < 0)
                return r;

        if (sym_TS_REQ_set_nonce(ts_req, nonce) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set nonce.");

        *ret_ts_req = TAKE_PTR(ts_req);
        return 0;
}
#if HAVE_LIBCURL
#        include "curl-util.h"
// Collects the response into a struct iovec, reallocationg as needed.
static size_t tsa_write_callback(char *buf, size_t size, size_t nmemb, void *userp) {

        struct iovec *response = ASSERT_PTR(userp);

        assert(size == 1); /* The docs say that this is always true. */

        log_debug("Got an answer from the TSA server (%zu bytes)", nmemb);

        if (nmemb != 0) {
                size_t new_size = size_add(response->iov_len, nmemb);

                if (new_size > TSA_RESPONSE_MAX_SIZE) {
                        log_warning("TSA answer too long (%zu > %u), refusing.",
                                    new_size,
                                    TSA_RESPONSE_MAX_SIZE);
                        return 0;
                }

                if (!iovec_append(response, &IOVEC_MAKE(buf, nmemb))) {
                        log_warning("Failed to store TSA answer (%zu bytes): out of memory", nmemb);
                        return 0; /* Returning < nmemb signals failure */
                }
        }

        return nmemb;
}
#endif

static int query_tsa(const TS_REQ *ts_req, TS_RESP **ret_ts_resp) {
#if HAVE_LIBCURL
        _cleanup_(curl_slist_free_allp) struct curl_slist *header = NULL;
        char error[CURL_ERROR_SIZE] = {};
        int r;

        assert(ts_req);
        assert(ret_ts_resp);

        r = dlopen_curl(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_(OPENSSL_freep) void *req_der = NULL;
        int req_len = sym_i2d_TS_REQ(
                        ts_req, (unsigned char **) &req_der); // Converts TS_REQ structure into der (binary).
        if (req_len < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to serialize TS_REQ.");

        r = curl_append_to_header(
                        &header,
                        STRV_MAKE("Content-Type: application/timestamp-query",
                                  "Accept: application/timestamp-reply"));
        if (r < 0)
                return log_error_errno(r, "Failed to create curl header: %m");

        _cleanup_(curl_easy_cleanupp)
                        CURL *curl = sym_curl_easy_init(); // Creates easy handle for single network transfer.
        if (!curl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSR), "Failed to initialize CURL.");

        /* If configured, set a timeout for the curl operation. */
        if (arg_network_timeout_usec != USEC_INFINITY &&
            !easy_setopt(curl,
                         LOG_ERR,
                         CURLOPT_TIMEOUT,
                         (long) DIV_ROUND_UP(arg_network_timeout_usec, USEC_PER_SEC)))
                return -EXFULL;

        /* Tell it to POST to the URL */
        if (!easy_setopt(curl, LOG_ERR, CURLOPT_POST, 1L))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_ERRORBUFFER, error))
                return -EXFULL;

        /* Where to write to */
        _cleanup_(iovec_done) struct iovec response = {};
        if (!easy_setopt(curl, LOG_ERR, CURLOPT_WRITEFUNCTION, tsa_write_callback))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_WRITEDATA, &response))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_HTTPHEADER, header))
                return -EXFULL;

        if (DEBUG_LOGGING)
                /* enable verbose for easier tracing */
                (void) easy_setopt(curl, LOG_WARNING, CURLOPT_VERBOSE, 1L);

        (void) easy_setopt(curl, LOG_WARNING, CURLOPT_USERAGENT, "systemd-report " GIT_VERSION);

        /*Query this TSA endpoint*/
        if (!easy_setopt(curl, LOG_ERR, CURLOPT_URL, arg_tsa_url))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_POSTFIELDSIZE, (long) req_len))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_POSTFIELDS, req_der))
                return -EXFULL;

        CURLcode code = sym_curl_easy_perform(curl);
        if (code != CURLE_OK)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EIO),
                                "Query to %s failed: %s",
                                arg_tsa_url,
                                empty_to_null(&error[0]) ?: sym_curl_easy_strerror(code));

        long http_status;
        code = sym_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
        if (code != CURLE_OK)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EUCLEAN),
                                "Failed to retrieve response code: %s",
                                sym_curl_easy_strerror(code));

        if (http_status != 200)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EIO),
                                "Query to %s failed with code %ld.",
                                arg_tsa_url,
                                http_status);

        if (response.iov_len == 0)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EBADMSG),
                                "Query to %s returned an empty response.",
                                arg_tsa_url);

        const unsigned char *p = response.iov_base; // Pointer to the start of the response data.
        _cleanup_(TS_RESP_freep) TS_RESP *ts_resp = sym_d2i_TS_RESP(
                        NULL,
                        &p,
                        (long) response.iov_len); // Decode the DER-encoded TS_RESP structure from the TSA response.
        if (!ts_resp)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EBADMSG),
                                "Failed to parse TSA response into TS_RESP structure.");

        TS_STATUS_INFO *status_info = sym_TS_RESP_get_status_info(ts_resp);
        if (!status_info)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "TSA response has no status info.");

        long status = sym_ASN1_INTEGER_get(sym_TS_STATUS_INFO_get0_status(status_info));
        if (!IN_SET(status, TS_STATUS_GRANTED, TS_STATUS_GRANTED_WITH_MODS))
                return log_error_errno(
                                SYNTHETIC_ERRNO(EBADMSG), "TSA rejected the request (status %ld).", status);

        if (!sym_TS_RESP_get_token(ts_resp))
                return log_error_errno(
                                SYNTHETIC_ERRNO(EBADMSG), "TSA granted the request but returned no token.");

        *ret_ts_resp = TAKE_PTR(ts_resp);
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Compiled without libcurl.");
#endif
}

static int build_ca_store(X509_STORE **ret_store) {
        int r;
        assert(ret_store);

        _cleanup_(X509_STORE_freep) X509_STORE *store = NULL;

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        store = sym_X509_STORE_new();
        if (!store)
                return log_oom();

        if (arg_certificate_authority) {
                if(sym_X509_STORE_load_file(store, arg_certificate_authority) != 1)
                        return log_openssl_errors(LOG_ERR, "Failed to load CA certificate from %s",
                                                  arg_certificate_authority);
        } else if (sym_X509_STORE_set_default_paths(store) != 1)
                 return log_openssl_errors(LOG_ERR, "Failed to set default paths for store.");

        *ret_store = TAKE_PTR(store);
        return 0;
}


static int response_verify(TS_REQ *ts_req, TS_RESP *ts_resp) {
        int r;

        assert(ts_req);
        assert(ts_resp);

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_(X509_STORE_freep) X509_STORE *store = NULL;
        _cleanup_(TS_VERIFY_CTX_freep) TS_VERIFY_CTX *ctx = NULL;

        r = build_ca_store(&store);
        if (r < 0)
                return r;

        ctx = sym_TS_REQ_to_TS_VERIFY_CTX(ts_req, /*ctx= */ NULL);
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to build TS verify context.");

        sym_TS_VERIFY_CTX_set0_store(ctx, TAKE_PTR(store));
        sym_TS_VERIFY_CTX_add_flags(ctx, TS_VFY_SIGNATURE);

        r = sym_TS_RESP_verify_response(ctx, ts_resp);
        if (r != 1)
                return log_openssl_errors(LOG_ERR, "Failed to verify TSA response");

        return 0;
}

static int tst_info_get_timestamp(TS_TST_INFO *tst_info, usec_t *ret) {
        struct tm tm = {};

        assert(tst_info);
        assert(ret);

        const ASN1_GENERALIZEDTIME *gt = sym_TS_TST_INFO_get_time(tst_info);
        if (!gt)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Timestamp token carries no time.");

        if (sym_ASN1_TIME_to_tm(gt, &tm) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse time in timestamp token.");

        time_t t = timegm(&tm);
        if (t == (time_t) -1)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Time in timestamp token is out of range.");

        *ret = (usec_t) t * USEC_PER_SEC;
        return 0;
}


static int vl_method_sign(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",
                 SD_JSON_VARIANT_STRING, json_dispatch_unhex_iovec,
                 offsetof(SignParameters, digest),
                 SD_JSON_MANDATORY },
                { "algorithm",
                 SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
                 offsetof(SignParameters, algorithm),
                 SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(sign_parameters_done) SignParameters sp = {};
        _cleanup_(TS_REQ_freep) TS_REQ *ts_req = NULL;
        _cleanup_(TS_RESP_freep) TS_RESP *ts_resp = NULL;

        int r;
        assert(link);
        assert(parameters);

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &sp);
        if (r != 0)
                return r;

        if (!iovec_is_set(&sp.digest))
                return sd_varlink_error_invalid_parameter_name(link, "digest");

        if (!streq(sp.algorithm, "SHA256"))
                return sd_varlink_error_invalid_parameter_name(link, "algorithm");

        r = build_timestamp_request(&sp.digest, sp.algorithm, &ts_req);
        if (r < 0)
                return r;
        r = query_tsa(ts_req, &ts_resp);
        if (r < 0)
                return r;

        r = response_verify(ts_req, ts_resp);
        if (r < 0)
                return r;

        TS_TST_INFO *tst_info = sym_TS_RESP_get_tst_info(ts_resp);
        if (!tst_info)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to get TST_INFO");

        usec_t ts;
        r = tst_info_get_timestamp(tst_info, &ts);
        if (r < 0)
                return r;

        _cleanup_(OPENSSL_freep) void *token_der = NULL;
        int token_len = sym_i2d_PKCS7(sym_TS_RESP_get_token(ts_resp), (unsigned char **) &token_der);
        if (token_len < 0)
                return log_error_errno(
                                SYNTHETIC_ERRNO(ENOMEM),
                                "Failed to serialize TS_TST_INFO structure into DER format.");

        // TSA Config (call )
        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "data",
                                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_BASE64(
                                                                        "timestampToken",
                                                                        token_der,
                                                                        (size_t) token_len),
                                                        SD_JSON_BUILD_PAIR_STRING(
                                                                        "timestamp",
                                                                        FORMAT_TIMESTAMP_STYLE(
                                                                                        ts, TIMESTAMP_UTC)),
                                                        SD_JSON_BUILD_PAIR_STRING("tsaUrl", arg_tsa_url)))));
}

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                {"TSA", "URL",                  config_parse_string,  0, &arg_tsa_url             },
                {"TSA", "NetworkTimeoutSec",    config_parse_sec,      0, &arg_network_timeout_usec},
                {"TSA", "CertificateAuthority", config_parse_path,    0, &arg_certificate_authority},
                {}
        };
        int r;
        r = config_parse_standard_file_with_dropins(
                        "systemd/report-sign-tsa.conf",
                        "TSA\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
        if (r < 0)
                return r;
        if(isempty(arg_tsa_url)) {
                r = free_and_strdup(&arg_tsa_url, TSA_ENDPOINT_URL_DEFAULT);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, /*flags=*/0, /*userdata=*/NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Report_Signer);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(vs, "io.systemd.Report.Signer.Sign", vl_method_sign);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(vs);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
        switch (c) {
        OPTION_COMMON_HELP:
                return command_print_help();

        OPTION_COMMON_VERSION:
                return version();

        OPTION_COMMON_INTROSPECT_CLI:
                return introspect_cli(SD_JSON_FORMAT_OFF);
        }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r == 0)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EINVAL), "This program can only run as a Varlink service.");
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;
        r = parse_config();
        if (r <  0)
                return r;

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);