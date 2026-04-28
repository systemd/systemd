/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "report.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "varlink-util.h"
#include "version.h"

#if HAVE_LIBCURL
#include "curl-util.h"

#define SERVER_ANSWER_MAX (1*1024*1024u)

static size_t output_callback(char *buf,
                              size_t size,
                              size_t nmemb,
                              void *userp) {

        Context *context = ASSERT_PTR(userp);
        int r;

        assert(size == 1);  /* The docs say that this is always true. */

        log_debug("Got an answer from the server (%zu bytes)", nmemb);

        if (nmemb != 0) {
                size_t new_size = size_add(iovw_size(&context->upload_answer), nmemb);

                if (new_size > SERVER_ANSWER_MAX) {
                        log_warning("Server answer too long (%zu > %u), refusing.", new_size, SERVER_ANSWER_MAX);
                        return 0;
                }

                if (memchr(buf, 0, nmemb)) {
                        log_warning("Server answer contains an embedded NUL, refusing.");
                        return 0;
                }

                r = iovw_extend(&context->upload_answer, buf, nmemb);
                if (r < 0) {
                        log_warning("Failed to store server answer (%zu bytes): out of memory", nmemb);
                        return 0;  /* Returning < nmemb signals failure */
                }
        }

        return nmemb;
}
#endif

static int build_json_report(Context *context, sd_json_variant **ret) {
        /* Convert the variant array to a JSON report. */

        assert(context);
        assert(ret);

        usec_t ts = now(CLOCK_REALTIME);
        int r;

        r = sd_json_buildo(ret,
                           SD_JSON_BUILD_PAIR_STRING("mediaType", "application/vnd.io.systemd.report"),
                           SD_JSON_BUILD_PAIR("timestamp",
                                              SD_JSON_BUILD_STRING(FORMAT_TIMESTAMP_STYLE(ts, TIMESTAMP_UTC))),
                           SD_JSON_BUILD_PAIR("metrics",
                                              SD_JSON_BUILD_VARIANT_ARRAY(context->metrics, context->n_metrics)));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON data: %m");
        return 0;
}

static int http_upload_collected(Context *context, sd_json_variant *report) {
#if HAVE_LIBCURL
        _cleanup_(curl_slist_free_allp) struct curl_slist *header = NULL;
        char error[CURL_ERROR_SIZE] = {};
        _cleanup_free_ char *json = NULL;
        int r;

        r = dlopen_curl(LOG_DEBUG);
        if (r < 0)
                return r;

        /* Upload a JSON report in text form as a single JSON object, instead of a JSON-SEQ list. */

        r = sd_json_variant_format(report, /* flags= */ 0, &json);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON data: %m");

        r = curl_append_to_header(&header,
                                  STRV_MAKE("Content-Type: application/json",
                                            "Accept: application/json"));
        if (r < 0)
                return log_error_errno(r, "Failed to create curl header: %m");

        r = curl_append_to_header(&header, arg_extra_headers);
        if (r < 0)
                return log_error_errno(r, "Failed to create curl header: %m");

        _cleanup_(curl_easy_cleanupp) CURL *curl = sym_curl_easy_init();
        if (!curl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSR),
                                       "Call to curl_easy_init failed.");

        /* If configured, set a timeout for the curl operation. */
        if (arg_network_timeout_usec != USEC_INFINITY &&
            !easy_setopt(curl, LOG_ERR, CURLOPT_TIMEOUT,
                         (long) DIV_ROUND_UP(arg_network_timeout_usec, USEC_PER_SEC)))
                return -EXFULL;

        /* Tell it to POST to the URL */
        if (!easy_setopt(curl, LOG_ERR, CURLOPT_POST, 1L))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_ERRORBUFFER, error))
                return -EXFULL;

        /* Where to write to */
        if (!easy_setopt(curl, LOG_ERR, CURLOPT_WRITEFUNCTION, output_callback))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_WRITEDATA, context))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_HTTPHEADER, header))
                return -EXFULL;

        if (DEBUG_LOGGING)
                /* enable verbose for easier tracing */
                (void) easy_setopt(curl, LOG_WARNING, CURLOPT_VERBOSE, 1L);

        (void) easy_setopt(curl, LOG_WARNING,
                           CURLOPT_USERAGENT, "systemd-report " GIT_VERSION);

        if (!streq_ptr(arg_key, "-") && (arg_key || startswith(arg_url, "https://"))) {
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSLKEY, arg_key ?: REPORT_PRIV_KEY_FILE))
                        return -EXFULL;
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSLCERT, arg_cert ?: REPORT_CERT_FILE))
                        return -EXFULL;
        }

        if (STRPTR_IN_SET(arg_trust, "-", "all")) {
                log_info("Server certificate verification disabled.");
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSL_VERIFYPEER, 0L))
                        return -EUCLEAN;
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSL_VERIFYHOST, 0L))
                        return -EUCLEAN;
        } else if (arg_trust || startswith(arg_url, "https://")) {
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_CAINFO, arg_trust ?: REPORT_TRUST_FILE))
                        return -EXFULL;
        }

        if (startswith(arg_url, "https://"))
                (void) easy_setopt(curl, LOG_WARNING, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

        /* Upload to this place */
        if (!easy_setopt(curl, LOG_ERR, CURLOPT_URL, arg_url))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_POSTFIELDS, json))
                return -EXFULL;

        CURLcode code = sym_curl_easy_perform(curl);
        if (code != CURLE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Upload to %s failed: %s", arg_url,
                                       empty_to_null(&error[0]) ?: sym_curl_easy_strerror(code));

        long status;
        code = sym_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (code != CURLE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Failed to retrieve response code: %s",
                                       sym_curl_easy_strerror(code));

        _cleanup_free_ char *ans = iovw_to_cstring(&context->upload_answer);
        if (!ans)
                return log_oom();

        if (!utf8_is_valid(ans))
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Upload to %s failed with code %ld and an invalid UTF-8 answer.",
                                       arg_url, status);

        if (status >= 300)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Upload to %s failed with code %ld: %s",
                                       arg_url, status, strna(ans));
        if (status < 200)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Upload to %s finished with unexpected code %ld: %s",
                                       arg_url, status, strna(ans));
        log_info("Upload to %s finished successfully with code %ld: %s",
                 arg_url, status, strna(ans));
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Compiled without libcurl.");
#endif
}

static int execute_dir_reply(
                sd_varlink *link,
                sd_json_variant *reply,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        Context *context = ASSERT_PTR(userdata);
        int r;

        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply);
                RET_GATHER(context->upload_result, r);
                return log_error_errno(r, "Upload via Varlink failed: %s", error_id);
        }

        log_info("Upload via Varlink was successful; reply follows:");
        // TODO: once we know what we want to put in the reply, replace the JSON dump by
        //       some formatted output.
        r = sd_json_variant_dump(reply, arg_json_format_flags, /* f= */ NULL, /* prefix= */ ">>> ");
        if (r < 0)
                return log_error_errno(r, "Failed to dump json object: %m");

        return 0;
}

static int upload_collected(Context *context, sd_json_variant *report) {
        int r;

        if (arg_url && STARTSWITH_SET(arg_url, "http://", "https://"))
                return http_upload_collected(context, report);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        r = sd_json_buildo(&params,
                           SD_JSON_BUILD_PAIR_VARIANT("report", report));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON data: %m");

        ssize_t jobs = varlink_execute_directory(
                        REPORT_UPLOAD_DIR,
                        "io.systemd.Report.Upload",
                        params,
                        /* more= */ false,
                        arg_network_timeout_usec,
                        execute_dir_reply,
                        /* userdata= */ context);
        if (jobs == -ENOENT)
                log_debug_errno(jobs, "Failed to execute upload via %s: %m", REPORT_UPLOAD_DIR);
        else if (jobs < 0)
                return log_error_errno(jobs, "Failed to execute upload via %s: %m", REPORT_UPLOAD_DIR);
        else if (jobs > 0)
                return log_full_errno_zerook(LOG_DEBUG, context->upload_result,
                                             "Upload via %s finished: %m", REPORT_UPLOAD_DIR);

        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                               "No upload mechanism found via %s.", REPORT_UPLOAD_DIR);
}

/* Make a structured report and either print it or upload it. */
int report_collected(Context *context) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *report = NULL;
        int r;

        r = build_json_report(context, &report);
        if (r < 0)
                return r;

        if (context->action == ACTION_UPLOAD)
                return upload_collected(context, report);

        /* Just print the report for now. */
        assert(context->action == ACTION_GENERATE);
        r = sd_json_variant_dump(report, arg_json_format_flags, /* f= */ NULL, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump json object: %m");
        return 0;
}
