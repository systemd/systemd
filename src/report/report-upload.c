/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "memstream-util.h"
#include "report.h"
#include "report-generate.h"
#include "report-upload.h"
#include "report-sign.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "varlink-util.h"
#include "version.h"

#define REPORT_UPLOAD_DIR "/run/systemd/report.upload"
#define SERVER_ANSWER_MAX (1U * 1024U * 1024U)

#if HAVE_LIBCURL
#include "curl-util.h"

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

static int http_upload_report(Context *context, sd_json_variant *report) {
#if HAVE_LIBCURL
        _cleanup_(curl_slist_free_allp) struct curl_slist *header = NULL;
        char error[CURL_ERROR_SIZE] = {};
        _cleanup_free_ char *json = NULL;
        int r;

        r = DLOPEN_CURL(LOG_DEBUG, SD_ELF_NOTE_DLOPEN_PRIORITY_REQUIRED);
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

        assert(link);

        Context *context = ASSERT_PTR(userdata);
        int r;

        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply);
                RET_GATHER(context->upload_result, r);
                log_error_errno(r, "Upload via Varlink failed: %s", error_id);
                if (reply)
                        (void) sd_json_variant_dump(reply, arg_json_format_flags,
                                                    /* f= */ NULL, /* prefix= */ NULL);
                return r;
        }

        printf("Upload via Varlink was successful; reply: ");
        // TODO: once we know what we want to put in the reply, replace the JSON dump by
        //       some formatted output.
        r = sd_json_variant_dump(reply, arg_json_format_flags, stderr, /* prefix= */ ">>> ");
        if (r < 0)
                return log_error_errno(r, "Failed to dump json object: %m");

        return 0;
}

static int varlink_upload_report(Context *context, sd_json_variant *report) {
        int r;

        assert(context);
        assert(report);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        if (arg_sign) {
                _cleanup_(memstream_done) MemStream ms = {};

                FILE *f = memstream_init(&ms);
                if (!f)
                        return log_oom();

                r = context_sign_report(context, report, /* json_flags= */ 0, f);
                if (r < 0)
                        return r;

                _cleanup_free_ char *buf = NULL;
                size_t sz = 0;

                r = memstream_finalize(&ms, &buf, &sz);
                if (r < 0)
                        return log_error_errno(r, "Failed to finalize memory stream: %m");

                r = sd_json_buildo(&params,
                                   SD_JSON_BUILD_PAIR_BASE64("reportData", buf, sz));
        } else
                r = sd_json_buildo(&params,
                                   SD_JSON_BUILD_PAIR_VARIANT("report", report));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON data: %m");

        ssize_t jobs = varlink_execute_directory(
                        REPORT_UPLOAD_DIR,
                        "io.systemd.Report.Uploader.Upload",
                        params,
                        /* more= */ false,
                        arg_network_timeout_usec,
                        execute_dir_reply,
                        /* userdata= */ context);
        if (jobs < 0)
                return log_error_errno(jobs, "Failed to execute upload via %s: %m", REPORT_UPLOAD_DIR);
        if (jobs == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                       "No upload mechanism found via %s.", REPORT_UPLOAD_DIR);
        if (context->upload_result < 0)
                /* The details were printed at error level by execute_dir_reply above. */
                return log_debug_errno(context->upload_result, "Upload via %s failed: %m", REPORT_UPLOAD_DIR);

        log_debug("Upload via %s finished successfully.", REPORT_UPLOAD_DIR);
        return 0;
}

int context_upload_report(Context *context) {
        int r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *report = NULL;
        r = context_build_report(context, &report);
        if (r < 0)
                return r;

        return (arg_url ? http_upload_report : varlink_upload_report)(context, report);
}
