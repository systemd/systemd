/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "log.h"
#include "report.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "version.h"

#if HAVE_LIBCURL
#include "curl-util.h"
#include <curl/easy.h>   /* Sadly this fails if ordered first. */

static size_t output_callback(char *buf,
                              size_t size,
                              size_t nmemb,
                              void *userp) {
        Context *context = ASSERT_PTR(userp);

        log_debug("The server answers (%zu bytes): %.*s",
                  size*nmemb, (int)(size * nmemb), buf);

        if (nmemb && !context->upload_answer) {
                context->upload_answer = strndup(buf, size * nmemb);
                if (!context->upload_answer)
                        log_warning("Failed to store server answer (%zu bytes): out of memory", size * nmemb);
        }

        return size * nmemb;
}
#endif

int upload_collected(Context *context) {
#if HAVE_LIBCURL
        _cleanup_(curl_slist_free_allp) struct curl_slist *header = NULL;
        struct curl_slist *l;
        char error[CURL_ERROR_SIZE] = {};
        _cleanup_free_ char *json = NULL;
        int r;

        {
                /* Convert our variant array to a JSON report.
                 * We won't need the JSON structure again, so free it quickly. */

                uint64_t id = 1; /* FIXME */
                const char *timestamp = "today";

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *vl = NULL;
                r = sd_json_buildo(&vl,
                                   SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_UNSIGNED(id)),
                                   SD_JSON_BUILD_PAIR("timestamp", SD_JSON_BUILD_STRING(timestamp)),
                                   SD_JSON_BUILD_PAIR("body",
                                                      SD_JSON_BUILD_VARIANT_ARRAY(context->metrics, context->n_metrics)));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON data: %m");

                r = sd_json_variant_format(vl, /* flags= */ 0, &json);
                if (r < 0)
                        return log_error_errno(r, "Failed to format JSON data: %m");

                log_debug("JSON: %s", json);
        }

        header = curl_slist_append(NULL, "Content-Type: application/json");
        if (!header)
                return log_oom();

        l = curl_slist_append(header, "Accept: application/json");
        if (!l)
                return log_oom();
        header = l;

        _cleanup_(curl_easy_cleanupp) CURL *curl = curl_easy_init();
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
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_SSL_VERIFYPEER, 0L))
                        return -EUCLEAN;
        } else if (arg_trust || startswith(arg_url, "https://")) {
                if (!easy_setopt(curl, LOG_ERR, CURLOPT_CAINFO, arg_trust ?: REPORT_TRUST_FILE))
                        return -EXFULL;
        }

        if (arg_key || arg_trust)
                (void) easy_setopt(curl, LOG_WARNING, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

        /* Upload to this place */
        if (!easy_setopt(curl, LOG_ERR, CURLOPT_URL, arg_url))
                return -EXFULL;

        if (!easy_setopt(curl, LOG_ERR, CURLOPT_POSTFIELDS, json))
                return -EXFULL;

        CURLcode code = curl_easy_perform(curl);
        if (code) {
                if (!isempty(error))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Upload to %s failed: %.*s",
                                               arg_url, (int) sizeof(error), error);
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Upload to %s failed: %s",
                                               arg_url, curl_easy_strerror(code));
        }

        long status;
        code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (code)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Failed to retrieve response code: %s",
                                       curl_easy_strerror(code));
        if (status >= 300)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Upload to %s failed with code %ld: %s",
                                       arg_url, status, strna(context->upload_answer));
        if (status < 200)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Upload to %s finished with unexpected code %ld: %s",
                                       arg_url, status, strna(context->upload_answer));
        log_debug("Upload to %s finished successfully with code %ld: %s",
                  arg_url, status, strna(context->upload_answer));
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Compiled without libcurl.");
#endif
}
