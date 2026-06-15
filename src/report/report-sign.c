/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "json-util.h"
#include "log.h"
#include "path-util.h"
#include "report.h"
#include "report-sign.h"
#include "sha256.h"
#include "time-util.h"
#include "varlink-util.h"

#define REPORT_SIGN_DIR "/run/systemd/report.sign"
#define REPORT_SIGN_TIMEOUT_USEC USEC_PER_MINUTE

typedef struct Signature {
        char *mechanism;
        sd_json_variant *data;
} Signature;

typedef struct SignatureList {
        Signature *signatures;
        size_t n_signatures;
        int result;
} SignatureList;

static void signature_done(Signature *s) {
        assert(s);

        s->data = sd_json_variant_unref(s->data);
        s->mechanism = mfree(s->mechanism);
}

static void signature_list_done(SignatureList *sl) {
        assert(sl);

        FOREACH_ARRAY(s, sl->signatures, sl->n_signatures)
                signature_done(s);

        sl->signatures = mfree(sl->signatures);
        sl->n_signatures = 0;
}

static int execute_dir_reply(
                sd_varlink *link,
                sd_json_variant *reply,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        SignatureList *sl = ASSERT_PTR(userdata);
        int r;

        assert(link);

        /* Get the socket name */
        const char *p = ASSERT_PTR(sd_varlink_get_description(link));

        _cleanup_free_ char *sn = NULL;
        r = path_extract_filename(p, &sn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract service name from '%s': %m", p);

        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply);
                RET_GATHER(sl->result, r);
                return log_error_errno(r, "Signing via Varlink service '%s' failed: %s", p, error_id);
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "data", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_variant, /* offset= */ 0, /* flags= */ 0 },
                {},
        };

        r = sd_json_dispatch(reply, dispatch_table, /* flags= */ 0, &array);
        if (r < 0)
                return log_error_errno(r, "Failed to dispatch method reply: %m");

        size_t n = 0;
        if (array) {
                sd_json_variant *s;
                JSON_VARIANT_ARRAY_FOREACH(s, array) {
                        if (!GREEDY_REALLOC(sl->signatures, sl->n_signatures + 1))
                                return log_oom();

                        Signature *i = sl->signatures + sl->n_signatures;

                        i->mechanism = strdup(sn);
                        if (!i->mechanism)
                                return log_oom();

                        i->data = sd_json_variant_ref(s);
                        sl->n_signatures++;

                        n++;
                }
        }

        if (n == 0)
                log_info("Mechanism '%s' succeeded, but returned no signatures.", p);
        else
                log_info("Successfully acquired %zu signatures from '%s'", n, p);

        return 0;
}

int context_sign_report(Context *context, sd_json_variant *report, sd_json_format_flags_t format_flags, FILE *output) {
        int r;

        assert(context);
        assert(report);

        /* When generating a signed report we switch to JSON-SEQ. We'll put the report as first object in the
         * stream, and then signature objects after it, that cover the precise binary representation of the
         * first object. We normalize the report JSON first, but this is not load bearing, as the signature
         * is about the binary representation of the JSON object sent over the wire, not the JSON object
         * itself. */

        format_flags |= SD_JSON_FORMAT_SEQ;
        format_flags &= ~SD_JSON_FORMAT_OFF;

        if (!output)
                output = stdout;

        _cleanup_free_ char *text = NULL;
        r = sd_json_variant_format(report, format_flags, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON data: %m");

        uint8_t digest[SHA256_DIGEST_SIZE];
        sha256_direct(text, strlen(text), digest);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        r = sd_json_buildo(&params,
                           SD_JSON_BUILD_PAIR_HEX("digest", digest, sizeof(digest)),
                           SD_JSON_BUILD_PAIR_STRING("algorithm", "SHA256"));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON data: %m");

        _cleanup_(signature_list_done) SignatureList sl = {};
        ssize_t jobs = varlink_execute_directory(
                        REPORT_SIGN_DIR,
                        "io.systemd.Report.Sign.Sign",
                        params,
                        /* more= */ false,
                        REPORT_SIGN_TIMEOUT_USEC,
                        execute_dir_reply,
                        /* userdata= */ &sl);
        if (jobs < 0)
                return log_error_errno(jobs, "Failed to execute signing via '%s': %m", REPORT_SIGN_DIR);
        if (jobs == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                       "No signing mechanism found via '%s'.", REPORT_SIGN_DIR);
        if (sl.result < 0)
                /* The details were printed at error level by execute_dir_reply above. */
                return log_debug_errno(sl.result, "Signing via '%s' failed: %m", REPORT_SIGN_DIR);
        if (sl.n_signatures == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOPKG),
                                       "No signatures acquired via '%s'.", REPORT_SIGN_DIR);

        fputs(text, output);

        FOREACH_ARRAY(s, sl.signatures, sl.n_signatures) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *sig = NULL;

                r = sd_json_variant_normalize(&s->data);
                if (r < 0)
                        return log_error_errno(r, "Failed to normalize JSON object: %m");

                r = sd_json_buildo(&sig,
                                   SD_JSON_BUILD_PAIR_STRING("mediaType", "application/vnd.io.systemd.report.signature"),
                                   SD_JSON_BUILD_PAIR_STRING("mechanism", s->mechanism),
                                   SD_JSON_BUILD_PAIR_HEX("sha256", digest, sizeof(digest)),
                                   JSON_BUILD_PAIR_VARIANT_NON_EMPTY("data", s->data));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON data: %m");

                r = sd_json_variant_dump(sig, format_flags, output, /* prefix= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to dump json object: %m");
        }

        log_debug("Signing via '%s' finished successfully.", REPORT_SIGN_DIR);
        return 0;
}
