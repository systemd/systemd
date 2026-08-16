/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-messages.h"

#include "analyze-verify-util.h"
#include "analyze-verify-varlink.h"
#include "log.h"
#include "tests.h"
#include "varlink-idl-util.h"
#include "varlink-io.systemd.Analyze.h"

TEST(build_reply) {
        VerifyDiagnostic items[] = {
                {
                        .priority = LOG_EMERG,
                        .message = (char*) "first",
                        .unit = (char*) "first.service",
                        .configuration_file = (char*) "/tmp/first.service",
                        .configuration_line = 7,
                        .message_id = (char*) SD_MESSAGE_INVALID_CONFIGURATION_STR,
                },
                { .priority = LOG_ERR,     .message = (char*) "second" },
                { .priority = LOG_WARNING, .message = (char*) "third"  },
                { .priority = LOG_NOTICE,  .message = (char*) "fourth" },
                { .priority = LOG_INFO,    .message = (char*) "fifth"  },
                { .priority = LOG_DAEMON|LOG_ERR, .message = (char*) "sixth" },
        };
        const VerifyUnitsResult result = {
                .diagnostics = {
                        .items = items,
                        .n_items = ELEMENTSOF(items),
                },
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;

        ASSERT_OK(verify_result_build_varlink_reply(
                        &result,
                        SIZE_MAX,
                        &reply,
                        /* ret_size= */ NULL));

        const sd_varlink_symbol *method = ASSERT_NOT_NULL(varlink_idl_find_symbol(
                        &vl_interface_io_systemd_Analyze,
                        SD_VARLINK_METHOD,
                        "Verify"));
        ASSERT_OK(varlink_idl_validate_method_reply(
                        method,
                        reply,
                        /* flags= */ 0,
                        /* reterr_bad_field= */ NULL));

        sd_json_variant *array = ASSERT_NOT_NULL(sd_json_variant_by_key(reply, "diagnostics"));
        ASSERT_TRUE(sd_json_variant_is_array(array));
        ASSERT_EQ(sd_json_variant_elements(array), ELEMENTSOF(items));

        static const char * const severities[] = {
                "error",
                "error",
                "warning",
                "notice",
                "info",
                "error",
        };

        FOREACH_ELEMENT(severity, severities) {
                size_t i = severity - severities;
                sd_json_variant *diagnostic = ASSERT_NOT_NULL(sd_json_variant_by_index(array, i));

                ASSERT_STREQ(
                                sd_json_variant_string(sd_json_variant_by_key(diagnostic, "severity")),
                                *severity);
                ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(diagnostic, "message")),
                             items[i].message);
        }

        sd_json_variant *first = ASSERT_NOT_NULL(sd_json_variant_by_index(array, 0));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(first, "unit")), "first.service");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(first, "configurationFile")),
                     "/tmp/first.service");
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(first, "configurationLine")), 7u);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(first, "messageId")),
                     SD_MESSAGE_INVALID_CONFIGURATION_STR);

        sd_json_variant *second = ASSERT_NOT_NULL(sd_json_variant_by_index(array, 1));
        ASSERT_NULL(sd_json_variant_by_key(second, "unit"));
        ASSERT_NULL(sd_json_variant_by_key(second, "configurationFile"));
        ASSERT_NULL(sd_json_variant_by_key(second, "configurationLine"));
        ASSERT_NULL(sd_json_variant_by_key(second, "messageId"));
}

TEST(empty_reply) {
        const VerifyUnitsResult result = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;

        ASSERT_OK(verify_result_build_varlink_reply(
                        &result,
                        SIZE_MAX,
                        &reply,
                        /* ret_size= */ NULL));

        sd_json_variant *array = ASSERT_NOT_NULL(sd_json_variant_by_key(reply, "diagnostics"));
        ASSERT_TRUE(sd_json_variant_is_array(array));
        ASSERT_EQ(sd_json_variant_elements(array), 0u);
}

TEST(reply_size) {
        VerifyDiagnostic item = {
                .priority = LOG_WARNING,
                .message = (char*) "quote: \"; control: \n",
        };
        const VerifyUnitsResult result = {
                .diagnostics = {
                        .items = &item,
                        .n_items = 1,
                },
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *envelope = NULL, *reply = NULL;
        _cleanup_free_ char *formatted = NULL;
        size_t size;

        ASSERT_OK(verify_result_build_varlink_reply(&result, SIZE_MAX, &reply, &size));
        ASSERT_OK(sd_json_buildo(&envelope, SD_JSON_BUILD_PAIR_VARIANT("parameters", reply)));
        ASSERT_OK(sd_json_variant_format(envelope, /* flags= */ 0, &formatted));
        ASSERT_STREQ(
                        formatted,
                        "{\"parameters\":{\"diagnostics\":[{\"severity\":\"warning\","
                        "\"message\":\"quote: \\\"; control: \\n\"}]}}");
        ASSERT_EQ(size, strlen(formatted) + 1);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *exact = NULL;
        ASSERT_OK(verify_result_build_varlink_reply(
                        &result,
                        size,
                        &exact,
                        /* ret_size= */ NULL));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *unchanged = sd_json_variant_ref(reply);
        sd_json_variant *sentinel = unchanged;
        size_t unchanged_size = SIZE_MAX;
        ASSERT_ERROR(verify_result_build_varlink_reply(
                             &result,
                             size - 1,
                             &unchanged,
                             &unchanged_size),
                     E2BIG);
        ASSERT_PTR_EQ(unchanged, sentinel);
        ASSERT_EQ(unchanged_size, SIZE_MAX);
}

DEFINE_TEST_MAIN(LOG_INFO);
