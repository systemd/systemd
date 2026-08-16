/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"
#include "sd-messages.h"

#include "analyze-verify-util.h"
#include "analyze-verify-varlink.h"
#include "fileio.h"
#include "log.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unit-name.h"
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
                .diagnostics = items,
                .n_diagnostics = ELEMENTSOF(items),
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;

        ASSERT_OK(verify_result_build_varlink_reply(&result, &reply));

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

        ASSERT_OK(verify_result_build_varlink_reply(&result, &reply));

        sd_json_variant *array = ASSERT_NOT_NULL(sd_json_variant_by_key(reply, "diagnostics"));
        ASSERT_TRUE(sd_json_variant_is_array(array));
        ASSERT_EQ(sd_json_variant_elements(array), 0u);
}

TEST(reply_serialization) {
        VerifyDiagnostic diagnostic = {
                .priority = LOG_WARNING,
                .message = (char*) "quote: \"; control: \n",
        };
        const VerifyUnitsResult result = {
                .diagnostics = &diagnostic,
                .n_diagnostics = 1,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *envelope = NULL, *reply = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_OK(verify_result_build_varlink_reply(&result, &reply));
        ASSERT_OK(sd_json_buildo(&envelope, SD_JSON_BUILD_PAIR_VARIANT("parameters", reply)));
        ASSERT_OK(sd_json_variant_format(envelope, /* flags= */ 0, &formatted));
        ASSERT_STREQ(
                        formatted,
                        "{\"parameters\":{\"diagnostics\":[{\"severity\":\"warning\","
                        "\"message\":\"quote: \\\"; control: \\n\"}]}}");
}

static void mask_single_character_instances_except(
                const char *directory,
                const char *template,
                const char *except) {

        assert(directory);
        assert(unit_name_is_valid(template, UNIT_NAME_TEMPLATE));
        assert(unit_instance_is_valid(except));
        assert(strlen(except) == 1);

        for (unsigned c = 1; c < 128; c++) {
                char instance[] = { (char) c, 0 };
                _cleanup_free_ char *name = NULL, *path = NULL;

                if (!unit_instance_is_valid(instance) || streq(instance, except))
                        continue;

                ASSERT_OK(unit_name_replace_instance(template, instance, &name));
                path = ASSERT_NOT_NULL(path_join(directory, name));
                ASSERT_OK_ERRNO(symlink("/dev/null", path));
        }
}

TEST(collect_unit_files) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_strv_free_ char **paths = NULL, **lookup_path = NULL;
        _cleanup_free_ char *high = NULL, *local = NULL, *low = NULL, *runtime = NULL;
        _cleanup_free_ char *broken = NULL, *duplicate_high = NULL, *duplicate_low = NULL;
        _cleanup_free_ char *local_unit = NULL, *regular = NULL, *real = NULL;
        _cleanup_free_ char *template = NULL, *concrete = NULL, *template_mask = NULL;
        _cleanup_free_ char *long_padding = NULL, *long_name = NULL, *long_template = NULL;
        _cleanup_free_ char *other_padding = NULL, *other_name = NULL, *other_template = NULL;
        _cleanup_free_ char *max_padding = NULL, *max_name = NULL, *max_template = NULL;
        _cleanup_free_ char *alias = NULL, *masked = NULL, *runtime_masked = NULL;
        _cleanup_free_ char *template_name = NULL;
        const char *entry;
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-analyze:verify-varlink.XXXXXX", &tmp));
        high = ASSERT_NOT_NULL(path_join(tmp, SYSTEM_CONFIG_UNIT_DIR));
        local = ASSERT_NOT_NULL(path_join(tmp, "/usr/local/lib/systemd/system"));
        low = ASSERT_NOT_NULL(path_join(tmp, SYSTEM_DATA_UNIT_DIR));
        runtime = ASSERT_NOT_NULL(path_join(tmp, "/run/systemd/system"));

        duplicate_high = ASSERT_NOT_NULL(path_join(high, "duplicate.service"));
        duplicate_low = ASSERT_NOT_NULL(path_join(low, "duplicate.service"));
        local_unit = ASSERT_NOT_NULL(path_join(local, "local.service"));
        regular = ASSERT_NOT_NULL(path_join(low, "regular.service"));
        real = ASSERT_NOT_NULL(path_join(high, "real.service"));
        template = ASSERT_NOT_NULL(path_join(low, "template@.target"));
        concrete = ASSERT_NOT_NULL(path_join(low, "template@a.target"));
        template_mask = ASSERT_NOT_NULL(path_join(high, "template@b.target"));
        broken = ASSERT_NOT_NULL(path_join(low, "broken.service"));
        alias = ASSERT_NOT_NULL(path_join(high, "alias.service"));
        masked = ASSERT_NOT_NULL(path_join(high, "masked.service"));
        runtime_masked = ASSERT_NOT_NULL(path_join(runtime, "runtime-masked.service"));

        long_padding = ASSERT_NOT_NULL(strrep(
                        "x", UNIT_NAME_MAX - 2 - STRLEN("@.target") - STRLEN("long-")));
        long_name = ASSERT_NOT_NULL(strjoin("long-", long_padding, "@.target"));
        ASSERT_EQ(strlen(long_name), (size_t) UNIT_NAME_MAX - 2);
        long_template = ASSERT_NOT_NULL(path_join(low, long_name));

        other_padding = ASSERT_NOT_NULL(strrep(
                        "y", UNIT_NAME_MAX - 2 - STRLEN("@.target") - STRLEN("other-")));
        other_name = ASSERT_NOT_NULL(strjoin("other-", other_padding, "@.target"));
        ASSERT_EQ(strlen(other_name), (size_t) UNIT_NAME_MAX - 2);
        other_template = ASSERT_NOT_NULL(path_join(low, other_name));

        max_padding = ASSERT_NOT_NULL(strrep(
                        "z", UNIT_NAME_MAX - 1 - STRLEN("@.target") - STRLEN("max-")));
        max_name = ASSERT_NOT_NULL(strjoin("max-", max_padding, "@.target"));
        ASSERT_EQ(strlen(max_name), (size_t) UNIT_NAME_MAX - 1);
        max_template = ASSERT_NOT_NULL(path_join(low, max_name));

        FOREACH_ARGUMENT(
                        entry,
                        duplicate_high,
                        duplicate_low,
                        local_unit,
                        regular,
                        real,
                        concrete,
                        long_template,
                        other_template,
                        max_template)
                ASSERT_OK(write_string_file(
                                entry,
                                "[Unit]\n",
                                WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(write_string_file(
                        template,
                        "[Unit]\nUnknownTemplateSetting=yes\n",
                        WRITE_STRING_FILE_CREATE));

        ASSERT_OK_ERRNO(symlink("missing.service", broken));
        ASSERT_OK_ERRNO(symlink("real.service", alias));
        ASSERT_OK_ERRNO(symlink("/dev/null", masked));
        ASSERT_OK_ERRNO(symlink("/dev/null", template_mask));
        ASSERT_OK(mkdir_p(runtime, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", runtime_masked));

        /* Each of these one-character-capacity templates has a free instance, but no instance is free
         * for both. This makes a global instance choice impossible while per-template choices work. */
        mask_single_character_instances_except(high, long_name, "a");
        mask_single_character_instances_except(high, other_name, "b");

        ASSERT_OK(verify_varlink_collect_unit_files(
                        RUNTIME_SCOPE_SYSTEM,
                        tmp,
                        &paths,
                        &lookup_path));

        ASSERT_EQ(strv_length(paths), 10u);
        FOREACH_ARGUMENT(entry, duplicate_high, real, local_unit, broken, max_template, regular, concrete)
                ASSERT_TRUE(strv_contains(paths, entry));
        FOREACH_ARGUMENT(
                        entry,
                        duplicate_low,
                        template,
                        long_template,
                        other_template,
                        alias,
                        masked,
                        runtime_masked)
                ASSERT_FALSE(strv_contains(paths, entry));

        ASSERT_OK(path_extract_filename(template, &template_name));

        const char *template_instance_path = NULL, *long_instance_path = NULL, *other_instance_path = NULL;
        STRV_FOREACH(candidate_path, paths) {
                _cleanup_free_ char *candidate_template = NULL;
                const char *name = last_path_component(*candidate_path);

                if (!unit_name_is_valid(name, UNIT_NAME_INSTANCE))
                        continue;

                ASSERT_OK(unit_name_template(name, &candidate_template));
                if (streq(candidate_template, template_name) && !path_equal(*candidate_path, concrete))
                        template_instance_path = *candidate_path;
                else if (streq(candidate_template, long_name))
                        long_instance_path = *candidate_path;
                else if (streq(candidate_template, other_name))
                        other_instance_path = *candidate_path;
        }

        ASSERT_NOT_NULL(template_instance_path);
        ASSERT_NOT_NULL(long_instance_path);
        ASSERT_NOT_NULL(other_instance_path);

        _cleanup_free_ char *template_instance = NULL, *long_instance = NULL, *other_instance = NULL;
        ASSERT_EQ(unit_name_to_instance(last_path_component(template_instance_path), &template_instance),
                  UNIT_NAME_INSTANCE);
        ASSERT_EQ(unit_name_to_instance(last_path_component(long_instance_path), &long_instance),
                  UNIT_NAME_INSTANCE);
        ASSERT_EQ(unit_name_to_instance(last_path_component(other_instance_path), &other_instance),
                  UNIT_NAME_INSTANCE);
        ASSERT_TRUE(unit_instance_is_valid(template_instance));
        ASSERT_FALSE(STR_IN_SET(template_instance, "a", "b"));
        ASSERT_EQ(strlen(long_instance), 1u);
        ASSERT_EQ(strlen(other_instance), 1u);
        ASSERT_FALSE(streq(long_instance, other_instance));
        ASSERT_EQ(strlen(last_path_component(long_instance_path)), (size_t) UNIT_NAME_MAX - 1);
        ASSERT_EQ(strlen(last_path_component(other_instance_path)), (size_t) UNIT_NAME_MAX - 1);

        ASSERT_NOT_NULL(strchr(tmp, ':'));
        ASSERT_TRUE(strv_contains(lookup_path, high));
        ASSERT_TRUE(strv_contains(lookup_path, local));
        ASSERT_TRUE(strv_contains(lookup_path, low));

        const VerifyUnitsParameters parameters = {
                .filenames = paths,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .root = tmp,
                .instance = "test_instance",
                .lookup_path_override = lookup_path,
                .suppress_output = true,
        };

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping verification, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);

        bool found_invalid_template = false, found_uninstantiable_template = false;
        FOREACH_ARRAY(diagnostic, result.diagnostics, result.n_diagnostics) {
                if (streq_ptr(diagnostic->unit, last_path_component(template_instance_path)) &&
                    streq_ptr(diagnostic->configuration_file, template) &&
                    streq_ptr(diagnostic->message_id, SD_MESSAGE_INVALID_CONFIGURATION_STR)) {
                        found_invalid_template = true;
                        continue;
                }

                if (!diagnostic->unit &&
                    streq_ptr(diagnostic->configuration_file, max_template) &&
                    startswith(diagnostic->message, "Failed to prepare filename "))
                        found_uninstantiable_template = true;
        }
        ASSERT_TRUE(found_invalid_template);
        ASSERT_TRUE(found_uninstantiable_template);
}

TEST(scan_lookup_path_override) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_strv_free_ char **paths = NULL, **lookup_path = NULL;
        _cleanup_free_ char *control = NULL, *low = NULL, *main = NULL, *shadow = NULL, *mask = NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-analyze-verify-varlink-path.XXXXXX", &tmp));
        control = ASSERT_NOT_NULL(path_join(tmp, "/run/systemd/system.control"));
        low = ASSERT_NOT_NULL(path_join(tmp, SYSTEM_DATA_UNIT_DIR));
        main = ASSERT_NOT_NULL(path_join(low, "main.target"));
        shadow = ASSERT_NOT_NULL(path_join(low, "shadowed.target"));
        mask = ASSERT_NOT_NULL(path_join(control, "shadowed.target"));

        ASSERT_OK(write_string_file(
                        main,
                        "[Unit]\nRequires=shadowed.target\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(write_string_file(shadow, "[Unit]\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(mkdir_p(control, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", mask));

        ASSERT_OK(verify_varlink_collect_unit_files(
                        RUNTIME_SCOPE_SYSTEM,
                        tmp,
                        &paths,
                        &lookup_path));
        ASSERT_TRUE(strv_equal(paths, STRV_MAKE(main)));
        ASSERT_TRUE(strv_contains(lookup_path, control));
        ASSERT_TRUE(strv_contains(lookup_path, low));

        const VerifyUnitsParameters parameters = {
                .filenames = paths,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .root = tmp,
                .instance = "test_instance",
                .lookup_path_override = lookup_path,
                .suppress_output = true,
        };

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping verification, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_LT(result.legacy_status, 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
