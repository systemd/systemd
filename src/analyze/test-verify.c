/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-messages.h"

#include "analyze-verify-util.h"
#include "env-util.h"
#include "execute.h"
#include "fileio.h"
#include "manager.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unit-name.h"

TEST(verify_nonexistent) {
        /* Negative cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/non/existent"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/non/existent"}, NULL) < 0);

        /* Ordinary cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/bin/echo"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/bin/echo"}, NULL) == 0);
}

static void test_verify_build_unit_path_one(const char *old, const char *expected) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *unit = NULL, *unit_path = NULL;
        char *unit_paths[2];

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify.XXXXXX", &tmp));
        unit = ASSERT_NOT_NULL(path_join(tmp, "test.service"));
        ASSERT_OK(write_string_file(unit, "[Unit]\nDescription=test\n", WRITE_STRING_FILE_CREATE));

        if (old)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));

        unit_paths[0] = unit;
        unit_paths[1] = NULL;

        if (expected) {
                ASSERT_OK(verify_build_unit_path(unit_paths, &unit_path));
                ASSERT_STREQ(unit_path, strjoina(tmp, expected));
        } else
                ASSERT_ERROR(verify_build_unit_path(unit_paths, &unit_path), EINVAL);

        ASSERT_TRUE(streq_ptr(getenv("SYSTEMD_UNIT_PATH"), old));
}

TEST(verify_build_unit_path) {
        _cleanup_free_ char *old_saved = getenv("SYSTEMD_UNIT_PATH") ? strdup(getenv("SYSTEMD_UNIT_PATH")) : NULL;
        ASSERT_TRUE(old_saved || !getenv("SYSTEMD_UNIT_PATH"));

        test_verify_build_unit_path_one(/* old= */ NULL, ":");
        test_verify_build_unit_path_one("", "");
        test_verify_build_unit_path_one(":", ":");
        test_verify_build_unit_path_one("/foo:", ":/foo:");
        test_verify_build_unit_path_one(":foo", /* expected= */ NULL);
        test_verify_build_unit_path_one("/foo::/bar", /* expected= */ NULL);

        if (old_saved)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old_saved, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));
}

TEST(manager_unit_path_override) {
        RuntimeScope scope;

        FOREACH_ARGUMENT(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER) {
                _cleanup_(manager_freep) Manager *m = NULL;

                ASSERT_OK(manager_new(scope, MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR, &m));
                ASSERT_OK(manager_set_unit_path_override(m, "/tmp/unit-path"));
                ASSERT_STREQ(m->unit_path_override, "/tmp/unit-path");

                manager_set_unit_name_map_limit(m, 123);
                ASSERT_EQ(m->unit_name_map_limit, 123u);

                if (scope == RUNTIME_SCOPE_USER)
                        ASSERT_STREQ(
                                        strv_env_get(m->transient_environment, "SYSTEMD_UNIT_PATH"),
                                        "/tmp/unit-path");
                else
                        ASSERT_NULL(strv_env_get(m->transient_environment, "SYSTEMD_UNIT_PATH"));
        }
}

TEST(verify_input_limits) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {
                .legacy_status = -EUCLEAN,
        };
        char *filenames[] = { (char*) "a.service", (char*) "bb.service", NULL };
        const size_t exact_bytes = STRLEN("a.service") + 1 + STRLEN("bb.service") + 1;
        VerifyUnitsLimits limits = {
                .input_filenames_max = 2,
                .input_filename_bytes_max = exact_bytes,
        };
        size_t n_filenames = SIZE_MAX;

        ASSERT_OK(verify_check_input_filenames(filenames, &limits, &n_filenames));
        ASSERT_EQ(n_filenames, 2u);

        limits.input_filenames_max = 1;
        n_filenames = SIZE_MAX;
        ASSERT_ERROR(verify_check_input_filenames(filenames, &limits, &n_filenames), E2BIG);
        ASSERT_EQ(n_filenames, SIZE_MAX);

        limits.input_filenames_max = 2;
        limits.input_filename_bytes_max = exact_bytes - 1;
        ASSERT_ERROR(verify_check_input_filenames(filenames, &limits, &n_filenames), E2BIG);
        ASSERT_EQ(n_filenames, SIZE_MAX);

        limits = (VerifyUnitsLimits) {};
        ASSERT_OK(verify_check_input_filenames(filenames, &limits, &n_filenames));
        ASSERT_EQ(n_filenames, 2u);

        const VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
                .limits.input_filenames_max = 1,
        };

        ASSERT_ERROR(verify_units(&parameters, &result), E2BIG);
        ASSERT_ERROR(result.legacy_status, EUCLEAN);
        ASSERT_EQ(result.diagnostics.n_items, 0u);
}

static int add_bounded_diagnostic(VerifyDiagnostics *diagnostics) {
        return verify_diagnostics_add(
                        diagnostics,
                        LOG_WARNING,
                        "bounded diagnostic",
                        "bounded.service",
                        "/tmp/bounded.service",
                        7,
                        SD_MESSAGE_INVALID_CONFIGURATION_STR);
}

TEST(verify_diagnostic_limits) {
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics reference = {};
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics count_limited = {
                .items_max = 1,
        };
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics byte_limited = {};
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics unlimited = {};
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics overflow = {
                .n_bytes = SIZE_MAX,
        };
        ASSERT_OK_POSITIVE(add_bounded_diagnostic(&reference));
        const size_t exact_bytes =
                sizeof(VerifyDiagnostic) +
                STRLEN("bounded diagnostic") + 1 +
                STRLEN("bounded.service") + 1 +
                STRLEN("/tmp/bounded.service") + 1 +
                STRLEN(SD_MESSAGE_INVALID_CONFIGURATION_STR) + 1;
        ASSERT_EQ(reference.n_bytes, exact_bytes);

        ASSERT_OK_POSITIVE(add_bounded_diagnostic(&count_limited));
        const char *first_message = count_limited.items[0].message;
        ASSERT_ERROR(add_bounded_diagnostic(&count_limited), E2BIG);
        ASSERT_EQ(count_limited.n_items, 1u);
        ASSERT_EQ(count_limited.n_bytes, exact_bytes);
        ASSERT_PTR_EQ(count_limited.items[0].message, first_message);

        byte_limited.bytes_max = exact_bytes - 1;
        ASSERT_ERROR(add_bounded_diagnostic(&byte_limited), E2BIG);
        ASSERT_EQ(byte_limited.n_items, 0u);
        ASSERT_EQ(byte_limited.n_bytes, 0u);

        byte_limited.bytes_max = exact_bytes;
        ASSERT_OK_POSITIVE(add_bounded_diagnostic(&byte_limited));
        ASSERT_EQ(byte_limited.n_bytes, exact_bytes);

        ASSERT_OK_POSITIVE(add_bounded_diagnostic(&unlimited));
        ASSERT_OK_POSITIVE(add_bounded_diagnostic(&unlimited));
        ASSERT_EQ(unlimited.n_items, 2u);
        ASSERT_EQ(unlimited.n_bytes, exact_bytes * 2);

        ASSERT_ERROR(add_bounded_diagnostic(&overflow), E2BIG);
        ASSERT_EQ(overflow.n_items, 0u);
        overflow.n_bytes = 0;

        overflow.n_items = SIZE_MAX;
        ASSERT_ERROR(add_bounded_diagnostic(&overflow), E2BIG);
        ASSERT_EQ(overflow.n_items, SIZE_MAX);
        overflow.n_items = 0;
}

TEST(verify_discover_unit_names) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(manager_freep) Manager *user_m = NULL;
        _cleanup_strv_free_ char **names = NULL, **unlimited = NULL, **user_names = NULL;
        _cleanup_strv_free_ char **expected_user_names = NULL;
        _cleanup_free_ char *high = NULL, *low = NULL, *override = NULL;
        _cleanup_free_ char *winner = NULL, *long_padding = NULL, *long_name = NULL, *long_instance = NULL;
        _cleanup_free_ char *impossible_padding = NULL, *impossible_name = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify-discover.XXXXXX", &tmp));
        high = ASSERT_NOT_NULL(path_join(tmp, "high"));
        low = ASSERT_NOT_NULL(path_join(tmp, "low"));
        ASSERT_OK(mkdir_p(high, 0755));
        ASSERT_OK(mkdir_p(low, 0755));

        winner = ASSERT_NOT_NULL(path_join(high, "winner.service"));
        ASSERT_OK(write_string_file(winner, "[Unit]\n", WRITE_STRING_FILE_CREATE));
        FOREACH_STRING(
                        name,
                        "winner.service",
                        "alias.service",
                        "masked.service",
                        "bad-alias.service",
                        "real.service",
                        "worker@.service") {
                _cleanup_free_ char *path = ASSERT_NOT_NULL(path_join(low, name));

                ASSERT_OK(write_string_file(path, "[Unit]\n", WRITE_STRING_FILE_CREATE));
        }

        _cleanup_free_ char *alias = ASSERT_NOT_NULL(path_join(high, "alias.service"));
        _cleanup_free_ char *masked = ASSERT_NOT_NULL(path_join(high, "masked.service"));
        _cleanup_free_ char *invalid = ASSERT_NOT_NULL(path_join(high, "bad-alias.service"));
        _cleanup_free_ char *broken = ASSERT_NOT_NULL(path_join(high, "broken.service"));
        _cleanup_free_ char *loop_a = ASSERT_NOT_NULL(path_join(high, "loop-a.service"));
        _cleanup_free_ char *loop_b = ASSERT_NOT_NULL(path_join(high, "loop-b.service"));
        _cleanup_free_ char *template_collision = ASSERT_NOT_NULL(path_join(high, "worker@verify.service"));
        ASSERT_OK_ERRNO(symlink("real.service", alias));
        ASSERT_OK_ERRNO(symlink("/dev/null", masked));
        ASSERT_OK_ERRNO(symlink("wrong.socket", invalid));
        ASSERT_OK_ERRNO(symlink("missing.service", broken));
        ASSERT_OK_ERRNO(symlink("loop-b.service", loop_a));
        ASSERT_OK_ERRNO(symlink("loop-a.service", loop_b));
        ASSERT_OK_ERRNO(symlink("/dev/null", template_collision));

        /* Occupy every one-character instance. Shortlex selection must continue with "aa", rather
         * than jumping to a longer numeric spelling and overlooking an available short instance. */
        for (const char *p = ALPHANUMERICAL ":-_.\\@"; *p; p++) {
                _cleanup_free_ char *instance = strndup(p, 1), *unit_name = NULL, *path = NULL;

                ASSERT_NOT_NULL(instance);
                ASSERT_OK(unit_name_replace_instance("worker@.service", instance, &unit_name));
                path = ASSERT_NOT_NULL(path_join(high, unit_name));
                ASSERT_OK_ERRNO(symlink("/dev/null", path));
        }

        _cleanup_free_ char *instance_dropin =
                ASSERT_NOT_NULL(path_join(low, "worker@prod.service.d/override.conf"));
        ASSERT_OK(write_string_file(
                        instance_dropin,
                        "[Unit]\nUnknownSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        _cleanup_free_ char *slice_dropin =
                ASSERT_NOT_NULL(path_join(low, "plain.slice.d/override.conf"));
        ASSERT_OK(write_string_file(
                        slice_dropin,
                        "[Unit]\nUnknownSliceSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        _cleanup_free_ char *device_dropin =
                ASSERT_NOT_NULL(path_join(low, "dev-test.device.d/override.conf"));
        ASSERT_OK(write_string_file(
                        device_dropin,
                        "[Unit]\nUnknownDeviceSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        _cleanup_free_ char *builtin_dropin =
                ASSERT_NOT_NULL(path_join(low, "basic.target.d/override.conf"));
        ASSERT_OK(write_string_file(
                        builtin_dropin,
                        "[Unit]\nUnknownBuiltinSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        FOREACH_STRING(
                        name,
                        "invalid@x.slice.d",
                        "invalid@.slice.d",
                        "invalid@x.device.d",
                        "invalid@.device.d") {
                _cleanup_free_ char *path = ASSERT_NOT_NULL(path_join(low, name, "override.conf"));

                ASSERT_OK(write_string_file(
                                path,
                                "[Unit]\nUnknownInvalidSetting=yes\n",
                                WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        }

        long_padding = ASSERT_NOT_NULL(strrep(
                        "x", UNIT_NAME_MAX - 2 - STRLEN("@.service") - STRLEN("long-")));
        long_name = ASSERT_NOT_NULL(strjoin("long-", long_padding, "@.service"));
        ASSERT_EQ(strlen(long_name), (size_t) UNIT_NAME_MAX - 2);
        _cleanup_free_ char *long_path = ASSERT_NOT_NULL(path_join(low, long_name));
        ASSERT_OK(write_string_file(long_path, "[Unit]\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(unit_name_replace_instance(long_name, "a", &long_instance));

        impossible_padding = ASSERT_NOT_NULL(strrep(
                        "x", UNIT_NAME_MAX - 1 - STRLEN("@.service") - STRLEN("uninst-")));
        impossible_name = ASSERT_NOT_NULL(strjoin("uninst-", impossible_padding, "@.service"));
        ASSERT_EQ(strlen(impossible_name), (size_t) UNIT_NAME_MAX - 1);
        _cleanup_free_ char *impossible_path = ASSERT_NOT_NULL(path_join(low, impossible_name));
        ASSERT_OK(write_string_file(impossible_path, "[Unit]\n", WRITE_STRING_FILE_CREATE));

        _cleanup_free_ char *orphan = ASSERT_NOT_NULL(path_join(low, "orphan@x.service.d/override.conf"));
        ASSERT_OK(write_string_file(
                        orphan,
                        "[Unit]\nUnknownOrphanSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        override = ASSERT_NOT_NULL(strjoin(high, ":", low));

        ASSERT_OK(manager_new(
                        RUNTIME_SCOPE_SYSTEM,
                        MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR,
                        &m));
        ASSERT_OK(lookup_paths_init_full(
                        &m->lookup_paths,
                        RUNTIME_SCOPE_SYSTEM,
                        0,
                        /* root_dir= */ NULL,
                        override));

        ASSERT_OK(verify_discover_unit_names(m, "verify", 93, &names));
        ASSERT_EQ(hashmap_size(m->unit_id_map), 80u);
        ASSERT_EQ(set_size(m->unit_path_cache), 93u);
        ASSERT_TRUE(strv_equal(
                        names,
                        STRV_MAKE(
                                        "alias.service",
                                        "bad-alias.service",
                                        "basic.target",
                                        "broken.service",
                                        "dev-test.device",
                                        long_instance,
                                        "loop-a.service",
                                        "loop-b.service",
                                        "plain.slice",
                                        "real.service",
                                        impossible_name,
                                        "winner.service",
                                        "worker@aa.service",
                                        "worker@prod.service")));
        ASSERT_FALSE(strv_contains(names, "orphan@x.service"));
        ASSERT_FALSE(strv_contains(names, "invalid@x.slice"));
        ASSERT_FALSE(strv_contains(names, "invalid@.slice"));
        ASSERT_FALSE(strv_contains(names, "invalid@x.device"));
        ASSERT_FALSE(strv_contains(names, "invalid@.device"));

        const char *winner_fragment = NULL;
        ASSERT_OK(unit_file_find_fragment(
                        m->unit_id_map,
                        m->unit_name_map,
                        "winner.service",
                        &winner_fragment,
                        /* ret_names= */ NULL));
        ASSERT_STREQ(winner_fragment, winner);

        char **unchanged = names;
        ASSERT_ERROR(verify_discover_unit_names(m, "verify", 92, &unchanged), E2BIG);
        ASSERT_PTR_EQ(unchanged, names);

        ASSERT_OK(verify_discover_unit_names(m, "verify", /* max_names= */ 0, &unlimited));
        ASSERT_TRUE(strv_equal(unlimited, names));

        ASSERT_OK(manager_new(
                        RUNTIME_SCOPE_USER,
                        MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR,
                        &user_m));
        ASSERT_OK(lookup_paths_init_full(
                        &user_m->lookup_paths,
                        RUNTIME_SCOPE_USER,
                        0,
                        /* root_dir= */ NULL,
                        override));
        ASSERT_OK(verify_discover_unit_names(user_m, "verify", 93, &user_names));
        expected_user_names = ASSERT_NOT_NULL(strv_copy(names));
        strv_remove(expected_user_names, "basic.target");
        ASSERT_TRUE(strv_equal(user_names, expected_user_names));
}

static VerifyDiagnostic* find_diagnostic(
                VerifyUnitsResult *result,
                const char *unit,
                const char *configuration_file,
                const char *message_id) {

        FOREACH_ARRAY(diagnostic, result->diagnostics.items, result->diagnostics.n_items)
                if (streq_ptr(diagnostic->unit, unit) &&
                    streq_ptr(diagnostic->configuration_file, configuration_file) &&
                    streq_ptr(diagnostic->message_id, message_id))
                        return diagnostic;

        return NULL;
}

TEST(verify_units_scan) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *unit_dir = NULL;
        _cleanup_free_ char *bad = NULL, *template = NULL, *concrete = NULL, *dropin = NULL;
        _cleanup_free_ char *alias = NULL, *broken = NULL, *loop_a = NULL, *loop_b = NULL;
        _cleanup_free_ char *load_error = NULL, *load_error_alias = NULL, *orphan = NULL;
        _cleanup_free_ char *slice_dropin = NULL, *builtin_dropin = NULL;
        _cleanup_free_ char *generated = NULL, *transient = NULL;
        _cleanup_free_ char *impossible_padding = NULL, *impossible_name = NULL, *impossible = NULL;
        _cleanup_free_ char *executable = NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify-scan.XXXXXX", &tmp));
        unit_dir = ASSERT_NOT_NULL(strjoin(tmp, SYSTEM_DATA_UNIT_DIR));
        executable = ASSERT_NOT_NULL(path_join(tmp, "/bin/true"));
        ASSERT_OK(write_string_file(
                        executable, "", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK_ERRNO(chmod(executable, 0755));

        bad = ASSERT_NOT_NULL(path_join(unit_dir, "bad.service"));
        template = ASSERT_NOT_NULL(path_join(unit_dir, "collision@.service"));
        concrete = ASSERT_NOT_NULL(path_join(unit_dir, "collision@verify.service"));
        dropin = ASSERT_NOT_NULL(path_join(unit_dir, "collision@prod.service.d/override.conf"));
        ASSERT_OK(write_string_file(
                        bad,
                        "[Unit]\nUnknownSetting=yes\n[Service]\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(write_string_file(
                        template,
                        "[Unit]\nUnknownTemplateSetting=yes\n[Service]\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(
                        concrete,
                        "[Service]\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(
                        dropin,
                        "[Unit]\nUnknownDropinSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        load_error = ASSERT_NOT_NULL(path_join(unit_dir, "load-error.service"));
        ASSERT_OK(write_string_file(load_error, "[Service]\n", WRITE_STRING_FILE_CREATE));

        impossible_padding = ASSERT_NOT_NULL(strrep(
                        "x", UNIT_NAME_MAX - 1 - STRLEN("@.service") - STRLEN("uninst-")));
        impossible_name = ASSERT_NOT_NULL(strjoin("uninst-", impossible_padding, "@.service"));
        impossible = ASSERT_NOT_NULL(path_join(unit_dir, impossible_name));
        ASSERT_OK(write_string_file(impossible, "[Unit]\n", WRITE_STRING_FILE_CREATE));

        orphan = ASSERT_NOT_NULL(path_join(unit_dir, "orphan@x.service.d/override.conf"));
        ASSERT_OK(write_string_file(
                        orphan,
                        "[Unit]\nUnknownOrphanSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        slice_dropin = ASSERT_NOT_NULL(path_join(unit_dir, "plain.slice.d/override.conf"));
        ASSERT_OK(write_string_file(
                        slice_dropin,
                        "[Unit]\nUnknownSliceSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        builtin_dropin = ASSERT_NOT_NULL(path_join(unit_dir, "basic.target.d/override.conf"));
        ASSERT_OK(write_string_file(
                        builtin_dropin,
                        "[Unit]\nUnknownBuiltinSetting=yes\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        generated = ASSERT_NOT_NULL(path_join(tmp, "/run/systemd/generator/generated.service"));
        transient = ASSERT_NOT_NULL(path_join(tmp, "/run/systemd/transient/transient.service"));
        ASSERT_OK(write_string_file(
                        generated,
                        "[Unit]\nUnknownGeneratedSetting=yes\n[Service]\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(write_string_file(
                        transient,
                        "[Unit]\nUnknownTransientSetting=yes\n[Service]\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        alias = ASSERT_NOT_NULL(path_join(unit_dir, "alias.service"));
        broken = ASSERT_NOT_NULL(path_join(unit_dir, "broken.service"));
        loop_a = ASSERT_NOT_NULL(path_join(unit_dir, "loop-a.service"));
        loop_b = ASSERT_NOT_NULL(path_join(unit_dir, "loop-b.service"));
        load_error_alias = ASSERT_NOT_NULL(path_join(unit_dir, "load-error-alias.service"));
        ASSERT_OK_ERRNO(symlink("bad.service", alias));
        ASSERT_OK_ERRNO(symlink("missing.service", broken));
        ASSERT_OK_ERRNO(symlink("loop-b.service", loop_a));
        ASSERT_OK_ERRNO(symlink("loop-a.service", loop_b));
        ASSERT_OK_ERRNO(symlink("load-error.service", load_error_alias));

        VerifyUnitsParameters parameters = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "verify",
                .root = tmp,
                .suppress_output = true,
        };

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_OK_ERRNO(access(generated, F_OK));
        ASSERT_OK_ERRNO(access(transient, F_OK));
        ASSERT_LT(result.legacy_status, 0);

        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "collision@a.service", template, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "collision@prod.service", dropin, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "broken.service", broken, /* message_id= */ NULL));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "loop-a.service", loop_a, /* message_id= */ NULL));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, impossible_name, impossible, /* message_id= */ NULL));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "plain.slice", slice_dropin, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "basic.target", builtin_dropin, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "generated.service", generated, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "transient.service", transient, SD_MESSAGE_INVALID_CONFIGURATION_STR));

        size_t n_load_error = 0;
        FOREACH_ARRAY(diagnostic, result.diagnostics.items, result.diagnostics.n_items)
                if (streq_ptr(diagnostic->configuration_file, load_error) &&
                    !diagnostic->message_id)
                        n_load_error++;
        ASSERT_EQ(n_load_error, 1u);

        FOREACH_ARRAY(diagnostic, result.diagnostics.items, result.diagnostics.n_items)
                ASSERT_FALSE(streq_ptr(diagnostic->unit, "orphan@x.service"));

        size_t n_bad = 0;
        FOREACH_ARRAY(diagnostic, result.diagnostics.items, result.diagnostics.n_items)
                if (streq_ptr(diagnostic->configuration_file, bad) &&
                    streq_ptr(diagnostic->message_id, SD_MESSAGE_INVALID_CONFIGURATION_STR))
                        n_bad++;
        ASSERT_EQ(n_bad, 1u);

        const bool had_unit_path = getenv("SYSTEMD_UNIT_PATH");
        const bool had_generator_path = getenv("SYSTEMD_GENERATOR_PATH");
        _cleanup_free_ char *old_unit_path = had_unit_path ? strdup(getenv("SYSTEMD_UNIT_PATH")) : NULL;
        _cleanup_free_ char *old_generator_path =
                had_generator_path ? strdup(getenv("SYSTEMD_GENERATOR_PATH")) : NULL;
        ASSERT_TRUE(old_unit_path || !had_unit_path);
        ASSERT_TRUE(old_generator_path || !had_generator_path);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", ":", 1));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_GENERATOR_PATH", "", 1));

        verify_units_result_done(&result);
        parameters.run_unit_generators = true;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "transient.service", transient, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_OK_ERRNO(access(transient, F_OK));

        if (had_unit_path)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old_unit_path, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));
        if (had_generator_path)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_GENERATOR_PATH", old_generator_path, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_GENERATOR_PATH"));

        parameters.run_unit_generators = false;

        verify_units_result_done(&result);
        result.legacy_status = -EUCLEAN;
        parameters.limits.unit_name_map_max = 1;
        ASSERT_ERROR(verify_units(&parameters, &result), E2BIG);
        ASSERT_ERROR(result.legacy_status, EUCLEAN);
        ASSERT_EQ(result.diagnostics.n_items, 0u);
}

TEST(verify_units_result) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *bad = NULL, *invalid = NULL, *load_error = NULL, *missing = NULL, *parse = NULL;
        char *filenames[3];
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify.XXXXXX", &tmp));
        bad = ASSERT_NOT_NULL(path_join(tmp, "bad.service"));
        invalid = ASSERT_NOT_NULL(path_join(tmp, "invalid"));
        load_error = ASSERT_NOT_NULL(path_join(tmp, "load-error.service"));
        missing = ASSERT_NOT_NULL(path_join(tmp, "missing.service"));
        parse = ASSERT_NOT_NULL(path_join(tmp, "parse.service"));
        ASSERT_OK(write_string_file(
                        bad,
                        "[Unit]\nUnknownSetting=yes\n[Service]\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(load_error, "[Service]\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(
                        parse,
                        "[Service]\nRemainAfterExit=invalid\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE));

        VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = _RECURSIVE_ERRORS_INVALID,
                .instance = "test_instance",
                .suppress_output = true,
        };

        filenames[0] = bad;
        filenames[1] = NULL;
        filenames[2] = NULL;

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_EQ(result.legacy_status, 0);

        VerifyDiagnostic *diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, "bad.service", bad, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_STREQ(diagnostic->configuration_file, bad);
        ASSERT_EQ(diagnostic->configuration_line, 2u);

        verify_units_result_done(&result);
        parameters.recursive_errors = RECURSIVE_ERRORS_NO;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, ENOTRECOVERABLE);

        /* Diagnostics and recursive error handling must not depend on the selected log verbosity. The
         * unknown-key path is gated by log_syntax_enabled(), while parse errors call log_syntax_internal()
         * directly, so keep both cases covered. */
        int old_max_level = log_set_max_level(LOG_ERR);

        verify_units_result_done(&result);
        parameters.suppress_output = false;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, ENOTRECOVERABLE);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "bad.service", bad, SD_MESSAGE_INVALID_CONFIGURATION_STR));

        verify_units_result_done(&result);
        filenames[0] = parse;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, ENOTRECOVERABLE);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "parse.service", parse, SD_MESSAGE_INVALID_CONFIGURATION_STR));

        log_set_max_level(old_max_level);
        parameters.suppress_output = true;

        verify_units_result_done(&result);
        filenames[0] = load_error;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_LT(result.legacy_status, 0);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, "load-error.service", load_error, /* message_id= */ NULL));
        ASSERT_STREQ(diagnostic->configuration_file, load_error);

        verify_units_result_done(&result);
        filenames[0] = missing;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_LT(result.legacy_status, 0);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, "missing.service", missing, /* message_id= */ NULL));
        ASSERT_STREQ(diagnostic->configuration_file, missing);

        verify_units_result_done(&result);
        filenames[0] = invalid;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, EINVAL);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, /* unit= */ NULL, invalid, /* message_id= */ NULL));
        ASSERT_STREQ(diagnostic->configuration_file, invalid);

        verify_units_result_done(&result);
        result.legacy_status = -EUCLEAN;
        parameters.limits.unit_name_map_max = 1;
        filenames[0] = bad;
        ASSERT_ERROR(verify_units(&parameters, &result), E2BIG);
        ASSERT_ERROR(result.legacy_status, EUCLEAN);
        ASSERT_EQ(result.diagnostics.n_items, 0u);

        /* Both callback-collected and directly synthesized diagnostics must turn a limit hit into an
         * atomic operational failure. */
        verify_units_result_done(&result);
        result.legacy_status = -EUCLEAN;
        parameters.limits.unit_name_map_max = 0;
        parameters.limits.diagnostic_bytes_max = 1;
        filenames[0] = bad;
        ASSERT_ERROR(verify_units(&parameters, &result), E2BIG);
        ASSERT_ERROR(result.legacy_status, EUCLEAN);
        ASSERT_EQ(result.diagnostics.n_items, 0u);

        filenames[0] = invalid;
        ASSERT_ERROR(verify_units(&parameters, &result), E2BIG);
        ASSERT_ERROR(result.legacy_status, EUCLEAN);
        ASSERT_EQ(result.diagnostics.n_items, 0u);

        verify_units_result_done(&result);
        result.legacy_status = -EUCLEAN;
        parameters.limits.diagnostic_bytes_max = 0;
        parameters.limits.diagnostics_max = 1;
        filenames[0] = bad;
        filenames[1] = invalid;
        ASSERT_ERROR(verify_units(&parameters, &result), E2BIG);
        ASSERT_ERROR(result.legacy_status, EUCLEAN);
        ASSERT_EQ(result.diagnostics.n_items, 0u);
}

TEST(verify_units_cycles) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_free_ char *unit_dir = NULL, *unbreakable = NULL, *breakable = NULL;
        char *filenames[2];
        int r;

        ASSERT_OK(get_testdata_dir("test-engine", &unit_dir));
        unbreakable = ASSERT_NOT_NULL(path_join(unit_dir, "d.service"));
        breakable = ASSERT_NOT_NULL(path_join(unit_dir, "e.service"));

        VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
                .suppress_output = true,
        };

        filenames[0] = unbreakable;
        filenames[1] = NULL;

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_LT(result.legacy_status, 0);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, /* unit= */ NULL, /* configuration_file= */ NULL,
                        SD_MESSAGE_UNIT_ORDERING_CYCLE_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, /* unit= */ NULL, /* configuration_file= */ NULL,
                        SD_MESSAGE_CANT_BREAK_ORDERING_CYCLE_STR));

        verify_units_result_done(&result);
        filenames[0] = breakable;

        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_OK(result.legacy_status);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, /* unit= */ NULL, /* configuration_file= */ NULL,
                        SD_MESSAGE_UNIT_ORDERING_CYCLE_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, /* unit= */ NULL, /* configuration_file= */ NULL,
                        SD_MESSAGE_DELETING_JOB_BECAUSE_ORDERING_CYCLE_STR));
}

TEST(verify_units_manager_diagnostics) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *warning = NULL, *unsafe = NULL, *nobody = NULL;
        char *filenames[2];
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify-diagnostics.XXXXXX", &tmp));
        warning = ASSERT_NOT_NULL(path_join(tmp, "warning.service"));
        unsafe = ASSERT_NOT_NULL(path_join(tmp, "unsafe.service"));
        nobody = ASSERT_NOT_NULL(path_join(tmp, "nobody.service"));
        ASSERT_OK(write_string_file(
                        warning,
                        "[Service]\nType=oneshot\nRuntimeMaxSec=1s\nExecStart=true\n",
                        WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(
                        unsafe,
                        "[Service]\nUser=unsafe@name\nExecStart=true\n",
                        WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(
                        nobody,
                        "[Service]\nUser=nobody\nExecStart=true\n",
                        WRITE_STRING_FILE_CREATE));

        VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
                .suppress_output = true,
        };

        filenames[0] = warning;
        filenames[1] = NULL;

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_OK(result.legacy_status);

        bool found = false;
        FOREACH_ARRAY(diagnostic, result.diagnostics.items, result.diagnostics.n_items)
                if (streq_ptr(diagnostic->unit, "warning.service") &&
                    strstr(diagnostic->message, "RuntimeMaxSec=")) {
                        found = true;
                        break;
                }
        ASSERT_TRUE(found);

        verify_units_result_done(&result);
        filenames[0] = unsafe;

        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_OK(result.legacy_status);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, /* unit= */ NULL, /* configuration_file= */ NULL,
                        SD_MESSAGE_UNSAFE_USER_NAME_STR));

        verify_units_result_done(&result);
        filenames[0] = nobody;

        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_OK(result.legacy_status);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "nobody.service", nobody, SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
