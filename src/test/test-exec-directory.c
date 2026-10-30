/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "cgroup.h"
#include "dbus-execute.h"
#include "dynamic-user.h"
#include "execute-serialize.h"
#include "execute.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "load-fragment.h"
#include "manager.h"
#include "rm-rf.h"
#include "service.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "unit.h"

static char *runtime_dir = NULL;

STATIC_DESTRUCTOR_REGISTER(runtime_dir, rm_rf_physical_and_freep);

static const char* const paths[] = {
        "plain", "with space", "with'quote", "with\"quote", "with:colon",
        "with\\backslash", "with\ttab", "with\nnewline", "with%specifier", "private-other",
};

static void assert_directory(
                const ExecDirectory *d,
                const char *source,
                const char *destination,
                ExecDirectoryFlags flags) {
        ASSERT_EQ(d->n_items, 1U);
        ASSERT_STREQ(d->items[0].path, source);
        ASSERT_EQ(d->items[0].flags, flags);
        if (isempty(destination))
                ASSERT_TRUE(strv_isempty(d->items[0].symlinks));
        else {
                ASSERT_EQ(strv_length(d->items[0].symlinks), 1U);
                ASSERT_STREQ(d->items[0].symlinks[0], destination);
        }
}

static void test_transient_directory_one(
                sd_bus *bus,
                Manager *manager,
                ExecDirectoryType type,
                const char *source,
                const char *destination,
                bool tuple,
                uint64_t flags,
                int expected) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(exec_context_done) ExecContext context = {};
        _cleanup_(exec_directory_done) ExecDirectory parsed = {};
        _cleanup_free_ char *text = NULL;
        _cleanup_(unit_freep) Unit *unit = NULL;
        size_t size = 0;
        FILE *f;

        ASSERT_OK(unit_new_for_name(manager, sizeof(Service), "test-exec-directory.service", &unit));
        unit->last_section_private = 1;
        ASSERT_NOT_NULL(f = open_memstream_unlocked(&text, &size));
        unit->transient_file = f;

        ASSERT_OK(sd_bus_message_new(bus, &message, SD_BUS_MESSAGE_METHOD_CALL));
        if (tuple)
                ASSERT_OK(sd_bus_message_append(message, "a(sst)", 1, source, strempty(destination), flags));
        else
                ASSERT_OK(sd_bus_message_append(message, "as", 1, source));
        ASSERT_OK(sd_bus_message_seal(message, 1, 0));
        ASSERT_OK(sd_bus_message_rewind(message, true));

        /* Validate first without applying anything, matching the manager's two-pass handling. */
        ASSERT_EQ(bus_exec_context_set_transient_property(
                          unit, &context,
                          tuple ? exec_directory_type_symlink_to_string(type) : exec_directory_type_to_string(type),
                          message, 0, &error), expected);
        ASSERT_EQ(context.directories[type].n_items, 0U);
        sd_bus_error_free(&error);
        ASSERT_OK(sd_bus_message_rewind(message, true));

        ASSERT_EQ(bus_exec_context_set_transient_property(
                          unit, &context,
                          tuple ? exec_directory_type_symlink_to_string(type) : exec_directory_type_to_string(type),
                          message, UNIT_RUNTIME, &error), expected);
        if (expected < 0) {
                ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS));
                ASSERT_EQ(context.directories[type].n_items, 0U);
                return;
        }

        ASSERT_OK_ERRNO(fflush(f));
        assert_directory(&context.directories[type], source, destination, flags);
        char *value = ASSERT_NOT_NULL(strchr(text, '=')) + 1;
        delete_trailing_chars(value, "\n");
        ASSERT_OK(config_parse_exec_directories(
                          "test.service", "test.conf", 1, "Service", 1,
                          exec_directory_type_to_string(type), 0, value, &parsed, unit));
        assert_directory(&parsed, source, destination, flags);
}

TEST(transient_directory_roundtrip) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        ASSERT_OK(sd_bus_new(&bus));
        bus->state = BUS_RUNNING; /* Only construct messages locally; no bus connection is needed. */

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &manager);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_OK(manager_startup(manager, NULL, NULL, NULL, NULL));

        for (ExecDirectoryType type = 0; type < _EXEC_DIRECTORY_TYPE_MAX; type++) {
                FOREACH_ELEMENT(path, paths) {
                        test_transient_directory_one(bus, manager, type, *path,
                                                     /* destination= */ NULL, /* tuple= */ false,
                                                     /* flags= */ 0, 1);
                        FOREACH_ELEMENT(flags, ((const uint64_t[]) {
                                        0, EXEC_DIRECTORY_READ_ONLY, EXEC_DIRECTORY_ONLY_CREATE,
                                        UINT64_C(1) << 32, (UINT64_C(1) << 32) | EXEC_DIRECTORY_READ_ONLY,
                                        UINT64_C(1) << 63, UINT64_MAX })) {
                                bool valid_flags = (*flags & ~((uint64_t) _EXEC_DIRECTORY_FLAGS_PUBLIC)) == 0;

                                test_transient_directory_one(bus, manager, type, *path,
                                                             /* destination= */ NULL, /* tuple= */ true,
                                                             *flags, valid_flags ? 1 : -EINVAL);
                                test_transient_directory_one(bus, manager, type, "source", *path,
                                                             /* tuple= */ true, *flags,
                                                             valid_flags && type != EXEC_DIRECTORY_CONFIGURATION ? 1 : -EINVAL);
                        }
                }
                FOREACH_STRING(path, "private", "private/nested") {
                        test_transient_directory_one(bus, manager, type, path,
                                                     /* destination= */ NULL, /* tuple= */ true,
                                                     EXEC_DIRECTORY_READ_ONLY, -EINVAL);
                        test_transient_directory_one(bus, manager, type, "source", path,
                                                     /* tuple= */ true, EXEC_DIRECTORY_READ_ONLY, -EINVAL);
                }
        }
}

TEST(executor_directory_roundtrip) {
        FOREACH_ELEMENT(path, paths) {
                _cleanup_(exec_context_done) ExecContext context = {}, parsed = {};
                _cleanup_(exec_params_deep_clear) ExecParameters parameters = EXEC_PARAMETERS_INIT(0);
                _cleanup_(cgroup_context_done) CGroupContext cgroup = {};
                _cleanup_(exec_command_done) ExecCommand command = {};
                _cleanup_fdset_free_ FDSet *fds = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_(exec_shared_runtime_done) ExecSharedRuntime shared = {
                        .userns_storage_socket = EBADF_PAIR,
                        .netns_storage_socket = EBADF_PAIR,
                        .ipcns_storage_socket = EBADF_PAIR,
                };
                _cleanup_(dynamic_creds_done) DynamicCreds creds = {};
                _cleanup_(exec_runtime_clear) ExecRuntime runtime = {
                        .ephemeral_storage_socket = EBADF_PAIR,
                        .shared = &shared,
                        .dynamic_creds = &creds,
                };

                exec_context_init(&context);
                exec_context_init(&parsed);
                context.private_var_tmp = PRIVATE_TMP_DISCONNECTED;
                sd_id128_to_string(parameters.invocation_id, parameters.invocation_id_string);
                cgroup_context_init(&cgroup);
                ASSERT_NOT_NULL(fds = fdset_new());
                ASSERT_NOT_NULL(f = tmpfile());

                for (ExecDirectoryType type = 0; type < _EXEC_DIRECTORY_TYPE_MAX; type++)
                        ASSERT_OK(exec_directory_add(&context.directories[type], *path,
                                                     type == EXEC_DIRECTORY_CONFIGURATION ? NULL : *path,
                                                     EXEC_DIRECTORY_READ_ONLY));

                ASSERT_OK(exec_serialize_invocation(f, fds, &context, &command, &parameters, NULL, &cgroup));
                ASSERT_OK_ERRNO(fseek(f, 0, SEEK_SET));
                ASSERT_OK(exec_deserialize_invocation(f, fds, &parsed, &command, &parameters, &runtime, &cgroup));

                for (ExecDirectoryType type = 0; type < _EXEC_DIRECTORY_TYPE_MAX; type++)
                        assert_directory(&parsed.directories[type], *path,
                                         type == EXEC_DIRECTORY_CONFIGURATION ? NULL : *path,
                                         EXEC_DIRECTORY_READ_ONLY);
        }
}

TEST(fragment_private_destination) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_(unit_freep) Unit *unit = NULL;
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &manager);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_OK(manager_startup(manager, NULL, NULL, NULL, NULL));
        ASSERT_OK(unit_new_for_name(manager, sizeof(Service), "test-exec-directory.service", &unit));

        for (ExecDirectoryType type = 0; type < _EXEC_DIRECTORY_TYPE_MAX; type++) {
                /* This type rejects any destination before checking the reserved prefix. */
                if (type == EXEC_DIRECTORY_CONFIGURATION)
                        continue;

                FOREACH_STRING(value, "source:private", "source:private/nested") {
                        _cleanup_(exec_directory_done) ExecDirectory directory = {};

                        ASSERT_OK(config_parse_exec_directories(
                                          "test.service", "test.conf", 1, "Service", 1,
                                          exec_directory_type_to_string(type), 0, value, &directory, unit));
                        ASSERT_EQ(directory.n_items, 0U);
                }
        }
}

static int intro(void) {
        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
