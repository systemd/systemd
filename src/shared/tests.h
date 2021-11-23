/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-daemon.h"

#include "macro.h"
#include "util.h"

static inline bool manager_errno_skip_test(int r) {
        return IN_SET(abs(r),
                      EPERM,
                      EACCES,
                      EADDRINUSE,
                      EHOSTDOWN,
                      ENOENT,
                      ENOMEDIUM /* cannot determine cgroup */
        );
}

char* setup_fake_runtime_dir(void);
int enter_cgroup_subroot(char **ret_cgroup);
int enter_cgroup_root(char **ret_cgroup);
int get_testdata_dir(const char *suffix, char **ret);
const char* get_catalog_dir(void);
bool slow_tests_enabled(void);
void test_setup_logging(int level);
int log_tests_skipped(const char *message);
int log_tests_skipped_errno(int r, const char *message);

bool have_namespaces(void);

/* We use the small but non-trivial limit here */
#define CAN_MEMLOCK_SIZE (512 * 1024U)
bool can_memlock(void);

#define TEST_REQ_RUNNING_SYSTEMD(x)                                 \
        if (sd_booted() > 0) {                                      \
                x;                                                  \
        } else {                                                    \
                printf("systemd not booted skipping '%s'\n", #x);   \
        }

/* Provide a convenient way to check if we're running in CI. */
const char *ci_environment(void);

typedef struct TestFunc {
        void (*f)(void);
        const char * const n;
} TestFunc;

/* See static-destruct.h for an explanation of how this works. */
#define REGISTER_TEST(func)                                                              \
        static void func(void);                                                          \
        _section_("SYSTEMD_TEST_TABLE") _alignptr_ _used_ _variable_no_sanitize_address_ \
        static const TestFunc UNIQ_T(static_test_table_entry, UNIQ) = {                  \
                .f = &(func),                                                            \
                .n = STRINGIFY(func),                                                    \
        }

extern const TestFunc _weak_ __start_SYSTEMD_TEST_TABLE[];
extern const TestFunc _weak_ __stop_SYSTEMD_TEST_TABLE[];

#define TEST(name)                  \
        REGISTER_TEST(test_##name); \
        static void test_##name(void)

static inline void run_test_table(void) {
        if (!__start_SYSTEMD_TEST_TABLE)
                return;

        const TestFunc *t = ALIGN_TO_PTR(__start_SYSTEMD_TEST_TABLE, sizeof(TestFunc*));
        while (t < __stop_SYSTEMD_TEST_TABLE) {
                log_info("/* %s */", t->n);
                t->f();
                t = ALIGN_TO_PTR(t + 1, sizeof(TestFunc*));
        }
}

#define DEFINE_CUSTOM_TEST_MAIN(log_level, intro, outro) \
        int main(int argc, char *argv[]) {               \
                test_setup_logging(log_level);           \
                save_argc_argv(argc, argv);              \
                intro;                                   \
                run_test_table();                        \
                outro;                                   \
                return EXIT_SUCCESS;                     \
        }

#define DEFINE_TEST_MAIN(log_level) DEFINE_CUSTOM_TEST_MAIN(log_level, , )
