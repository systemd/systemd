/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "sd-daemon.h"

#include "env-util.h"
#include "string-util.h"

#define TEST_REQ_RUNNING_SYSTEMD(x)                                 \
        if (sd_booted() > 0) {                                      \
                x;                                                  \
        } else {                                                    \
                printf("systemd not booted skipping '%s'\n", #x);   \
        }

#define MANAGER_SKIP_TEST(r)                                    \
        IN_SET(r,                                               \
               -EPERM,                                          \
               -EACCES,                                         \
               -EADDRINUSE,                                     \
               -EHOSTDOWN,                                      \
               -ENOENT,                                         \
               -ENOMEDIUM /* cannot determine cgroup */         \
               )

char* setup_fake_runtime_dir(void);
const char* get_testdata_dir(void);
const char* get_catalog_dir(void);
bool slow_tests_enabled(void);
void test_setup_logging(int level);
int log_tests_skipped(const char *message);
int log_tests_skipped_errno(int r, const char *message);

bool have_namespaces(void);

/* https://docs.travis-ci.com/user/environment-variables#default-environment-variables */
static inline bool is_run_on_travis_ci(void) {
        return streq_ptr(getenv("TRAVIS"), "true");
}

static inline bool is_run_with_partial_msan(void) {
        return HAS_FEATURE_MEMORY_SANITIZER &&
                getenv_bool("MSAN_FULLY_INSTRUMENTED") == 0;
}
