/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-daemon.h"

#include "macro.h"

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
