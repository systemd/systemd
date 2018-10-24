/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

char* setup_fake_runtime_dir(void);
const char* get_testdata_dir(void);
const char* get_catalog_dir(void);
bool slow_tests_enabled(void);
void test_setup_logging(int level);
int log_tests_skipped(const char *message);
int log_tests_skipped_errno(int r, const char *message);

bool have_namespaces(void);
