/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

char* setup_fake_runtime_dir(void);
const char* get_testdata_dir(void);
const char* get_catalog_dir(void);
bool slow_tests_enabled(void);
int log_tests_skipped(const char *message);
