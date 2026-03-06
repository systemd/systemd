/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "shared-forward.h"

int verb_cat_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_info_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_trigger_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_settle_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_control_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_monitor_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_hwdb_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_test_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_builtin_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_verify_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_wait_main(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_lock_main(int argc, char *argv[], uintptr_t _data, void *userdata);

int print_version(void);
