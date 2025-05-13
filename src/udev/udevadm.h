/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "forward.h"

int cat_main(int argc, char *argv[], void *userdata);
int info_main(int argc, char *argv[], void *userdata);
int trigger_main(int argc, char *argv[], void *userdata);
int settle_main(int argc, char *argv[], void *userdata);
int control_main(int argc, char *argv[], void *userdata);
int monitor_main(int argc, char *argv[], void *userdata);
int hwdb_main(int argc, char *argv[], void *userdata);
int test_main(int argc, char *argv[], void *userdata);
int builtin_main(int argc, char *argv[], void *userdata);
int verify_main(int argc, char *argv[], void *userdata);
int wait_main(int argc, char *argv[], void *userdata);
int lock_main(int argc, char *argv[], void *userdata);

int print_version(void);
