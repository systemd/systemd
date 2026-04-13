/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int verb_show_environment(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_set_environment(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_import_environment(int argc, char *argv[], uintptr_t _data, void *userdata);
