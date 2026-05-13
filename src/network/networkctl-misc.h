/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int verb_link_delete(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_link_varlink_simple_method(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_reload(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_persistent_storage(int argc, char *argv[], uintptr_t _data, void *userdata);
