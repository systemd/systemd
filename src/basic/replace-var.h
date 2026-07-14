/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

char* replace_var(const char *text, char *(*lookup)(const char *variable, void *userdata), void *userdata);
