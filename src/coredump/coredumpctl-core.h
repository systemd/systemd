/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int acquire_core(sd_journal *j, int fd, char **ret_tmpfile, char **ret_path);

int verb_dump_core(int argc, char *argv[], uintptr_t _data, void *userdata);
