/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int save_core(sd_journal *j, FILE *file, char **path, bool *unlink_temp);

int verb_dump_core(int argc, char *argv[], uintptr_t _data, void *userdata);
