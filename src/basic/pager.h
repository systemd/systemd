/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "macro.h"
#include "static-destruct.h"

typedef enum PagerFlags {
        PAGER_DISABLE     = 1 << 0,
        PAGER_JUMP_TO_END = 1 << 1,
} PagerFlags;

extern pid_t pager_pid;

int pager_open(PagerFlags flags);
void pager_close(void);
bool pager_have(void) _pure_;

int show_man_page(const char *page, bool null_stdio);

void pager_closep(pid_t *p);
STATIC_DESTRUCTOR_REGISTER(pager_pid, pager_closep);
