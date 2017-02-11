/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "time-util.h"

typedef int (*gather_stdout_callback_t) (int fd, void *arg);

enum {
        STDOUT_GENERATE,   /* from generators to helper process */
        STDOUT_COLLECT,    /* from helper process to main process */
        STDOUT_CONSUME,    /* process data in main process */
        _STDOUT_CONSUME_MAX,
};

int execute_directories(
                const char* const* directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[]);

extern const gather_stdout_callback_t gather_environment[_STDOUT_CONSUME_MAX];
