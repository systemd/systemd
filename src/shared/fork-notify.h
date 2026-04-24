/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "output-mode.h"
#include "shared-forward.h"

typedef void (*fork_notify_handler_t)(void *userdata);

int fork_notify(char * const *argv, fork_notify_handler_t child_handler, void *child_userdata, PidRef *ret_pidref);

void fork_notify_terminate(PidRef *pidref);

void fork_notify_terminate_many(sd_event_source **array, size_t n);

int journal_fork(RuntimeScope scope, char * const *units, OutputMode output, PidRef *ret_pidref);

int fork_journal_remote(
                const char *listen_address,
                const char *output,
                uint64_t max_use,
                uint64_t keep_free,
                uint64_t max_file_size,
                uint64_t max_files,
                PidRef *ret_pidref);
