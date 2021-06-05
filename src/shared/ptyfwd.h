/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-event.h"

#include "macro.h"

typedef struct PTYForward PTYForward;

typedef enum PTYForwardFlags {
        PTY_FORWARD_READ_ONLY = 1,

        /* Continue reading after hangup? */
        PTY_FORWARD_IGNORE_VHANGUP = 2,

        /* Continue reading after hangup but only if we never read anything else? */
        PTY_FORWARD_IGNORE_INITIAL_VHANGUP = 4,
} PTYForwardFlags;

typedef int (*PTYForwardHandler)(PTYForward *f, int rcode, void *userdata);

int pty_forward_new(sd_event *event, int master, PTYForwardFlags flags, PTYForward **f);
PTYForward *pty_forward_free(PTYForward *f);

int pty_forward_get_last_char(PTYForward *f, char *ch);

int pty_forward_set_ignore_vhangup(PTYForward *f, bool ignore_vhangup);
bool pty_forward_get_ignore_vhangup(PTYForward *f);

bool pty_forward_is_done(PTYForward *f);

void pty_forward_set_handler(PTYForward *f, PTYForwardHandler handler, void *userdata);

bool pty_forward_drain(PTYForward *f);

int pty_forward_set_priority(PTYForward *f, int64_t priority);

int pty_forward_set_width_height(PTYForward *f, unsigned width, unsigned height);

DEFINE_TRIVIAL_CLEANUP_FUNC(PTYForward*, pty_forward_free);
