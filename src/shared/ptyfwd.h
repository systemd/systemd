/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct PTYForward PTYForward;

typedef enum PTYForwardFlags {
        /* Only output to STDOUT, never try to read from STDIN */
        PTY_FORWARD_READ_ONLY              = 1 << 0,

        /* Continue reading after hangup? */
        PTY_FORWARD_IGNORE_VHANGUP         = 1 << 1,

        /* Continue reading after hangup but only if we never read anything else? */
        PTY_FORWARD_IGNORE_INITIAL_VHANGUP = 1 << 2,

        /* Don't tint the background, or set window title */
        PTY_FORWARD_DUMB_TERMINAL          = 1 << 3,
} PTYForwardFlags;

typedef int (*PTYForwardHangupHandler)(PTYForward *f, int rcode, void *userdata);
typedef int (*PTYForwardHotkeyHandler)(PTYForward *f, char key, void *userdata);

#define N_PTY_FORWARD_SIGNALS 7
extern const int pty_forward_signals[N_PTY_FORWARD_SIGNALS];

int pty_forward_new(sd_event *event, int master, PTYForwardFlags flags, PTYForward **ret);
PTYForward* pty_forward_free(PTYForward *f);

int pty_forward_honor_vhangup(PTYForward *f);
bool pty_forward_vhangup_honored(const PTYForward *f);

void pty_forward_set_hangup_handler(PTYForward *f, PTYForwardHangupHandler handler, void *userdata);
void pty_forward_set_hotkey_handler(PTYForward *f, PTYForwardHotkeyHandler handler, void *userdata);

int pty_forward_drain(PTYForward *f);

int pty_forward_set_priority(PTYForward *f, int64_t priority);

int pty_forward_set_width_height(PTYForward *f, unsigned width, unsigned height);

int pty_forward_set_background_color(PTYForward *f, const char *color);

int pty_forward_set_title(PTYForward *f, const char *title);
int pty_forward_set_titlef(PTYForward *f, const char *format, ...) _printf_(2,3);

int pty_forward_set_title_prefix(PTYForward *f, const char *prefix);

bool shall_set_terminal_title(void);

int pty_forward_set_window_title(
                PTYForward *f,
                Glyph circle,           /* e.g. GLYPH_GREEN_CIRCLE */
                const char *hostname,   /* Can be NULL, and obtained by gethostname_strict() in that case. */
                char * const *msg);

DEFINE_TRIVIAL_CLEANUP_FUNC(PTYForward*, pty_forward_free);
