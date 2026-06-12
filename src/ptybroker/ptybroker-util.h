/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-json.h"

#include "ptybroker-forward.h"

enum EndOfLine {
        EOL_NEWLINE         = 1 << 0,
        EOL_CARRIAGE_RETURN = 1 << 1,
        EOL_FORM_FEED       = 1 << 2,
        EOL_NUL             = 1 << 3,
        _EOL_MASK_ALL       = EOL_NEWLINE|EOL_CARRIAGE_RETURN|EOL_FORM_FEED|EOL_NUL,
};

bool pseudo_tty_name_valid(const char *s);
bool pseudo_tty_description_valid(const char *s);
bool pseudo_tty_tag_valid(const char *s);

/* Let's short cut these two, we want similar validation for them */
#define dollar_term_valid(s) pseudo_tty_tag_valid(s)
#define dollar_colorterm_valid(s) pseudo_tty_tag_valid(s)

EndOfLine end_of_line_from_char(char c);

typedef struct TerminalSettings {
        unsigned columns;
        unsigned lines;
        char *dollar_term;
        char *dollar_colorterm;
        int dollar_no_color;
} TerminalSettings;

#define TERMINAL_SETTINGS_NULL (TerminalSettings) { \
        .columns = UINT_MAX,           \
        .lines = UINT_MAX,             \
        .dollar_no_color = -1,         \
}

#define TAKE_TERMINAL_SETTINGS(var) TAKE_GENERIC(var, TerminalSettings, TERMINAL_SETTINGS_NULL)

void terminal_settings_done(TerminalSettings *ts);
int terminal_settings_from_json(sd_json_variant *v, TerminalSettings *ret);
int terminal_settings_to_json(const TerminalSettings *ts, sd_json_variant **ret);
int terminal_settings_settle(TerminalSettings *ts);
int terminal_settings_copy(TerminalSettings *ret, const TerminalSettings *ts);
int terminal_settings_merge(TerminalSettings *ts, const TerminalSettings *override);
int terminal_settings_sync_size_fd(TerminalSettings *ts, int fd, const char *path);
