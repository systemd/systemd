#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <stdarg.h>
#include <stdio.h>

#include "macro.h"
#include "time-util.h"

#define ANSI_HIGHLIGHT_ON "\x1B[1;39m"
#define ANSI_RED_ON "\x1B[31m"
#define ANSI_HIGHLIGHT_RED_ON "\x1B[1;31m"
#define ANSI_GREEN_ON "\x1B[32m"
#define ANSI_HIGHLIGHT_GREEN_ON "\x1B[1;32m"
#define ANSI_HIGHLIGHT_YELLOW_ON "\x1B[1;33m"
#define ANSI_HIGHLIGHT_BLUE_ON "\x1B[1;34m"
#define ANSI_HIGHLIGHT_OFF "\x1B[0m"
#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

int reset_terminal_fd(int fd, bool switch_to_text);
int reset_terminal(const char *name);

int open_terminal(const char *name, int mode);
int acquire_terminal(const char *name, bool fail, bool force, bool ignore_tiocstty_eperm, usec_t timeout);
int release_terminal(void);

int terminal_vhangup_fd(int fd);
int terminal_vhangup(const char *name);

int chvt(int vt);

int read_one_char(FILE *f, char *ret, usec_t timeout, bool *need_nl);
int ask_char(char *ret, const char *replies, const char *text, ...) _printf_(3, 4);
int ask_string(char **ret, const char *text, ...) _printf_(2, 3);

int vt_disallocate(const char *name);

char *resolve_dev_console(char **active);
bool tty_is_vc(const char *tty);
bool tty_is_vc_resolve(const char *tty);
bool tty_is_console(const char *tty) _pure_;
int vtnr_from_tty(const char *tty);
const char *default_term_for_tty(const char *tty);

void warn_melody(void);

int make_stdio(int fd);
int make_null_stdio(void);
int make_console_stdio(void);

int status_vprintf(const char *status, bool ellipse, bool ephemeral, const char *format, va_list ap) _printf_(4,0);
int status_printf(const char *status, bool ellipse, bool ephemeral, const char *format, ...) _printf_(4,5);

int fd_columns(int fd);
unsigned columns(void);
int fd_lines(int fd);
unsigned lines(void);
void columns_lines_cache_reset(int _unused_ signum);

bool on_tty(void);

static inline const char *ansi_highlight(void) {
        return on_tty() ? ANSI_HIGHLIGHT_ON : "";
}

static inline const char *ansi_highlight_red(void) {
        return on_tty() ? ANSI_HIGHLIGHT_RED_ON : "";
}

static inline const char *ansi_highlight_green(void) {
        return on_tty() ? ANSI_HIGHLIGHT_GREEN_ON : "";
}

static inline const char *ansi_highlight_yellow(void) {
        return on_tty() ? ANSI_HIGHLIGHT_YELLOW_ON : "";
}

static inline const char *ansi_highlight_blue(void) {
        return on_tty() ? ANSI_HIGHLIGHT_BLUE_ON : "";
}

static inline const char *ansi_highlight_off(void) {
        return on_tty() ? ANSI_HIGHLIGHT_OFF : "";
}

int get_ctty_devnr(pid_t pid, dev_t *d);
int get_ctty(pid_t, dev_t *_devnr, char **r);

int getttyname_malloc(int fd, char **r);
int getttyname_harder(int fd, char **r);
