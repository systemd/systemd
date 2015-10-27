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

#define ANSI_RED "\x1B[0;31m"
#define ANSI_GREEN "\x1B[0;32m"
#define ANSI_UNDERLINE "\x1B[0;4m"
#define ANSI_HIGHLIGHT "\x1B[0;1;39m"
#define ANSI_HIGHLIGHT_RED "\x1B[0;1;31m"
#define ANSI_HIGHLIGHT_GREEN "\x1B[0;1;32m"
#define ANSI_HIGHLIGHT_YELLOW "\x1B[0;1;33m"
#define ANSI_HIGHLIGHT_BLUE "\x1B[0;1;34m"
#define ANSI_HIGHLIGHT_UNDERLINE "\x1B[0;1;4m"
#define ANSI_NORMAL "\x1B[0m"

#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

/* Set cursor to top left corner and clear screen */
#define ANSI_HOME_CLEAR "\x1B[H\x1B[2J"

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

int make_stdio(int fd);
int make_null_stdio(void);
int make_console_stdio(void);

int fd_columns(int fd);
unsigned columns(void);
int fd_lines(int fd);
unsigned lines(void);
void columns_lines_cache_reset(int _unused_ signum);

bool on_tty(void);

static inline const char *ansi_underline(void) {
        return on_tty() ? ANSI_UNDERLINE : "";
}

static inline const char *ansi_highlight(void) {
        return on_tty() ? ANSI_HIGHLIGHT : "";
}

static inline const char *ansi_highlight_underline(void) {
        return on_tty() ? ANSI_HIGHLIGHT_UNDERLINE : "";
}

static inline const char *ansi_highlight_red(void) {
        return on_tty() ? ANSI_HIGHLIGHT_RED : "";
}

static inline const char *ansi_highlight_green(void) {
        return on_tty() ? ANSI_HIGHLIGHT_GREEN : "";
}

static inline const char *ansi_highlight_yellow(void) {
        return on_tty() ? ANSI_HIGHLIGHT_YELLOW : "";
}

static inline const char *ansi_highlight_blue(void) {
        return on_tty() ? ANSI_HIGHLIGHT_BLUE : "";
}

static inline const char *ansi_normal(void) {
        return on_tty() ? ANSI_NORMAL : "";
}

int get_ctty_devnr(pid_t pid, dev_t *d);
int get_ctty(pid_t, dev_t *_devnr, char **r);

int getttyname_malloc(int fd, char **r);
int getttyname_harder(int fd, char **r);

int ptsname_malloc(int fd, char **ret);
int ptsname_namespace(int pty, char **ret);

int openpt_in_namespace(pid_t pid, int flags);
int open_terminal_in_namespace(pid_t pid, const char *name, int mode);
