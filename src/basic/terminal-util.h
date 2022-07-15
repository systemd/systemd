/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

/* Regular colors */
#define ANSI_BLACK   "\x1B[0;30m" /* Some type of grey usually. */
#define ANSI_RED     "\x1B[0;31m"
#define ANSI_GREEN   "\x1B[0;32m"
#define ANSI_YELLOW  "\x1B[0;33m"
#define ANSI_BLUE    "\x1B[0;34m"
#define ANSI_MAGENTA "\x1B[0;35m"
#define ANSI_CYAN    "\x1B[0;36m"
#define ANSI_WHITE   "\x1B[0;37m" /* This is actually rendered as light grey, legible even on a white
                                   * background. See ANSI_HIGHLIGHT_WHITE for real white. */

#define ANSI_BRIGHT_BLACK   "\x1B[0;90m"
#define ANSI_BRIGHT_RED     "\x1B[0;91m"
#define ANSI_BRIGHT_GREEN   "\x1B[0;92m"
#define ANSI_BRIGHT_YELLOW  "\x1B[0;93m"
#define ANSI_BRIGHT_BLUE    "\x1B[0;94m"
#define ANSI_BRIGHT_MAGENTA "\x1B[0;95m"
#define ANSI_BRIGHT_CYAN    "\x1B[0;96m"
#define ANSI_BRIGHT_WHITE   "\x1B[0;97m"

#define ANSI_GREY    "\x1B[0;38;5;245m"

/* Bold/highlighted */
#define ANSI_HIGHLIGHT_BLACK    "\x1B[0;1;30m"
#define ANSI_HIGHLIGHT_RED      "\x1B[0;1;31m"
#define ANSI_HIGHLIGHT_GREEN    "\x1B[0;1;32m"
#define _ANSI_HIGHLIGHT_YELLOW  "\x1B[0;1;33m" /* This yellow is currently not displayed well by some terminals */
#define ANSI_HIGHLIGHT_BLUE     "\x1B[0;1;34m"
#define ANSI_HIGHLIGHT_MAGENTA  "\x1B[0;1;35m"
#define ANSI_HIGHLIGHT_CYAN     "\x1B[0;1;36m"
#define ANSI_HIGHLIGHT_WHITE    "\x1B[0;1;37m"
#define ANSI_HIGHLIGHT_YELLOW4  "\x1B[0;1;38;5;100m"
#define ANSI_HIGHLIGHT_KHAKI3   "\x1B[0;1;38;5;185m"
#define ANSI_HIGHLIGHT_GREY     "\x1B[0;1;38;5;245m"

#define ANSI_HIGHLIGHT_YELLOW   ANSI_HIGHLIGHT_KHAKI3 /* Replacement yellow that is more legible */

/* Underlined */
#define ANSI_GREY_UNDERLINE              "\x1B[0;4;38;5;245m"
#define ANSI_HIGHLIGHT_RED_UNDERLINE     "\x1B[0;1;4;31m"
#define ANSI_HIGHLIGHT_GREEN_UNDERLINE   "\x1B[0;1;4;32m"
#define ANSI_HIGHLIGHT_YELLOW_UNDERLINE  "\x1B[0;1;4;38;5;185m"
#define ANSI_HIGHLIGHT_BLUE_UNDERLINE    "\x1B[0;1;4;34m"
#define ANSI_HIGHLIGHT_MAGENTA_UNDERLINE "\x1B[0;1;4;35m"
#define ANSI_HIGHLIGHT_GREY_UNDERLINE    "\x1B[0;1;4;38;5;245m"

/* Other ANSI codes */
#define ANSI_UNDERLINE "\x1B[0;4m"
#define ANSI_HIGHLIGHT "\x1B[0;1;39m"
#define ANSI_HIGHLIGHT_UNDERLINE "\x1B[0;1;4m"

/* Fallback colors: 256 -> 16 */
#define ANSI_HIGHLIGHT_GREY_FALLBACK   "\x1B[0;1;90m"
#define ANSI_HIGHLIGHT_YELLOW_FALLBACK "\x1B[0;1;33m"

/* Reset/clear ANSI styles */
#define ANSI_NORMAL "\x1B[0m"

/* Erase characters until the end of the line */
#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

/* Move cursor up one line */
#define ANSI_REVERSE_LINEFEED "\x1BM"

/* Set cursor to top left corner and clear screen */
#define ANSI_HOME_CLEAR "\x1B[H\x1B[2J"

int reset_terminal_fd(int fd, bool switch_to_text);
int reset_terminal(const char *name);

int open_terminal(const char *name, int mode);

/* Flags for tweaking the way we become the controlling process of a terminal. */
typedef enum AcquireTerminalFlags {
        /* Try to become the controlling process of the TTY. If we can't return -EPERM. */
        ACQUIRE_TERMINAL_TRY        = 0,

        /* Tell the kernel to forcibly make us the controlling process of the TTY. Returns -EPERM if the kernel doesn't allow that. */
        ACQUIRE_TERMINAL_FORCE      = 1,

        /* If we can't become the controlling process of the TTY right-away, then wait until we can. */
        ACQUIRE_TERMINAL_WAIT       = 2,

        /* Pick one of the above, and then OR this flag in, in order to request permissive behaviour, if we can't become controlling process then don't mind */
        ACQUIRE_TERMINAL_PERMISSIVE = 1 << 2,
} AcquireTerminalFlags;

/* Limits the use of ANSI colors to a subset. */
typedef enum ColorMode {
        /* No colors, monochrome output. */
        COLOR_OFF,

        /* All colors, no restrictions. */
        COLOR_ON,

        /* Only the base 16 colors. */
        COLOR_16,

        /* Only 256 colors. */
        COLOR_256,

        /* For truecolor or 24bit color support.*/
        COLOR_24BIT,

        _COLOR_INVALID = -EINVAL,
} ColorMode;

int acquire_terminal(const char *name, AcquireTerminalFlags flags, usec_t timeout);
int release_terminal(void);

int terminal_vhangup_fd(int fd);
int terminal_vhangup(const char *name);

int terminal_set_size_fd(int fd, const char *ident, unsigned rows, unsigned cols);

int chvt(int vt);

int read_one_char(FILE *f, char *ret, usec_t timeout, bool *need_nl);
int ask_char(char *ret, const char *replies, const char *text, ...) _printf_(3, 4);
int ask_string(char **ret, const char *text, ...) _printf_(2, 3);

int vt_disallocate(const char *name);

int resolve_dev_console(char **ret);
int get_kernel_consoles(char ***ret);
bool tty_is_vc(const char *tty);
bool tty_is_vc_resolve(const char *tty);
bool tty_is_console(const char *tty) _pure_;
int vtnr_from_tty(const char *tty);
const char *default_term_for_tty(const char *tty);

int make_console_stdio(void);

int fd_columns(int fd);
unsigned columns(void);
int fd_lines(int fd);
unsigned lines(void);

void columns_lines_cache_reset(int _unused_ signum);
void reset_terminal_feature_caches(void);

bool on_tty(void);
bool terminal_is_dumb(void);
ColorMode get_color_mode(void);
bool underline_enabled(void);
bool dev_console_colors_enabled(void);

static inline bool colors_enabled(void) {

        /* Returns true if colors are considered supported on our stdout. */
        return get_color_mode() != COLOR_OFF;
}

#define DEFINE_ANSI_FUNC(name, NAME)                            \
        static inline const char *ansi_##name(void) {           \
                return colors_enabled() ? ANSI_##NAME : "";     \
        }

#define DEFINE_ANSI_FUNC_256(name, NAME, FALLBACK)             \
        static inline const char *ansi_##name(void) {          \
                switch (get_color_mode()) {                    \
                        case COLOR_OFF: return "";             \
                        case COLOR_16: return ANSI_##FALLBACK; \
                        default : return ANSI_##NAME;          \
                }                                              \
        }

#define DEFINE_ANSI_FUNC_UNDERLINE(name, NAME)                            \
        static inline const char *ansi_##name(void) {                     \
                return underline_enabled() ? ANSI_##NAME ANSI_UNDERLINE : \
                        colors_enabled() ? ANSI_##NAME : "";              \
        }


#define DEFINE_ANSI_FUNC_UNDERLINE_256(name, NAME, FALLBACK)                                                           \
        static inline const char *ansi_##name(void) {                                                                  \
                switch (get_color_mode()) {                                                                            \
                        case COLOR_OFF: return "";                                                                     \
                        case COLOR_16: return underline_enabled() ? ANSI_##FALLBACK ANSI_UNDERLINE : ANSI_##FALLBACK;  \
                        default : return underline_enabled() ? ANSI_##NAME ANSI_UNDERLINE: ANSI_##NAME;                \
                }                                                                                                      \
        }

DEFINE_ANSI_FUNC(normal,            NORMAL);
DEFINE_ANSI_FUNC(highlight,         HIGHLIGHT);
DEFINE_ANSI_FUNC(black,             BLACK);
DEFINE_ANSI_FUNC(red,               RED);
DEFINE_ANSI_FUNC(green,             GREEN);
DEFINE_ANSI_FUNC(yellow,            YELLOW);
DEFINE_ANSI_FUNC(blue,              BLUE);
DEFINE_ANSI_FUNC(magenta,           MAGENTA);
DEFINE_ANSI_FUNC(cyan,              CYAN);
DEFINE_ANSI_FUNC(white,             WHITE);
DEFINE_ANSI_FUNC_256(grey,          GREY, BRIGHT_BLACK);

DEFINE_ANSI_FUNC(bright_black,      BRIGHT_BLACK);
DEFINE_ANSI_FUNC(bright_red,        BRIGHT_RED);
DEFINE_ANSI_FUNC(bright_green,      BRIGHT_GREEN);
DEFINE_ANSI_FUNC(bright_yellow,     BRIGHT_YELLOW);
DEFINE_ANSI_FUNC(bright_blue,       BRIGHT_BLUE);
DEFINE_ANSI_FUNC(bright_magenta,    BRIGHT_MAGENTA);
DEFINE_ANSI_FUNC(bright_cyan,       BRIGHT_CYAN);
DEFINE_ANSI_FUNC(bright_white,      BRIGHT_WHITE);

DEFINE_ANSI_FUNC(highlight_black,       HIGHLIGHT_BLACK);
DEFINE_ANSI_FUNC(highlight_red,         HIGHLIGHT_RED);
DEFINE_ANSI_FUNC(highlight_green,       HIGHLIGHT_GREEN);
DEFINE_ANSI_FUNC_256(highlight_yellow,  HIGHLIGHT_YELLOW, HIGHLIGHT_YELLOW_FALLBACK);
DEFINE_ANSI_FUNC_256(highlight_yellow4, HIGHLIGHT_YELLOW4, HIGHLIGHT_YELLOW_FALLBACK);
DEFINE_ANSI_FUNC(highlight_blue,        HIGHLIGHT_BLUE);
DEFINE_ANSI_FUNC(highlight_magenta,     HIGHLIGHT_MAGENTA);
DEFINE_ANSI_FUNC(highlight_cyan,        HIGHLIGHT_CYAN);
DEFINE_ANSI_FUNC_256(highlight_grey,    HIGHLIGHT_GREY, HIGHLIGHT_GREY_FALLBACK);
DEFINE_ANSI_FUNC(highlight_white,       HIGHLIGHT_WHITE);

static inline const char* _ansi_highlight_yellow(void) {
        return colors_enabled() ? _ANSI_HIGHLIGHT_YELLOW : "";
}

DEFINE_ANSI_FUNC_UNDERLINE(underline,                       NORMAL);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_underline,             HIGHLIGHT);
DEFINE_ANSI_FUNC_UNDERLINE_256(grey_underline,              GREY, BRIGHT_BLACK);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_red_underline,         HIGHLIGHT_RED);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_green_underline,       HIGHLIGHT_GREEN);
DEFINE_ANSI_FUNC_UNDERLINE_256(highlight_yellow_underline,  HIGHLIGHT_YELLOW, HIGHLIGHT_YELLOW_FALLBACK);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_blue_underline,        HIGHLIGHT_BLUE);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_magenta_underline,     HIGHLIGHT_MAGENTA);
DEFINE_ANSI_FUNC_UNDERLINE_256(highlight_grey_underline,    HIGHLIGHT_GREY, HIGHLIGHT_GREY_FALLBACK);

int get_ctty_devnr(pid_t pid, dev_t *d);
int get_ctty(pid_t, dev_t *_devnr, char **r);

int getttyname_malloc(int fd, char **r);
int getttyname_harder(int fd, char **r);

int ptsname_malloc(int fd, char **ret);

int openpt_allocate(int flags, char **ret_slave);
int openpt_allocate_in_namespace(pid_t pid, int flags, char **ret_slave);
int open_terminal_in_namespace(pid_t pid, const char *name, int mode);

int vt_default_utf8(void);
int vt_reset_keyboard(int fd);
int vt_restore(int fd);
int vt_release(int fd, bool restore_vt);

void get_log_colors(int priority, const char **on, const char **off, const char **highlight);

static inline const char* ansi_highlight_green_red(bool b) {
        return b ? ansi_highlight_green() : ansi_highlight_red();
}

/* This assumes there is a 'tty' group */
#define TTY_MODE 0620
