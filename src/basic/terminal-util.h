/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "macro.h"
#include "pidref.h"
#include "time-util.h"

/* Erase characters until the end of the line */
#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

/* Erase characters until end of screen */
#define ANSI_ERASE_TO_END_OF_SCREEN "\x1B[J"

/* Move cursor up one line */
#define ANSI_REVERSE_LINEFEED "\x1BM"

/* Set cursor to top left corner and clear screen */
#define ANSI_HOME_CLEAR "\x1B[H\x1B[2J"

/* Push/pop a window title off the stack of window titles */
#define ANSI_WINDOW_TITLE_PUSH "\x1b[22;2t"
#define ANSI_WINDOW_TITLE_POP "\x1b[23;2t"

/* ANSI "string terminator" character ("ST"). Terminal emulators typically allow three different ones: 0x07,
 * 0x9c, and 0x1B 0x5C. We'll avoid 0x07 (BEL, aka ^G) since it might trigger unexpected TTY signal
 * handling. And we'll avoid 0x9c since that's also valid regular codepoint in UTF-8 and elsewhere, and
 * creates ambiguities. Because of that some terminal emulators explicitly choose not to support it. Hence we
 * use 0x1B 0x5c */
#define ANSI_ST "\e\\"

/* The "operating system command" ("OSC") start sequence */
#define ANSI_OSC "\e]"

bool isatty_safe(int fd);

int terminal_reset_defensive(int fd, bool switch_to_text);
int terminal_reset_defensive_locked(int fd, bool switch_to_text);

int terminal_set_cursor_position(int fd, unsigned row, unsigned column);

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

int acquire_terminal(const char *name, AcquireTerminalFlags flags, usec_t timeout);
int release_terminal(void);

int terminal_new_session(void);
static inline void terminal_detach_session(void) {
        (void) setsid();
        (void) release_terminal();
}

int terminal_vhangup_fd(int fd);
int terminal_vhangup(const char *tty);

int terminal_set_size_fd(int fd, const char *ident, unsigned rows, unsigned cols);
int proc_cmdline_tty_size(const char *tty, unsigned *ret_rows, unsigned *ret_cols);

int chvt(int vt);

int read_one_char(FILE *f, char *ret, usec_t timeout, bool *need_nl);
int ask_char(char *ret, const char *replies, const char *text, ...) _printf_(3, 4);
int ask_string(char **ret, const char *text, ...) _printf_(2, 3);
bool any_key_to_proceed(void);
int show_menu(char **x, unsigned n_columns, unsigned width, unsigned percentage);

int vt_disallocate(const char *name);

int resolve_dev_console(char **ret);
int get_kernel_consoles(char ***ret);
bool tty_is_vc(const char *tty);
bool tty_is_vc_resolve(const char *tty);
bool tty_is_console(const char *tty) _pure_;
int vtnr_from_tty(const char *tty);
const char* default_term_for_tty(const char *tty);

void reset_dev_console_fd(int fd, bool switch_to_text);
int lock_dev_console(void);
int make_console_stdio(void);

int getenv_columns(void);
int fd_columns(int fd);
unsigned columns(void);
int fd_lines(int fd);
unsigned lines(void);

void columns_lines_cache_reset(int _unused_ signum);
void reset_terminal_feature_caches(void);

bool on_tty(void);
bool getenv_terminal_is_dumb(void);
bool terminal_is_dumb(void);

/* Limits the use of ANSI colors to a subset. */
typedef enum ColorMode {
        COLOR_OFF,   /* No colors, monochrome output. */
        COLOR_16,    /* Only the base 16 colors. */
        COLOR_256,   /* Only 256 colors. */
        COLOR_24BIT, /* For truecolor or 24bit color support, no restriction. */
        _COLOR_MODE_MAX,
        _COLOR_MODE_INVALID = -EINVAL,
} ColorMode;

const char* color_mode_to_string(ColorMode m) _const_;
ColorMode color_mode_from_string(const char *s) _pure_;

ColorMode get_color_mode(void);
static inline bool colors_enabled(void) {
        /* Returns true if colors are considered supported on our stdout. */
        return get_color_mode() != COLOR_OFF;
}

bool underline_enabled(void);
bool dev_console_colors_enabled(void);

int get_ctty_devnr(pid_t pid, dev_t *ret);
int get_ctty(pid_t, dev_t *ret_devnr, char **ret);

int getttyname_malloc(int fd, char **ret);
int getttyname_harder(int fd, char **ret);

int ptsname_malloc(int fd, char **ret);

int openpt_allocate(int flags, char **ret_peer);
int openpt_allocate_in_namespace(const PidRef *pidref, int flags, char **ret_peer);

int vt_restore(int fd);
int vt_release(int fd, bool restore_vt);

void get_log_colors(int priority, const char **on, const char **off, const char **highlight);

/* Assume TTY_MODE is defined in config.h. Also, this assumes there is a 'tty' group. */
assert_cc((TTY_MODE & ~0666) == 0);
assert_cc((TTY_MODE & 0711) == 0600);

void termios_disable_echo(struct termios *termios);

int get_default_background_color(double *ret_red, double *ret_green, double *ret_blue);
int terminal_get_size_by_dsr(int input_fd, int output_fd, unsigned *ret_rows, unsigned *ret_columns);

int terminal_fix_size(int input_fd, int output_fd);

int terminal_is_pty_fd(int fd);

int pty_open_peer(int fd, int mode);

static inline bool osc_char_is_valid(char c) {
        /* Checks whether the specified character is safe to be included inside an ANSI OSC sequence, as per
         * ECMA-48 5th edition, section 8.3.89 */
        return (unsigned char) c >= 32U && (unsigned char) c < 127;
}

static inline bool vtnr_is_valid(unsigned n) {
        return n >= 1 && n <= 63;
}
