/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

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

/* The "device control string" ("DCS") start sequence */
#define ANSI_DCS "\eP"

/* The "operating system command" ("OSC") start sequence */
#define ANSI_OSC "\e]"

/* ANSI "string terminator" character ("ST"). Terminal emulators typically allow three different ones: 0x07,
 * 0x9c, and 0x1B 0x5C. We'll avoid 0x07 (BEL, aka ^G) since it might trigger unexpected TTY signal handling.
 * And we'll avoid 0x9c since that's also valid regular codepoint in UTF-8 and elsewhere, and creates
 * ambiguities. Because of that some terminal emulators explicitly choose not to support it. Hence we use
 * 0x1B 0x5c. */
#define ANSI_ST "\e\\"

bool isatty_safe(int fd);

typedef enum TerminalResetFlags {
        TERMINAL_RESET_SWITCH_TO_TEXT = 1 << 0,
        TERMINAL_RESET_AVOID_ANSI_SEQ = 1 << 1,
        TERMINAL_RESET_FORCE_ANSI_SEQ = 1 << 2,
} TerminalResetFlags;

int terminal_reset_defensive(int fd, TerminalResetFlags flags);
int terminal_reset_defensive_locked(int fd, TerminalResetFlags flags);

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

        /* The combined mask of the above */
        _ACQUIRE_TERMINAL_MODE_MASK = ACQUIRE_TERMINAL_TRY | ACQUIRE_TERMINAL_FORCE | ACQUIRE_TERMINAL_WAIT,

        /* Pick one of the above, and then OR this flag in, in order to request permissive behaviour, if we can't become controlling process then don't mind */
        ACQUIRE_TERMINAL_PERMISSIVE = 1 << 2,

        /* Check for pending SIGTERM while waiting for inotify (SIGTERM must be blocked by caller) */
        ACQUIRE_TERMINAL_WATCH_SIGTERM = 1 << 3,
} AcquireTerminalFlags;

int acquire_terminal(const char *name, AcquireTerminalFlags flags, usec_t timeout);
int release_terminal(void);

int terminal_new_session(void);
void terminal_detach_session(void);

int terminal_vhangup_fd(int fd);
int terminal_vhangup(const char *tty);

int terminal_set_size_fd(int fd, const char *ident, unsigned rows, unsigned cols);
int proc_cmdline_tty_size(const char *tty, unsigned *ret_rows, unsigned *ret_cols);

int chvt(int vt);

int read_one_char(FILE *f, char *ret, usec_t timeout, bool echo, bool *need_nl);
int ask_char(char *ret, const char *replies, const char *text, ...) _printf_(3, 4);

typedef int (*GetCompletionsCallback)(const char *key, char ***ret_list, void *userdata);
int ask_string_full(char **ret, GetCompletionsCallback cb, void *userdata, const char *text, ...) _printf_(4, 5);
#define ask_string(ret, text, ...) ask_string_full(ret, NULL, NULL, text, ##__VA_ARGS__)

bool any_key_to_proceed(void);
int show_menu(char **x, size_t n_columns, size_t column_width, unsigned ellipsize_percentage, const char *grey_prefix, bool with_numbers);

int vt_disallocate(const char *name);

int resolve_dev_console(char **ret);
int get_kernel_consoles(char ***ret);
bool tty_is_vc(const char *tty);
bool tty_is_vc_resolve(const char *tty);
bool tty_is_console(const char *tty) _pure_;
int vtnr_from_tty(const char *tty);

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

bool dev_console_colors_enabled(void);

int get_ctty_devnr(pid_t pid, dev_t *ret);
int get_ctty(pid_t, dev_t *ret_devnr, char **ret);

int getttyname_malloc(int fd, char **ret);
int getttyname_harder(int fd, char **ret);

int ptsname_malloc(int fd, char **ret);

int openpt_allocate(int flags, char **ret_peer_path);
int openpt_allocate_in_namespace(const PidRef *pidref, int flags, char **ret_peer_path);

int vt_restore(int fd);
int vt_release(int fd, bool restore);

void get_log_colors(int priority, const char **on, const char **off, const char **highlight);

/* Assume TTY_MODE is defined in config.h. Also, this assumes there is a 'tty' group. */
assert_cc((TTY_MODE & ~0666) == 0);
assert_cc((TTY_MODE & 0711) == 0600);

void termios_disable_echo(struct termios *termios);

/* The $TERM value we use for terminals other than the Linux console */
#define FALLBACK_TERM "vt220"

int get_default_background_color(double *ret_red, double *ret_green, double *ret_blue);
int terminal_get_size_by_dsr(int input_fd, int output_fd, unsigned *ret_rows, unsigned *ret_columns);
int terminal_fix_size(int input_fd, int output_fd);

int terminal_get_terminfo_by_dcs(int fd, char **ret_name);
int have_terminfo_file(const char *name);
int query_term_for_tty(const char *tty, char **ret_term);

int terminal_is_pty_fd(int fd);

int pty_open_peer(int fd, int mode);

static inline bool osc_char_is_valid(char c) {
        /* Checks whether the specified character is safe to be included inside an ANSI OSC sequence, as per
         * ECMA-48 5th edition, section 8.3.89 */
        return (unsigned char) c >= 32 && (unsigned char) c < 127;
}

#define VTNR_MAX 63

static inline bool vtnr_is_valid(unsigned n) {
        return n >= 1 && n <= VTNR_MAX;
}
