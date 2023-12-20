/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "ptyfwd.h"
#include "stat-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"

typedef enum AnsiColorState  {
        ANSI_COLOR_STATE_TEXT,
        ANSI_COLOR_STATE_ESC,
        ANSI_COLOR_STATE_CSI_SEQUENCE,
        ANSI_COLOR_STATE_NEWLINE,
        _ANSI_COLOR_STATE_MAX,
        _ANSI_COLOR_STATE_INVALID = -EINVAL,
} AnsiColorState;

struct PTYForward {
        sd_event *event;

        int input_fd;
        int output_fd;
        int master;

        PTYForwardFlags flags;

        sd_event_source *stdin_event_source;
        sd_event_source *stdout_event_source;
        sd_event_source *master_event_source;

        sd_event_source *sigwinch_event_source;

        struct termios saved_stdin_attr;
        struct termios saved_stdout_attr;

        bool close_input_fd:1;
        bool close_output_fd:1;

        bool saved_stdin:1;
        bool saved_stdout:1;

        bool stdin_readable:1;
        bool stdin_hangup:1;
        bool stdout_writable:1;
        bool stdout_hangup:1;
        bool master_readable:1;
        bool master_writable:1;
        bool master_hangup:1;

        bool read_from_master:1;

        bool done:1;
        bool drain:1;

        bool last_char_set:1;
        char last_char;

        char in_buffer[LINE_MAX], *out_buffer;
        size_t out_buffer_size;
        size_t in_buffer_full, out_buffer_full;

        usec_t escape_timestamp;
        unsigned escape_counter;

        PTYForwardHandler handler;
        void *userdata;

        char *background_color;
        AnsiColorState ansi_color_state;
        char *csi_sequence;
};

#define ESCAPE_USEC (1*USEC_PER_SEC)

static void pty_forward_disconnect(PTYForward *f) {

        if (!f)
                return;

        f->stdin_event_source = sd_event_source_unref(f->stdin_event_source);
        f->stdout_event_source = sd_event_source_unref(f->stdout_event_source);

        f->master_event_source = sd_event_source_unref(f->master_event_source);
        f->sigwinch_event_source = sd_event_source_unref(f->sigwinch_event_source);
        f->event = sd_event_unref(f->event);

        if (f->output_fd >= 0) {
                if (f->saved_stdout)
                        (void) tcsetattr(f->output_fd, TCSANOW, &f->saved_stdout_attr);

                /* STDIN/STDOUT should not be non-blocking normally, so let's reset it */
                (void) fd_nonblock(f->output_fd, false);

                if (colors_enabled())
                        (void) loop_write(f->output_fd, ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE, SIZE_MAX);

                if (f->close_output_fd)
                        f->output_fd = safe_close(f->output_fd);
        }

        if (f->input_fd >= 0) {
                if (f->saved_stdin)
                        (void) tcsetattr(f->input_fd, TCSANOW, &f->saved_stdin_attr);

                (void) fd_nonblock(f->input_fd, false);
                if (f->close_input_fd)
                        f->input_fd = safe_close(f->input_fd);
        }

        f->saved_stdout = f->saved_stdin = false;

        f->out_buffer = mfree(f->out_buffer);
        f->out_buffer_size = 0;
        f->out_buffer_full = 0;
        f->in_buffer_full = 0;

        f->csi_sequence = mfree(f->csi_sequence);
        f->ansi_color_state = _ANSI_COLOR_STATE_INVALID;
}

static int pty_forward_done(PTYForward *f, int rcode) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        assert(f);

        if (f->done)
                return 0;

        e = sd_event_ref(f->event);

        f->done = true;
        pty_forward_disconnect(f);

        if (f->handler)
                return f->handler(f, rcode, f->userdata);
        else
                return sd_event_exit(e, rcode < 0 ? EXIT_FAILURE : rcode);
}

static bool look_for_escape(PTYForward *f, const char *buffer, size_t n) {
        const char *p;

        assert(f);
        assert(buffer);
        assert(n > 0);

        for (p = buffer; p < buffer + n; p++) {

                /* Check for ^] */
                if (*p == 0x1D) {
                        usec_t nw = now(CLOCK_MONOTONIC);

                        if (f->escape_counter == 0 || nw > f->escape_timestamp + ESCAPE_USEC) {
                                f->escape_timestamp = nw;
                                f->escape_counter = 1;
                        } else {
                                (f->escape_counter)++;

                                if (f->escape_counter >= 3)
                                        return true;
                        }
                } else {
                        f->escape_timestamp = 0;
                        f->escape_counter = 0;
                }
        }

        return false;
}

static bool ignore_vhangup(PTYForward *f) {
        assert(f);

        if (f->flags & PTY_FORWARD_IGNORE_VHANGUP)
                return true;

        if ((f->flags & PTY_FORWARD_IGNORE_INITIAL_VHANGUP) && !f->read_from_master)
                return true;

        return false;
}

static bool drained(PTYForward *f) {
        int q = 0;

        assert(f);

        if (f->out_buffer_full > 0)
                return false;

        if (f->master_readable)
                return false;

        if (ioctl(f->master, TIOCINQ, &q) < 0)
                log_debug_errno(errno, "TIOCINQ failed on master: %m");
        else if (q > 0)
                return false;

        if (ioctl(f->master, TIOCOUTQ, &q) < 0)
                log_debug_errno(errno, "TIOCOUTQ failed on master: %m");
        else if (q > 0)
                return false;

        return true;
}

static char *background_color_sequence(PTYForward *f) {
        assert(f);
        assert(f->background_color);

        /* This sets the background color to the desired one, and erase the rest of the line with it */

        return strjoin("\x1B[", f->background_color, "m", ANSI_ERASE_TO_END_OF_LINE);
}

static int insert_string(PTYForward *f, size_t offset, const char *s) {
        assert(f);
        assert(offset <= f->out_buffer_full);
        assert(s);

        size_t l = strlen(s);
        assert(l <= INT_MAX); /* Make sure we can still return this */

        void *p = realloc(f->out_buffer, MAX(f->out_buffer_full + l, (size_t) LINE_MAX));
        if (!p)
                return -ENOMEM;

        f->out_buffer = p;
        f->out_buffer_size = MALLOC_SIZEOF_SAFE(f->out_buffer);

        memmove(f->out_buffer + offset + l, f->out_buffer + offset, f->out_buffer_full - offset);
        memcpy(f->out_buffer + offset, s, l);
        f->out_buffer_full += l;

        return 0;
}

static int insert_erase_newline(PTYForward *f, size_t offset) {
        _cleanup_free_ char *s = NULL;

        assert(f);
        assert(f->background_color);

        s = background_color_sequence(f);
        if (!s)
                return -ENOMEM;

        return insert_string(f, offset, s);
}

static int is_csi_background_reset_sequence(const char *seq) {
        enum {
                COLOR_TOKEN_NO,
                COLOR_TOKEN_START,
                COLOR_TOKEN_8BIT,
                COLOR_TOKEN_24BIT_R,
                COLOR_TOKEN_24BIT_G,
                COLOR_TOKEN_24BIT_B,
        } token_state = COLOR_TOKEN_NO;

        bool b = false;
        int r;

        assert(seq);

        /* This parses CSI "m" sequences, and determines if they reset the background color. If so returns
         * 1. This can then be used to insert another sequence that sets the color to the desired
         * replacement. */

        for (;;) {
                _cleanup_free_ char *token = NULL;

                r = extract_first_word(&seq, &token, ";", EXTRACT_RELAX|EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                switch (token_state) {

                case COLOR_TOKEN_NO:

                        if (STR_IN_SET(token, "", "0", "00", "49"))
                                b = true; /* These tokens set the background back to normal */
                        else if (STR_IN_SET(token, "40", "41", "42", "43", "44", "45", "46", "47", "48"))
                                b = false; /* And these tokens set them to something other than normal */

                        if (STR_IN_SET(token, "38", "48", "58"))
                                token_state = COLOR_TOKEN_START; /* These tokens mean an 8bit or 24bit color will follow */
                        break;

                case COLOR_TOKEN_START:

                        if (STR_IN_SET(token, "5", "05"))
                                token_state = COLOR_TOKEN_8BIT; /* 8bit color */
                        else if (STR_IN_SET(token, "2", "02"))
                                token_state = COLOR_TOKEN_24BIT_R;  /* 24bit color */
                        else
                                token_state = COLOR_TOKEN_NO; /* something weird? */
                        break;

                case COLOR_TOKEN_24BIT_R:
                        token_state = COLOR_TOKEN_24BIT_G;
                        break;

                case COLOR_TOKEN_24BIT_G:
                        token_state = COLOR_TOKEN_24BIT_B;
                        break;

                case COLOR_TOKEN_8BIT:
                case COLOR_TOKEN_24BIT_B:
                        token_state = COLOR_TOKEN_NO;
                        break;
                }
        }

        return b;
}

static int insert_background_fix(PTYForward *f, size_t offset) {
        assert(f);
        assert(f->background_color);

        if (!is_csi_background_reset_sequence(strempty(f->csi_sequence)))
                return 0;

        _cleanup_free_ char *s = NULL;
        s = strjoin(";", f->background_color);
        if (!s)
                return -ENOMEM;

        return insert_string(f, offset, s);
}

static int pty_forward_ansi_process(PTYForward *f, size_t offset) {
        int r;

        assert(f);
        assert(offset <= f->out_buffer_full);

        if (!f->background_color)
                return 0;

        for (size_t i = offset; i < f->out_buffer_full; i++) {
                char c = f->out_buffer[i];

                switch (f->ansi_color_state) {

                case ANSI_COLOR_STATE_TEXT:
                        if (c == '\n')
                                f->ansi_color_state = ANSI_COLOR_STATE_NEWLINE;
                        if (c == 0x1B) /* ESC */
                                f->ansi_color_state = ANSI_COLOR_STATE_ESC;
                        break;

                case ANSI_COLOR_STATE_NEWLINE: {
                        /* Immediately after a newline insert an ANSI sequence to erase the line with a background color */

                        r = insert_erase_newline(f, i);
                        if (r < 0)
                                return r;

                        i += r;

                        f->ansi_color_state = ANSI_COLOR_STATE_TEXT;
                        break;
                }

                case ANSI_COLOR_STATE_ESC: {

                        if (c == '[')
                                f->ansi_color_state = ANSI_COLOR_STATE_CSI_SEQUENCE;
                        else
                                f->ansi_color_state = ANSI_COLOR_STATE_TEXT;

                        break;
                }

                case ANSI_COLOR_STATE_CSI_SEQUENCE: {

                        if (c >= 0x20 && c <= 0x3F) {
                                /* If this is a "parameter" or "intermediary" byte (i.e. ranges 0x20…0x2F and
                                 * 0x30…0x3F) then we are still in the CSI sequence */

                                if (strlen_ptr(f->csi_sequence) >= 64) {
                                        /* Safety check: lets not accept unbounded CSI sequences */

                                        f->csi_sequence = mfree(f->csi_sequence);
                                        f->ansi_color_state = ANSI_COLOR_STATE_TEXT;
                                } else if (!strextend(&f->csi_sequence, CHAR_TO_STR(c)))
                                        return -ENOMEM;
                        } else {
                                /* Otherwise, the CSI sequence is over */

                                if (c == 'm') {
                                        /* This is an "SGR" (Select Graphic Rendition) sequence. Patch in our background color. */
                                        r = insert_background_fix(f, i);
                                        if (r < 0)
                                                return r;

                                        i += r;
                                }

                                f->csi_sequence = mfree(f->csi_sequence);
                                f->ansi_color_state = ANSI_COLOR_STATE_TEXT;
                        }

                        break;
                }

                default:
                        assert_not_reached();
                }
        }

        return 0;
}

static int shovel(PTYForward *f) {
        ssize_t k;
        int r;

        assert(f);

        if (f->out_buffer_size == 0 && f->background_color) {
                /* Erase the first line when we start */
                f->out_buffer = background_color_sequence(f);
                if (!f->out_buffer)
                        return pty_forward_done(f, log_oom());

                f->out_buffer_full = strlen(f->out_buffer);
                f->out_buffer_size = MALLOC_SIZEOF_SAFE(f->out_buffer);
        }

        if (f->out_buffer_size < LINE_MAX) {
                /* Make sure we always have room for at least one "line" */
                void *p = realloc(f->out_buffer, LINE_MAX);
                if (!p)
                        return pty_forward_done(f, log_oom());

                f->out_buffer = p;
                f->out_buffer_size = MALLOC_SIZEOF_SAFE(p);
        }

        while ((f->stdin_readable && f->in_buffer_full <= 0) ||
               (f->master_writable && f->in_buffer_full > 0) ||
               (f->master_readable && f->out_buffer_full <= 0) ||
               (f->stdout_writable && f->out_buffer_full > 0)) {

                if (f->stdin_readable && f->in_buffer_full < LINE_MAX) {

                        k = read(f->input_fd, f->in_buffer + f->in_buffer_full, LINE_MAX - f->in_buffer_full);
                        if (k < 0) {

                                if (errno == EAGAIN)
                                        f->stdin_readable = false;
                                else if (errno == EIO || ERRNO_IS_DISCONNECT(errno)) {
                                        f->stdin_readable = false;
                                        f->stdin_hangup = true;

                                        f->stdin_event_source = sd_event_source_unref(f->stdin_event_source);
                                } else {
                                        log_error_errno(errno, "read(): %m");
                                        return pty_forward_done(f, -errno);
                                }
                        } else if (k == 0) {
                                /* EOF on stdin */
                                f->stdin_readable = false;
                                f->stdin_hangup = true;

                                f->stdin_event_source = sd_event_source_unref(f->stdin_event_source);
                        } else {
                                /* Check if ^] has been pressed three times within one second. If we get this we quite
                                 * immediately. */
                                if (look_for_escape(f, f->in_buffer + f->in_buffer_full, k))
                                        return pty_forward_done(f, -ECANCELED);

                                f->in_buffer_full += (size_t) k;
                        }
                }

                if (f->master_writable && f->in_buffer_full > 0) {

                        k = write(f->master, f->in_buffer, f->in_buffer_full);
                        if (k < 0) {

                                if (IN_SET(errno, EAGAIN, EIO))
                                        f->master_writable = false;
                                else if (IN_SET(errno, EPIPE, ECONNRESET)) {
                                        f->master_writable = f->master_readable = false;
                                        f->master_hangup = true;

                                        f->master_event_source = sd_event_source_unref(f->master_event_source);
                                } else {
                                        log_error_errno(errno, "write(): %m");
                                        return pty_forward_done(f, -errno);
                                }
                        } else {
                                assert(f->in_buffer_full >= (size_t) k);
                                memmove(f->in_buffer, f->in_buffer + k, f->in_buffer_full - k);
                                f->in_buffer_full -= k;
                        }
                }

                if (f->master_readable && f->out_buffer_full < MIN(f->out_buffer_size, (size_t) LINE_MAX)) {

                        k = read(f->master, f->out_buffer + f->out_buffer_full, f->out_buffer_size - f->out_buffer_full);
                        if (k < 0) {

                                /* Note that EIO on the master device might be caused by vhangup() or
                                 * temporary closing of everything on the other side, we treat it like EAGAIN
                                 * here and try again, unless ignore_vhangup is off. */

                                if (errno == EAGAIN || (errno == EIO && ignore_vhangup(f)))
                                        f->master_readable = false;
                                else if (IN_SET(errno, EPIPE, ECONNRESET, EIO)) {
                                        f->master_readable = f->master_writable = false;
                                        f->master_hangup = true;

                                        f->master_event_source = sd_event_source_unref(f->master_event_source);
                                } else {
                                        log_error_errno(errno, "read(): %m");
                                        return pty_forward_done(f, -errno);
                                }
                        } else {
                                f->read_from_master = true;
                                size_t scan_index = f->out_buffer_full;
                                f->out_buffer_full += (size_t) k;

                                r = pty_forward_ansi_process(f, scan_index);
                                if (r < 0)
                                        return pty_forward_done(f, log_error_errno(r, "Failed to scan for ANSI sequences: %m"));
                        }
                }

                if (f->stdout_writable && f->out_buffer_full > 0) {

                        k = write(f->output_fd, f->out_buffer, f->out_buffer_full);
                        if (k < 0) {

                                if (errno == EAGAIN)
                                        f->stdout_writable = false;
                                else if (errno == EIO || ERRNO_IS_DISCONNECT(errno)) {
                                        f->stdout_writable = false;
                                        f->stdout_hangup = true;
                                        f->stdout_event_source = sd_event_source_unref(f->stdout_event_source);
                                } else {
                                        log_error_errno(errno, "write(): %m");
                                        return pty_forward_done(f, -errno);
                                }

                        } else {

                                if (k > 0) {
                                        f->last_char = f->out_buffer[k-1];
                                        f->last_char_set = true;
                                }

                                assert(f->out_buffer_full >= (size_t) k);
                                memmove(f->out_buffer, f->out_buffer + k, f->out_buffer_full - k);
                                f->out_buffer_full -= k;
                        }
                }
        }

        if (f->stdin_hangup || f->stdout_hangup || f->master_hangup) {
                /* Exit the loop if any side hung up and if there's
                 * nothing more to write or nothing we could write. */

                if ((f->out_buffer_full <= 0 || f->stdout_hangup) &&
                    (f->in_buffer_full <= 0 || f->master_hangup))
                        return pty_forward_done(f, 0);
        }

        /* If we were asked to drain, and there's nothing more to handle from the master, then call the callback
         * too. */
        if (f->drain && drained(f))
                return pty_forward_done(f, 0);

        return 0;
}

static int on_master_event(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        PTYForward *f = ASSERT_PTR(userdata);

        assert(e);
        assert(e == f->master_event_source);
        assert(fd >= 0);
        assert(fd == f->master);

        if (revents & (EPOLLIN|EPOLLHUP))
                f->master_readable = true;

        if (revents & (EPOLLOUT|EPOLLHUP))
                f->master_writable = true;

        return shovel(f);
}

static int on_stdin_event(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        PTYForward *f = ASSERT_PTR(userdata);

        assert(e);
        assert(e == f->stdin_event_source);
        assert(fd >= 0);
        assert(fd == f->input_fd);

        if (revents & (EPOLLIN|EPOLLHUP))
                f->stdin_readable = true;

        return shovel(f);
}

static int on_stdout_event(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        PTYForward *f = ASSERT_PTR(userdata);

        assert(e);
        assert(e == f->stdout_event_source);
        assert(fd >= 0);
        assert(fd == f->output_fd);

        if (revents & (EPOLLOUT|EPOLLHUP))
                f->stdout_writable = true;

        return shovel(f);
}

static int on_sigwinch_event(sd_event_source *e, const struct signalfd_siginfo *si, void *userdata) {
        PTYForward *f = ASSERT_PTR(userdata);
        struct winsize ws;

        assert(e);
        assert(e == f->sigwinch_event_source);

        /* The window size changed, let's forward that. */
        if (ioctl(f->output_fd, TIOCGWINSZ, &ws) >= 0)
                (void) ioctl(f->master, TIOCSWINSZ, &ws);

        return 0;
}

int pty_forward_new(
                sd_event *event,
                int master,
                PTYForwardFlags flags,
                PTYForward **ret) {

        _cleanup_(pty_forward_freep) PTYForward *f = NULL;
        struct winsize ws;
        int r;

        f = new(PTYForward, 1);
        if (!f)
                return -ENOMEM;

        *f = (struct PTYForward) {
                .flags = flags,
                .master = -EBADF,
                .input_fd = -EBADF,
                .output_fd = -EBADF,
        };

        if (event)
                f->event = sd_event_ref(event);
        else {
                r = sd_event_default(&f->event);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, PTY_FORWARD_READ_ONLY))
                f->output_fd = STDOUT_FILENO;
        else {
                /* If we shall be invoked in interactive mode, let's switch on non-blocking mode, so that we
                 * never end up staving one direction while we block on the other. However, let's be careful
                 * here and not turn on O_NONBLOCK for stdin/stdout directly, but of re-opened copies of
                 * them. This has two advantages: when we are killed abruptly the stdin/stdout fds won't be
                 * left in O_NONBLOCK state for the next process using them. In addition, if some process
                 * running in the background wants to continue writing to our stdout it can do so without
                 * being confused by O_NONBLOCK. */

                f->input_fd = fd_reopen(STDIN_FILENO, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (f->input_fd < 0) {
                        /* Handle failures gracefully, after all certain fd types cannot be reopened
                         * (sockets, …) */
                        log_debug_errno(f->input_fd, "Failed to reopen stdin, using original fd: %m");

                        r = fd_nonblock(STDIN_FILENO, true);
                        if (r < 0)
                                return r;

                        f->input_fd = STDIN_FILENO;
                } else
                        f->close_input_fd = true;

                f->output_fd = fd_reopen(STDOUT_FILENO, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (f->output_fd < 0) {
                        log_debug_errno(f->output_fd, "Failed to reopen stdout, using original fd: %m");

                        r = fd_nonblock(STDOUT_FILENO, true);
                        if (r < 0)
                                return r;

                        f->output_fd = STDOUT_FILENO;
                } else
                        f->close_output_fd = true;
        }

        r = fd_nonblock(master, true);
        if (r < 0)
                return r;

        f->master = master;

        if (ioctl(f->output_fd, TIOCGWINSZ, &ws) < 0)
                /* If we can't get the resolution from the output fd, then use our internal, regular width/height,
                 * i.e. something derived from $COLUMNS and $LINES if set. */
                ws = (struct winsize) {
                        .ws_row = lines(),
                        .ws_col = columns(),
                };

        (void) ioctl(master, TIOCSWINSZ, &ws);

        if (!(flags & PTY_FORWARD_READ_ONLY)) {
                int same;

                assert(f->input_fd >= 0);

                same = inode_same_at(f->input_fd, NULL, f->output_fd, NULL, AT_EMPTY_PATH);
                if (same < 0)
                        return same;

                if (tcgetattr(f->input_fd, &f->saved_stdin_attr) >= 0) {
                        struct termios raw_stdin_attr;

                        f->saved_stdin = true;

                        raw_stdin_attr = f->saved_stdin_attr;
                        cfmakeraw(&raw_stdin_attr);

                        if (!same)
                                raw_stdin_attr.c_oflag = f->saved_stdin_attr.c_oflag;

                        (void) tcsetattr(f->input_fd, TCSANOW, &raw_stdin_attr);
                }

                if (!same && tcgetattr(f->output_fd, &f->saved_stdout_attr) >= 0) {
                        struct termios raw_stdout_attr;

                        f->saved_stdout = true;

                        raw_stdout_attr = f->saved_stdout_attr;
                        cfmakeraw(&raw_stdout_attr);
                        raw_stdout_attr.c_iflag = f->saved_stdout_attr.c_iflag;
                        raw_stdout_attr.c_lflag = f->saved_stdout_attr.c_lflag;
                        (void) tcsetattr(f->output_fd, TCSANOW, &raw_stdout_attr);
                }

                r = sd_event_add_io(f->event, &f->stdin_event_source, f->input_fd, EPOLLIN|EPOLLET, on_stdin_event, f);
                if (r < 0 && r != -EPERM)
                        return r;

                if (r >= 0)
                        (void) sd_event_source_set_description(f->stdin_event_source, "ptyfwd-stdin");
        }

        r = sd_event_add_io(f->event, &f->stdout_event_source, f->output_fd, EPOLLOUT|EPOLLET, on_stdout_event, f);
        if (r == -EPERM)
                /* stdout without epoll support. Likely redirected to regular file. */
                f->stdout_writable = true;
        else if (r < 0)
                return r;
        else
                (void) sd_event_source_set_description(f->stdout_event_source, "ptyfwd-stdout");

        r = sd_event_add_io(f->event, &f->master_event_source, master, EPOLLIN|EPOLLOUT|EPOLLET, on_master_event, f);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(f->master_event_source, "ptyfwd-master");

        r = sd_event_add_signal(f->event, &f->sigwinch_event_source, SIGWINCH, on_sigwinch_event, f);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(f->sigwinch_event_source, "ptyfwd-sigwinch");

        *ret = TAKE_PTR(f);

        return 0;
}

PTYForward *pty_forward_free(PTYForward *f) {
        if (!f)
                return NULL;
        pty_forward_disconnect(f);
        free(f->background_color);
        return mfree(f);
}

int pty_forward_get_last_char(PTYForward *f, char *ch) {
        assert(f);
        assert(ch);

        if (!f->last_char_set)
                return -ENXIO;

        *ch = f->last_char;
        return 0;
}

int pty_forward_set_ignore_vhangup(PTYForward *f, bool b) {
        int r;

        assert(f);

        if (!!(f->flags & PTY_FORWARD_IGNORE_VHANGUP) == b)
                return 0;

        SET_FLAG(f->flags, PTY_FORWARD_IGNORE_VHANGUP, b);

        if (!ignore_vhangup(f)) {

                /* We shall now react to vhangup()s? Let's check
                 * immediately if we might be in one */

                f->master_readable = true;
                r = shovel(f);
                if (r < 0)
                        return r;
        }

        return 0;
}

bool pty_forward_get_ignore_vhangup(PTYForward *f) {
        assert(f);

        return !!(f->flags & PTY_FORWARD_IGNORE_VHANGUP);
}

bool pty_forward_is_done(PTYForward *f) {
        assert(f);

        return f->done;
}

void pty_forward_set_handler(PTYForward *f, PTYForwardHandler cb, void *userdata) {
        assert(f);

        f->handler = cb;
        f->userdata = userdata;
}

bool pty_forward_drain(PTYForward *f) {
        assert(f);

        /* Starts draining the forwarder. Specifically:
         *
         * - Returns true if there are no unprocessed bytes from the pty, false otherwise
         *
         * - Makes sure the handler function is called the next time the number of unprocessed bytes hits zero
         */

        f->drain = true;
        return drained(f);
}

int pty_forward_set_priority(PTYForward *f, int64_t priority) {
        int r;
        assert(f);

        if (f->stdin_event_source) {
                r = sd_event_source_set_priority(f->stdin_event_source, priority);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_priority(f->stdout_event_source, priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(f->master_event_source, priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(f->sigwinch_event_source, priority);
        if (r < 0)
                return r;

        return 0;
}

int pty_forward_set_width_height(PTYForward *f, unsigned width, unsigned height) {
        struct winsize ws;

        assert(f);

        if (width == UINT_MAX && height == UINT_MAX)
                return 0; /* noop */

        if (width != UINT_MAX &&
            (width == 0 || width > USHRT_MAX))
                return -ERANGE;

        if (height != UINT_MAX &&
            (height == 0 || height > USHRT_MAX))
                return -ERANGE;

        if (width == UINT_MAX || height == UINT_MAX) {
                if (ioctl(f->master, TIOCGWINSZ, &ws) < 0)
                        return -errno;

                if (width != UINT_MAX)
                        ws.ws_col = width;
                if (height != UINT_MAX)
                        ws.ws_row = height;
        } else
                ws = (struct winsize) {
                        .ws_row = height,
                        .ws_col = width,
                };

        if (ioctl(f->master, TIOCSWINSZ, &ws) < 0)
                return -errno;

        /* Make sure we ignore SIGWINCH window size events from now on */
        f->sigwinch_event_source = sd_event_source_unref(f->sigwinch_event_source);

        return 0;
}

int pty_forward_set_background_color(PTYForward *f, const char *color) {
        assert(f);

        return free_and_strdup(&f->background_color, color);
}
