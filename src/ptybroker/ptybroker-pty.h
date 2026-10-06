/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "forward.h"
#include "list.h"
#include "pidref.h"
#include "ptybroker-forward.h"
#include "ptybroker-util.h"

enum FrontendType {
        FRONTEND_TAKE,    /* return frontend fd to client, don't keep duplicate */
        FRONTEND_NULL,    /* read data from pty, and write it to monitors + eat it up if not monitored */
        FRONTEND_LOG,     /* read data from pty, and write it to journal log + monitors */
        _FRONTEND_TYPE_MAX,
        _FRONTEND_TYPE_INVALID = -EINVAL,
};

enum BackendType {
        BACKEND_TAKE,     /* return backend fd to client, don't keep duplicate */
        BACKEND_SHELL,    /* connect shell to backend */
        _BACKEND_TYPE_MAX,
        _BACKEND_TYPE_INVALID = -EINVAL,
};

struct PseudoTTY {
        Manager *manager;

        char *name;
        char *description;
        char *tag;

        TerminalSettings terminal_settings;

        FrontendType frontend_type;
        BackendType backend_type;

        int frontend_fd; /* aka "master" */
        int backend_fd;  /* aka "slave" */
        int pin_fd;      /* O_PATH on backend_fd */
        char *backend_path;
        char *unit;

        /* Connection to the service manager while the StartTransient() call for the shell unit is in flight */
        sd_varlink *start_shell_link;

        /* Client connection whose AcquirePty() reply is deferred until the shell unit start completed, plus
         * the prepared reply parameters */
        sd_varlink *acquire_link;
        sd_json_variant *acquire_reply;
        bool acquire_monitor;

        /* Identity of the client that allocated this PTY */
        PidRef owner_pidref;
        uid_t owner_uid;
        gid_t owner_gid;

        /* A line-based buffer with the last few lines of output on this PTY */
        char **track_buffer;
        size_t track_buffer_next_line;
        size_t track_buffer_allocated_lines;
        size_t track_buffer_n_bytes; /* Sum of the payload bytes of all lines currently in the track buffer */

        struct iovec frontend_write_buffer;
        struct iovec frontend_read_buffer;
        EndOfLine eol_mask;

        sd_event_source *io_event_source;
        sd_event_source *backend_inotify_event_source;

        sd_event_source *vhangup_event_source;
        Set *vhangup_links;

        size_t n_monitors;
        LIST_HEAD(PseudoTTYMonitor, monitors);

        bool in_free_queue;
        LIST_FIELDS(PseudoTTY, free_queue);
};

PseudoTTY* pseudo_tty_free(PseudoTTY *pty);
DEFINE_TRIVIAL_CLEANUP_FUNC(PseudoTTY*, pseudo_tty_free);

int pseudo_tty_new(PseudoTTY **ret);
int pseudo_tty_link(PseudoTTY *pty, Manager *m);

int pseudo_tty_set_events(PseudoTTY *pty);

void pseudo_tty_add_to_free_queue(PseudoTTY *pty);

int pseudo_tty_watch_frontend_fd(PseudoTTY *pty, sd_event *event);
int pseudo_tty_watch_backend_node(PseudoTTY *pty, sd_event *event);

int pseudo_tty_track_buffer_to_json(PseudoTTY *pty, size_t n_lines, sd_json_variant **ret);

int pseudo_tty_vhangup(PseudoTTY *pty);

int pseudo_tty_sync_winsize(PseudoTTY *pty);

DECLARE_STRING_TABLE_LOOKUP(frontend_type, FrontendType);
DECLARE_STRING_TABLE_LOOKUP(backend_type, BackendType);
