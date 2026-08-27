/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-varlink.h"

#include "ansi-seq.h"
#include "list.h"
#include "ptybroker-forward.h"

struct PseudoTTYMonitor {
        /* A structure kept for every monitor connection. A single pseudo TTY may have multiple monitors associated. */
        PseudoTTY *pty;
        sd_varlink *link;
        sd_event_source *io_event_source;
        struct iovec buffer;         /* Data still to be written to the monitor connection */
        bool hang_up_on_disconnect;  /* If true, hang up the pty once this monitor is disconnected */

        /* OSC 2811 terminal dimension tracking */
        bool osc_winsize;            /* If true, subscribe to dimension changes of the monitor's terminal */
        unsigned columns, lines;     /* Most recent dimensions reported by the monitor, 0 if not known yet */
        AnsiSeqParser output_parser; /* Tracks sequence boundaries on the stream we send to the monitor */
        AnsiSeqParser input_parser;  /* Tracks + captures sequences on the stream we receive from the monitor */
        bool subscribe_pending;      /* Send a subscribe sequence at the next safe position of the output stream */
        struct iovec input_hold;     /* Bytes of an incomplete sequence on the input stream, held back from the
                                      * pty's frontend write buffer until we know whether to excise them */

        LIST_FIELDS(PseudoTTYMonitor, monitors);
};

PseudoTTYMonitor* pseudo_tty_monitor_free(PseudoTTYMonitor *monitor);
DEFINE_TRIVIAL_CLEANUP_FUNC(PseudoTTYMonitor*, pseudo_tty_monitor_free);

int pseudo_tty_monitor_new(sd_varlink *link, bool osc_winsize, PseudoTTYMonitor **ret);
void pseudo_tty_monitor_link(PseudoTTYMonitor *monitor, PseudoTTY *pty);

int pseudo_tty_monitor_push_pending(PseudoTTYMonitor *monitor);

int pseudo_tty_monitor_set_events(PseudoTTYMonitor *monitor);

size_t pseudo_tty_monitor_space(PseudoTTYMonitor *monitor);

int pseudo_tty_monitor_enqueue_output(PseudoTTYMonitor *monitor, const void *data, size_t n);
