/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sd-event.h>
#include <sd-varlink.h>

#include "list.h"
#include "ptybroker-forward.h"

struct PseudoTTYMonitor {
        /* A structure kept for every monitor connection. A single pseudo TTY may have multiple monitors associated. */
        PseudoTTY *pty;
        sd_varlink *link;
        sd_event_source *io_event_source;
        struct iovec buffer; /* Data still to be written to the monitor connection */
        bool hang_up_on_disconnect; /* If true, hang up the pty once this monitor is disconnected */
        LIST_FIELDS(PseudoTTYMonitor, monitors);
};

PseudoTTYMonitor *pseudo_tty_monitor_free(PseudoTTYMonitor *monitor);
DEFINE_TRIVIAL_CLEANUP_FUNC(PseudoTTYMonitor*, pseudo_tty_monitor_free);

int pseudo_tty_monitor_new(sd_varlink *link, PseudoTTYMonitor **ret);
void pseudo_tty_monitor_link(PseudoTTYMonitor *monitor, PseudoTTY *pty);

int pseudo_tty_monitor_set_events(PseudoTTYMonitor *monitor);

size_t pseudo_tty_monitor_space(PseudoTTYMonitor *monitor);
