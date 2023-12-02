/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "pidref.h"

typedef struct Inhibitor Inhibitor;

typedef enum InhibitWhat {
        INHIBIT_SHUTDOWN             = 1 << 0,
        INHIBIT_SLEEP                = 1 << 1,
        INHIBIT_IDLE                 = 1 << 2,
        INHIBIT_HANDLE_POWER_KEY     = 1 << 3,
        INHIBIT_HANDLE_SUSPEND_KEY   = 1 << 4,
        INHIBIT_HANDLE_HIBERNATE_KEY = 1 << 5,
        INHIBIT_HANDLE_LID_SWITCH    = 1 << 6,
        INHIBIT_HANDLE_REBOOT_KEY    = 1 << 7,
        _INHIBIT_WHAT_MAX            = 1 << 8,
        _INHIBIT_WHAT_INVALID        = -EINVAL,
} InhibitWhat;

typedef enum InhibitMode {
        INHIBIT_BLOCK,
        INHIBIT_BLOCK_WEAK,
        INHIBIT_DELAY,
        INHIBIT_DELAY_WEAK,
        _INHIBIT_MODE_MAX,
        _INHIBIT_MODE_INVALID = -EINVAL,
} InhibitMode;

#include "logind.h"

struct Inhibitor {
        Manager *manager;

        sd_event_source *event_source;

        char *id;
        char *state_file;

        bool started;

        InhibitWhat what;
        char *who;
        char *why;
        InhibitMode mode;

        PidRef pid;
        uid_t uid;

        dual_timestamp since;

        char *fifo_path;
        int fifo_fd;
};

int inhibitor_new(Manager *m, const char* id, Inhibitor **ret);
Inhibitor* inhibitor_free(Inhibitor *i);

DEFINE_TRIVIAL_CLEANUP_FUNC(Inhibitor*, inhibitor_free);

int inhibitor_load(Inhibitor *i);

int inhibitor_start(Inhibitor *i);
void inhibitor_stop(Inhibitor *i);

int inhibitor_create_fifo(Inhibitor *i);

bool inhibitor_is_orphan(Inhibitor *i);

InhibitWhat manager_inhibit_what(Manager *m, bool block);
bool manager_is_inhibited(Manager *m, InhibitWhat w, bool block, dual_timestamp *since, bool ignore_inactive, bool ignore_uid, uid_t uid, Inhibitor **offending);

static inline bool inhibit_what_is_valid(InhibitWhat w) {
        return w > 0 && w < _INHIBIT_WHAT_MAX;
}

const char* inhibit_what_to_string(InhibitWhat k);
int inhibit_what_from_string(const char *s);

const char* inhibit_mode_to_string(InhibitMode k);
InhibitMode inhibit_mode_from_string(const char *s);
