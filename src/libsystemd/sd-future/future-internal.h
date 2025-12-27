/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <signal.h>

#include "sd-forward.h"

struct sd_future {
        unsigned n_ref;

        int type;
        int state;
        int result;

        Set *waiters;

        sd_future_func_t callback;
        void *userdata;

        union {
                struct {
                        sd_event_source *source;
                        uint32_t revents;
                } io;
                struct {
                        sd_event_source *source;
                        uint64_t usec;
                } time;
                struct {
                        sd_event_source *source;
                        siginfo_t si;
                } child;
                struct {
                        sd_future *target;
                } wait;
                struct {
                        sd_bus_slot *slot;
                        sd_bus_message *reply;
                } bus;
                struct {
                        Fiber *fiber;
                } fiber;
        };
};

int sd_future_resolve(sd_future *f, int result);
