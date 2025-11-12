/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-future.h"

typedef struct sd_future sd_future;

struct sd_future {
        int state;
        int result;
        union {
                struct {
                        sd_event_source *source;
                        int fd;
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
                        sd_event_source *source;
                        sd_future *target;
                } wait;
                struct {
                        sd_bus_slot *slot;
                        sd_bus_message *reply;
                } bus;
        };
};
