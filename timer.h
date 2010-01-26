/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef footimerhfoo
#define footimerhfoo

typedef struct Timer Timer;

#include "unit.h"

typedef enum TimerState {
        TIMER_DEAD,
        TIMER_WAITING,
        TIMER_RUNNING,
        _TIMER_STATE_MAX
} TimerState;

struct Timer {
        Meta meta;

        TimerState state;

        clockid_t clock_id;
        usec_t next_elapse;

        Service *service;
};

const UnitVTable timer_vtable;

#endif
