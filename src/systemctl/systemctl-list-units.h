/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int list_units(int argc, char *argv[], void *userdata);
int list_sockets(int argc, char *argv[], void *userdata);
int list_timers(int argc, char *argv[], void *userdata);

usec_t calc_next_elapse(dual_timestamp *nw, dual_timestamp *next);
