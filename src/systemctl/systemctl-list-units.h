/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int verb_list_units(int argc, char *argv[], void *userdata);
int verb_list_sockets(int argc, char *argv[], void *userdata);
int verb_list_timers(int argc, char *argv[], void *userdata);
int verb_list_automounts(int argc, char *argv[], void *userdata);

usec_t calc_next_elapse(dual_timestamp *nw, dual_timestamp *next);
