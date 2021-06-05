/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "unit.h"
#include "bus-object.h"

extern const sd_bus_vtable bus_job_vtable[];
extern const BusObjectImplementation job_object;

int bus_job_method_cancel(sd_bus_message *message, void *job, sd_bus_error *error);
int bus_job_method_get_waiting_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error);

void bus_job_send_change_signal(Job *j);
void bus_job_send_pending_change_signal(Job *j, bool including_new);
void bus_job_send_removed_signal(Job *j);

int bus_job_coldplug_bus_track(Job *j);
int bus_job_track_sender(Job *j, sd_bus_message *m);
