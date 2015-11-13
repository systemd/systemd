/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct Transaction Transaction;

#include "unit.h"
#include "manager.h"
#include "job.h"
#include "hashmap.h"

struct Transaction {
        /* Jobs to be added */
        Hashmap *jobs;      /* Unit object => Job object list 1:1 */
        Job *anchor_job;      /* the job the user asked for */
        bool irreversible;
};

Transaction *transaction_new(bool irreversible);
void transaction_free(Transaction *tr);

int transaction_add_job_and_dependencies(
                Transaction *tr,
                JobType type,
                Unit *unit,
                Job *by,
                bool matters,
                bool conflicts,
                bool ignore_requirements,
                bool ignore_order,
                sd_bus_error *e);
int transaction_activate(Transaction *tr, Manager *m, JobMode mode, sd_bus_error *e);
int transaction_add_isolate_jobs(Transaction *tr, Manager *m);
void transaction_abort(Transaction *tr);
