/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct Transaction Transaction;

#include "hashmap.h"
#include "job.h"
#include "manager.h"
#include "unit.h"

struct Transaction {
        /* Jobs to be added */
        Hashmap *jobs;      /* Unit object => Job object list 1:1 */
        Job *anchor_job;      /* the job the user asked for */
        bool irreversible;
};

Transaction *transaction_new(bool irreversible);
void transaction_free(Transaction *tr);

void transaction_add_propagate_reload_jobs(Transaction *tr, Unit *unit, Job *by, bool ignore_order, sd_bus_error *e);
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
int transaction_activate(Transaction *tr, Manager *m, JobMode mode, Set *affected, sd_bus_error *e);
int transaction_add_isolate_jobs(Transaction *tr, Manager *m);
void transaction_abort(Transaction *tr);
