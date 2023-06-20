/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
Transaction *transaction_free(Transaction *tr);
Transaction *transaction_abort_and_free(Transaction *tr);
DEFINE_TRIVIAL_CLEANUP_FUNC(Transaction*, transaction_abort_and_free);

typedef enum TransactionAddFlags {
        TRANSACTION_MATTERS             = 1 << 0,
        TRANSACTION_CONFLICTS           = 1 << 1,
        TRANSACTION_IGNORE_REQUIREMENTS = 1 << 2,
        TRANSACTION_IGNORE_ORDER        = 1 << 3,
} TransactionAddFlags;

void transaction_add_propagate_reload_jobs(
                Transaction *tr,
                Unit *unit, Job *by,
                TransactionAddFlags flags);

int transaction_add_job_and_dependencies(
                Transaction *tr,
                JobType type,
                Unit *unit,
                Job *by,
                TransactionAddFlags flags,
                sd_bus_error *e);

int transaction_activate(Transaction *tr, Manager *m, JobMode mode, Set *affected, sd_bus_error *e);
int transaction_add_isolate_jobs(Transaction *tr, Manager *m);
int transaction_add_triggering_jobs(Transaction *tr, Unit *u);
