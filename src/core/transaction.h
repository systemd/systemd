#ifndef footransactionhfoo
#define footransactionhfoo

typedef struct Transaction Transaction;

#include "unit.h"
#include "manager.h"
#include "job.h"
#include "hashmap.h"

struct Transaction {
        /* Jobs to be added */
        Hashmap *jobs;      /* Unit object => Job object list 1:1 */
        JobDependency *anchor;
};

Transaction *transaction_new(void);
void transaction_free(Transaction *tr);

int transaction_add_job_and_dependencies(
                Transaction *tr,
                JobType type,
                Unit *unit,
                Job *by,
                bool matters,
                bool override,
                bool conflicts,
                bool ignore_requirements,
                bool ignore_order,
                DBusError *e,
                Job **_ret);
int transaction_activate(Transaction *tr, Manager *m, JobMode mode, DBusError *e);
int transaction_add_isolate_jobs(Transaction *tr, Manager *m);
void transaction_abort(Transaction *tr);

#endif
