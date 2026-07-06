/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "list.h"
#include "pidref.h"
#include "prioq.h"
#include "tests.h"
#include "udev-manager.h"

TEST(devpath_conflict) {
        assert_se(!devpath_conflict(NULL, NULL));
        assert_se(!devpath_conflict(NULL, "/devices/pci0000:00/0000:00:1c.4"));
        assert_se(!devpath_conflict("/devices/pci0000:00/0000:00:1c.4", NULL));
        assert_se(!devpath_conflict("/devices/pci0000:00/0000:00:1c.4", "/devices/pci0000:00/0000:00:00.0"));
        assert_se(!devpath_conflict("/devices/virtual/net/veth99", "/devices/virtual/net/veth999"));

        assert_se(devpath_conflict("/devices/pci0000:00/0000:00:1c.4", "/devices/pci0000:00/0000:00:1c.4"));
        assert_se(devpath_conflict("/devices/pci0000:00/0000:00:1c.4", "/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0"));
        assert_se(devpath_conflict("/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0/nvme/nvme0/nvme0n1",
                                   "/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0/nvme/nvme0/nvme0n1/nvme0n1p1"));
}

TEST(manager_free_with_attached_worker) {
        /* Reproduce an abnormal udevd shutdown */

        _cleanup_(manager_freep) Manager *manager = manager_new();
        ASSERT_NOT_NULL(manager);

        Event *event = new(Event, 1);
        ASSERT_NOT_NULL(event);
        *event = (Event) {
                .n_ref = 1,
                .manager = manager,
                .state = EVENT_RUNNING,
                .locked_event_prioq_index = PRIOQ_IDX_NULL,
        };
        LIST_PREPEND(event, manager->events, event);

        Worker *worker = new(Worker, 1);
        ASSERT_NOT_NULL(worker);
        *worker = (Worker) {
                .manager = manager,
                .pidref = PIDREF_NULL,
                .state = WORKER_RUNNING,
                .event = event,
        };
        event->worker = worker;
        ASSERT_OK(hashmap_ensure_put(&manager->workers, &worker_hash_op, &worker->pidref, worker));

        /* manager_free() runs via the cleanup attribute and must not dereference the freed worker. */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
