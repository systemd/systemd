/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
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

TEST(worker_free_detaches_event) {
        /* worker_free() must clear the back-pointer of the event it is processing, otherwise the event is
         * left referencing the freed worker. This happens e.g. on manager_free(), which frees the workers
         * before the events still referencing them. */

        Worker *worker = ASSERT_PTR(new0(Worker, 1));
        worker->pidref = PIDREF_NULL;

        _cleanup_free_ Event *event = ASSERT_PTR(new0(Event, 1));

        worker->event = event;
        event->worker = worker;

        worker_free(worker);

        ASSERT_NULL(event->worker);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
