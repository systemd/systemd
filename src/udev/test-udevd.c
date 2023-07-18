/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

DEFINE_TEST_MAIN(LOG_DEBUG);
