/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-unit-util.h"
#include "unit-def.h"
#include "tests.h"

TEST(bus_dump_runtime_properties) {
        for (UnitType t = 0; t < _UNIT_TYPE_MAX; t++) {
                log_info("==================== %s ====================", unit_type_to_string(t));
                bus_dump_runtime_properties(stdout, t);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
