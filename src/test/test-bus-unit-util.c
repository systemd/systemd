/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-unit-util.h"
#include "unit-def.h"
#include "tests.h"

TEST(bus_dump_transient_settings) {
        /* -1 is for generic unit, natural numbers are for specific unit types */
        for (UnitType t = -1; t < _UNIT_TYPE_MAX; t++) {
                log_info("==================== %s ====================", t < 0 ? "unit" : unit_type_to_string(t));
                bus_dump_transient_settings(stdout, t);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
