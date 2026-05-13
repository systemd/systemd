/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "machine.h"
#include "tests.h"
#include "test-varlink-idl-util.h"
#include "varlink-io.systemd.Machine.h"

TEST(machine_enums_idl) {
        TEST_IDL_ENUM(MachineClass, machine_class, vl_type_MachineClass);
        TEST_IDL_ENUM(KillWhom, kill_whom, vl_type_KillWhom);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
