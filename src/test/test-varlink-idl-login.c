/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "logind-session.h"
#include "tests.h"
#include "test-varlink-idl-util.h"
#include "varlink-io.systemd.Login.h"

TEST(login_enums_idl) {
        TEST_IDL_ENUM(SessionType, session_type, vl_type_SessionType);
        /* SessionClass has SESSION_NONE ("none") as an internal sentinel that is intentionally not exposed
         * via Varlink. Only validate the IDL→C direction. */
        TEST_IDL_ENUM_FROM_STRING(SessionClass, session_class, vl_type_SessionClass);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
