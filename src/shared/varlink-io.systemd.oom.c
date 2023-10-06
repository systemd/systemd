/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.oom.h"

/* This is oomd's Varlink service, where oomd is server and systemd --user is the client.
 *
 * Compare with io.systemd.ManagedOOM where the client/server roles of the service manager and oomd are
 * swapped! */

VARLINK_DEFINE_STRUCT_TYPE(
                ControlGroup,
                VARLINK_DEFINE_FIELD(mode, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(path, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(property, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(limit, VARLINK_INT, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                ReportManagedOOMCGroups,
                VARLINK_DEFINE_INPUT_BY_TYPE(cgroups, ControlGroup, VARLINK_ARRAY));

VARLINK_DEFINE_INTERFACE(
                io_systemd_oom,
                "io.systemd.oom",
                &vl_method_ReportManagedOOMCGroups,
                &vl_type_ControlGroup);
