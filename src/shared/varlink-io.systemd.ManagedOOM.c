/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.ManagedOOM.h"

/* Pull in vl_type_ControlGroup, since both interfaces need it */
#include "varlink-io.systemd.oom.h"

/* This is PID1's Varlink service, where PID 1 is the server and oomd is the client.
 *
 * Compare with io.systemd.oom where the client/server roles of oomd and the service manager are swapped! */

static SD_VARLINK_DEFINE_METHOD_FULL(
                SubscribeManagedOOMCGroups,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(cgroups, ControlGroup, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(SubscriptionTaken);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_ManagedOOM,
                "io.systemd.ManagedOOM",
                &vl_method_SubscribeManagedOOMCGroups,
                &vl_type_ControlGroup,
                &vl_error_SubscriptionTaken);
