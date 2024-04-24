/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Machine.h"
#include "varlink-idl.h"

static VARLINK_DEFINE_METHOD(
                Register,
                VARLINK_DEFINE_INPUT(name,              VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(id,                VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(service,           VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(class,             VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(leader,            VARLINK_INT,    0),
                VARLINK_DEFINE_INPUT(rootDirectory,     VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(ifIndices,         VARLINK_INT,    VARLINK_ARRAY|VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(vsockCid,          VARLINK_INT,    VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(sshAddress,        VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(sshPrivateKeyPath, VARLINK_STRING, VARLINK_NULLABLE));

VARLINK_DEFINE_INTERFACE(
                io_systemd_Machine,
                "io.systemd.Machine",
                &vl_method_Register);
