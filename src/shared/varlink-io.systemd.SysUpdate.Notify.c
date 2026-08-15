/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.SysUpdate.Notify.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Resource,
                SD_VARLINK_DEFINE_FIELD(transfer, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                OnCompletedUpdate,
                SD_VARLINK_DEFINE_INPUT(component, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(version, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(resources, Resource, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_SysUpdate_Notify,
                "io.systemd.SysUpdate.Notify",
                &vl_type_Resource,
                &vl_method_OnCompletedUpdate);
