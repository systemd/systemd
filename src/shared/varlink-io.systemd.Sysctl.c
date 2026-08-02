/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Sysctl.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SysctlSetting,
                SD_VARLINK_FIELD_COMMENT("A sysctl key. This can take a glob pattern."),
                SD_VARLINK_DEFINE_FIELD(key, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A sysctl value to be written. When this is unspecified, the setting is handled as an exclude entry of other glob patterns."),
                SD_VARLINK_DEFINE_FIELD(value, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Ignore errors in writing sysctl value."),
                SD_VARLINK_DEFINE_FIELD(ignoreFailure, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Verify sysctl value after write."),
                SD_VARLINK_DEFINE_FIELD(verify, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Apply,
                SD_VARLINK_FIELD_COMMENT("settings"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(settings, SysctlSetting, SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Sysctl,
                "io.systemd.Sysctl",
                SD_VARLINK_INTERFACE_COMMENT("Sysctl APIs."),
                SD_VARLINK_SYMBOL_COMMENT("A structure encapsulating sysctl setting."),
                &vl_type_SysctlSetting,
                SD_VARLINK_SYMBOL_COMMENT("Apply settings."),
                &vl_method_Apply);
