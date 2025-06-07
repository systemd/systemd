/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.FactoryReset.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                FactoryResetMode,
                SD_VARLINK_FIELD_COMMENT("Factory reset is not supported on this OS."),
                SD_VARLINK_DEFINE_ENUM_VALUE(unsupported),
                SD_VARLINK_FIELD_COMMENT("Factory reset not requested."),
                SD_VARLINK_DEFINE_ENUM_VALUE(unspecified),
                SD_VARLINK_FIELD_COMMENT("Factory reset explicitly turned off."),
                SD_VARLINK_DEFINE_ENUM_VALUE(off),
                SD_VARLINK_FIELD_COMMENT("Factory reset is currently being executed."),
                SD_VARLINK_DEFINE_ENUM_VALUE(on),
                SD_VARLINK_FIELD_COMMENT("Factory reset has been completed during the current boot."),
                SD_VARLINK_DEFINE_ENUM_VALUE(complete),
                SD_VARLINK_FIELD_COMMENT("Factory reset has been requested for the next boot."),
                SD_VARLINK_DEFINE_ENUM_VALUE(pending));

static SD_VARLINK_DEFINE_METHOD(
                GetFactoryResetMode,
                SD_VARLINK_FIELD_COMMENT("The current factory reset mode"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(mode, FactoryResetMode, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanRequestFactoryReset,
                SD_VARLINK_DEFINE_OUTPUT(supported, SD_VARLINK_BOOL, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_FactoryReset,
                "io.systemd.FactoryReset",
                SD_VARLINK_INTERFACE_COMMENT("APIs to query factory reset status"),
                SD_VARLINK_SYMBOL_COMMENT("Encodes the current factory reset status"),
                &vl_type_FactoryResetMode,
                SD_VARLINK_SYMBOL_COMMENT("Report the current factory reset status"),
                &vl_method_GetFactoryResetMode,
                SD_VARLINK_SYMBOL_COMMENT("Returns whether requesting a factory reset is available (by invoking the factory-reset.target unit)."),
                &vl_method_CanRequestFactoryReset);
