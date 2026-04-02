/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.Facts.h"

static SD_VARLINK_DEFINE_ERROR(NoSuchFact);

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Fact family name, e.g. io.systemd.Basic.Hostname"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                /* This is currently an unused placeholder. Add examples when we have them. */
                SD_VARLINK_FIELD_COMMENT("Fact object name"),
                SD_VARLINK_DEFINE_OUTPUT(object, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Fact value"),
                SD_VARLINK_DEFINE_OUTPUT(value, SD_VARLINK_ANY, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Describe,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Fact family name, e.g. io.systemd.Basic.Hostname"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Fact family description"),
                SD_VARLINK_DEFINE_OUTPUT(description, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Facts,
                "io.systemd.Facts",
                SD_VARLINK_INTERFACE_COMMENT("Facts APIs"),
                SD_VARLINK_SYMBOL_COMMENT("Method to get a list of facts and their values"),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("Method to get the fact families"),
                &vl_method_Describe,
                SD_VARLINK_SYMBOL_COMMENT("No such fact found"),
                &vl_error_NoSuchFact);
