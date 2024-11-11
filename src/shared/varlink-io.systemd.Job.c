/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "build.h"
#include "varlink-io.systemd.Job.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ActivationDetails,
                SD_VARLINK_DEFINE_FIELD(key, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(value, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(NoSuchJob);

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("If non-null the ID of a job"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The job ID"),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The unit associated with the job"),
                SD_VARLINK_DEFINE_OUTPUT(unit, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The job type"),
                SD_VARLINK_DEFINE_OUTPUT(jobType, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The job state"),
                SD_VARLINK_DEFINE_OUTPUT(state, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The job activation details"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(activationDetails, ActivationDetails, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Job,
                "io.systemd.Job",
                SD_VARLINK_SYMBOL_COMMENT("Activation defailts of job"),
                &vl_type_ActivationDetails,
                SD_VARLINK_SYMBOL_COMMENT("List jobs"),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("No matching job found"),
                &vl_error_NoSuchJob);
