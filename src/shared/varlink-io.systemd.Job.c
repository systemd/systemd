/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Job.h"

/* Keep in sync with job_type_table[] in src/core/job.c */
SD_VARLINK_DEFINE_ENUM_TYPE(
                JobType,
                SD_VARLINK_DEFINE_ENUM_VALUE(start),
                SD_VARLINK_DEFINE_ENUM_VALUE(verify_active),
                SD_VARLINK_DEFINE_ENUM_VALUE(stop),
                SD_VARLINK_DEFINE_ENUM_VALUE(reload),
                SD_VARLINK_DEFINE_ENUM_VALUE(reload_or_start),
                SD_VARLINK_DEFINE_ENUM_VALUE(restart),
                SD_VARLINK_DEFINE_ENUM_VALUE(try_restart),
                SD_VARLINK_DEFINE_ENUM_VALUE(try_reload),
                SD_VARLINK_DEFINE_ENUM_VALUE(nop));

/* Keep in sync with job_state_table[] in src/core/job.c */
SD_VARLINK_DEFINE_ENUM_TYPE(
                JobState,
                SD_VARLINK_DEFINE_ENUM_VALUE(waiting),
                SD_VARLINK_DEFINE_ENUM_VALUE(running),
                SD_VARLINK_DEFINE_ENUM_VALUE(finished));

/* Keep in sync with job_result_table[] in src/core/job.c */
SD_VARLINK_DEFINE_ENUM_TYPE(
                JobResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(done),
                SD_VARLINK_DEFINE_ENUM_VALUE(canceled),
                SD_VARLINK_DEFINE_ENUM_VALUE(timeout),
                SD_VARLINK_DEFINE_ENUM_VALUE(failed),
                SD_VARLINK_DEFINE_ENUM_VALUE(dependency),
                SD_VARLINK_DEFINE_ENUM_VALUE(skipped),
                SD_VARLINK_DEFINE_ENUM_VALUE(invalid),
                SD_VARLINK_DEFINE_ENUM_VALUE(assert),
                SD_VARLINK_DEFINE_ENUM_VALUE(unsupported),
                SD_VARLINK_DEFINE_ENUM_VALUE(collected),
                SD_VARLINK_DEFINE_ENUM_VALUE(once),
                SD_VARLINK_DEFINE_ENUM_VALUE(frozen),
                SD_VARLINK_DEFINE_ENUM_VALUE(concurrency));

/* Field names match the D-Bus Job properties (Id, JobType, State) */
SD_VARLINK_DEFINE_STRUCT_TYPE(
                Job,
                SD_VARLINK_FIELD_COMMENT("The numeric job ID"),
                SD_VARLINK_DEFINE_FIELD(Id, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The job type"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(JobType, JobType, 0),
                SD_VARLINK_FIELD_COMMENT("Current job state. 'finished' indicates the job has completed; in that case Result is also set."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(State, JobState, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Job result. Only set once the job has reached the 'finished' state."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, JobResult, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                JobContext,
                SD_VARLINK_FIELD_COMMENT("The unit name this job operates on"),
                SD_VARLINK_DEFINE_FIELD(Unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The job type"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(JobType, JobType, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                JobRuntime,
                SD_VARLINK_FIELD_COMMENT("The numeric job ID"),
                SD_VARLINK_DEFINE_FIELD(Id, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Current job state"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(State, JobState, 0),
                SD_VARLINK_FIELD_COMMENT("Job result. Only set once the job has reached the 'finished' state."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, JobResult, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Activation details describing what triggered this job, as key-value pairs"),
                SD_VARLINK_DEFINE_FIELD(ActivationDetails, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_MAP));

static SD_VARLINK_DEFINE_ERROR(
                NoSuchJob,
                SD_VARLINK_DEFINE_FIELD(parameter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("If non-null, filter by job ID"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If non-null, filter by unit name"),
                SD_VARLINK_DEFINE_INPUT(unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Job context"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(context, JobContext, 0),
                SD_VARLINK_FIELD_COMMENT("Job runtime information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(runtime, JobRuntime, 0));

static SD_VARLINK_DEFINE_METHOD(
                Cancel,
                SD_VARLINK_FIELD_COMMENT("The job ID to cancel"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                ClearAll);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Job,
                "io.systemd.Job",
                SD_VARLINK_INTERFACE_COMMENT("Job management interface for the systemd service manager."),
                SD_VARLINK_SYMBOL_COMMENT("List queued jobs"),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("Cancel a specific job"),
                &vl_method_Cancel,
                SD_VARLINK_SYMBOL_COMMENT("Cancel all pending jobs"),
                &vl_method_ClearAll,
                SD_VARLINK_SYMBOL_COMMENT("Job type"),
                &vl_type_JobType,
                SD_VARLINK_SYMBOL_COMMENT("Job state"),
                &vl_type_JobState,
                SD_VARLINK_SYMBOL_COMMENT("Job result"),
                &vl_type_JobResult,
                SD_VARLINK_SYMBOL_COMMENT("A job object (legacy, used by io.systemd.Unit.StartTransient)"),
                &vl_type_Job,
                SD_VARLINK_SYMBOL_COMMENT("Job context"),
                &vl_type_JobContext,
                SD_VARLINK_SYMBOL_COMMENT("Job runtime information"),
                &vl_type_JobRuntime,
                SD_VARLINK_SYMBOL_COMMENT("The specified job does not exist"),
                &vl_error_NoSuchJob);
