/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "job.h"
#include "tests.h"
#include "test-varlink-idl-util.h"
#include "varlink-io.systemd.Job.h"

TEST(job_enums_idl) {
        TEST_IDL_ENUM(JobType, job_type, vl_type_JobType);
        TEST_IDL_ENUM(JobState, job_state, vl_type_JobState);
        TEST_IDL_ENUM(JobResult, job_result, vl_type_JobResult);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
