/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "service.h"
#include "tests.h"
#include "unit.h"

int main(int argc, char *argv[]) {
        const ServiceState test_states[] = { SERVICE_DEAD, SERVICE_RUNNING };

        test_setup_logging(LOG_DEBUG);

        FOREACH_ELEMENT(state, test_states) {
                /* fake a unit */
                Service s = {
                        .meta.load_state = UNIT_LOADED,
                        .type = SERVICE_SIMPLE,
                        .state = *state,
                };
                Unit *u = UNIT(&s);

                printf("\nWith collapsing for service state %s\n"
                       "=========================================\n", service_state_to_string(s.state));
                for (JobType a = 0; a < _JOB_TYPE_MAX_MERGING; a++) {
                        for (JobType b = 0; b < _JOB_TYPE_MAX_MERGING; b++) {

                                JobType ab = a;
                                bool merged_ab = job_type_merge_and_collapse(&ab, b, u) >= 0;

                                if (!job_type_is_mergeable(a, b)) {
                                        assert_se(!merged_ab);
                                        printf("Not mergeable: %s + %s\n", job_type_to_string(a), job_type_to_string(b));
                                        continue;
                                }

                                assert_se(merged_ab);
                                printf("%s + %s = %s\n", job_type_to_string(a), job_type_to_string(b), job_type_to_string(ab));

                                for (JobType c = 0; c < _JOB_TYPE_MAX_MERGING; c++) {

                                        /* Verify transitivity of mergeability of job types */
                                        assert_se(!job_type_is_mergeable(a, b) ||
                                               !job_type_is_mergeable(b, c) ||
                                               job_type_is_mergeable(a, c));

                                        /* Verify that merged entries can be merged with the same entries
                                         * they can be merged with separately */
                                        assert_se(!job_type_is_mergeable(a, c) || job_type_is_mergeable(ab, c));
                                        assert_se(!job_type_is_mergeable(b, c) || job_type_is_mergeable(ab, c));

                                        /* Verify that if a merged with b is not mergeable with c, then
                                         * either a or b is not mergeable with c either. */
                                        assert_se(job_type_is_mergeable(ab, c) || !job_type_is_mergeable(a, c) || !job_type_is_mergeable(b, c));

                                        JobType bc = b;
                                        if (job_type_merge_and_collapse(&bc, c, u) >= 0) {

                                                /* Verify associativity */

                                                JobType ab_c = ab;
                                                assert_se(job_type_merge_and_collapse(&ab_c, c, u) == 0);

                                                JobType bc_a = bc;
                                                assert_se(job_type_merge_and_collapse(&bc_a, a, u) == 0);

                                                JobType a_bc = a;
                                                assert_se(job_type_merge_and_collapse(&a_bc, bc, u) == 0);

                                                assert_se(ab_c == bc_a);
                                                assert_se(ab_c == a_bc);

                                                printf("%s + %s + %s = %s\n", job_type_to_string(a), job_type_to_string(b), job_type_to_string(c), job_type_to_string(ab_c));
                                        }
                                }
                        }
                }
        }

        return 0;
}
