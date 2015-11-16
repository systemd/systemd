/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>

#include "job.h"
#include "service.h"
#include "unit.h"

int main(int argc, char*argv[]) {
        JobType a, b, c, ab, bc, ab_c, bc_a, a_bc;
        const ServiceState test_states[] = { SERVICE_DEAD, SERVICE_RUNNING };
        unsigned i;
        bool merged_ab;

        /* fake a unit */
        static Service s = {
                .meta.load_state = UNIT_LOADED,
                .type = SERVICE_SIMPLE,
        };
        Unit *u = UNIT(&s);

        for (i = 0; i < ELEMENTSOF(test_states); i++) {
                s.state = test_states[i];
                printf("\nWith collapsing for service state %s\n"
                       "=========================================\n", service_state_to_string(s.state));
                for (a = 0; a < _JOB_TYPE_MAX_MERGING; a++) {
                        for (b = 0; b < _JOB_TYPE_MAX_MERGING; b++) {

                                ab = a;
                                merged_ab = (job_type_merge_and_collapse(&ab, b, u) >= 0);

                                if (!job_type_is_mergeable(a, b)) {
                                        assert_se(!merged_ab);
                                        printf("Not mergeable: %s + %s\n", job_type_to_string(a), job_type_to_string(b));
                                        continue;
                                }

                                assert_se(merged_ab);
                                printf("%s + %s = %s\n", job_type_to_string(a), job_type_to_string(b), job_type_to_string(ab));

                                for (c = 0; c < _JOB_TYPE_MAX_MERGING; c++) {

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

                                        bc = b;
                                        if (job_type_merge_and_collapse(&bc, c, u) >= 0) {

                                                /* Verify associativity */

                                                ab_c = ab;
                                                assert_se(job_type_merge_and_collapse(&ab_c, c, u) == 0);

                                                bc_a = bc;
                                                assert_se(job_type_merge_and_collapse(&bc_a, a, u) == 0);

                                                a_bc = a;
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
