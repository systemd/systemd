/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "job.h"

int main(int argc, char*argv[]) {
        JobType a, b, c, d, e, f, g;

        for (a = 0; a < _JOB_TYPE_MAX; a++)
                for (b = 0; b < _JOB_TYPE_MAX; b++) {

                        if (!job_type_mergeable(a, b))
                                printf("Not mergeable: %s + %s\n", job_type_to_string(a), job_type_to_string(b));

                        for (c = 0; c < _JOB_TYPE_MAX; c++) {

                                /* Verify transitivity of mergeability
                                 * of job types */
                                assert(!job_type_mergeable(a, b) ||
                                       !job_type_mergeable(b, c) ||
                                       job_type_mergeable(a, c));

                                d = a;
                                if (job_type_merge(&d, b) >= 0) {

                                        printf("%s + %s = %s\n", job_type_to_string(a), job_type_to_string(b), job_type_to_string(d));

                                        /* Verify that merged entries can be
                                         * merged with the same entries they
                                         * can be merged with seperately */
                                        assert(!job_type_mergeable(a, c) || job_type_mergeable(d, c));
                                        assert(!job_type_mergeable(b, c) || job_type_mergeable(d, c));

                                        /* Verify that if a merged
                                         * with b is not mergable with
                                         * c then either a or b is not
                                         * mergeable with c either. */
                                        assert(job_type_mergeable(d, c) || !job_type_mergeable(a, c) || !job_type_mergeable(b, c));

                                        e = b;
                                        if (job_type_merge(&e, c) >= 0) {

                                                /* Verify associativity */

                                                f = d;
                                                assert(job_type_merge(&f, c) == 0);

                                                g = e;
                                                assert(job_type_merge(&g, a) == 0);

                                                assert(f == g);

                                                printf("%s + %s + %s = %s\n", job_type_to_string(a), job_type_to_string(b), job_type_to_string(c), job_type_to_string(d));
                                        }
                                }
                        }
                }


        return 0;
}
