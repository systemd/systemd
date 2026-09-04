# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : 'TEST-89-RESOLVED-MDNS',
                # The conformance scorecard subtest runs its packet-level scenarios
                # serially on top of the container testcases; the default 1800 is
                # too tight for that on a loaded or sanitizer-instrumented runner.
                'timeout' : 3600,
                # Start the long test early, like the other long ones, so it does
                # not determine the wall time alone from the back of the queue.
                'priority' : 10,
        },
]
