/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>
#include <unistd.h>

#include "format-util.h"
#include "log.h"
#include "process-util.h"
#include "util.h"

assert_cc(LOG_REALM_REMOVE_LEVEL(LOG_REALM_PLUS_LEVEL(LOG_REALM_SYSTEMD, LOG_FTP | LOG_DEBUG))
          == LOG_REALM_SYSTEMD);
assert_cc(LOG_REALM_REMOVE_LEVEL(LOG_REALM_PLUS_LEVEL(LOG_REALM_UDEV, LOG_LOCAL7 | LOG_DEBUG))
          == LOG_REALM_UDEV);
assert_cc((LOG_REALM_PLUS_LEVEL(LOG_REALM_SYSTEMD, LOG_LOCAL3 | LOG_DEBUG) & LOG_FACMASK)
          == LOG_LOCAL3);
assert_cc((LOG_REALM_PLUS_LEVEL(LOG_REALM_UDEV, LOG_USER | LOG_INFO) & LOG_PRIMASK)
          == LOG_INFO);

#define X10(x) x x x x x x x x x x
#define X100(x) X10(X10(x))
#define X1000(x) X100(X10(x))

static void test_log_console(void) {
        log_struct(LOG_INFO,
                   "MESSAGE=Waldo PID="PID_FMT, getpid_cached(),
                   "SERVICE=piepapo");
}

static void test_log_journal(void) {
        log_struct(LOG_INFO,
                   "MESSAGE=Foobar PID="PID_FMT, getpid_cached(),
                   "SERVICE=foobar");

        log_struct(LOG_INFO,
                   "MESSAGE=Foobar PID="PID_FMT, getpid_cached(),
                   "FORMAT_STR_TEST=1=%i A=%c 2=%hi 3=%li 4=%lli 1=%p foo=%s 2.5=%g 3.5=%g 4.5=%Lg",
                   (int) 1, 'A', (short) 2, (long int) 3, (long long int) 4, (void*) 1, "foo", (float) 2.5f, (double) 3.5, (long double) 4.5,
                   "SUFFIX=GOT IT");
}

static void test_long_lines(void) {
        log_object_internal(LOG_NOTICE,
                            EUCLEAN,
                            X1000("abcd_") ".txt",
                            1000000,
                            X1000("fff") "unc",
                            "OBJECT=",
                            X1000("obj_") "ect",
                            "EXTRA=",
                            X1000("ext_") "tra",
                            "asdfasdf %s asdfasdfa", "foobar");
}

int main(int argc, char* argv[]) {
        int target;

        for (target = 0; target <  _LOG_TARGET_MAX; target++) {
                log_set_target(target);
                log_open();

                test_log_console();
                test_log_journal();
                test_long_lines();
        }

        return 0;
}
