/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-bus.h"

#include "bus-locator.h"
#include "fd-util.h"
#include "tests.h"

static int inhibit(sd_bus *bus, const char *what) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *who = "Test Tool", *reason = "Just because!", *mode = "block";
        int fd;
        int r;

        r = bus_call_method(bus, bus_login_mgr, "Inhibit", &error, &reply, "ssss", what, who, reason, mode);
        assert_se(r >= 0);

        r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_UNIX_FD, &fd);
        assert_se(r >= 0);
        assert_se(fd >= 0);

        return fcntl(fd, F_DUPFD_CLOEXEC, 3);
}

static void print_inhibitors(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *what, *who, *why, *mode;
        uint32_t uid, pid;
        unsigned n = 0;
        int r;

        r = bus_call_method(bus, bus_login_mgr, "ListInhibitors", &error, &reply, NULL);
        assert_se(r >= 0);

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssuu)");
        assert_se(r >= 0);

        while ((r = sd_bus_message_read(reply, "(ssssuu)", &what, &who, &why, &mode, &uid, &pid)) > 0) {
                printf("what=<%s> who=<%s> why=<%s> mode=<%s> uid=<%"PRIu32"> pid=<%"PRIu32">\n",
                       what, who, why, mode, uid, pid);

                n++;
        }
        assert_se(r >= 0);

        printf("%u inhibitors\n", n);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int fd1, fd2;
        int r;

        test_setup_logging(LOG_DEBUG);

        r = sd_bus_open_system(&bus);
        assert_se(r >= 0);

        print_inhibitors(bus);

        fd1 = inhibit(bus, "sleep");
        assert_se(fd1 >= 0);
        print_inhibitors(bus);

        fd2 = inhibit(bus, "idle:shutdown");
        assert_se(fd2 >= 0);
        print_inhibitors(bus);

        safe_close(fd1);
        sleep(1);
        print_inhibitors(bus);

        safe_close(fd2);
        sleep(1);
        print_inhibitors(bus);

        return 0;
}
