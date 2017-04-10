/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "log.h"
#include "journal-importer.h"
#include "string-util.h"
#include "tests.h"

static void assert_iovec_entry(const struct iovec *iovec, const char* content) {
        assert_se(strlen(content) == iovec->iov_len);
        assert_se(memcmp(content, iovec->iov_base, iovec->iov_len) == 0);
}

#define COREDUMP_PROC_GROUP                                             \
        "COREDUMP_PROC_CGROUP=1:name=systemd:/\n"                       \
        "0::/user.slice/user-1002.slice/user@1002.service/gnome-terminal-server.service\n"

static void test_basic_parsing(void) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = {};
        int r;

        imp.fd = open(get_testdata_dir("/journal-data/journal-1.txt"), O_RDONLY|O_CLOEXEC);
        assert_se(imp.fd >= 0);

        do
                r = journal_importer_process_data(&imp);
        while (r == 0 && !journal_importer_eof(&imp));
        assert_se(r == 1);

        /* We read one entry, so we should get EOF on next read, but not yet */
        assert_se(!journal_importer_eof(&imp));

        assert_se(imp.iovw.count == 6);
        assert_iovec_entry(&imp.iovw.iovec[0], "_BOOT_ID=1531fd22ec84429e85ae888b12fadb91");
        assert_iovec_entry(&imp.iovw.iovec[1], "_TRANSPORT=journal");
        assert_iovec_entry(&imp.iovw.iovec[2], COREDUMP_PROC_GROUP);
        assert_iovec_entry(&imp.iovw.iovec[3], "COREDUMP_RLIMIT=-1");
        assert_iovec_entry(&imp.iovw.iovec[4], COREDUMP_PROC_GROUP);
        assert_iovec_entry(&imp.iovw.iovec[5], "_SOURCE_REALTIME_TIMESTAMP=1478389147837945");

        /* Let's check if we get EOF now */
        r = journal_importer_process_data(&imp);
        assert_se(r == 0);
        assert_se(journal_importer_eof(&imp));
}

static void test_bad_input(void) {
        _cleanup_(journal_importer_cleanup) JournalImporter imp = {};
        int r;

        imp.fd = open(get_testdata_dir("/journal-data/journal-2.txt"), O_RDONLY|O_CLOEXEC);
        assert_se(imp.fd >= 0);

        do
                r = journal_importer_process_data(&imp);
        while (!journal_importer_eof(&imp));
        assert_se(r == 0); /* If we don't have enough input, 0 is returned */

        assert_se(journal_importer_eof(&imp));
}

int main(int argc, char **argv) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        test_basic_parsing();
        test_bad_input();

        return 0;
}
