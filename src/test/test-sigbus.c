/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <sys/mman.h>

#include "fd-util.h"
#include "sigbus.h"
#include "util.h"

int main(int argc, char *argv[]) {
        _cleanup_close_ int fd = -1;
        char template[] = "/tmp/sigbus-test-XXXXXX";
        void *addr = NULL;
        uint8_t *p;

        sigbus_install();

        assert_se(sigbus_pop(&addr) == 0);

        assert_se((fd = mkostemp(template, O_RDWR|O_CREAT|O_EXCL)) >= 0);
        assert_se(unlink(template) >= 0);
        assert_se(fallocate(fd, 0, 0, page_size() * 8) >= 0);

        p = mmap(NULL, page_size() * 16, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        assert_se(p != MAP_FAILED);

        assert_se(sigbus_pop(&addr) == 0);

        p[0] = 0xFF;
        assert_se(sigbus_pop(&addr) == 0);

        p[page_size()] = 0xFF;
        assert_se(sigbus_pop(&addr) == 0);

        p[page_size()*8] = 0xFF;
        p[page_size()*8+1] = 0xFF;
        p[page_size()*10] = 0xFF;
        assert_se(sigbus_pop(&addr) > 0);
        assert_se(addr == p + page_size() * 8);
        assert_se(sigbus_pop(&addr) > 0);
        assert_se(addr == p + page_size() * 10);
        assert_se(sigbus_pop(&addr) == 0);

        sigbus_reset();
}
