/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "unit-name.h"

const char *arg_dest = "/tmp";

static bool has_option(const char *haystack, const char *needle) {
        const char *f = haystack;
        size_t l;

        l = strlen(needle);

        while ((f = strstr(f, needle))) {

                if (f > haystack && f[-1] != ',') {
                        f++;
                        continue;
                }

                if (f[l] != 0 && f[l] == ',') {
                        f++;
                        continue;
                }

                return true;
        }

        return false;
}

static int create_disk(
                const char *name,
                const char *device,
                const char *password,
                const char *options) {

        char *p = NULL, *n = NULL, *d = NULL, *u = NULL, *from = NULL, *to = NULL, *e = NULL;
        int r;
        FILE *f = NULL;

        assert(name);
        assert(device);

        if (!(n = unit_name_build_escape("cryptsetup", name, ".service"))) {
                r = -ENOMEM;
                log_error("Failed to allocate unit name.");
                goto fail;
        }

        if (asprintf(&p, "%s/%s", arg_dest, n) < 0) {
                r = -ENOMEM;
                log_error("Failed to allocate unit file name.");
                goto fail;
        }

        if (!(u = fstab_node_to_udev_node(device))) {
                r = -ENOMEM;
                log_error("Failed to allocate device node.");
                goto fail;
        }

        if (!(d = unit_name_from_path(u, ".device"))) {
                r = -ENOMEM;
                log_error("Failed to allocate device name.");
                goto fail;
        }

        if (!(f = fopen(p, "wxe"))) {
                r = -errno;
                log_error("Failed to create unit file: %m");
                goto fail;
        }

        fprintf(f,
                "[Unit]\n"
                "Description=Cryptography Setup for %%f\n"
                "DefaultDependencies=no\n"
                "BindTo=%s dev-mapper-%%i.device\n"
                "After=systemd-readahead-collect.service systemd-readahead-replay.service %s\n"
                "Before=dev-mapper-%%i.device shutdown.target cryptsetup.target\n",
                d, d);

        if (password && (streq(password, "/dev/urandom") ||
                         streq(password, "/dev/random") ||
                         streq(password, "/dev/hw_random")))
                fprintf(f,
                        "After=systemd-random-seed-load.service\n");

        fprintf(f,
                "\n[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "ExecStart=" SYSTEMD_CRYPTSETUP_PATH " attach '%s' '%s' '%s' '%s'\n"
                "ExecStop=" SYSTEMD_CRYPTSETUP_PATH " detach '%s'\n",
                name, u, strempty(password), strempty(options),
                name);

        if (options && has_option(options, "tmp"))
                fprintf(f,
                        "ExecStartPost=/sbin/mke2fs '%s'",
                        u);

        if (options && has_option(options, "swap"))
                fprintf(f,
                        "ExecStartPost=/sbin/mkswap '%s'",
                        u);

        fflush(f);

        if (ferror(f)) {
                r = -errno;
                log_error("Failed to write file: %m");
                goto fail;
        }

        if (asprintf(&from, "../%s", n) < 0) {
                r = -ENOMEM;
                goto fail;
        }

        if (!options || !has_option(options, "noauto")) {

                if (asprintf(&to, "%s/%s.wants/%s", arg_dest, d, n) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

                mkdir_parents(to, 0755);

                if (symlink(from, to) < 0) {
                        log_error("Failed to create symlink '%s' to '%s': %m", from, to);
                        r = -errno;
                        goto fail;
                }

                free(to);
                to = NULL;

                if (!options || !has_option(options, "nofail")) {

                        if (asprintf(&to, "%s/cryptsetup.target.wants/%s", arg_dest, n) < 0) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        mkdir_parents(to, 0755);

                        if (symlink(from, to) < 0) {
                                log_error("Failed to create symlink '%s' to '%s': %m", from, to);
                                r = -errno;
                                goto fail;
                        }
                }
        }

        free(to);
        to = NULL;

        e = unit_name_escape(name);
        if (asprintf(&to, "%s/dev-mapper-%s.device.requires/%s", arg_dest, e, n) < 0) {
                r = -ENOMEM;
                goto fail;
        }

        mkdir_parents(to, 0755);

        if (symlink(from, to) < 0) {
                log_error("Failed to create symlink '%s' to '%s': %m", from, to);
                r = -errno;
                goto fail;
        }

        r = 0;

fail:
        free(p);
        free(n);
        free(d);
        free(e);

        free(from);
        free(to);

        if (f)
                fclose(f);

        return r;
}

int main(int argc, char *argv[]) {
        FILE *f;
        int r = EXIT_SUCCESS;
        unsigned n = 0;

        if (argc > 2) {
                log_error("This program takes one or no arguments.");
                return EXIT_FAILURE;
        }

        arg_dest = argv[1];

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (!(f = fopen("/etc/crypttab", "re"))) {

                if (errno == ENOENT)
                        r = EXIT_SUCCESS;
                else {
                        r = EXIT_FAILURE;
                        log_error("Failed to open /etc/crypttab: %m");
                }

                goto finish;
        }

        for (;;) {
                char line[LINE_MAX], *l;
                char *name = NULL, *device = NULL, *password = NULL, *options = NULL;
                int k;

                if (!(fgets(line, sizeof(line), f)))
                        break;

                n++;

                l = strstrip(line);
                if (*l == '#' || *l == 0)
                        continue;

                if ((k = sscanf(l, "%ms %ms %ms %ms", &name, &device, &password, &options)) < 2 || k > 4) {
                        log_error("Failed to parse /etc/crypttab:%u, ignoring.", n);
                        r = EXIT_FAILURE;
                        goto next;
                }

                if (create_disk(name, device, password, options) < 0)
                        r = EXIT_FAILURE;

        next:
                free(name);
                free(device);
                free(password);
                free(options);
        }

finish:
        return r;
}
