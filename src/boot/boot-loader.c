/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Kay Sievers

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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <ctype.h>
#include <sys/timex.h>

#include "boot.h"
#include "boot-loader.h"
#include "build.h"
#include "util.h"
#include "strv.h"
#include "conf-files.h"

static char *loader_fragment_read_title(const char *fragment) {
        FILE *f;
        char line[LINE_MAX];
        char *title = NULL;

        f = fopen(fragment, "re");
        if (!f)
                return NULL;

        while (fgets(line, sizeof(line), f) != NULL) {
                char *s;
                size_t l;

                l = strlen(line);
                if (l < 1)
                        continue;
                if (line[l-1] == '\n')
                        line[l-1] = '\0';

                s = line;
                while (isspace(s[0]))
                        s++;

                if (s[0] == '#')
                        continue;

                if (!startswith(s, "title"))
                        continue;

                s += strlen("title");
                if (!isspace(s[0]))
                        continue;
                while (isspace(s[0]))
                        s++;

                title = strdup(s);
                break;
        }

        fclose(f);
        return title;
}

int boot_loader_read_entries(struct boot_info *info) {
        _cleanup_strv_free_ char **files = NULL;
        static const char *loader_dir[] = { "/boot/loader/entries", NULL};
        unsigned int count;
        unsigned int i;
        int err;

        err = conf_files_list_strv(&files, ".conf", NULL, loader_dir);
        if (err < 0)
                return err;

        count = strv_length(files);
        info->loader_entries = new0(struct boot_info_entry, count);
        if (!info->loader_entries)
                return -ENOMEM;

        for (i = 0; i < count; i++) {
                info->loader_entries[i].title = loader_fragment_read_title(files[i]);
                info->loader_entries[i].path = strdup(files[i]);
                if (!info->loader_entries[i].title || !info->loader_entries[i].path) {
                        free(info->loader_entries[i].title);
                        free(info->loader_entries[i].path);
                        return -ENOMEM;
                }
                info->loader_entries_count++;
        }

        return 0;
}

int boot_loader_find_active_entry(struct boot_info *info, const char *loader_active) {
        char *fn;
        unsigned int i;

        if (!loader_active)
                return -ENOENT;
        if (info->loader_entries_count == 0)
                return -ENOENT;

        if (asprintf(&fn, "/boot/loader/entries/%s.conf", loader_active) < 0)
                return -ENOMEM;

        for (i = 0; i < info->loader_entries_count; i++) {
                if (streq(fn, info->loader_entries[i].path)) {
                        info->loader_entry_active = i;
                        break;
                }
        }

        free(fn);
        return 0;
}
