/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Auke Kok <auke-jan.h.kok@intel.com>

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
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include "readahead-common.h"

int main_analyze(const char *pack_path)
{
        char line[LINE_MAX];
        char path[PATH_MAX];
        FILE *pack;
        int a;
        int missing = 0;
        off_t size;
        off_t tsize = 0;
        uint64_t inode;
        uint32_t b;
        uint32_t c;
        struct stat st;

        if (!pack_path)
                pack_path = "/.readahead";

        pack = fopen(pack_path, "re");
        if (!pack) {
                log_error("Pack file missing.");
                goto fail;
        }

        if (!fgets(line, sizeof(line), pack)) {
                log_error("Pack file corrupt.");
                goto fail;
        }

        char_array_0(line);

        if (!endswith(line, READAHEAD_PACK_FILE_VERSION)) {
                log_error("Pack file version incompatible with this parser.");
                goto fail;
        }

        if ((a = getc(pack)) == EOF) {
                log_error("Pack file corrupt.");
                goto fail;
        }

        fprintf(stdout, "   pct  sections     size: path\n");
        fprintf(stdout, "   ===  ========     ====: ====\n");

        while(true) {
                int pages = 0;
                int sections = 0;

                if (!fgets(path, sizeof(path), pack))
                        break; /* done */

                path[strlen(path)-1] = 0;

                if (fread(&inode, sizeof(inode), 1, pack) != 1) {
                        log_error("Pack file corrupt.");
                        goto fail;
                }

                while (true) {
                        if (fread(&b, sizeof(b), 1, pack) != 1  ||
                            fread(&c, sizeof(c), 1, pack) != 1) {
                                log_error("Pack file corrupt.");
                                goto fail;
                        }
                        if ((b == 0) && (c == 0))
                                break;

                        /* Uncomment this to get all the chunks separately
                        fprintf(stdout, " %d: %d %d\n", sections, b, c);
                         */

                        pages += (c - b);
                        sections++;
                }

                if (stat(path, &st) == 0) {
                        if (sections == 0)
                                size = st.st_size;
                        else
                                size = pages * page_size();

                        tsize += size;

                        fprintf(stdout, "  %4d%% (%2d) %12ld: %s\n",
                                sections ? (int)(size / st.st_size * 100.0) : 100,
                                sections ? sections : 1,
                                (unsigned long)size,
                                path);
                } else {
                        fprintf(stdout, "  %4dp (%2d) %12s: %s (MISSING)\n",
                                sections ? pages : -1,
                                sections ? sections : 1,
                                "???",
                                path);
                        missing++;
                }

        }

        fclose(pack);

        fprintf(stdout, "\nHOST:    %s", line);
        fprintf(stdout, "TYPE:    %c\n", a);
        fprintf(stdout, "MISSING: %d\n", missing);
        fprintf(stdout, "TOTAL:   %ld\n", tsize);

        return EXIT_SUCCESS;


fail:
        fclose(pack);
        return EXIT_FAILURE;
}
