/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/
/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

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

/*
 * Test Unifont Helper
 * This tries opening the binary unifont glyph-array and renders some glyphs.
 * The glyphs are then compared to hard-coded glyphs.
 */

#include <stdio.h>
#include <string.h>
#include "macro.h"
#include "unifont-def.h"
#include "unifont.h"

static void render(char *w, const unifont_glyph *g) {
        unsigned int i, j;
        const uint8_t *d = g->data;

        for (j = 0; j < 16; ++j) {
                for (i = 0; i < 8 * g->cwidth; ++i) {
                        if (d[i / 8] & (1 << (7 - i % 8)))
                                *w++ = '#';
                        else
                                *w++ = ' ';
                }
                *w++ = '\n';
                d += g->stride;
        }

        *w++ = 0;
}

static void test_unifont(void) {
        char buf[4096];
        unifont_glyph g;
        unifont *u;

        assert_se(unifont_new(&u) >= 0);

        /* lookup invalid font */
        assert_se(unifont_lookup(u, &g, 0xffffffffU) < 0);

        /* lookup and render 'A' */
        assert_se(unifont_lookup(u, &g, 'A') >= 0);
        assert_se(g.width == 8);
        assert_se(g.height == 16);
        assert_se(g.stride >= 1);
        assert_se(g.cwidth == 1);
        assert_se(g.data != NULL);
        render(buf, &g);
        assert_se(!strcmp(buf,
                          "        \n"
                          "        \n"
                          "        \n"
                          "        \n"
                          "   ##   \n"
                          "  #  #  \n"
                          "  #  #  \n"
                          " #    # \n"
                          " #    # \n"
                          " ###### \n"
                          " #    # \n"
                          " #    # \n"
                          " #    # \n"
                          " #    # \n"
                          "        \n"
                          "        \n"
                          ));

        /* lookup and render '什' */
        assert_se(unifont_lookup(u, &g, 0x4ec0) >= 0);
        assert_se(g.width == 16);
        assert_se(g.height == 16);
        assert_se(g.stride >= 2);
        assert_se(g.cwidth == 2);
        assert_se(g.data != NULL);
        render(buf, &g);
        assert_se(!strcmp(buf,
                          "    #     #     \n"
                          "    #     #     \n"
                          "    #     #     \n"
                          "   #      #     \n"
                          "   #      #     \n"
                          "  ##      #     \n"
                          "  ## ########## \n"
                          " # #      #     \n"
                          "#  #      #     \n"
                          "   #      #     \n"
                          "   #      #     \n"
                          "   #      #     \n"
                          "   #      #     \n"
                          "   #      #     \n"
                          "   #      #     \n"
                          "   #      #     \n"
                          ));

        unifont_unref(u);
}

int main(int argc, char **argv) {
        if (access(UNIFONT_PATH, F_OK))
                return 77;

        test_unifont();

        return 0;
}
