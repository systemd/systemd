/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

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

#include <errno.h>
#include <stdlib.h>
#include "consoled.h"
#include "list.h"
#include "macro.h"
#include "util.h"

static int terminal_write_fn(term_screen *screen, void *userdata, const void *buf, size_t size) {
        Terminal *t = userdata;
        int r;

        if (t->pty) {
                r = pty_write(t->pty, buf, size);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int terminal_pty_fn(Pty *pty, void *userdata, unsigned int event, const void *ptr, size_t size) {
        Terminal *t = userdata;
        int r;

        switch (event) {
        case PTY_CHILD:
                log_debug("PTY child exited");
                t->pty = pty_unref(t->pty);
                break;
        case PTY_DATA:
                r = term_screen_feed_text(t->screen, ptr, size);
                if (r < 0)
                        log_error_errno(r, "Cannot update screen state: %m");

                workspace_dirty(t->workspace);
                break;
        }

        return 0;
}

int terminal_new(Terminal **out, Workspace *w) {
        _cleanup_(terminal_freep) Terminal *t = NULL;
        int r;

        assert(w);

        t = new0(Terminal, 1);
        if (!t)
                return -ENOMEM;

        t->workspace = w;
        LIST_PREPEND(terminals_by_workspace, w->terminal_list, t);

        r = term_parser_new(&t->parser, true);
        if (r < 0)
                return r;

        r = term_screen_new(&t->screen, terminal_write_fn, t, NULL, NULL);
        if (r < 0)
                return r;

        r = term_screen_set_answerback(t->screen, "systemd-console");
        if (r < 0)
                return r;

        if (out)
                *out = t;
        t = NULL;
        return 0;
}

Terminal *terminal_free(Terminal *t) {
        if (!t)
                return NULL;

        assert(t->workspace);

        if (t->pty) {
                (void) pty_signal(t->pty, SIGHUP);
                pty_close(t->pty);
                pty_unref(t->pty);
        }
        term_screen_unref(t->screen);
        term_parser_free(t->parser);
        LIST_REMOVE(terminals_by_workspace, t->workspace->terminal_list, t);
        free(t);

        return NULL;
}

void terminal_resize(Terminal *t) {
        uint32_t width, height, fw, fh;
        int r;

        assert(t);

        width = t->workspace->width;
        height = t->workspace->height;
        fw = unifont_get_width(t->workspace->manager->uf);
        fh = unifont_get_height(t->workspace->manager->uf);

        width = (fw > 0) ? width / fw : 0;
        height = (fh > 0) ? height / fh : 0;

        if (t->pty) {
                r = pty_resize(t->pty, width, height);
                if (r < 0)
                        log_error_errno(r, "Cannot resize pty: %m");
        }

        r = term_screen_resize(t->screen, width, height);
        if (r < 0)
                log_error_errno(r, "Cannot resize screen: %m");
}

void terminal_run(Terminal *t) {
        pid_t pid;

        assert(t);

        if (t->pty)
                return;

        pid = pty_fork(&t->pty,
                       t->workspace->manager->event,
                       terminal_pty_fn,
                       t,
                       term_screen_get_width(t->screen),
                       term_screen_get_height(t->screen));
        if (pid < 0) {
                log_error_errno(pid, "Cannot fork PTY: %m");
                return;
        } else if (pid == 0) {
                /* child */

                char **argv = (char*[]){
                        (char*)getenv("SHELL") ? : (char*)_PATH_BSHELL,
                        NULL
                };

                setenv("TERM", "xterm-256color", 1);
                setenv("COLORTERM", "systemd-console", 1);

                execve(argv[0], argv, environ);
                log_error_errno(errno, "Cannot exec %s (%d): %m", argv[0], -errno);
                _exit(1);
        }
}

static void terminal_feed_keyboard(Terminal *t, idev_data *data) {
        idev_data_keyboard *kdata = &data->keyboard;
        int r;

        if (!data->resync && (kdata->value == 1 || kdata->value == 2)) {
                assert_cc(TERM_KBDMOD_CNT == (int)IDEV_KBDMOD_CNT);
                assert_cc(TERM_KBDMOD_IDX_SHIFT == (int)IDEV_KBDMOD_IDX_SHIFT &&
                          TERM_KBDMOD_IDX_CTRL == (int)IDEV_KBDMOD_IDX_CTRL &&
                          TERM_KBDMOD_IDX_ALT == (int)IDEV_KBDMOD_IDX_ALT &&
                          TERM_KBDMOD_IDX_LINUX == (int)IDEV_KBDMOD_IDX_LINUX &&
                          TERM_KBDMOD_IDX_CAPS == (int)IDEV_KBDMOD_IDX_CAPS);

                r = term_screen_feed_keyboard(t->screen,
                                              kdata->keysyms,
                                              kdata->n_syms,
                                              kdata->ascii,
                                              kdata->codepoints,
                                              kdata->mods);
                if (r < 0)
                        log_error_errno(r, "Cannot feed keyboard data to screen: %m");
        }
}

void terminal_feed(Terminal *t, idev_data *data) {
        switch (data->type) {
        case IDEV_DATA_KEYBOARD:
                terminal_feed_keyboard(t, data);
                break;
        }
}

static void terminal_fill(uint8_t *dst,
                          uint32_t width,
                          uint32_t height,
                          uint32_t stride,
                          uint32_t value) {
        uint32_t i, j, *px;

        for (j = 0; j < height; ++j) {
                px = (uint32_t*)dst;

                for (i = 0; i < width; ++i)
                        *px++ = value;

                dst += stride;
        }
}

static void terminal_blend(uint8_t *dst,
                           uint32_t width,
                           uint32_t height,
                           uint32_t dst_stride,
                           const uint8_t *src,
                           uint32_t src_stride,
                           uint32_t fg,
                           uint32_t bg) {
        uint32_t i, j, *px;

        for (j = 0; j < height; ++j) {
                px = (uint32_t*)dst;

                for (i = 0; i < width; ++i) {
                        if (!src || src[i / 8] & (1 << (7 - i % 8)))
                                *px = fg;
                        else
                                *px = bg;

                        ++px;
                }

                src += src_stride;
                dst += dst_stride;
        }
}

typedef struct {
        const grdev_display_target *target;
        unifont *uf;
        uint32_t cell_width;
        uint32_t cell_height;
        bool dirty;
} TerminalDrawContext;

static int terminal_draw_cell(term_screen *screen,
                              void *userdata,
                              unsigned int x,
                              unsigned int y,
                              const term_attr *attr,
                              const uint32_t *ch,
                              size_t n_ch,
                              unsigned int ch_width) {
        TerminalDrawContext *ctx = userdata;
        const grdev_display_target *target = ctx->target;
        grdev_fb *fb = target->back;
        uint32_t xpos, ypos, width, height;
        uint32_t fg, bg;
        unifont_glyph g;
        uint8_t *dst;
        int r;

        if (n_ch > 0) {
                r = unifont_lookup(ctx->uf, &g, *ch);
                if (r < 0)
                        r = unifont_lookup(ctx->uf, &g, 0xfffd);
                if (r < 0)
                        unifont_fallback(&g);
        }

        xpos = x * ctx->cell_width;
        ypos = y * ctx->cell_height;

        if (xpos >= fb->width || ypos >= fb->height)
                return 0;

        width = MIN(fb->width - xpos, ctx->cell_width * ch_width);
        height = MIN(fb->height - ypos, ctx->cell_height);

        term_attr_to_argb32(attr, &fg, &bg, NULL);

        ctx->dirty = true;

        dst = fb->maps[0];
        dst += fb->strides[0] * ypos + sizeof(uint32_t) * xpos;

        if (n_ch < 1) {
                terminal_fill(dst,
                              width,
                              height,
                              fb->strides[0],
                              bg);
        } else {
                if (width > g.width)
                        terminal_fill(dst + sizeof(uint32_t) * g.width,
                                      width - g.width,
                                      height,
                                      fb->strides[0],
                                      bg);
                if (height > g.height)
                        terminal_fill(dst + fb->strides[0] * g.height,
                                      width,
                                      height - g.height,
                                      fb->strides[0],
                                      bg);

                terminal_blend(dst,
                               width,
                               height,
                               fb->strides[0],
                               g.data,
                               g.stride,
                               fg,
                               bg);
        }

        return 0;
}

bool terminal_draw(Terminal *t, const grdev_display_target *target) {
        TerminalDrawContext ctx = { };
        uint64_t age;

        assert(t);
        assert(target);

        /* start up terminal on first frame */
        terminal_run(t);

        ctx.target = target;
        ctx.uf = t->workspace->manager->uf;
        ctx.cell_width = unifont_get_width(ctx.uf);
        ctx.cell_height = unifont_get_height(ctx.uf);
        ctx.dirty = false;

        if (target->front) {
                /* if the frontbuffer is new enough, no reason to redraw */
                age = term_screen_get_age(t->screen);
                if (age != 0 && age <= target->front->data.u64)
                        return false;
        } else {
                /* force flip if no frontbuffer is set, yet */
                ctx.dirty = true;
        }

        term_screen_draw(t->screen, terminal_draw_cell, &ctx, &target->back->data.u64);

        return ctx.dirty;
}
