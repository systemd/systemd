/***
  Copyright 2014 Tom Gundersen

  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation files
  (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of the Software,
  and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
***/

#include <stdlib.h>

typedef struct SDEventSource {
        GSource source;
        GPollFD pollfd;
        sd_event *event;
} SDEventSource;

static gboolean event_prepare(GSource *source, gint *timeout_) {
        return sd_event_prepare(((SDEventSource *)source)->event) > 0;
}

static gboolean event_check(GSource *source) {
        return sd_event_wait(((SDEventSource *)source)->event, 0) > 0;
}

static gboolean event_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
        return sd_event_dispatch(((SDEventSource *)source)->event) > 0;
}

static void event_finalize(GSource *source) {
        sd_event_unref(((SDEventSource *)source)->event);
}

static GSourceFuncs event_funcs = {
        .prepare = event_prepare,
        .check = event_check,
        .dispatch = event_dispatch,
        .finalize = event_finalize,
};

GSource *g_sd_event_create_source(sd_event *event) {
        SDEventSource *source;

        source = (SDEventSource *)g_source_new(&event_funcs, sizeof(SDEventSource));

        source->event = sd_event_ref(event);
        source->pollfd.fd = sd_event_get_fd(event);
        source->pollfd.events = G_IO_IN | G_IO_HUP | G_IO_ERR;

        g_source_add_poll((GSource *)source, &source->pollfd);

        return (GSource *)source;
}
