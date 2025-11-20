/* SPDX-License-Identifier: MIT-0 */

#include <stdlib.h>
#include <glib.h>
#include <systemd/sd-event.h>

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
