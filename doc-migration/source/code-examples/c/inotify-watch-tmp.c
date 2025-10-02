/* SPDX-License-Identifier: MIT-0 */

#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>

#include <systemd/sd-event.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

static int inotify_handler(sd_event_source *source,
                           const struct inotify_event *event,
                           void *userdata) {

  const char *desc = NULL;

  sd_event_source_get_description(source, &desc);

  if (event->mask & IN_Q_OVERFLOW)
    printf("inotify-handler <%s>: overflow\n", desc);
  else if (event->mask & IN_CREATE)
    printf("inotify-handler <%s>: create on %s\n", desc, event->name);
  else if (event->mask & IN_DELETE)
    printf("inotify-handler <%s>: delete on %s\n", desc, event->name);
  else if (event->mask & IN_MOVED_TO)
    printf("inotify-handler <%s>: moved-to on %s\n", desc, event->name);

  /* Terminate the program if an "exit" file appears */
  if ((event->mask & (IN_CREATE|IN_MOVED_TO)) &&
      strcmp(event->name, "exit") == 0)
    sd_event_exit(sd_event_source_get_event(source), 0);

  return 1;
}

int main(int argc, char **argv) {
  _cleanup_(sd_event_unrefp) sd_event *event = NULL;
  _cleanup_(sd_event_source_unrefp) sd_event_source *source1 = NULL, *source2 = NULL;

  const char *path1 = argc > 1 ? argv[1] : "/tmp";
  const char *path2 = argc > 2 ? argv[2] : NULL;

  /* Note: failure handling is omitted for brevity */

  sd_event_default(&event);

  sd_event_add_inotify(event, &source1, path1,
                       IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_TO,
                       inotify_handler, NULL);
  if (path2)
    sd_event_add_inotify(event, &source2, path2,
                         IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_TO,
                         inotify_handler, NULL);

  sd_event_loop(event);

  return 0;
}
