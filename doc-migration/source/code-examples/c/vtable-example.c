/* SPDX-License-Identifier: MIT-0 */

#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <systemd/sd-bus.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

typedef struct object {
  char *name;
  uint32_t number;
} object;

static int method(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  int r;

  printf("Got called with userdata=%p\n", userdata);

  if (sd_bus_message_is_method_call(m,
                                    "org.freedesktop.systemd.VtableExample",
                                    "Method4"))
    return 1;

  const char *string;
  r = sd_bus_message_read(m, "s", &string);
  if (r < 0) {
    fprintf(stderr, "sd_bus_message_read() failed: %s\n", strerror(-r));
    return 0;
  }

  r = sd_bus_reply_method_return(m, "s", string);
  if (r < 0) {
    fprintf(stderr, "sd_bus_reply_method_return() failed: %s\n", strerror(-r));
    return 0;
  }

  return 1;
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD(
            "Method1", "s", "s", method, 0),
        SD_BUS_METHOD_WITH_NAMES_OFFSET(
            "Method2",
            "so", SD_BUS_PARAM(string) SD_BUS_PARAM(path),
            "s", SD_BUS_PARAM(returnstring),
            method, offsetof(object, number),
            SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_METHOD_WITH_ARGS_OFFSET(
            "Method3",
            SD_BUS_ARGS("s", string, "o", path),
            SD_BUS_RESULT("s", returnstring),
            method, offsetof(object, number),
            SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS(
            "Method4",
            SD_BUS_NO_ARGS,
            SD_BUS_NO_RESULT,
            method,
            SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL(
            "Signal1",
            "so",
            0),
        SD_BUS_SIGNAL_WITH_NAMES(
            "Signal2",
            "so", SD_BUS_PARAM(string) SD_BUS_PARAM(path),
            0),
        SD_BUS_SIGNAL_WITH_ARGS(
            "Signal3",
            SD_BUS_ARGS("s", string, "o", path),
            0),
        SD_BUS_WRITABLE_PROPERTY(
            "AutomaticStringProperty", "s", NULL, NULL,
            offsetof(object, name),
            SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_WRITABLE_PROPERTY(
            "AutomaticIntegerProperty", "u", NULL, NULL,
            offsetof(object, number),
            SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

int main(int argc, char **argv) {
  _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
  int r;

  sd_bus_default(&bus);

  object object = { .number = 666 };
  object.name = strdup("name");
  if (!object.name) {
    fprintf(stderr, "OOM\n");
    return EXIT_FAILURE;
  }

  r = sd_bus_add_object_vtable(bus, NULL,
                               "/org/freedesktop/systemd/VtableExample",
                               "org.freedesktop.systemd.VtableExample",
                               vtable,
                               &object);
  if (r < 0) {
    fprintf(stderr, "sd_bus_add_object_vtable() failed: %s\n", strerror(-r));
    return EXIT_FAILURE;
  }

  r = sd_bus_request_name(bus,
                          "org.freedesktop.systemd.VtableExample",
                          0);
  if (r < 0) {
    fprintf(stderr, "sd_bus_request_name() failed: %s\n", strerror(-r));
    return EXIT_FAILURE;
  }

  for (;;) {
    r = sd_bus_wait(bus, UINT64_MAX);
    if (r < 0) {
      fprintf(stderr, "sd_bus_wait() failed: %s\n", strerror(-r));
      return EXIT_FAILURE;
    }

    r = sd_bus_process(bus, NULL);
    if (r < 0) {
      fprintf(stderr, "sd_bus_process() failed: %s\n", strerror(-r));
      return EXIT_FAILURE;
    }
  }

  r = sd_bus_release_name(bus, "org.freedesktop.systemd.VtableExample");
  if (r < 0) {
    fprintf(stderr, "sd_bus_release_name() failed: %s\n", strerror(-r));
    return EXIT_FAILURE;
  }

  free(object.name);

  return 0;
}
