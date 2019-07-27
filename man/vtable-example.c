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
  printf("Got called with userdata=%p\n", userdata);
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

#define check(x) ({                             \
  int r = x;                                    \
  errno = r < 0 ? -r : 0;                       \
  printf(#x ": %m\n");                          \
  if (r < 0)                                    \
    return EXIT_FAILURE;                        \
  })

int main(int argc, char **argv) {
  _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

  sd_bus_default(&bus);

  object object = { .number = 666 };
  check((object.name = strdup("name")) != NULL);

  check(sd_bus_add_object_vtable(bus, NULL, "/object",
                                 "org.freedesktop.systemd.VtableExample",
                                 vtable,
                                 &object));

  for (;;) {
    check(sd_bus_wait(bus, UINT64_MAX));
    check(sd_bus_process(bus, NULL));
  }

  free(object.name);

  return 0;
}
