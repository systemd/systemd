/* SPDX-License-Identifier: MIT-0 */

#include <stdio.h>

#include <systemd/sd-bus.h>

int read_strings_from_message(sd_bus_message *m) {
  int r;

  r = sd_bus_message_enter_container(m, 'a', "s");
  if (r < 0)
    return r;

  for (;;) {
    const char *s;

    r = sd_bus_message_read(m, "s", &s);
    if (r < 0)
      return r;
    if (r == 0)
      break;

    printf("%s\n", s);
  }

  return sd_bus_message_exit_container(m);
}
