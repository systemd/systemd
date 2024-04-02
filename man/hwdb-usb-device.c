/* SPDX-License-Identifier: MIT-0 */

#include <stdio.h>
#include <stdint.h>
#include <systemd/sd-hwdb.h>

int print_usb_properties(uint16_t vid, uint16_t pid) {
  char match[128];
  sd_hwdb *hwdb;
  const char *key, *value;
  int r;

  /* Match this USB vendor and product ID combination */
  snprintf(match, sizeof match, "usb:v%04Xp%04X", vid, pid);

  r = sd_hwdb_new(&hwdb);
  if (r < 0)
    return r;

  SD_HWDB_FOREACH_PROPERTY(hwdb, match, key, value)
    printf("%s: \"%s\" → \"%s\"\n", match, key, value);

  sd_hwdb_unref(hwdb);
  return 0;
}

int main(int argc, char **argv) {
  print_usb_properties(0x046D, 0xC534);
  return 0;
}
