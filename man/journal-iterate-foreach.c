/* SPDX-License-Identifier: MIT-0 */

#include <errno.h>
#include <stdio.h>
#include <systemd/sd-journal.h>

int main(int argc, char *argv[]) {
  int r;
  sd_journal *j;
  r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
  if (r < 0) {
    errno = -r;
    fprintf(stderr, "Failed to open journal: %m\n");
    return 1;
  }
  SD_JOURNAL_FOREACH(j) {
    const char *d;
    size_t l;

    r = sd_journal_get_data(j, "MESSAGE", (const void **)&d, &l);
    if (r < 0) {
      errno = -r;
      fprintf(stderr, "Failed to read message field: %m\n");
      continue;
    }

    printf("%.*s\n", (int) l, d);
  }
  sd_journal_close(j);
  return 0;
}
