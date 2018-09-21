#include <stdio.h>
#include <string.h>
#include <systemd/sd-journal.h>

int main(int argc, char *argv[]) {
  int r;
  sd_journal *j;
  r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
  if (r < 0) {
    fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
    return 1;
  }
  for (;;)  {
    const void *d;
    size_t l;
    r = sd_journal_next(j);
    if (r < 0) {
      fprintf(stderr, "Failed to iterate to next entry: %s\n", strerror(-r));
      break;
    }
    if (r == 0) {
      /* Reached the end, let's wait for changes, and try again */
      r = sd_journal_wait(j, (uint64_t) -1);
      if (r < 0) {
        fprintf(stderr, "Failed to wait for changes: %s\n", strerror(-r));
        break;
      }
      continue;
    }
    r = sd_journal_get_data(j, "MESSAGE", &d, &l);
    if (r < 0) {
      fprintf(stderr, "Failed to read message field: %s\n", strerror(-r));
      continue;
    }
    printf("%.*s\n", (int) l, (const char*) d);
  }
  sd_journal_close(j);
  return 0;
}
