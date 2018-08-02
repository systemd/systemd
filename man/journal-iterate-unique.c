#include <stdio.h>
#include <string.h>
#include <systemd/sd-journal.h>

int main(int argc, char *argv[]) {
  sd_journal *j;
  const void *d;
  size_t l;
  int r;

  r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
  if (r < 0) {
    fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
    return 1;
  }
  r = sd_journal_query_unique(j, "_SYSTEMD_UNIT");
  if (r < 0) {
    fprintf(stderr, "Failed to query journal: %s\n", strerror(-r));
    return 1;
  }
  SD_JOURNAL_FOREACH_UNIQUE(j, d, l)
    printf("%.*s\n", (int) l, (const char*) d);
  sd_journal_close(j);
  return 0;
}
