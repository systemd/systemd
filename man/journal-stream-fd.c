/* SPDX-License-Identifier: MIT-0 */

#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-daemon.h>

int main(int argc, char *argv[]) {
  int fd;
  FILE *log;
  fd = sd_journal_stream_fd("test", LOG_INFO, 1);
  if (fd < 0) {
    errno = -fd;
    fprintf(stderr, "Failed to create stream fd: %m\n");
    return 1;
  }
  log = fdopen(fd, "w");
  if (!log) {
    fprintf(stderr, "Failed to create file object: %m\n");
    close(fd);
    return 1;
  }
  fprintf(log, "Hello World!\n");
  fprintf(log, SD_WARNING "This is a warning!\n");
  fclose(log);
  return 0;
}
