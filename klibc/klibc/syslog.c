/*
 * syslog.c
 *
 * Issue syslog messages via the kernel printk queue.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

/* Maximum size for a kernel message */
#define BUFLEN 1024

/* Logging node */
#define LOGDEV "/dev/kmsg"

/* Max length of ID string */
#define MAXID 31		/* MAXID+6 must be < BUFLEN */

int __syslog_fd = -1;
static char id[MAXID+1];

void openlog(const char *ident, int option, int facility)
{
  int fd;

  (void)option; (void)facility;	/* Unused */
  
  if ( __syslog_fd == -1 ) {
    __syslog_fd = fd = open(LOGDEV, O_WRONLY);
    if ( fd == -1 )
      return;
    fcntl(fd, F_SETFD, (long)FD_CLOEXEC);
  }
  
  strncpy(id, ident?ident:"", MAXID);
  id[MAXID] = '\0';		/* Make sure it's null-terminated */
}

void vsyslog(int prio, const char *format, va_list ap)
{
  char buf[BUFLEN];
  int len;
  int fd;

  if ( __syslog_fd == -1 )
    openlog(NULL, 0, 0);

  buf[0] = '<';
  buf[1] = LOG_PRI(prio)+'0';
  buf[2] = '>';
  len = 3;

  if ( *id )
    len += sprintf(buf+3, "%s: ", id);

  len += vsnprintf(buf+len, BUFLEN-len, format, ap);

  if ( len > BUFLEN-1 ) len = BUFLEN-1;
  buf[len++] = '\n';

  fd = __syslog_fd;
  if ( fd == -1 )
    fd = 2;			/* Failed to open log, write to stderr */

  write(fd, buf, len);
}

void syslog(int prio, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsyslog(prio, format, ap);
  va_end(ap);
}
