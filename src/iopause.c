/* Public domain. */

#include "taia.h"
#include "select.h"
#include "iopause.h"

void iopause(iopause_fd *x,unsigned int len,struct taia *deadline,struct taia *stamp)
{
  struct taia t;
  int millisecs;
  double d;
  int i;

  if (taia_less(deadline,stamp))
    millisecs = 0;
  else {
    t = *stamp;
    taia_sub(&t,deadline,&t);
    d = taia_approx(&t);
    if (d > 1000.0) d = 1000.0;
    millisecs = d * 1000.0 + 20.0;
  }

  for (i = 0;i < len;++i)
    x[i].revents = 0;

#ifdef IOPAUSE_POLL

  poll(x,len,millisecs);
  /* XXX: some kernels apparently need x[0] even if len is 0 */
  /* XXX: how to handle EAGAIN? are kernels really this dumb? */
  /* XXX: how to handle EINVAL? when exactly can this happen? */

#else
{

  struct timeval tv;
  fd_set rfds;
  fd_set wfds;
  int nfds;
  int fd;

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);

  nfds = 1;
  for (i = 0;i < len;++i) {
    fd = x[i].fd;
    if (fd < 0) continue;
    if (fd >= 8 * sizeof(fd_set)) continue; /*XXX*/

    if (fd >= nfds) nfds = fd + 1;
    if (x[i].events & IOPAUSE_READ) FD_SET(fd,&rfds);
    if (x[i].events & IOPAUSE_WRITE) FD_SET(fd,&wfds);
  }

  tv.tv_sec = millisecs / 1000;
  tv.tv_usec = 1000 * (millisecs % 1000);

  if (select(nfds,&rfds,&wfds,(fd_set *) 0,&tv) <= 0)
    return;
    /* XXX: for EBADF, could seek out and destroy the bad descriptor */

  for (i = 0;i < len;++i) {
    fd = x[i].fd;
    if (fd < 0) continue;
    if (fd >= 8 * sizeof(fd_set)) continue; /*XXX*/

    if (x[i].events & IOPAUSE_READ)
      if (FD_ISSET(fd,&rfds)) x[i].revents |= IOPAUSE_READ;
    if (x[i].events & IOPAUSE_WRITE)
      if (FD_ISSET(fd,&wfds)) x[i].revents |= IOPAUSE_WRITE;
  }

}
#endif

}
