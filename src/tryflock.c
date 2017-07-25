/* Public domain. */

#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>

main()
{
  flock(0,LOCK_EX | LOCK_UN | LOCK_NB);
}
