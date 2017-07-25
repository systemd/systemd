/* Public domain. */

#include <sys/types.h>
#include <sys/stat.h>

void main()
{
  mkfifo("temp-trymkffo",0);
}
