#include <stdio.h>
#include <time.h>

int main(int argc, char *argv[])
{
  struct timeval tv;
  struct timespec ts;
  int i;
  const char *rv, *rs;

  for ( i = 1 ; i < argc ; i++ ) {
    rs = strtotimespec(argv[i], &ts);
    rv = strtotimeval(argv[i], &tv);
    printf("String:   \"%s\"\n"
	   "Timespec: %ld.%09ld\n"
	   "Residual: \"%s\"\n"
	   "Timeval:  %ld.%06ld\n"
	   "Residual: \"%s\"\n",
	   argv[i],
	   (long)ts.tv_sec, (long)ts.tv_nsec, rs,
	   (long)tv.tv_sec, (long)tv.tv_usec, rv);
  }
  
  return 0;
}

	   
