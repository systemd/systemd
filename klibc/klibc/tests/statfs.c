#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/vfs.h>

static void do_statfs(const char *path)
{
  struct statfs sfs;

  if ( statfs(path, &sfs) ) {
    perror(path);
    exit(1);
  }

  printf("Path = %s\n"
	 "   f_type     = %#jx\n"
	 "   f_bsize    = %jd\n"
	 "   f_blocks   = %jd\n"
	 "   f_bfree    = %jd\n"
	 "   f_bavail   = %jd\n"
	 "   f_files    = %jd\n"
	 "   f_ffree    = %jd\n"
	 "   f_namelen  = %jd\n",
	 path,
	 (uintmax_t)sfs.f_type,
	 (intmax_t)sfs.f_bsize,
	 (intmax_t)sfs.f_blocks,
	 (intmax_t)sfs.f_bfree,
	 (intmax_t)sfs.f_bavail,
	 (intmax_t)sfs.f_files,
	 (intmax_t)sfs.f_ffree,
	 (intmax_t)sfs.f_namelen);
}

int main(int argc, char *argv[])
{
  int i;

  for ( i = 1 ; i < argc ; i++ )
    do_statfs(argv[i]);

  return 0;
}
