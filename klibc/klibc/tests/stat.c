#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

static void do_stat(const char *path)
{
  struct stat st;

  if ( stat(path, &st) ) {
    perror(path);
    exit(1);
  }

  printf("Path = %s\n"
	 "   st_dev       = %#jx (%u,%u)\n"
	 "   st_ino       = %ju\n"
	 "   st_mode      = %#jo\n"
	 "   st_nlink     = %ju\n"
	 "   st_uid       = %ju\n"
	 "   st_gid       = %ju\n"
	 "   st_rdev      = %#jx (%u,%u)\n"
	 "   st_size      = %ju\n"
	 "   st_blksize   = %ju\n"
	 "   st_blocks    = %ju\n",
	 path,
	 (uintmax_t)st.st_dev, major(st.st_dev), minor(st.st_dev),
	 (uintmax_t)st.st_ino,
	 (uintmax_t)st.st_mode,
	 (uintmax_t)st.st_nlink,
	 (uintmax_t)st.st_uid,
	 (uintmax_t)st.st_gid,
	 (uintmax_t)st.st_rdev, major(st.st_rdev), minor(st.st_rdev),
	 (uintmax_t)st.st_size,
	 (uintmax_t)st.st_blksize,
	 (uintmax_t)st.st_blocks);

#ifdef _STATBUF_ST_NSEC
  printf("   st_atim      = %jd.%09u\n"
	 "   st.mtim      = %jd.%09u\n"
	 "   st.ctim      = %jd.%09u\n",
	 (uintmax_t)st.st_atim.tv_sec, (unsigned int)st.st_atim.tv_nsec,
	 (uintmax_t)st.st_mtim.tv_sec, (unsigned int)st.st_mtim.tv_nsec,
	 (uintmax_t)st.st_ctim.tv_sec, (unsigned int)st.st_ctim.tv_nsec);
#else
  printf("   st_atime     = %jd\n"
	 "   st.mtime     = %jd\n"
	 "   st.ctime     = %jd\n",
	 (uintmax_t)st.st_atime,
	 (uintmax_t)st.st_mtime,
	 (uintmax_t)st.st_ctime);
#endif
}

int main(int argc, char *argv[])
{
  int i;

  for ( i = 1 ; i < argc ; i++ )
    do_stat(argv[i]);

  return 0;
}
