#include <stdio.h>
#include <unistd.h>

int main(void)
{
	printf("pid   = %u\n", getpid());
	printf("ppid  = %u\n", getppid());
	printf("uid   = %u\n", getuid());
	printf("euid  = %u\n", geteuid());
	printf("gid   = %u\n", getgid());
	printf("egid  = %u\n", getegid());
	sleep(10);
	return 0;
}
