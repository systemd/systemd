#include <stdio.h>
#include <signal.h>

int main(void)
{
#ifdef SIGRTMIN
	printf("sigrtmin = %d, sigrtmax = %d\n", SIGRTMIN, SIGRTMAX);
#else
	printf("No realtime signals\n");
#endif
	return 0;
}
