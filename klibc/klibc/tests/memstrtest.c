#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char t1[256], t2[256];
    int i;
    int r;

    for(i = 0; i < sizeof(t1); i++)
	t1[i] = t2[i] = (unsigned char)i;

    r = memcmp(t1, t2, sizeof(t1));
    printf("memcmp r = %d\n", r);
    r = memcmp(t1, t2, sizeof(t1)/2);
    printf("memcmp r = %d\n", r);
    t1[255] = 0;
    r = memcmp(t1, t2, sizeof(t1));
    printf("memcmp r = %d\n", r);

    for (i = 0; i < sizeof(t1); i++)
	t1[i] = 0xaa;
    memset(t2, 0xaa, sizeof(t2));
    r = memcmp(t1, t2, sizeof(t1));
    printf("memcmp r = %d\n", r);
    return 0;
}

