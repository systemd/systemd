#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

int main(void)
{
  int r, i;
  char buffer[512];

  r = snprintf(buffer, 512, "Hello, %d", 37);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'d", 37373737);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'x", 0xdeadbeef);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'#X", 0xdeadbeef);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'#llo", 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  /* Make sure overflow works correctly */
  memset(buffer, '\xff', 512);
  r = snprintf(buffer, 16, "Hello, %'#llo", 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);
  for ( i = 16 ; i < 512 ; i++ )
    assert ( buffer[i] == '\xff' );

  r = snprintf(buffer, 512, "Hello, %'#40.20llo", 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'#-40.20llo", 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'#*.*llo", 40, 20, 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'#*.*llo", -40, 20, 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'#*.*llo", -40, -20, 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %'#*.*llx", -40, -20, 0123456701234567ULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %p", &buffer);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %P", &buffer);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %20p", &buffer);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %-20p", &buffer);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 512, "Hello, %-20p", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 20, "Hello, %'-20p", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 15, "Hello, %'-20p", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 3, "Hello, %'-20p", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  /* This shouldn't change buffer in any way! */
  r = snprintf(buffer, 0, "Hello, %'-20p", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  for ( i = -30 ; i <= 30 ; i++ ) {
    r = snprintf(buffer, 40, "Hello, %'*p", i, NULL);
    printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);
  }

  r = snprintf(buffer, 40, "Hello, %'-20s", "String");
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'20s", "String");
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'020s", "String");
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'-20s", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'20s", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'020s", NULL);
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'-20c", '*');
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'20c", '*');
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  r = snprintf(buffer, 40, "Hello, %'020c", '*');
  printf("buffer = \"%s\" (%d), r = %d\n", buffer, strlen(buffer), r);

  return 0;
}

