#include <stdio.h>
#include <unistd.h>

int main(void)
{
  static const char hello[] = "Hello, World!\n";
  _fwrite(hello, sizeof hello-1, stdout);
  return 0;
}
