#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  (void)argc; (void)argv;

  /* Set SETENV */
  setenv("SETENV", "setenv", 1);

  /* Set PUTENV */
  putenv("PUTENV=putenv");

  /* Print the results... */
  printf("SETENV = %s\n", getenv("SETENV"));
  printf("PUTENV = %s\n", getenv("PUTENV"));

  /* Override tests */
  setenv("SETENV", "setenv_good", 1);
  putenv("PUTENV=putenv_good");
  printf("SETENV = %s\n", getenv("SETENV"));
  printf("PUTENV = %s\n", getenv("PUTENV"));

  /* Non-override test */
  setenv("SETENV", "setenv_bad", 0);
  setenv("NEWENV", "newenv_good", 0);
  printf("SETENV = %s\n", getenv("SETENV"));
  printf("NEWENV = %s\n", getenv("NEWENV"));

  /* Undef test */
  unsetenv("SETENV");
  unsetenv("NEWENV");
  printf("SETENV = %s\n", getenv("SETENV"));
  printf("NEWENV = %s\n", getenv("NEWENV"));

  return 0;
}
