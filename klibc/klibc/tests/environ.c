#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[], char *envp[])
{
  int i;

  /* Verify envp == environ */
  printf("Verifying envp == environ... %s\n",
	 (envp == environ) ? "ok" : "ERROR");

  /* Test argc/argv */
  printf("argc = %d, argv = %p\n", argc, argv);
  for ( i = 0 ; i < argc ; i++ ) {
    printf("argv[%2d] = %s\n", i, argv[i]);
  }

  /* Test environ */
  for ( i = 0 ; envp[i] ; i++ )
    printf("%s\n", envp[i]);

  return 0;
}
