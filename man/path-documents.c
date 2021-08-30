#include <stdio.h>
#include <stdlib.h>
#include <sd-path.h>

int main(void) {
  int r;
  char *t;

  r = sd_path_lookup(SD_PATH_USER_DOCUMENTS, NULL, &t);
  if (r < 0)
    return EXIT_FAILURE;

  printf("~/Documents: %s\n", t);
  free(t);

  return EXIT_SUCCESS;
}
