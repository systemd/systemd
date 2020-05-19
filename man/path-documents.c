#include <stdio.h>
#include <sd-path.h>

int main(void) {
  char *t;

  sd_path_lookup(SD_PATH_USER_DOCUMENTS, NULL, &t);
  printf("~/Documents: %s\n", t);
}
