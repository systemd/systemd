#include <stdio.h>
#include <systemd/sd-id128.h>

#define OUR_APPLICATION_ID SD_ID128_MAKE(c2,73,27,73,23,db,45,4e,a6,3b,b9,6e,79,b5,3e,97)

int main(int argc, char *argv[]) {
  sd_id128_t id;
  sd_id128_get_machine_app_specific(OUR_APPLICATION_ID, &id);
  printf("Our application ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(id));
  return 0;
}
