#include <unistd.h>
#include <sys/reboot.h>

int main(void) {
  return(reboot(0));
}
