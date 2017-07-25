#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(void) {
  int s;

  s =socket(AF_INET, SOCK_STREAM, 0);
  return(close(s));
}
