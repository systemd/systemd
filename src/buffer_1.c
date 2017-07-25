/* Public domain. */

#include "buffer.h"

char buffer_1_space[BUFFER_OUTSIZE];
static buffer it = BUFFER_INIT(buffer_unixwrite,1,buffer_1_space,sizeof buffer_1_space);
buffer *buffer_1 = &it;
