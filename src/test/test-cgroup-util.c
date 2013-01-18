#include <assert.h>

#include "util.h"
#include "cgroup-util.h"

#define check_c_t_u(path, code, result) \
{ \
   char a[] = path; \
   char *unit = NULL; \
   assert_se(cgroup_to_unit(a, &unit) == code); \
   assert(code < 0 || streq(unit, result));                 \
}


static void test_cgroup_to_unit(void) {
        check_c_t_u("/system/getty@.service/tty2", 0, "getty@tty2.service");
        check_c_t_u("/system/getty@.service/", -EINVAL, "getty@tty2.service");
        check_c_t_u("/system/getty@.service", -EINVAL, "getty@tty2.service");
        check_c_t_u("/system/getty.service", 0, "getty.service");
        check_c_t_u("/system/getty", -EINVAL, "getty.service");
}

int main(void) {
        test_cgroup_to_unit();

        return 0;
}
