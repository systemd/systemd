#include "libdevmapper/libdevmapper.h"
                                                                                
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <linux/kdev_t.h>

static void usage(char * progname) {
	fprintf(stderr, "usage : %s major minor\n", progname);
	exit(1);
}

int main(int argc, char **argv)
{
        int r = 0;
        struct dm_names *names;
        unsigned next = 0;
	int major, minor;
                                                                                
	/* sanity check */
	if (argc != 3)
		usage(argv[0]);

	major = atoi(argv[1]);
	minor = atoi(argv[2]);

        struct dm_task *dmt;
                                                                                
        if (!(dmt = dm_task_create(DM_DEVICE_LIST)))
                return 0;
                                                                                
        if (!dm_task_run(dmt))
                goto out;
                                                                                
        if (!(names = dm_task_get_names(dmt)))
                goto out;
                                                                                
        if (!names->dev) {
                printf("No devices found\n");
                goto out;
        }
                                                                                
        do {
                names = (void *) names + next;
		if ((int) MAJOR(names->dev) == major &&
		    (int) MINOR(names->dev) == minor) {
	                printf("%s\n", names->name);
			goto out;
		}
                next = names->next;
        } while (next);
                                                                                
      /* No correspondance found */
      r = 1;

      out:
        dm_task_destroy(dmt);
        return r;
}

