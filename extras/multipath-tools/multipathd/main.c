#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libdevmapper.h>
#include <syslog.h>
#include <signal.h>
#include <wait.h>

#include "devinfo.h"
#include "checkers.h"

#define CHECKINT 5
#define MAXPATHS 2048
#define FILENAMESIZE 256
#define MAPNAMESIZE 64
#define TARGETTYPESIZE 16
#define PARAMSSIZE 2048
#define MAXMAPS 512

#define MULTIPATH "/sbin/multipath"
#define PIDFILE "/var/run/multipathd.pid"

#ifndef DEBUG
#define DEBUG 1
#endif
#define LOG(x, y, z...) if (DEBUG >= x) syslog(x, y, ##z)

struct path
{
	int major;
	int minor;
	char mapname[MAPNAMESIZE];
	int (*checkfn) (char *);
};

struct paths
{
	pthread_mutex_t *lock;
	struct path *paths_h;
};

struct event_thread
{
	pthread_t *thread;
	pthread_mutex_t *waiter_lock;
	char mapname[MAPNAMESIZE];
};

struct devmap
{
	char mapname[MAPNAMESIZE];
};

/* global var */
pthread_mutex_t *event_lock;
pthread_cond_t *event;

int makenode (char *devnode, int major, int minor)
{
	dev_t dev;
	
	dev = makedev (major, minor);
        unlink (devnode);
	
	return mknod(devnode, S_IFBLK | S_IRUSR | S_IWUSR, dev);
}

int select_checkfn(struct path *path_p)
{
	char devnode[FILENAMESIZE];
	char vendor[8];
	char product[16];
	char rev[4];
	int i, r;

	/* default checkfn */
	path_p->checkfn = &readsector0;
	
	sprintf (devnode, "/tmp/.select.%i.%i", path_p->major, path_p->minor);

	r = makenode (devnode, path_p->major, path_p->minor);
	
	if (r < 0) {
		LOG(2, "[select_checkfn] can not make node %s", devnode);
		return r;
	}

	r = get_lun_strings(vendor, product, rev, devnode);

	if (r) {
		LOG(2, "[select_checkfn] can not get strings");
		return r;
	}

	r = unlink (devnode);

	if (r < 0) {
		LOG(2, "[select_checkfn] can not unlink %s", devnode);
		return r;
	}

	static struct {
		char * vendor;
		char * product;
		int (*checkfn) (char *);
	} wlist[] = {
		{"COMPAQ  ", "HSV110 (C)COMPAQ", &tur},
		{"COMPAQ  ", "MSA1000         ", &tur},
		{"COMPAQ  ", "MSA1000 VOLUME  ", &tur},
		{"DEC     ", "HSG80           ", &tur},
		{"HP      ", "HSV100          ", &readsector0},
		{NULL, NULL, NULL},
	};
	
	for (i = 0; wlist[i].vendor; i++) {
		if (strncmp(vendor, wlist[i].vendor, 8) == 0 &&
		    strncmp(product, wlist[i].product, 16) == 0) {
			path_p->checkfn = wlist[i].checkfn;
		}
	}

	return 0;
}

int get_devmaps (struct devmap *devmaps)
{
	struct devmap *devmaps_p;
	struct dm_task *dmt, *dmt1;
	struct dm_names *names = NULL;
	unsigned next = 0;
	void *nexttgt;
	int r = 0;
	long long start, length;
	char *target_type = NULL;
	char *params;

	memset (devmaps, 0, MAXMAPS * sizeof (struct devmap));

	if (!(dmt = dm_task_create(DM_DEVICE_LIST))) {
		r = 1;
		goto out;
	}

	if (!dm_task_run(dmt)) {
		r = 1;
		goto out;
	}

	if (!(names = dm_task_get_names(dmt))) {
		r = 1;
		goto out;
	}

	if (!names->dev) {
		LOG (1, "[get_devmaps] no devmap found");
		goto out;
	}

	devmaps_p = devmaps;

	do {
		/* keep only multipath maps */

		names = (void *) names + next;
		nexttgt = NULL;
		LOG (3, "[get_devmaps] iterate on devmap names : %s", names->name);

		LOG (3, "[get_devmaps]  dm_task_create(DM_DEVICE_STATUS)");
		if (!(dmt1 = dm_task_create(DM_DEVICE_STATUS)))
			goto out1;
		
		LOG (3, "[get_devmaps]  dm_task_set_name(dmt1, names->name)");
		if (!dm_task_set_name(dmt1, names->name))
			goto out1;
		
		LOG (3, "[get_devmaps]  dm_task_run(dmt1)");
		if (!dm_task_run(dmt1))
			goto out1;
		LOG (3, "[get_devmaps]  DM_DEVICE_STATUS ioctl done");
		do {
			LOG (3, "[get_devmaps]   iterate on devmap's targets");
			nexttgt = dm_get_next_target(dmt1, nexttgt,
						   &start,
						   &length,
						   &target_type,
						   &params);


			LOG (3, "[get_devmaps]   test target_type existence");
			if (!target_type)
				goto out1;
			
			LOG (3, "[get_devmaps]   test target_type is multipath");
			if (!strncmp (target_type, "multipath", 9)) {
				strcpy (devmaps_p->mapname, names->name);
				devmaps_p++;
				
				/* test vector overflow */
				if (devmaps_p - devmaps >= MAXMAPS * sizeof (struct devmap)) {
					LOG (1, "[get_devmaps] devmaps overflow");
					dm_task_destroy(dmt1);
					r = 1;
					goto out;
				}
			}

		} while (nexttgt);

out1:
		dm_task_destroy(dmt1);
		next = names->next;

	} while (next);

out:
	dm_task_destroy(dmt);

	LOG (3, "[get_devmaps] done");
	return r;
}

int checkpath (struct path *path_p)
{
	char devnode[FILENAMESIZE];
	int r;
	
	LOG (2, "[checkpath] checking path %i:%i", path_p->major, path_p->minor);
	sprintf (devnode, "/tmp/.checker.%i.%i", path_p->major, path_p->minor);
	
	if (path_p->checkfn == NULL) {
		LOG (1, "[checkpath] test function not set for path %i:%i",
		     path_p->major, path_p->minor);
		return 1;
	}

	r = makenode (devnode, path_p->major, path_p->minor);

	if (r < 0) {
		LOG (2, "[checkpath] can not make node for %s", devnode);
		return r;
	}

	r = path_p->checkfn(devnode);
	unlink (devnode);
				
	return r;
}
		
int updatepaths (struct devmap *devmaps, struct paths *failedpaths)
{
	struct path *path_p;
	struct devmap *devmaps_p;
	void *next;
	struct dm_task *dmt;
	long long start, length;
	char *target_type = NULL;
	char *params, *p1, *p2;
	char word[6];
	int i;
	
	path_p = failedpaths->paths_h;
	
	pthread_mutex_lock (failedpaths->lock);
	memset (failedpaths->paths_h, 0, MAXPATHS * sizeof (struct path));

	/* first pass */
	/* ask DM the failed path list */

	devmaps_p = devmaps;

	while (*devmaps_p->mapname != 0x0) {
		next = NULL;
		
		if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
			break;
		
		if (!dm_task_set_name(dmt, devmaps_p->mapname))
			goto out;
		
		if (!dm_task_run(dmt))
			goto out;

		do {
			next = dm_get_next_target(dmt, next, &start, &length,
						   &target_type, &params);

			/* begin ugly parser */
			p1 = params;
			p2 = params;
			while (*p1) {
				/* p2 lags at the begining of the word p1 parses */
				while (*p1 != ' ') {
					/* if the current word is a path */
					if (*p1 == ':') {
						/* p1 jumps to path state */
						while (*p1 != 'A' && *p1 != 'F')
							p1++; 
						
						/* store path info */

						path_p->checkfn = NULL;

						i = 0;
						memset (&word, 'O', 6 * sizeof (char));
						while (*p2 != ':') {
							word[i++] = *p2;
							p2++;
						}
						path_p->major = atoi (word);
						
						p2++;
						i = 0;
						memset (&word, 'O', 6 * sizeof (char));
						while (*p2 != ' ') {
							word[i++] = *p2;
							p2++;
						}
						path_p->minor = atoi (word);

						strcpy (path_p->mapname, devmaps_p->mapname);

						/* 
						 * discard active paths
						 * don't trust the A status flag : double check
						 */
						if (*p1 == 'A' &&
						    !select_checkfn (path_p) &&
						    checkpath (path_p)) {
							LOG(2, "[updatepaths] discard %i:%i as valid path",
							    path_p->major, path_p->minor);
							p1++;
							memset (path_p, 0, sizeof(struct path));
							continue;
						}
						
						path_p++;

						/* test vector overflow */
						if (path_p - failedpaths->paths_h >= MAXPATHS * sizeof (struct path)) {
							LOG (1, "[updatepaths] path_h overflow");
							pthread_mutex_unlock (failedpaths->lock);
							return 1;
						}
					}
					p1++;
				}
				p2 = p1;
				p1++;
			}
		} while (next);
			
out:
		dm_task_destroy(dmt);
		devmaps_p++;
		
	}

	pthread_mutex_unlock (failedpaths->lock);
	return 0;
}

int geteventnr (char *name)
{
	struct dm_task *dmt;
	struct dm_info info;
	
	if (!(dmt = dm_task_create(DM_DEVICE_INFO)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (!dm_task_get_info(dmt, &info))
		return 0;

	if (!info.exists) {
		LOG(1, "Device %s does not exist", name);
		return 0;
	}

out:
	dm_task_destroy(dmt);

	return info.event_nr;
}

void *waitevent (void * et)
{
	int event_nr;
	struct event_thread *waiter;

	waiter = (struct event_thread *)et;
	pthread_mutex_lock (waiter->waiter_lock);

	event_nr = geteventnr (waiter->mapname);

	struct dm_task *dmt;

	if (!(dmt = dm_task_create(DM_DEVICE_WAITEVENT)))
		return 0;

	if (!dm_task_set_name(dmt, waiter->mapname))
		goto out;

	if (event_nr && !dm_task_set_event_nr(dmt, event_nr))
		goto out;

	dm_task_run(dmt);

out:
	dm_task_destroy(dmt);

	/* tell waiterloop we have an event */
	pthread_mutex_lock (event_lock);
	pthread_cond_signal(event);
	pthread_mutex_unlock (event_lock);
	
	/* release waiter_lock so that waiterloop knows we are gone */
	pthread_mutex_unlock (waiter->waiter_lock);
	pthread_exit(waiter->thread);

	return (NULL);
}

void *waiterloop (void *ap)
{
	struct paths *failedpaths;
	struct devmap *devmaps, *devmaps_p;
	struct event_thread *waiters, *waiters_p;
	int r;

	/* inits */
	failedpaths = (struct paths *)ap;
	devmaps = malloc (MAXMAPS * sizeof (struct devmap));
	waiters = malloc (MAXMAPS * sizeof (struct event_thread));
	memset (waiters, 0, MAXMAPS * sizeof (struct event_thread));

	while (1) {
		
		/* update devmap list */
		LOG (1, "[event thread] refresh devmaps list");
		get_devmaps (devmaps);

		/* update failed paths list */
		LOG (1, "[event thread] refresh failpaths list");
		updatepaths (devmaps, failedpaths);
		
		/* start waiters on all devmaps */
		LOG (1, "[event thread] start up event loops");
		waiters_p = waiters;
		devmaps_p = devmaps;

		while (*devmaps_p->mapname != 0x0) {
			
			/* find out if devmap already has a running waiter thread */
			while (*waiters_p->mapname != 0x0) {
				if (!strcmp (waiters_p->mapname, devmaps_p->mapname))
					break;
				waiters_p++;
			}
					
			/* no event_thread struct : init it */
			if (*waiters_p->mapname == 0x0) {
				strcpy (waiters_p->mapname, devmaps_p->mapname);
				waiters_p->thread = malloc (sizeof (pthread_t));
				waiters_p->waiter_lock = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
				pthread_mutex_init (waiters_p->waiter_lock, NULL);
			}
			
			/* event_thread struct found */
			if (*waiters_p->mapname != 0x0) {
				r = pthread_mutex_trylock (waiters_p->waiter_lock);
				/* thread already running : out */

				if (r)
					goto out;
				
				pthread_mutex_unlock (waiters_p->waiter_lock);
			}
			
			LOG (1, "[event thread] create event thread for %s", waiters_p->mapname);
			pthread_create (waiters_p->thread, NULL, waitevent, waiters_p);
out:
			waiters_p = waiters;
			devmaps_p++;
		}

		/* wait event condition */
		pthread_mutex_lock (event_lock);
		pthread_cond_wait(event, event_lock);
		pthread_mutex_unlock (event_lock);

		LOG (1, "[event thread] event caught");
	}

	return (NULL);
}

void *checkerloop (void *ap)
{
	struct paths *failedpaths;
	struct path *path_p;
	char *cmdargs[4] = {MULTIPATH, "-D", NULL, NULL};
	char major[5];
	char minor[5];
	int status;

	failedpaths = (struct paths *)ap;

	LOG (1, "[checker thread] path checkers start up");

	while (1) {
		path_p = failedpaths->paths_h;
		pthread_mutex_lock (failedpaths->lock);
		LOG (2, "[checker thread] checking paths");
		while (path_p->major != 0) {
			
			if (checkpath (path_p)) {
				LOG (1, "[checker thread] reconfigure %s\n", path_p->mapname);
				snprintf (major, 5, "%i", path_p->major);
				snprintf (minor, 5, "%i", path_p->minor);
				cmdargs[2] = major;
				cmdargs[3] = minor;
				if (fork () == 0)
					execve (cmdargs[0], cmdargs, NULL);

				wait (&status);
				/* MULTIPATH will ask for failedpaths refresh (SIGHUP) */
			}
			
			path_p++;
			
			/* test vector overflow */
			if (path_p - failedpaths->paths_h >= MAXPATHS * sizeof (struct path)) {
				LOG (1, "[checker thread] path_h overflow");
				pthread_mutex_unlock (failedpaths->lock);
				return (NULL);
			}
		}
		pthread_mutex_unlock (failedpaths->lock);
		sleep(CHECKINT);
	}

	return (NULL);
}

struct paths *initpaths (void)
{
	struct paths *failedpaths;

	failedpaths = malloc (sizeof (struct paths));
	failedpaths->paths_h = malloc (MAXPATHS * sizeof (struct path));
	failedpaths->lock = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
	pthread_mutex_init (failedpaths->lock, NULL);
	event = (pthread_cond_t *) malloc (sizeof (pthread_cond_t));
	pthread_cond_init (event, NULL);
	event_lock = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
	pthread_mutex_init (event_lock, NULL);
	
	return (failedpaths);
}

void pidfile (pid_t pid)
{
	FILE *file;
	struct stat *buf;

	buf = malloc (sizeof (struct stat));

	if (!stat (PIDFILE, buf)) {
		LOG(1, "[master thread] already running : out");
		free (buf);
		exit (1);
	}
		
	umask (022);
	pid = setsid ();

	if (pid < -1) {
		LOG(1, "[master thread] setsid() error");
		exit (1);
	}
	
	file = fopen (PIDFILE, "w");
	fprintf (file, "%d\n", pid);
	fclose (file);
	free (buf);
}

void *
signal_set(int signo, void (*func) (int))
{
	int r;
	struct sigaction sig;
	struct sigaction osig;

	sig.sa_handler = func;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;

	r = sigaction(signo, &sig, &osig);

	if (r < 0)
		return (SIG_ERR);
	else
		return (osig.sa_handler);
}

void sighup (int sig)
{
	LOG (1, "[master thread] SIGHUP caught : refresh devmap list");

	/* ask for failedpaths refresh */
	pthread_mutex_lock (event_lock);
	pthread_cond_signal(event);
	pthread_mutex_unlock (event_lock);
}

void sigend (int sig)
{
	LOG (1, "[master thread] unlink pidfile");
	unlink (PIDFILE);
	LOG (1, "[master thread] --------shut down-------");
	exit (0);
}

void signal_init(void)
{
	signal_set(SIGHUP, sighup);
	signal_set(SIGINT, sigend);
	signal_set(SIGTERM, sigend);
	signal_set(SIGKILL, sigend);
}

int main (int argc, char *argv[])
{
	pthread_t wait, check;
	struct paths *failedpaths;
	pid_t pid;

	pid = fork ();

	/* can't fork */
	if (pid < 0)
		exit (1);

	/* let the parent die happy */
	if (pid > 0)
		exit (0);
	
	/* child's play */
	openlog (argv[0], 0, LOG_DAEMON);
	LOG (1, "[master thread] --------start up--------");

	pidfile (pid);
	signal_init ();

	failedpaths = initpaths ();
	
	pthread_create (&wait, NULL, waiterloop, failedpaths);
	pthread_create (&check, NULL, checkerloop, failedpaths);
	pthread_join (wait, NULL);
	pthread_join (check, NULL);

	return 0;
}
