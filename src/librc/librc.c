/*
 * librc
 * core RC functions
 */

/*
 * Copyright (c) 2007-2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

const char librc_copyright[] = "Copyright (c) 2007-2008 Roy Marples";

#include "queue.h"
#include "librc.h"
#include <helpers.h>
#ifdef __FreeBSD__
#  include <sys/sysctl.h>
#endif

#define RC_RUNLEVEL	RC_SVCDIR "/softlevel"

#ifndef S_IXUGO
#  define S_IXUGO (S_IXUSR | S_IXGRP | S_IXOTH)
#endif

/* File stream used for plugins to write environ vars to */
FILE *rc_environ_fd = NULL;

typedef struct rc_service_state_name {
	RC_SERVICE state;
	const char *name;
} rc_service_state_name_t;

/* We MUST list the states below 0x10 first
 * The rest can be in any order */
static const rc_service_state_name_t rc_service_state_names[] = {
	{ RC_SERVICE_STARTED,     "started" },
	{ RC_SERVICE_STOPPED,     "stopped" },
	{ RC_SERVICE_STARTING,    "starting" },
	{ RC_SERVICE_STOPPING,    "stopping" },
	{ RC_SERVICE_INACTIVE,    "inactive" },
	{ RC_SERVICE_WASINACTIVE, "wasinactive" },
	{ RC_SERVICE_HOTPLUGGED,  "hotplugged" },
	{ RC_SERVICE_FAILED,      "failed" },
	{ RC_SERVICE_SCHEDULED,   "scheduled"},
	{ 0, NULL}
};

#define LS_INITD	0x01
#define LS_DIR		0x02
static RC_STRINGLIST *
ls_dir(const char *dir, int options)
{
	DIR *dp;
	struct dirent *d;
	RC_STRINGLIST *list = NULL;
	struct stat buf;
	size_t l;
	char file[PATH_MAX];
	int r;

	list = rc_stringlist_new();
	if ((dp = opendir(dir)) == NULL)
		return list;
	while (((d = readdir(dp)) != NULL)) {
		if (d->d_name[0] != '.') {
			if (options & LS_INITD) {
				/* Check that our file really exists.
				 * This is important as a service maybe in a
				 * runlevel, but could have been removed. */
				snprintf(file, sizeof(file), "%s/%s",
				    dir, d->d_name);
				r = stat(file, &buf);
				if (r != 0)
					continue;

				/* .sh files are not init scripts */
				l = strlen(d->d_name);
				if (l > 2 && d->d_name[l - 3] == '.' &&
				    d->d_name[l - 2] == 's' &&
				    d->d_name[l - 1] == 'h')
					continue;
			}
			if (options & LS_DIR) {
				snprintf(file, sizeof(file), "%s/%s",
				    dir, d->d_name);
				if (stat(file, &buf) != 0 ||
				    !S_ISDIR(buf.st_mode))
					continue;
			}
			rc_stringlist_add(list, d->d_name);
		}
	}
	closedir(dp);
	return list;
}

static bool
rm_dir(const char *pathname, bool top)
{
	DIR *dp;
	struct dirent *d;
	char file[PATH_MAX];
	struct stat s;
	bool retval = true;

	if ((dp = opendir(pathname)) == NULL)
		return false;

	errno = 0;
	while (((d = readdir(dp)) != NULL) && errno == 0) {
		if (strcmp(d->d_name, ".") != 0 &&
		    strcmp(d->d_name, "..") != 0)
		{
			snprintf(file, sizeof(file),
			    "%s/%s", pathname, d->d_name);
			if (stat(file, &s) != 0) {
				retval = false;
				break;
			}
			if (S_ISDIR(s.st_mode)) {
				if (!rm_dir(file, true))
				{
					retval = false;
					break;
				}
			} else {
				if (unlink(file)) {
					retval = false;
					break;
				}
			}
		}
	}
	closedir(dp);

	if (!retval)
		return false;

	if (top && rmdir(pathname) != 0)
		return false;

	return true;
}

/* Other systems may need this at some point, but for now it's Linux only */
#ifdef __linux__
static bool
file_regex(const char *file, const char *regex)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	regex_t re;
	bool retval = true;
	int result;

	if (!(fp = fopen(file, "r")))
		return false;

	if ((result = regcomp(&re, regex, REG_EXTENDED | REG_NOSUB)) != 0) {
		fclose(fp);
		line = xmalloc(sizeof(char) * BUFSIZ);
		regerror(result, &re, line, BUFSIZ);
		fprintf(stderr, "file_regex: %s", line);
		free(line);
		return false;
	}

	while ((rc_getline(&line, &len, fp))) {
		char *str = line;
		/* some /proc files have \0 separated content so we have to
		   loop through the 'line' */
		do {
			if (regexec(&re, str, 0, NULL, 0) == 0)
				goto found;
			str += strlen(str) + 1;
			/* len is the size of allocated buffer and we don't
			   want call regexec BUFSIZE times. find next str */
			while (str < line + len && *str == '\0')
				str++;
		} while (str < line + len);
	}
	retval = false;
found:
	fclose(fp);
	free(line);
	regfree(&re);

	return retval;
}
#endif


static const char *
get_systype(void)
{
	char *systype = rc_conf_value("rc_sys");
	if (systype) {
		char *s = systype;
		/* Convert to uppercase */
		while (s && *s) {
			if (islower((unsigned char) *s))
				*s = toupper((unsigned char) *s);
			s++;
		}
	}
	return systype;
}

static const char *
detect_prefix(const char *systype)
{
#ifdef PREFIX
	return RC_SYS_PREFIX;
#else
	if (systype) {
		if (strcmp(systype, RC_SYS_NONE) == 0)
			return NULL;
		if (strcmp(systype, RC_SYS_PREFIX) == 0)
			return RC_SYS_PREFIX;
	}

	return NULL;
#endif
}

static const char *
detect_container(const char *systype _unused)
{
#ifdef __FreeBSD__
	if (systype) {
		if (strcmp(systype, RC_SYS_NONE) == 0)
		       return NULL;
		if (strcmp(systype, RC_SYS_JAIL) == 0)
			return RC_SYS_JAIL;
	}

	int jailed = 0;
	size_t len = sizeof(jailed);

	if (sysctlbyname("security.jail.jailed", &jailed, &len, NULL, 0) == 0)
		if (jailed == 1)
			return RC_SYS_JAIL;
#endif

#ifdef __linux__
	if (systype) {
		if (strcmp(systype, RC_SYS_NONE) == 0)
			return NULL;
		if (strcmp(systype, RC_SYS_UML) == 0)
			return RC_SYS_UML;
		if (strcmp(systype, RC_SYS_VSERVER) == 0)
			return RC_SYS_VSERVER;
		if (strcmp(systype, RC_SYS_OPENVZ) == 0)
			return RC_SYS_OPENVZ;
		if (strcmp(systype, RC_SYS_LXC) == 0)
			return RC_SYS_LXC;
		if (strcmp(systype, RC_SYS_RKT) == 0)
				return RC_SYS_RKT;
		if (strcmp(systype, RC_SYS_SYSTEMD_NSPAWN) == 0)
				return RC_SYS_SYSTEMD_NSPAWN;
		if (strcmp(systype, RC_SYS_DOCKER) == 0)
				return RC_SYS_DOCKER;
	}
	if (file_regex("/proc/cpuinfo", "UML"))
		return RC_SYS_UML;
	else if (file_regex("/proc/self/status",
		"(s_context|VxID):[[:space:]]*[1-9]"))
		return RC_SYS_VSERVER;
	else if (exists("/proc/vz/veinfo") && !exists("/proc/vz/version"))
		return RC_SYS_OPENVZ;
	else if (file_regex("/proc/self/status",
		"envID:[[:space:]]*[1-9]"))
		return RC_SYS_OPENVZ; /* old test */
	else if (file_regex("/proc/1/environ", "container=lxc"))
		return RC_SYS_LXC;
	else if (file_regex("/proc/1/environ", "container=rkt"))
		return RC_SYS_RKT;
	else if (file_regex("/proc/1/environ", "container=systemd-nspawn"))
		return RC_SYS_SYSTEMD_NSPAWN;
	else if (exists("/.dockerenv"))
		return RC_SYS_DOCKER;
	/* old test, I'm not sure when this was valid. */
	else if (file_regex("/proc/1/environ", "container=docker"))
		return RC_SYS_DOCKER;
#endif

	return NULL;
}

static const char *
detect_vm(const char *systype _unused)
{
#ifdef __NetBSD__
	if (systype) {
		if (strcmp(systype, RC_SYS_NONE) == 0)
			return NULL;
		if (strcmp(systype, RC_SYS_XEN0) == 0)
			return RC_SYS_XEN0;
		if (strcmp(systype, RC_SYS_XENU) == 0)
			return RC_SYS_XENU;
	}
	if (exists("/kern/xen/privcmd"))
		return RC_SYS_XEN0;
	if (exists("/kern/xen"))
		return RC_SYS_XENU;
#endif

#ifdef __linux__
	if (systype) {
		if (strcmp(systype, RC_SYS_NONE) == 0)
			return NULL;
		if (strcmp(systype, RC_SYS_XEN0) == 0)
			return RC_SYS_XEN0;
		if (strcmp(systype, RC_SYS_XENU) == 0)
			return RC_SYS_XENU;
	}
	if (exists("/proc/xen")) {
		if (file_regex("/proc/xen/capabilities", "control_d"))
			return RC_SYS_XEN0;
		return RC_SYS_XENU;
	}
#endif

	return NULL;
}

const char *
rc_sys(void)
{
	const char *systype;
	const char *sys;

	systype = get_systype();
	sys = detect_prefix(systype);
	if (!sys) {
		sys = detect_container(systype);
		if (!sys) {
			sys = detect_vm(systype);
		}
	}

	return sys;
}
librc_hidden_def(rc_sys)

static const char *
rc_parse_service_state(RC_SERVICE state)
{
	int i;

	for (i = 0; rc_service_state_names[i].name; i++) {
		if (rc_service_state_names[i].state == state)
			return rc_service_state_names[i].name;
	}
	return NULL;
}

/* Returns a list of all the chained runlevels used by the
 * specified runlevel in dependency order, including the
 * specified runlevel. */
static void
get_runlevel_chain(const char *runlevel, RC_STRINGLIST *level_list, RC_STRINGLIST *ancestor_list)
{
	char path[PATH_MAX];
	RC_STRINGLIST *dirs;
	RC_STRING *d, *parent;
	const char *nextlevel;

	/*
	 * If we haven't been passed a runlevel or a level list, or
	 * if the passed runlevel doesn't exist then we're done already!
	 */
	if (!runlevel || !level_list || !rc_runlevel_exists(runlevel))
		return;

	/*
	 * We want to add this runlevel to the list but if
	 * it is already in the list it needs to go at the
	 * end again.
	 */
	if (rc_stringlist_find(level_list, runlevel))
		rc_stringlist_delete(level_list, runlevel);
	rc_stringlist_add(level_list, runlevel);

	/*
	 * We can now do exactly the above procedure for our chained
	 * runlevels.
	 */
	snprintf(path, sizeof(path), "%s/%s", RC_RUNLEVELDIR, runlevel);
	dirs = ls_dir(path, LS_DIR);
	TAILQ_FOREACH(d, dirs, entries) {
		nextlevel = d->value;

		/* Check for loop */
		if (rc_stringlist_find(ancestor_list, nextlevel)) {
			fprintf(stderr, "Loop detected in stacked runlevels attempting to enter runlevel %s!\n",
			    nextlevel);
			fprintf(stderr, "Ancestors:\n");
			TAILQ_FOREACH(parent, ancestor_list, entries)
				fprintf(stderr, "\t%s\n", parent->value);
			exit(1);
		}

		/* Add new ancestor */
		rc_stringlist_add(ancestor_list, nextlevel);

		get_runlevel_chain(nextlevel, level_list, ancestor_list);

		rc_stringlist_delete(ancestor_list, nextlevel);
	}
	rc_stringlist_free(dirs);
}

bool
rc_runlevel_starting(void)
{
	return exists(RC_STARTING);
}
librc_hidden_def(rc_runlevel_starting)

bool
rc_runlevel_stopping(void)
{
	return exists(RC_STOPPING);
}
librc_hidden_def(rc_runlevel_stopping)

RC_STRINGLIST *rc_runlevel_list(void)
{
	return ls_dir(RC_RUNLEVELDIR, LS_DIR);
}
librc_hidden_def(rc_runlevel_list)

char *
rc_runlevel_get(void)
{
	FILE *fp;
	char *runlevel = NULL;
	size_t i;

	if ((fp = fopen(RC_RUNLEVEL, "r"))) {
		runlevel = xmalloc(sizeof(char) * PATH_MAX);
		if (fgets(runlevel, PATH_MAX, fp)) {
			i = strlen(runlevel) - 1;
			if (runlevel[i] == '\n')
				runlevel[i] = 0;
		} else
			*runlevel = '\0';
		fclose(fp);
	}

	if (!runlevel || !*runlevel) {
		free(runlevel);
		runlevel = xstrdup(RC_LEVEL_SYSINIT);
	}

	return runlevel;
}
librc_hidden_def(rc_runlevel_get)

bool
rc_runlevel_set(const char *runlevel)
{
	FILE *fp = fopen(RC_RUNLEVEL, "w");

	if (!fp)
		return false;
	fprintf(fp, "%s", runlevel);
	fclose(fp);
	return true;
}
librc_hidden_def(rc_runlevel_set)

bool
rc_runlevel_exists(const char *runlevel)
{
	char path[PATH_MAX];
	struct stat buf;

	if (!runlevel || strcmp(runlevel, ".") == 0 || strcmp(runlevel, "..") == 0)
		return false;
	snprintf(path, sizeof(path), "%s/%s", RC_RUNLEVELDIR, runlevel);
	if (stat(path, &buf) == 0 && S_ISDIR(buf.st_mode))
		return true;
	return false;
}
librc_hidden_def(rc_runlevel_exists)

bool
rc_runlevel_stack(const char *dst, const char *src)
{
	char d[PATH_MAX], s[PATH_MAX];

	if (!rc_runlevel_exists(dst) || !rc_runlevel_exists(src))
		return false;
	snprintf(s, sizeof(s), "../%s", src);
	snprintf(d, sizeof(s), "%s/%s/%s", RC_RUNLEVELDIR, dst, src);
	return (symlink(s, d) == 0 ? true : false);
}
librc_hidden_def(rc_runlevel_stack)

bool
rc_runlevel_unstack(const char *dst, const char *src)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s/%s", RC_RUNLEVELDIR, dst, src);
	return (unlink(path) == 0 ? true : false);
}
librc_hidden_def(rc_runlevel_unstack)

RC_STRINGLIST *
rc_runlevel_stacks(const char *runlevel)
{
	RC_STRINGLIST *stack, *ancestor_list;
	stack = rc_stringlist_new();
	ancestor_list = rc_stringlist_new();
	rc_stringlist_add(ancestor_list, runlevel);
	get_runlevel_chain(runlevel, stack, ancestor_list);
	rc_stringlist_free(ancestor_list);
	return stack;
}
librc_hidden_def(rc_runlevel_stacks)

/* Resolve a service name to its full path */
char *
rc_service_resolve(const char *service)
{
	char buffer[PATH_MAX];
	char file[PATH_MAX];
	int r;
	struct stat buf;

	if (!service)
		return NULL;

	if (service[0] == '/')
		return xstrdup(service);

	/* First check started services */
	snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s", "started", service);
	if (lstat(file, &buf) || ! S_ISLNK(buf.st_mode)) {
		snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s",
		    "inactive", service);
		if (lstat(file, &buf) || ! S_ISLNK(buf.st_mode))
			*file = '\0';
	}

	if (*file) {
		memset(buffer, 0, sizeof(buffer));
		r = readlink(file, buffer, sizeof(buffer));
		if (r > 0)
			return xstrdup(buffer);
	}

#ifdef RC_LOCAL_INITDIR
	/* Nope, so lets see if the user has written it */
	snprintf(file, sizeof(file), RC_LOCAL_INITDIR "/%s", service);
	if (stat(file, &buf) == 0)
		return xstrdup(file);
#endif

	/* System scripts take precedence over 3rd party ones */
	snprintf(file, sizeof(file), RC_INITDIR "/%s", service);
	if (stat(file, &buf) == 0)
		return xstrdup(file);

#ifdef RC_PKG_INITDIR
	/* Check RC_PKG_INITDIR */
	snprintf(file, sizeof(file), RC_PKG_INITDIR "/%s", service);
	if (stat(file, &buf) == 0)
		return xstrdup(file);
#endif

	return NULL;
}
librc_hidden_def(rc_service_resolve)

bool
rc_service_exists(const char *service)
{
	char *file;
	bool retval = false;
	size_t len;
	struct stat buf;

	if (!service) {
		errno = EINVAL;
		return false;
	}

	len = strlen(service);

	/* .sh files are not init scripts */
	if (len > 2 && service[len - 3] == '.' &&
	    service[len - 2] == 's' &&
	    service[len - 1] == 'h') {
		errno = EINVAL;
		return false;
	}

	if (!(file = rc_service_resolve(service))) {
		errno = ENOENT;
		return false;
	}

	if (stat(file, &buf) == 0) {
		if (buf.st_mode & S_IXUGO)
			retval = true;
		else
			errno = ENOEXEC;
	}
	free(file);
	return retval;
}
librc_hidden_def(rc_service_exists)

#define OPTSTR \
". '%s'; echo $extra_commands $extra_started_commands $extra_stopped_commands"

RC_STRINGLIST *
rc_service_extra_commands(const char *service)
{
	char *svc;
	char *cmd = NULL;
	char *buffer = NULL;
	size_t len = 0;
	RC_STRINGLIST *commands = NULL;
	char *token;
	char *p;
	FILE *fp;
	size_t l;

	if (!(svc = rc_service_resolve(service)))
		return NULL;

	l = strlen(OPTSTR) + strlen(svc) + 1;
	cmd = xmalloc(sizeof(char) * l);
	snprintf(cmd, l, OPTSTR, svc);
	free(svc);

	if ((fp = popen(cmd, "r"))) {
		rc_getline(&buffer, &len, fp);
		p = buffer;
		commands = rc_stringlist_new();

		while ((token = strsep(&p, " ")))
			if (token[0] != '\0')
				rc_stringlist_add(commands, token);

		pclose(fp);
		free(buffer);
	}

	free(cmd);
	return commands;
}
librc_hidden_def(rc_service_extra_commands)

#define DESCSTR ". '%s'; echo \"${description%s%s}\""
char *
rc_service_description(const char *service, const char *option)
{
	char *svc;
	char *cmd;
	char *desc = NULL;
	size_t len = 0;
	FILE *fp;
	size_t l;

	if (!(svc = rc_service_resolve(service)))
		return NULL;

	if (!option)
		option = "";

	l = strlen(DESCSTR) + strlen(svc) + strlen(option) + 2;
	cmd = xmalloc(sizeof(char) * l);
	snprintf(cmd, l, DESCSTR, svc, *option ? "_" : "", option);
	free(svc);
	if ((fp = popen(cmd, "r"))) {
		rc_getline(&desc, &len, fp);
		pclose(fp);
	}
	free(cmd);
	return desc;
}
librc_hidden_def(rc_service_description)

bool
rc_service_in_runlevel(const char *service, const char *runlevel)
{
	char file[PATH_MAX];

	snprintf(file, sizeof(file), RC_RUNLEVELDIR "/%s/%s",
	    runlevel, basename_c(service));
	return exists(file);
}
librc_hidden_def(rc_service_in_runlevel)

bool
rc_service_mark(const char *service, const RC_SERVICE state)
{
	char file[PATH_MAX];
	int i = 0;
	int skip_state = -1;
	const char *base;
	char *init = rc_service_resolve(service);
	bool skip_wasinactive = false;
	int s;
	char was[PATH_MAX];
	RC_STRINGLIST *dirs;
	RC_STRING *dir;
	int serrno;

	if (!init)
		return false;

	base = basename_c(service);
	if (state != RC_SERVICE_STOPPED) {
		if (!exists(init)) {
			free(init);
			return false;
		}

		snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s",
		    rc_parse_service_state(state), base);
		if (exists(file))
			unlink(file);
		i = symlink(init, file);
		if (i != 0) {
			free(init);
			return false;
		}
		skip_state = state;
	}

	if (state == RC_SERVICE_HOTPLUGGED || state == RC_SERVICE_FAILED) {
		free(init);
		return true;
	}

	/* Remove any old states now */
	for (i = 0; rc_service_state_names[i].name; i++) {
		s = rc_service_state_names[i].state;

		if ((s != skip_state &&
			s != RC_SERVICE_STOPPED &&
			s != RC_SERVICE_HOTPLUGGED &&
			s != RC_SERVICE_SCHEDULED) &&
		    (! skip_wasinactive || s != RC_SERVICE_WASINACTIVE))
		{
			snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s",
			    rc_service_state_names[i].name, base);
			if (exists(file)) {
				if ((state == RC_SERVICE_STARTING ||
					state == RC_SERVICE_STOPPING) &&
				    s == RC_SERVICE_INACTIVE)
				{
					snprintf(was, sizeof(was),
					    RC_SVCDIR "/%s/%s",
					    rc_parse_service_state(RC_SERVICE_WASINACTIVE),
					    base);
					if (symlink(init, was) == -1)
						return false;
					skip_wasinactive = true;
				}
				if (unlink(file) == -1) {
					free(init);
					return false;
				}
			}
		}
	}

	/* Remove the exclusive state if we're inactive */
	if (state == RC_SERVICE_STARTED ||
	    state == RC_SERVICE_STOPPED ||
	    state == RC_SERVICE_INACTIVE)
	{
		snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s",
		    "exclusive", base);
		unlink(file);
	}

	/* Remove any options and daemons the service may have stored */
	if (state == RC_SERVICE_STOPPED) {
		snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s",
		    "options", base);
		rm_dir(file, true);

		snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s",
		    "daemons", base);
		rm_dir(file, true);

		rc_service_schedule_clear(service);
	}

	/* These are final states, so remove us from scheduled */
	if (state == RC_SERVICE_STARTED || state == RC_SERVICE_STOPPED) {
		snprintf(file, sizeof(file), RC_SVCDIR "/%s", "scheduled");
		dirs = ls_dir(file, 0);
		TAILQ_FOREACH(dir, dirs, entries) {
			snprintf(was, sizeof(was), "%s/%s/%s",
			    file, dir->value, base);
			unlink(was);

			/* Try and remove the dir; we don't care about errors */
			snprintf(was, sizeof(was), "%s/%s", file, dir->value);
			serrno = errno;
			rmdir(was);
			errno = serrno;
		}
		rc_stringlist_free(dirs);
	}
	free(init);
	return true;
}
librc_hidden_def(rc_service_mark)

RC_SERVICE
rc_service_state(const char *service)
{
	int i;
	int state = RC_SERVICE_STOPPED;
	char file[PATH_MAX];
	RC_STRINGLIST *dirs;
	RC_STRING *dir;
	const char *base = basename_c(service);

	for (i = 0; rc_service_state_names[i].name; i++) {
		snprintf(file, sizeof(file), RC_SVCDIR "/%s/%s",
		    rc_service_state_names[i].name, base);
		if (exists(file)) {
			if (rc_service_state_names[i].state <= 0x10)
				state = rc_service_state_names[i].state;
			else
				state |= rc_service_state_names[i].state;
		}
	}

	if (state & RC_SERVICE_STOPPED) {
		dirs = ls_dir(RC_SVCDIR "/scheduled", 0);
		TAILQ_FOREACH(dir, dirs, entries) {
			snprintf(file, sizeof(file),
			    RC_SVCDIR "/scheduled/%s/%s",
			    dir->value, service);
			if (exists(file)) {
				state |= RC_SERVICE_SCHEDULED;
				break;
			}
		}
		rc_stringlist_free(dirs);
	}

	return state;
}
librc_hidden_def(rc_service_state)

char *
rc_service_value_get(const char *service, const char *option)
{
	char *buffer = NULL;
	size_t len = 0;
	char file[PATH_MAX];

	snprintf(file, sizeof(file), RC_SVCDIR "/options/%s/%s",
	    service, option);
	rc_getfile(file, &buffer, &len);

	return buffer;
}
librc_hidden_def(rc_service_value_get)

bool
rc_service_value_set(const char *service, const char *option,
    const char *value)
{
	FILE *fp;
	char file[PATH_MAX];
	char *p = file;

	p += snprintf(file, sizeof(file), RC_SVCDIR "/options/%s", service);
	if (mkdir(file, 0755) != 0 && errno != EEXIST)
		return false;

	snprintf(p, sizeof(file) - (p - file), "/%s", option);
	if (value) {
		if (!(fp = fopen(file, "w")))
			return false;
		fprintf(fp, "%s", value);
		fclose(fp);
	} else {
		unlink(file);
	}
		return true;
}
librc_hidden_def(rc_service_value_set)


bool
rc_service_schedule_start(const char *service, const char *service_to_start)
{
	char file[PATH_MAX];
	char *p = file;
	char *init;
	bool retval;

	/* service may be a provided service, like net */
	if (! service || ! rc_service_exists(service_to_start))
		return false;

	p += snprintf(file, sizeof(file), RC_SVCDIR "/scheduled/%s",
	    basename_c(service));
	if (mkdir(file, 0755) != 0 && errno != EEXIST)
		return false;

	init = rc_service_resolve(service_to_start);
	snprintf(p, sizeof(file) - (p - file),
	    "/%s", basename_c(service_to_start));
	retval = (exists(file) || symlink(init, file) == 0);
	free(init);
	return retval;
}
librc_hidden_def(rc_service_schedule_start)

bool
rc_service_schedule_clear(const char *service)
{
	char dir[PATH_MAX];

	snprintf(dir, sizeof(dir), RC_SVCDIR "/scheduled/%s",
	    basename_c(service));
	if (!rm_dir(dir, true) && errno == ENOENT)
		return true;
	return false;
}
librc_hidden_def(rc_service_schedule_clear)

RC_STRINGLIST *
rc_services_in_runlevel(const char *runlevel)
{
	char dir[PATH_MAX];
	RC_STRINGLIST *list = NULL;

	if (!runlevel) {
#ifdef RC_PKG_INITDIR
		RC_STRINGLIST *pkg = ls_dir(RC_PKG_INITDIR, LS_INITD);
#endif
#ifdef RC_LOCAL_INITDIR
		RC_STRINGLIST *local = ls_dir(RC_LOCAL_INITDIR, LS_INITD);
#endif

		list = ls_dir(RC_INITDIR, LS_INITD);

#ifdef RC_PKG_INITDIR
		TAILQ_CONCAT(list, pkg, entries);
		free(pkg);
#endif
#ifdef RC_LOCAL_INITDIR
		TAILQ_CONCAT(list, local, entries);
		free(local);
#endif
		return list;
	}

	/* These special levels never contain any services */
	if (strcmp(runlevel, RC_LEVEL_SINGLE) != 0) {
		snprintf(dir, sizeof(dir), RC_RUNLEVELDIR "/%s", runlevel);
		list = ls_dir(dir, LS_INITD);
	}
	if (!list)
		list = rc_stringlist_new();
	return list;
}
librc_hidden_def(rc_services_in_runlevel)

RC_STRINGLIST *
rc_services_in_runlevel_stacked(const char *runlevel)
{
	RC_STRINGLIST *list, *stacks, *sl;
	RC_STRING *stack;

	list = rc_services_in_runlevel(runlevel);
	stacks = rc_runlevel_stacks(runlevel);
	TAILQ_FOREACH(stack, stacks, entries) {
		sl = rc_services_in_runlevel(stack->value);
		TAILQ_CONCAT(list, sl, entries);
		free(sl);
	}
	return list;
}
librc_hidden_def(rc_services_in_runlevel_stacked)

RC_STRINGLIST *
rc_services_in_state(RC_SERVICE state)
{
	RC_STRINGLIST *services;
	RC_STRINGLIST *list;
	RC_STRINGLIST *dirs;
	RC_STRING *d;
	char dir[PATH_MAX];
	char *p = dir;

	p += snprintf(dir, sizeof(dir), RC_SVCDIR "/%s",
	    rc_parse_service_state(state));

	if (state != RC_SERVICE_SCHEDULED)
		return ls_dir(dir, LS_INITD);

	dirs = ls_dir(dir, 0);
	list = rc_stringlist_new();
	if (! dirs)
		return list;

	TAILQ_FOREACH(d, dirs, entries) {
		snprintf(p, sizeof(dir) - (p - dir), "/%s", d->value);
		services = ls_dir(dir, LS_INITD);
		if (services) {
			TAILQ_CONCAT(list, services, entries);
			free(services);
		}
	}
	rc_stringlist_free(dirs);
	return list;
}
librc_hidden_def(rc_services_in_state)

bool
rc_service_add(const char *runlevel, const char *service)
{
	bool retval;
	char *init;
	char file[PATH_MAX];
	char path[MAXPATHLEN] = { '\0' };
	char *p = NULL;
	char binit[PATH_MAX];
	char *i;

	if (!rc_runlevel_exists(runlevel)) {
		errno = ENOENT;
		return false;
	}

	if (rc_service_in_runlevel(service, runlevel)) {
		errno = EEXIST;
		return false;
	}

	i = init = rc_service_resolve(service);
	snprintf(file, sizeof(file), RC_RUNLEVELDIR "/%s/%s",
	    runlevel, basename_c(service));

	/* We need to ensure that only things in /etc/init.d are added
	 * to the boot runlevel */
	if (strcmp(runlevel, RC_LEVEL_BOOT) == 0) {
		p = realpath(dirname(init), path);
		if (!*p) {
			free(init);
			return false;
		}
		if (strcmp(path, RC_INITDIR) != 0) {
			free(init);
			errno = EPERM;
			return false;
		}
		snprintf(binit, sizeof(binit), RC_INITDIR "/%s", service);
		i = binit;
	}

	retval = (symlink(i, file) == 0);
	free(init);
	return retval;
}
librc_hidden_def(rc_service_add)

bool
rc_service_delete(const char *runlevel, const char *service)
{
	char file[PATH_MAX];

	snprintf(file, sizeof(file), RC_RUNLEVELDIR "/%s/%s",
	    runlevel, basename_c(service));
	if (unlink(file) == 0)
		return true;
	return false;
}
librc_hidden_def(rc_service_delete)

RC_STRINGLIST *
rc_services_scheduled_by(const char *service)
{
	RC_STRINGLIST *dirs = ls_dir(RC_SVCDIR "/scheduled", 0);
	RC_STRINGLIST *list = rc_stringlist_new();
	RC_STRING *dir;
	char file[PATH_MAX];

	TAILQ_FOREACH(dir, dirs, entries) {
		snprintf(file, sizeof(file), RC_SVCDIR "/scheduled/%s/%s",
		    dir->value, service);
		if (exists(file))
			rc_stringlist_add(list, file);
	}
	rc_stringlist_free(dirs);
	return list;
}
librc_hidden_def(rc_services_scheduled_by)

RC_STRINGLIST *
rc_services_scheduled(const char *service)
{
	char dir[PATH_MAX];

	snprintf(dir, sizeof(dir), RC_SVCDIR "/scheduled/%s",
	    basename_c(service));
	return ls_dir(dir, LS_INITD);
}
librc_hidden_def(rc_services_scheduled)
