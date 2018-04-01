/*
 * rc-misc.c
 * rc misc functions
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

#include <fnmatch.h>

#include "queue.h"
#include "librc.h"
#include "helpers.h"

bool
rc_yesno(const char *value)
{
	if (!value) {
		errno = ENOENT;
		return false;
	}

	if (strcasecmp(value, "yes") == 0 ||
	    strcasecmp(value, "y") == 0 ||
	    strcasecmp(value, "true") == 0 ||
	    strcasecmp(value, "1") == 0)
		return true;

	if (strcasecmp(value, "no") != 0 &&
	    strcasecmp(value, "n") != 0 &&
	    strcasecmp(value, "false") != 0 &&
	    strcasecmp(value, "0") != 0)
		errno = EINVAL;

	return false;
}
librc_hidden_def(rc_yesno)


/**
 * Read the entire @file into the buffer and set @len to the
 * size of the buffer when finished. For C strings, this will
 * be strlen(buffer) + 1.
 * Don't forget to free the buffer afterwards!
 */
bool
rc_getfile(const char *file, char **buffer, size_t *len)
{
	bool ret = false;
	FILE *fp;
	int fd;
	struct stat st;
	size_t done, left;

	fp = fopen(file, "re");
	if (!fp)
		return false;

	/* assume fileno() never fails */
	fd = fileno(fp);

	if (fstat(fd, &st))
		goto finished;

	left = st.st_size;
	*len = left + 1; /* NUL terminator */
	*buffer = xrealloc(*buffer, *len);
	while (left) {
		done = fread(*buffer, sizeof(*buffer[0]), left, fp);
		if (done == 0 && ferror(fp))
			goto finished;
		left -= done;
	}
	ret = true;

 finished:
	if (!ret) {
		free(*buffer);
		*len = 0;
	} else
		(*buffer)[*len - 1] = '\0';
	fclose(fp);
	return ret;
}
librc_hidden_def(rc_getfile)

ssize_t
rc_getline(char **line, size_t *len, FILE *fp)
{
	char *p;
	size_t last = 0;

	while (!feof(fp)) {
		if (*line == NULL || last != 0) {
			*len += BUFSIZ;
			*line = xrealloc(*line, *len);
		}
		p = *line + last;
		memset(p, 0, BUFSIZ);
		if (fgets(p, BUFSIZ, fp) == NULL)
			break;
		last += strlen(p);
		if (last && (*line)[last - 1] == '\n') {
			(*line)[last - 1] = '\0';
			break;
		}
	}
	return last;
}
librc_hidden_def(rc_getline)

char *
rc_proc_getent(const char *ent _unused)
{
#ifdef __linux__
	FILE *fp;
	char *proc, *p, *value = NULL;
	size_t i, len;

	if (!exists("/proc/cmdline"))
		return NULL;

	if (!(fp = fopen("/proc/cmdline", "r")))
		return NULL;

	proc = NULL;
	i = 0;
	if (rc_getline(&proc, &i, fp) == -1 || proc == NULL)
		return NULL;

	if (proc != NULL) {
		len = strlen(ent);

		while ((p = strsep(&proc, " "))) {
			if (strncmp(ent, p, len) == 0 && (p[len] == '\0' || p[len] == ' ' || p[len] == '=')) {
				p += len;

				if (*p == '=')
					p++;

				value = xstrdup(p);
			}
		}
	}

	if (!value)
		errno = ENOENT;

	fclose(fp);
	free(proc);

	return value;
#else
	return NULL;
#endif
}
librc_hidden_def(rc_proc_getent)

RC_STRINGLIST *
rc_config_list(const char *file)
{
	FILE *fp;
	char *buffer = NULL;
	size_t len = 0;
	char *p;
	char *token;
	RC_STRINGLIST *list = rc_stringlist_new();

	if (!(fp = fopen(file, "r")))
		return list;

	while ((rc_getline(&buffer, &len, fp))) {
		p = buffer;
		/* Strip leading spaces/tabs */
		while ((*p == ' ') || (*p == '\t'))
			p++;

		/* Get entry - we do not want comments */
		token = strsep(&p, "#");
		if (token && (strlen(token) > 1)) {
			/* If not variable assignment then skip */
			if (strchr(token, '=')) {
				/* Stip the newline if present */
				if (token[strlen(token) - 1] == '\n')
					token[strlen(token) - 1] = 0;

				rc_stringlist_add(list, token);
			}
		}
	}
	fclose(fp);
	free(buffer);

	return list;
}
librc_hidden_def(rc_config_list)

static void rc_config_set_value(RC_STRINGLIST *config, char *value)
{
	RC_STRING *cline;
	char *entry;
	size_t i = 0;
	char *newline;
	char *p = value;
	bool replaced;
	char *token;

	if (! p)
		return;
	if (strncmp(p, "export ", 7) == 0)
		p += 7;
	if (! (token = strsep(&p, "=")))
		return;

	entry = xstrdup(token);
	/* Preserve shell coloring */
	if (*p == '$')
		token = value;
	else
		do {
			/* Bash variables are usually quoted */
			token = strsep(&p, "\"\'");
		} while (token && *token == '\0');

	/* Drop a newline if that's all we have */
	if (token) {
		i = strlen(token) - 1;
		if (token[i] == '\n')
			token[i] = 0;

		i = strlen(entry) + strlen(token) + 2;
		newline = xmalloc(sizeof(char) * i);
		snprintf(newline, i, "%s=%s", entry, token);
	} else {
		i = strlen(entry) + 2;
		newline = xmalloc(sizeof(char) * i);
		snprintf(newline, i, "%s=", entry);
	}

	replaced = false;
	/* In shells the last item takes precedence, so we need to remove
	   any prior values we may already have */
	TAILQ_FOREACH(cline, config, entries) {
		i = strlen(entry);
		if (strncmp(entry, cline->value, i) == 0 && cline->value[i] == '=') {
			/* We have a match now - to save time we directly replace it */
			free(cline->value);
			cline->value = newline;
			replaced = true;
			break;
		}
	}

	if (!replaced) {
		rc_stringlist_add(config, newline);
		free(newline);
	}
	free(entry);
}

/*
 * Override some specific rc.conf options on the kernel command line.
 * I only know how to do this in Linux, so if someone wants to supply
 * a patch for this on *BSD or tell me how to write the code to do this,
 * any suggestions are welcome.
 */
static RC_STRINGLIST *rc_config_kcl(RC_STRINGLIST *config)
{
#ifdef __linux__
	RC_STRINGLIST *overrides;
	RC_STRING *cline, *override, *config_np;
	char *tmp = NULL;
	char *value = NULL;
	size_t varlen = 0;
	size_t len = 0;

	overrides = rc_stringlist_new();

	/* A list of variables which may be overridden on the kernel command line */
	rc_stringlist_add(overrides, "rc_parallel");

	TAILQ_FOREACH(override, overrides, entries) {
		varlen = strlen(override->value);
		value = rc_proc_getent(override->value);

		/* No need to continue if there's nothing to override */
		if (!value) {
			free(value);
			continue;
		}

		if (value != NULL) {
			len = varlen + strlen(value) + 2;
			tmp = xmalloc(sizeof(char) * len);
			snprintf(tmp, len, "%s=%s", override->value, value);
		}

		/*
		 * Whenever necessary remove the old config entry first to prevent
		 * duplicates
		 */
		TAILQ_FOREACH_SAFE(cline, config, entries, config_np) {
			if (strncmp(override->value, cline->value, varlen) == 0
				&& cline->value[varlen] == '=') {
				rc_stringlist_delete(config, cline->value);
				break;
			}
		}

		/* Add the option (var/value) to the current config */
		rc_stringlist_add(config, tmp);

		free(tmp);
		free(value);
	}

	rc_stringlist_free(overrides);
#endif
	return config;
}

static RC_STRINGLIST * rc_config_directory(RC_STRINGLIST *config)
{
	DIR *dp;
	struct dirent *d;
	RC_STRINGLIST *rc_conf_d_files = rc_stringlist_new();
	RC_STRING *fname;
	RC_STRINGLIST *rc_conf_d_list;
	char path[PATH_MAX];
	RC_STRING *line;

	if ((dp = opendir(RC_CONF_D)) != NULL) {
		while ((d = readdir(dp)) != NULL) {
			if (fnmatch("*.conf", d->d_name, FNM_PATHNAME) == 0) {
				rc_stringlist_addu(rc_conf_d_files, d->d_name);
			}
		}
		closedir(dp);

		if (rc_conf_d_files) {
			rc_stringlist_sort(&rc_conf_d_files);
			TAILQ_FOREACH(fname, rc_conf_d_files, entries) {
				if (! fname->value)
					continue;
				sprintf(path, "%s/%s", RC_CONF_D, fname->value);
				rc_conf_d_list = rc_config_list(path);
				TAILQ_FOREACH(line, rc_conf_d_list, entries)
					if (line->value)
						rc_config_set_value(config, line->value);
				rc_stringlist_free(rc_conf_d_list);
			}
			rc_stringlist_free(rc_conf_d_files);
		}
	}
	return config;
}

RC_STRINGLIST *
rc_config_load(const char *file)
{
	RC_STRINGLIST *list;
	RC_STRINGLIST *config;
	RC_STRING *line;

	list = rc_config_list(file);
	config = rc_stringlist_new();
	TAILQ_FOREACH(line, list, entries) {
		rc_config_set_value(config, line->value);
	}
	rc_stringlist_free(list);

	return config;
}
librc_hidden_def(rc_config_load)

char *
rc_config_value(RC_STRINGLIST *list, const char *entry)
{
	RC_STRING *line;
	char *p;
	size_t len;

	len = strlen(entry);
	TAILQ_FOREACH(line, list, entries) {
		p = strchr(line->value, '=');
		if (p != NULL) {
			if (strncmp(entry, line->value, len) == 0 && line->value[len] == '=')
				return ++p;
		}
	}
	return NULL;
}
librc_hidden_def(rc_config_value)

/* Global for caching the strings loaded from rc.conf to avoid reparsing for
 * each rc_conf_value call */
static RC_STRINGLIST *rc_conf = NULL;

static void
_free_rc_conf(void)
{
	rc_stringlist_free(rc_conf);
}

char *
rc_conf_value(const char *setting)
{
	RC_STRINGLIST *old;
	RC_STRING *s;
	char *p;

	if (! rc_conf) {
		rc_conf = rc_config_load(RC_CONF);
		atexit(_free_rc_conf);

		/* Support old configs. */
		if (exists(RC_CONF_OLD)) {
			old = rc_config_load(RC_CONF_OLD);
			TAILQ_CONCAT(rc_conf, old, entries);
			free(old);
		}

		rc_conf = rc_config_directory(rc_conf);
	rc_conf = rc_config_kcl(rc_conf);

		/* Convert old uppercase to lowercase */
		TAILQ_FOREACH(s, rc_conf, entries) {
			p = s->value;
			while (p && *p && *p != '=') {
				if (isupper((unsigned char)*p))
					*p = tolower((unsigned char)*p);
				p++;
			}
		}
	}

	return rc_config_value(rc_conf, setting);
}
librc_hidden_def(rc_conf_value)
