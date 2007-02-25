/*
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2006 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "udev.h"
#include "udev_rules.h"


void udev_rules_iter_init(struct udev_rules *rules)
{
	dbg("bufsize=%zi", rules->bufsize);
	rules->current = 0;
}

struct udev_rule *udev_rules_iter_next(struct udev_rules *rules)
{
	static struct udev_rule *rule;

	if (!rules)
		return NULL;

	dbg("current=%zi", rules->current);
	if (rules->current >= rules->bufsize) {
		dbg("no more rules");
		return NULL;
	}

	/* get next rule */
	rule = (struct udev_rule *) (rules->buf + rules->current);
	rules->current += sizeof(struct udev_rule) + rule->bufsize;

	return rule;
}

struct udev_rule *udev_rules_iter_label(struct udev_rules *rules, const char *label)
{
	static struct udev_rule *rule;

next:
	dbg("current=%zi", rules->current);
	if (rules->current >= rules->bufsize) {
		dbg("no more rules");
		return NULL;
	}
	rule = (struct udev_rule *) (rules->buf + rules->current);

	if (strcmp(&rule->buf[rule->label.val_off], label) != 0) {
		dbg("moving forward, looking for label '%s'", label);
		rules->current += sizeof(struct udev_rule) + rule->bufsize;
		goto next;
	}

	dbg("found label '%s'", label);
	return rule;
}

static int get_key(char **line, char **key, enum key_operation *operation, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (linepos == NULL && linepos[0] == '\0')
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]) || linepos[0] == ',')
		linepos++;

	/* get the key */
	if (linepos[0] == '\0')
		return -1;
	*key = linepos;

	while (1) {
		linepos++;
		if (linepos[0] == '\0')
			return -1;
		if (isspace(linepos[0]))
			break;
		if (linepos[0] == '=')
			break;
		if ((linepos[0] == '+') || (linepos[0] == '!') || (linepos[0] == ':'))
			if (linepos[1] == '=')
				break;
	}

	/* remember end of key */
	temp = linepos;

	/* skip whitespace after key */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/* get operation type */
	if (linepos[0] == '=' && linepos[1] == '=') {
		*operation = KEY_OP_MATCH;
		linepos += 2;
		dbg("operator=match");
	} else if (linepos[0] == '!' && linepos[1] == '=') {
		*operation = KEY_OP_NOMATCH;
		linepos += 2;
		dbg("operator=nomatch");
	} else if (linepos[0] == '+' && linepos[1] == '=') {
		*operation = KEY_OP_ADD;
		linepos += 2;
		dbg("operator=add");
	} else if (linepos[0] == '=') {
		*operation = KEY_OP_ASSIGN;
		linepos++;
		dbg("operator=assign");
	} else if (linepos[0] == ':' && linepos[1] == '=') {
		*operation = KEY_OP_ASSIGN_FINAL;
		linepos += 2;
		dbg("operator=assign_final");
	} else
		return -1;

	/* terminate key */
	temp[0] = '\0';
	dbg("key='%s'", *key);

	/* skip whitespace after operator */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/* get the value*/
	if (linepos[0] == '"')
		linepos++;
	else
		return -1;
	*value = linepos;

	temp = strchr(linepos, '"');
	if (!temp)
		return -1;
	temp[0] = '\0';
	temp++;
	dbg("value='%s'", *value);

	/* move line to next key */
	*line = temp;

	return 0;
}

/* extract possible KEY{attr} */
static char *get_key_attribute(char *str)
{
	char *pos;
	char *attr;

	attr = strchr(str, '{');
	if (attr != NULL) {
		attr++;
		pos = strchr(attr, '}');
		if (pos == NULL) {
			err("missing closing brace for format");
			return NULL;
		}
		pos[0] = '\0';
		dbg("attribute='%s'", attr);
		return attr;
	}

	return NULL;
}

static int add_rule_key(struct udev_rule *rule, struct key *key,
			enum key_operation operation, const char *value)
{
	size_t val_len = strnlen(value, PATH_SIZE);

	key->operation = operation;

	key->val_off = rule->bufsize;
	strlcpy(rule->buf + rule->bufsize, value, val_len+1);
	rule->bufsize += val_len+1;

	return 0;
}

static int add_rule_key_pair(struct udev_rule *rule, struct key_pairs *pairs,
			     enum key_operation operation, const char *key, const char *value)
{
	size_t key_len = strnlen(key, PATH_SIZE);

	if (pairs->count >= PAIRS_MAX) {
		err("skip, too many keys of the same type in a single rule");
		return -1;
	}

	add_rule_key(rule, &pairs->keys[pairs->count].key, operation, value);

	/* add the key-name of the pair */
	pairs->keys[pairs->count].key_name_off = rule->bufsize;
	strlcpy(rule->buf + rule->bufsize, key, key_len+1);
	rule->bufsize += key_len+1;

	pairs->count++;

	return 0;
}

static int add_to_rules(struct udev_rules *rules, char *line, const char *filename, unsigned int lineno)
{
	struct udev_rule *rule;
	size_t rule_size;
	int valid;
	char *linepos;
	char *attr;
	size_t padding;
	int physdev = 0;
	int retval;

	/* get all the keys */
	rule = calloc(1, sizeof (struct udev_rule) + LINE_SIZE);
	if (!rule) {
		err("malloc failed");
		return -1;
	}
	linepos = line;
	valid = 0;

	while (1) {
		char *key;
		char *value;
		enum key_operation operation = KEY_OP_UNSET;

		retval = get_key(&linepos, &key, &operation, &value);
		if (retval)
			break;

		if (strcasecmp(key, "ACTION") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid ACTION operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->action, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DEVPATH") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid DEVPATH operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->devpath, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNEL") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid KERNEL operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->kernel, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEM") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid SUBSYSTEM operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->subsystem, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVER") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid DRIVER operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->driver, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTR{", sizeof("ATTR{")-1) == 0) {
			attr = get_key_attribute(key + sizeof("ATTR")-1);
			if (attr == NULL) {
				err("error parsing ATTR attribute");
				goto invalid;
			}
			if (add_rule_key_pair(rule, &rule->attr, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNELS") == 0 ||
		    strcasecmp(key, "ID") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid KERNELS operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->kernels, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEMS") == 0 ||
		    strcasecmp(key, "BUS") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid SUBSYSTEMS operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->subsystems, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVERS") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid DRIVERS operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->drivers, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTRS{", sizeof("ATTRS{")-1) == 0 ||
		    strncasecmp(key, "SYSFS{", sizeof("SYSFS{")-1) == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid ATTRS operation");
				goto invalid;
			}
			attr = get_key_attribute(key + sizeof("ATTRS")-1);
			if (attr == NULL) {
				err("error parsing ATTRS attribute");
				goto invalid;
			}
			if (strncmp(attr, "device/", 7) == 0)
				err("the 'device' link is deprecated and will be removed from a future kernel, "
				    "please fix it in %s:%u", filename, lineno);
			else if (strchr(attr, '/') != NULL)
				err("do not reference parent sysfs directories directly, that may break with a future kernel, "
				    "please fix it in %s:%u", filename, lineno);
			if (add_rule_key_pair(rule, &rule->attrs, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ENV{", sizeof("ENV{")-1) == 0) {
			attr = get_key_attribute(key + sizeof("ENV")-1);
			if (attr == NULL) {
				err("error parsing ENV attribute");
				goto invalid;
			}
			if (strncmp(attr, "PHYSDEV", 7) == 0)
				physdev = 1;
			if (add_rule_key_pair(rule, &rule->env, operation, attr, value) != 0)
				goto invalid;
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "PROGRAM") == 0) {
			add_rule_key(rule, &rule->program, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "RESULT") == 0) {
			if (operation != KEY_OP_MATCH &&
			    operation != KEY_OP_NOMATCH) {
				err("invalid RESULT operation");
				goto invalid;
			}
			add_rule_key(rule, &rule->result, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "IMPORT", sizeof("IMPORT")-1) == 0) {
			attr = get_key_attribute(key + sizeof("IMPORT")-1);
			if (attr && strstr(attr, "program")) {
				dbg("IMPORT will be executed");
				rule->import_type  = IMPORT_PROGRAM;
			} else if (attr && strstr(attr, "file")) {
				dbg("IMPORT will be included as file");
				rule->import_type  = IMPORT_FILE;
			} else if (attr && strstr(attr, "parent")) {
				dbg("IMPORT will include the parent values");
				rule->import_type = IMPORT_PARENT;
			} else {
				/* figure it out if it is executable */
				char file[PATH_SIZE];
				char *pos;
				struct stat stats;

				strlcpy(file, value, sizeof(file));
				pos = strchr(file, ' ');
				if (pos)
					pos[0] = '\0';

				/* allow programs in /lib/udev called without the path */
				if (strchr(file, '/') == NULL) {
					strlcpy(file, "/lib/udev/", sizeof(file));
					strlcat(file, value, sizeof(file));
					pos = strchr(file, ' ');
					if (pos)
						pos[0] = '\0';
				}

				dbg("IMPORT auto mode for '%s'", file);
				if (!lstat(file, &stats) && (stats.st_mode & S_IXUSR)) {
					dbg("IMPORT is executable, will be executed (autotype)");
					rule->import_type  = IMPORT_PROGRAM;
				} else {
					dbg("IMPORT is not executable, will be included as file (autotype)");
					rule->import_type  = IMPORT_FILE;
				}
			}
			add_rule_key(rule, &rule->import, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "RUN") == 0) {
			add_rule_key(rule, &rule->run, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "WAIT_FOR_SYSFS") == 0) {
			add_rule_key(rule, &rule->wait_for_sysfs, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "LABEL") == 0) {
			add_rule_key(rule, &rule->label, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "GOTO") == 0) {
			add_rule_key(rule, &rule->goto_label, operation, value);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "NAME", sizeof("NAME")-1) == 0) {
			attr = get_key_attribute(key + sizeof("NAME")-1);
			if (attr != NULL) {
				if (strstr(attr, "all_partitions") != NULL) {
					dbg("creation of partition nodes requested");
					rule->partitions = DEFAULT_PARTITIONS_COUNT;
				}
				if (strstr(attr, "ignore_remove") != NULL) {
					dbg("remove event should be ignored");
					rule->ignore_remove = 1;
				}
			}
			if (value[0] == '\0')
				dbg("name empty, node creation supressed");
			add_rule_key(rule, &rule->name, operation, value);
			continue;
		}

		if (strcasecmp(key, "SYMLINK") == 0) {
			add_rule_key(rule, &rule->symlink, operation, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "OWNER") == 0) {
			valid = 1;
			if (rules->resolve_names && (!strchr(value, '$') && !strchr(value, '%'))) {
				char *endptr;
				strtoul(value, &endptr, 10);
				if (endptr[0] != '\0') {
					char owner[32];
					uid_t uid = lookup_user(value);
					dbg("replacing username='%s' by id=%i", value, uid);
					sprintf(owner, "%u", (unsigned int) uid);
					add_rule_key(rule, &rule->owner, operation, owner);
					continue;
				}
			}

			add_rule_key(rule, &rule->owner, operation, value);
			continue;
		}

		if (strcasecmp(key, "GROUP") == 0) {
			valid = 1;
			if (rules->resolve_names && (!strchr(value, '$') && !strchr(value, '%'))) {
				char *endptr;
				strtoul(value, &endptr, 10);
				if (endptr[0] != '\0') {
					char group[32];
					gid_t gid = lookup_group(value);
					dbg("replacing groupname='%s' by id=%i", value, gid);
					sprintf(group, "%u", (unsigned int) gid);
					add_rule_key(rule, &rule->group, operation, group);
					continue;
				}
			}

			add_rule_key(rule, &rule->group, operation, value);
			continue;
		}

		if (strcasecmp(key, "MODE") == 0) {
			rule->mode = strtol(value, NULL, 8);
			rule->mode_operation = operation;
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "OPTIONS") == 0) {
			if (strstr(value, "last_rule") != NULL) {
				dbg("last rule to be applied");
				rule->last_rule = 1;
			}
			if (strstr(value, "ignore_device") != NULL) {
				dbg("device should be ignored");
				rule->ignore_device = 1;
			}
			if (strstr(value, "ignore_remove") != NULL) {
				dbg("remove event should be ignored");
				rule->ignore_remove = 1;
			}
			if (strstr(value, "all_partitions") != NULL) {
				dbg("creation of partition nodes requested");
				rule->partitions = DEFAULT_PARTITIONS_COUNT;
			}
			valid = 1;
			continue;
		}

		err("unknown key '%s' in %s:%u", key, filename, lineno);
	}

	if (physdev && rule->wait_for_sysfs.operation == KEY_OP_UNSET)
		err("PHYSDEV* values are deprecated and will be removed from a future kernel, "
		    "please fix it in %s:%u", filename, lineno);

	/* skip line if not any valid key was found */
	if (!valid)
		goto invalid;

	/* grow buffer and add rule */
	rule_size = sizeof(struct udev_rule) + rule->bufsize;
	padding = (sizeof(size_t) - rule_size % sizeof(size_t)) % sizeof(size_t);
	dbg("add %zi padding bytes", padding);
	rule_size += padding;
	rule->bufsize += padding;

	rules->buf = realloc(rules->buf, rules->bufsize + rule_size);
	if (!rules->buf) {
		err("realloc failed");
		goto exit;
	}
	dbg("adding rule to offset %zi", rules->bufsize);
	memcpy(rules->buf + rules->bufsize, rule, rule_size);
	rules->bufsize += rule_size;
exit:
	free(rule);
	return 0;

invalid:
	free(rule);
	err("invalid rule '%s:%u'", filename, lineno);
	return -1;
}

static int parse_file(struct udev_rules *rules, const char *filename)
{
	char line[LINE_SIZE];
	char *bufline;
	unsigned int lineno;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;
	int retval = 0;

	if (file_map(filename, &buf, &bufsize) != 0) {
		err("can't open '%s' as rules file: %s", filename, strerror(errno));
		return -1;
	}
	info("reading '%s' as rules file", filename);

	/* loop through the whole file */
	cur = 0;
	lineno = 0;
	while (cur < bufsize) {
		unsigned int i, j;

		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		/* eat the whitespace */
		while ((count > 0) && isspace(bufline[0])) {
			bufline++;
			count--;
		}
		if (count == 0)
			continue;

		/* see if this is a comment */
		if (bufline[0] == COMMENT_CHARACTER)
			continue;

		if (count >= sizeof(line)) {
			err("line too long, rule skipped '%s:%u'", filename, lineno);
			continue;
		}

		/* skip backslash and newline from multiline rules */
		for (i = j = 0; i < count; i++) {
			if (bufline[i] == '\\' && bufline[i+1] == '\n')
				continue;

			line[j++] = bufline[i];
		}
		line[j] = '\0';

		dbg("read '%s'", line);
		add_to_rules(rules, line, filename, lineno);
	}

	file_unmap(buf, bufsize);
	return retval;
}

int udev_rules_init(struct udev_rules *rules, int resolve_names)
{
	struct stat stats;
	int retval;

	memset(rules, 0x00, sizeof(struct udev_rules));
	rules->resolve_names = resolve_names;

	/* parse rules file or all matching files in directory */
	if (stat(udev_rules_dir, &stats) != 0)
		return -1;

	if ((stats.st_mode & S_IFMT) != S_IFDIR) {
		dbg("parse single rules file '%s'", udev_rules_dir);
		retval = parse_file(rules, udev_rules_dir);
	} else {
		struct name_entry *name_loop, *name_tmp;
		LIST_HEAD(name_list);

		dbg("parse rules directory '%s'", udev_rules_dir);
		retval = add_matching_files(&name_list, udev_rules_dir, RULESFILE_SUFFIX);

		list_for_each_entry_safe(name_loop, name_tmp, &name_list, node) {
			if (stat(name_loop->name, &stats) == 0) {
				if (stats.st_size)
					parse_file(rules, name_loop->name);
				else
					dbg("empty rules file '%s'", name_loop->name);
			} else
				err("could not read '%s': %s", name_loop->name, strerror(errno));
			list_del(&name_loop->node);
			free(name_loop);
		}
	}

	return retval;
}

void udev_rules_cleanup(struct udev_rules *rules)
{
	if (rules->buf) {
		free(rules->buf);
		rules->buf = NULL;
	}
}
