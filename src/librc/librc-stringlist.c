/*
 * librc-strlist.h
 * String list functions to make using queue(3) a little easier.
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

#include "queue.h"
#include "librc.h"

RC_STRINGLIST *
rc_stringlist_new(void)
{
	RC_STRINGLIST *l = xmalloc(sizeof(*l));
	TAILQ_INIT(l);
	return l;
}
librc_hidden_def(rc_stringlist_new)

RC_STRING *
rc_stringlist_add(RC_STRINGLIST *list, const char *value)
{
	RC_STRING *s = xmalloc(sizeof(*s));

	s->value = xstrdup(value);
	TAILQ_INSERT_TAIL(list, s, entries);
	return s;
}
librc_hidden_def(rc_stringlist_add)

RC_STRING *
rc_stringlist_addu(RC_STRINGLIST *list, const char *value)
{
	RC_STRING *s;

	TAILQ_FOREACH(s, list, entries)
	    if (strcmp(s->value, value) == 0) {
		    errno = EEXIST;
		    return NULL;
	    }

	return rc_stringlist_add(list, value);
}
librc_hidden_def(rc_stringlist_addu)

bool
rc_stringlist_delete(RC_STRINGLIST *list, const char *value)
{
	RC_STRING *s;

	TAILQ_FOREACH(s, list, entries)
	    if (strcmp(s->value, value) == 0) {
		    TAILQ_REMOVE(list, s, entries);
		    free(s->value);
		    free(s);
		    return true;
	    }

	errno = EEXIST;
	return false;
}
librc_hidden_def(rc_stringlist_delete)

RC_STRING *
rc_stringlist_find(RC_STRINGLIST *list, const char *value)
{
	RC_STRING *s;

	if (list) {
		TAILQ_FOREACH(s, list, entries)
		    if (strcmp(s->value, value) == 0)
			    return s;
	}
	return NULL;
}
librc_hidden_def(rc_stringlist_find)

RC_STRINGLIST *
rc_stringlist_split(const char *value, const char *sep)
{
	RC_STRINGLIST *list = rc_stringlist_new();
	char *d = xstrdup(value);
	char *p = d, *token;

	while ((token = strsep(&p, sep)))
		rc_stringlist_add(list, token);
	free(d);

	return list;
}
librc_hidden_def(rc_stringlist_split)

void
rc_stringlist_sort(RC_STRINGLIST **list)
{
	RC_STRINGLIST *l = *list;
	RC_STRINGLIST *new = rc_stringlist_new();
	RC_STRING *s;
	RC_STRING *sn;
	RC_STRING *n;
	RC_STRING *last;

	TAILQ_FOREACH_SAFE(s, l, entries, sn) {
		TAILQ_REMOVE(l, s, entries);
		last = NULL;
		TAILQ_FOREACH(n, new, entries) {
			if (strcmp(s->value, n->value) < 0)
				break;
			last = n;
		}
		if (last)
			TAILQ_INSERT_AFTER(new, last, s, entries);
		else
			TAILQ_INSERT_HEAD(new, s, entries);
	}

	/* Now we've sorted the list, copy across the new head */
	free(l);
	*list = new;
}
librc_hidden_def(rc_stringlist_sort)

void
rc_stringlist_free(RC_STRINGLIST *list)
{
	RC_STRING *s1;
	RC_STRING *s2;

	if (!list)
		return;

	s1 = TAILQ_FIRST(list);
	while (s1) {
		s2 = TAILQ_NEXT(s1, entries);
		free(s1->value);
		free(s1);
		s1 = s2;
	}
	free(list);
}
librc_hidden_def(rc_stringlist_free)
