/* 
   Unix SMB/CIFS implementation.
   Samba database functions
   Copyright (C) Andrew Tridgell              1999-2000
   Copyright (C) Paul `Rusty' Russell		   2000
   Copyright (C) Jeremy Allison			   2000
   Copyright (C) Andrew Esh                        2001

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctype.h>
#include <signal.h>
#include "tdb.h"

/* a tdb tool for manipulating a tdb database */

#define FSTRING_LEN 256
typedef char fstring[FSTRING_LEN];

typedef struct connections_key {
	pid_t pid;
	int cnum;
	fstring name;
} connections_key;

typedef struct connections_data {
	int magic;
	pid_t pid;
	int cnum;
	uid_t uid;
	gid_t gid;
	char name[24];
	char addr[24];
	char machine[128];
	time_t start;
} connections_data;

static TDB_CONTEXT *tdb;

static int print_rec(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state);

static void print_asc(unsigned char *buf,int len)
{
	int i;

	/* We're probably printing ASCII strings so don't try to display
	   the trailing NULL character. */

	if (buf[len - 1] == 0)
	        len--;

	for (i=0;i<len;i++)
		printf("%c",isprint(buf[i])?buf[i]:'.');
}

static void print_data(unsigned char *buf,int len)
{
	int i=0;
	if (len<=0) return;
	printf("[%03X] ",i);
	for (i=0;i<len;) {
		printf("%02X ",(int)buf[i]);
		i++;
		if (i%8 == 0) printf(" ");
		if (i%16 == 0) {      
			print_asc(&buf[i-16],8); printf(" ");
			print_asc(&buf[i-8],8); printf("\n");
			if (i<len) printf("[%03X] ",i);
		}
	}
	if (i%16) {
		int n;
		
		n = 16 - (i%16);
		printf(" ");
		if (n>8) printf(" ");
		while (n--) printf("   ");
		
		n = i%16;
		if (n > 8) n = 8;
		print_asc(&buf[i-(i%16)],n); printf(" ");
		n = (i%16) - n;
		if (n>0) print_asc(&buf[i-n],n); 
		printf("\n");    
	}
}

static void help(void)
{
	printf("\n"
"tdbtool: \n"
"  create    dbname     : create a database\n"
"  open      dbname     : open an existing database\n"
"  erase                : erase the database\n"
"  dump                 : dump the database as strings\n"
"  insert    key  data  : insert a record\n"
"  move      key  file  : move a record to a destination tdb\n"
"  store     key  data  : store a record (replace)\n"
"  show      key        : show a record by key\n"
"  delete    key        : delete a record by key\n"
"  list                 : print the database hash table and freelist\n"
"  free                 : print the database freelist\n"
"  1 | first            : print the first record\n"
"  n | next             : print the next record\n"
"  q | quit             : terminate\n"
"  \\n                   : repeat 'next' command\n"
"\n");
}

static void terror(char *why)
{
	printf("%s\n", why);
}

static char *get_token(int startover)
{
	static char tmp[1024];
	static char *cont = NULL;
	char *insert, *start;
	char *k = strtok(NULL, " ");

	if (!k)
	  return NULL;

	if (startover)
	  start = tmp;
	else
	  start = cont;

	strcpy(start, k);
	insert = start + strlen(start) - 1;
	while (*insert == '\\') {
	  *insert++ = ' ';
	  k = strtok(NULL, " ");
	  if (!k)
	    break;
	  strcpy(insert, k);
	  insert = start + strlen(start) - 1;
	}

	/* Get ready for next call */
	cont = start + strlen(start) + 1;
	return start;
}

static void create_tdb(void)
{
	char *tok = get_token(1);
	if (!tok) {
		help();
		return;
	}
	if (tdb) tdb_close(tdb);
	tdb = tdb_open(tok, 0, TDB_CLEAR_IF_FIRST,
		       O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (!tdb) {
		printf("Could not create %s: %s\n", tok, strerror(errno));
	}
}

static void open_tdb(void)
{
	char *tok = get_token(1);
	if (!tok) {
		help();
		return;
	}
	if (tdb) tdb_close(tdb);
	tdb = tdb_open(tok, 0, 0, O_RDWR, 0600);
	if (!tdb) {
		printf("Could not open %s: %s\n", tok, strerror(errno));
	}
}

static void insert_tdb(void)
{
	char *k = get_token(1);
	char *d = get_token(0);
	TDB_DATA key, dbuf;

	if (!k || !d) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k)+1;
	dbuf.dptr = d;
	dbuf.dsize = strlen(d)+1;

	if (tdb_store(tdb, key, dbuf, TDB_INSERT) == -1) {
		terror("insert failed");
	}
}

static void store_tdb(void)
{
	char *k = get_token(1);
	char *d = get_token(0);
	TDB_DATA key, dbuf;

	if (!k || !d) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k)+1;
	dbuf.dptr = d;
	dbuf.dsize = strlen(d)+1;

	printf("Storing key:\n");
	print_rec(tdb, key, dbuf, NULL);

	if (tdb_store(tdb, key, dbuf, TDB_REPLACE) == -1) {
		terror("store failed");
	}
}

static void show_tdb(void)
{
	char *k = get_token(1);
	TDB_DATA key, dbuf;

	if (!k) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k)+1;

	dbuf = tdb_fetch(tdb, key);
	if (!dbuf.dptr) {
		/* maybe it is non-NULL terminated key? */
		key.dsize = strlen(k); 
		dbuf = tdb_fetch(tdb, key);
		
		if ( !dbuf.dptr ) {
			terror("fetch failed");
			return;
		}
	}
	
	/* printf("%s : %*.*s\n", k, (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr); */
	print_rec(tdb, key, dbuf, NULL);
	
	free( dbuf.dptr );
	
	return;
}

static void delete_tdb(void)
{
	char *k = get_token(1);
	TDB_DATA key;

	if (!k) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k)+1;

	if (tdb_delete(tdb, key) != 0) {
		terror("delete failed");
	}
}

static void move_rec(void)
{
	char *k = get_token(1);
	char *file = get_token(0);	
	TDB_DATA key, dbuf;
	TDB_CONTEXT *dst_tdb;

	if (!k) {
		help();
		return;
	}
	
	if ( !file ) {
		terror("need destination tdb name");
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k)+1;

	dbuf = tdb_fetch(tdb, key);
	if (!dbuf.dptr) {
		/* maybe it is non-NULL terminated key? */
		key.dsize = strlen(k); 
		dbuf = tdb_fetch(tdb, key);
		
		if ( !dbuf.dptr ) {
			terror("fetch failed");
			return;
		}
	}
	
	print_rec(tdb, key, dbuf, NULL);
	
	dst_tdb = tdb_open(file, 0, 0, O_RDWR, 0600);
	if ( !dst_tdb ) {
		terror("unable to open destination tdb");
		return;
	}
	
	if ( tdb_store( dst_tdb, key, dbuf, TDB_REPLACE ) == -1 ) {
		terror("failed to move record");
	}
	else
		printf("record moved\n");
	
	tdb_close( dst_tdb );
	
	return;
}

#if 0
static int print_conn_key(TDB_DATA key)
{
	printf( "pid    =%5d   ", ((connections_key*)key.dptr)->pid);
	printf( "cnum   =%10d  ", ((connections_key*)key.dptr)->cnum);
	printf( "name   =[%s]\n", ((connections_key*)key.dptr)->name);
	return 0;
}

static int print_conn_data(TDB_DATA dbuf)
{
	printf( "pid    =%5d   ", ((connections_data*)dbuf.dptr)->pid);
	printf( "cnum   =%10d  ", ((connections_data*)dbuf.dptr)->cnum);
	printf( "name   =[%s]\n", ((connections_data*)dbuf.dptr)->name);
	
	printf( "uid    =%5d   ",  ((connections_data*)dbuf.dptr)->uid);
	printf( "addr   =[%s]\n", ((connections_data*)dbuf.dptr)->addr);
	printf( "gid    =%5d   ",  ((connections_data*)dbuf.dptr)->gid);
	printf( "machine=[%s]\n", ((connections_data*)dbuf.dptr)->machine);
	printf( "start  = %s\n",   ctime(&((connections_data*)dbuf.dptr)->start));
	return 0;
}
#endif

static int print_rec(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
#if 0
	print_conn_key(key);
	print_conn_data(dbuf);
	return 0;
#else
	printf("\nkey %d bytes\n", key.dsize);
	print_asc(key.dptr, key.dsize);
	printf("\ndata %d bytes\n", dbuf.dsize);
	print_data(dbuf.dptr, dbuf.dsize);
	return 0;
#endif
}

static int print_key(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	print_asc(key.dptr, key.dsize);
	printf("\n");
	return 0;
}

static int total_bytes;

static int traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	total_bytes += dbuf.dsize;
	return 0;
}

static void info_tdb(void)
{
	int count;
	total_bytes = 0;
	if ((count = tdb_traverse(tdb, traverse_fn, NULL) == -1))
		printf("Error = %s\n", tdb_errorstr(tdb));
	else
		printf("%d records totalling %d bytes\n", count, total_bytes);
}

static char *tdb_getline(char *prompt)
{
	static char line[1024];
	char *p;
	fputs(prompt, stdout);
	line[0] = 0;
	p = fgets(line, sizeof(line)-1, stdin);
	if (p) p = strchr(p, '\n');
	if (p) *p = 0;
	return p?line:NULL;
}

static int do_delete_fn(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf,
                     void *state)
{
    return tdb_delete(the_tdb, key);
}

static void first_record(TDB_CONTEXT *the_tdb, TDB_DATA *pkey)
{
	TDB_DATA dbuf;
	*pkey = tdb_firstkey(the_tdb);
	
	dbuf = tdb_fetch(the_tdb, *pkey);
	if (!dbuf.dptr) terror("fetch failed");
	else {
		/* printf("%s : %*.*s\n", k, (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr); */
		print_rec(the_tdb, *pkey, dbuf, NULL);
	}
}

static void next_record(TDB_CONTEXT *the_tdb, TDB_DATA *pkey)
{
	TDB_DATA dbuf;
	*pkey = tdb_nextkey(the_tdb, *pkey);
	
	dbuf = tdb_fetch(the_tdb, *pkey);
	if (!dbuf.dptr) 
		terror("fetch failed");
	else
		/* printf("%s : %*.*s\n", k, (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr); */
		print_rec(the_tdb, *pkey, dbuf, NULL);
}

int main(int argc, char *argv[])
{
    int bIterate = 0;
    char *line;
    char *tok;
	TDB_DATA iterate_kbuf;

    if (argv[1]) {
	static char tmp[1024];
        sprintf(tmp, "open %s", argv[1]);
        tok=strtok(tmp," ");
        open_tdb();
    }

    while ((line = tdb_getline("tdb> "))) {

        /* Shell command */
        
        if (line[0] == '!') {
            system(line + 1);
            continue;
        }
        
        if ((tok = strtok(line," "))==NULL) {
           if (bIterate)
              next_record(tdb, &iterate_kbuf);
           continue;
        }
        if (strcmp(tok,"create") == 0) {
            bIterate = 0;
            create_tdb();
            continue;
        } else if (strcmp(tok,"open") == 0) {
            open_tdb();
            continue;
        } else if ((strcmp(tok, "q") == 0) ||
                   (strcmp(tok, "quit") == 0)) {
            break;
	}
            
        /* all the rest require a open database */
        if (!tdb) {
            bIterate = 0;
            terror("database not open");
            help();
            continue;
        }
            
        if (strcmp(tok,"insert") == 0) {
            bIterate = 0;
            insert_tdb();
        } else if (strcmp(tok,"store") == 0) {
            bIterate = 0;
            store_tdb();
        } else if (strcmp(tok,"show") == 0) {
            bIterate = 0;
            show_tdb();
        } else if (strcmp(tok,"erase") == 0) {
            bIterate = 0;
            tdb_traverse(tdb, do_delete_fn, NULL);
        } else if (strcmp(tok,"delete") == 0) {
            bIterate = 0;
            delete_tdb();
        } else if (strcmp(tok,"dump") == 0) {
            bIterate = 0;
            tdb_traverse(tdb, print_rec, NULL);
        } else if (strcmp(tok,"move") == 0) {
            bIterate = 0;
            move_rec();
        } else if (strcmp(tok,"list") == 0) {
            tdb_dump_all(tdb);
        } else if (strcmp(tok, "free") == 0) {
            tdb_printfreelist(tdb);
        } else if (strcmp(tok,"info") == 0) {
            info_tdb();
        } else if ( (strcmp(tok, "1") == 0) ||
                    (strcmp(tok, "first") == 0)) {
            bIterate = 1;
            first_record(tdb, &iterate_kbuf);
        } else if ((strcmp(tok, "n") == 0) ||
                   (strcmp(tok, "next") == 0)) {
            next_record(tdb, &iterate_kbuf);
        } else if ((strcmp(tok, "keys") == 0)) {
                bIterate = 0;
                tdb_traverse(tdb, print_key, NULL);
        } else {
            help();
        }
    }

    if (tdb) tdb_close(tdb);

    return 0;
}
