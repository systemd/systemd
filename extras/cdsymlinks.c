/* cdsymlinks.c
 *
 * Map cdrom, cd-r, cdrw, dvd, dvdrw, dvdram to suitable devices.
 * Prefers cd* for DVD-incapable and cdrom and dvd for read-only devices.
 * First parameter is the kernel device name.
 * Second parameter, if present, must be "-d" => output the full mapping.
 *
 * Usage:
 * BUS="ide", KERNEL="hd[a-z]", PROGRAM="/etc/udev/cdsymlinks.sh %k", SYMLINK="%c{1} %c{2} %c{3} %c{4} %c{5} %c{6}"
 * BUS="scsi", KERNEL="sr[0-9]*", PROGRAM="/etc/udev/cdsymlinks.sh %k", SYMLINK="%c{1} %c{2} %c{3} %c{4} %c{5} %c{6}"
 * BUS="scsi", KERNEL="scd[0-9]*", PROGRAM="/etc/udev/cdsymlinks.sh %k", SYMLINK="%c{1} %c{2} %c{3} %c{4} %c{5} %c{6}"
 * (this last one is "just in case")
 *
 * (c) 2004 Darren Salt <linux@youmustbejoking.demon.co.uk>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <strings.h>
#include <sys/types.h>
#include <dirent.h>

#include <unistd.h>

#include <wordexp.h>

static const char *progname;

/* This file provides us with our devices and capabilities information. */
#define CDROM_INFO "/proc/sys/dev/cdrom/info"

/* This file contains our default settings. */
#define CONFIGURATION "/etc/udev/cdsymlinks.conf"
/* Default output types configuration, in the presence of an empty list */
#define OUTPUT_DEFAULT "CD CDRW DVD DVDRW DVDRAM"

static int debug = 0;

/* List item */
struct list_item_t {
  struct list_item_t *next;
  char *data;
};

/* List root. Note offset of list_t->head and list_item_t->next */
struct list_t {
  struct list_item_t *head, *tail;
};

/* Configuration variables */
static struct list_t allowed_output = {0};
static int numbered_links = 1;

/* Available devices */
static struct list_t Devices = {0};

/* Devices' capabilities in full (same order as available devices list).
 * There's no cap_CD; all are assumed able to read CDs.
 */
static struct list_t cap_DVDRAM = {0}, cap_DVDRW = {0}, cap_DVD = {0},
		     cap_CDRW = {0}, cap_CDR = {0}, cap_CDWMRW = {0},
		     cap_CDMRW = {0};

/* Device capabilities by name */
static struct list_t dev_DVDRAM = {0}, dev_DVDRW = {0}, dev_DVD = {0},
		     dev_CDRW = {0}, dev_CDR = {0}, dev_CDWMRW = {0},
		     dev_CDMRW = {0};
#define dev_CD Devices


/*
 * Some library-like bits first...
 */

static void
errexit (const char *reason)
{
  fprintf (stderr, "%s: %s: %s\n", progname, reason, strerror (errno));
  exit (2);
}


static void
msgexit (const char *reason)
{
  fprintf (stderr, "%s: %s\n", progname, reason);
  exit (2);
}


static void
errwarn (const char *reason)
{
  fprintf (stderr, "%s: warning: %s: %s\n", progname, reason, strerror (errno));
}


static void
msgwarn (const char *reason)
{
  fprintf (stderr, "%s: warning: %s\n", progname, reason);
}


static void *
xmalloc (size_t size)
{
  void *mem = malloc (size);
  if (size && !mem)
    msgexit ("malloc failed");
  return mem;
}


static char *
xstrdup (const char *text)
{
  char *mem = xmalloc (strlen (text) + 1);
  return strcpy (mem, text);
}


/* Append a string to a list. The string is duplicated. */
static void
list_append (struct list_t *list, const char *data)
{
  struct list_item_t *node = xmalloc (sizeof (struct list_item_t));
  node->next = NULL;
  if (list->tail)
    list->tail->next = node;
  list->tail = node;
  if (!list->head)
    list->head = node;
  node->data = xstrdup (data);
}


/* Prepend a string to a list. The string is duplicated. */
static void
list_prepend (struct list_t *list, const char *data)
{
  struct list_item_t *node = xmalloc (sizeof (struct list_item_t));
  node->next = list->head;
  list->head = node;
  if (!list->tail)
    list->tail = node;
  node->data = xstrdup (data);
}


/* Delete a lists's contents, freeing claimed memory */
static void
list_delete (struct list_t *list)
{
  struct list_item_t *node = list->head;
  while (node)
  {
    struct list_item_t *n = node;
    node = node->next;
    free (n->data);
    free (n);
  }
  list->tail = list->head = NULL;
}


/* Print out a list on one line, each item space-prefixed, no LF */
static void
list_print (const struct list_t *list, FILE *stream)
{
  const struct list_item_t *node = (const struct list_item_t *)list;
  while ((node = node->next) != NULL)
    fprintf (stream, " %s", node->data);
}


/* Return the nth item in a list (count from 0)
 * If there aren't enough items in the list, return the requested default
 */
static const struct list_item_t *
list_nth (const struct list_t *list, size_t nth)
{
  const struct list_item_t *node = list->head;
  while (nth && node)
  {
    node = node->next;
    --nth;
  }
  return node;
}


/* Return the first matching item in a list, or NULL */
static const struct list_item_t *
list_search (const struct list_t *list, const char *data)
{
  const struct list_item_t *node = list->head;
  while (node)
  {
    if (!strcmp (node->data, data))
      return node;
    node = node->next;
  }
  return NULL;
}


/* Split up a string on whitespace & assign the resulting tokens to a list.
 * Ignore everything up until the first colon (if present).
 */
static void
list_assign_split (struct list_t *list, char *text)
{
  char *token = strchr (text, ':');
  token = strtok (token ? token + 1 : text, " \t");
  while (token)
  {
    list_prepend (list, token);
    token = strtok (0, " \t\n");
  }
}



/* Gather the default settings. */
static void
read_defaults (void)
{
  FILE *conf = fopen (CONFIGURATION, "r");
  if (!conf)
  {
    if (errno != ENOENT)
      errwarn ("error accessing configuration");
  }
  else
  {
    char *text = NULL;
    size_t textlen;
    while (getline (&text, &textlen, conf) != -1)
    {
      wordexp_t p = {0};
      int len = strlen (text);
      if (len && text[len - 1] == '\n')
	text[--len] = '\0';
      if (len && text[len - 1] == '\r')
	text[--len] = '\0';
      if (!len)
	continue;
      char *token = text + strspn (text, " \t");
      if (!*token || *token == '#')
	continue;
      switch (len = wordexp (text, &p, 0))
      {
      case WRDE_NOSPACE:
	msgexit ("malloc failed");
      case 0:
	if (p.we_wordc == 1)
	{
	  if (!strncmp (p.we_wordv[0], "OUTPUT=", 7))
          {
            list_delete (&allowed_output);
            list_assign_split (&allowed_output, p.we_wordv[0] + 7);
          }
          else if (!strncmp (p.we_wordv[0], "NUMBERED_LINKS=", 14))
            numbered_links = atoi (p.we_wordv[0] + 14);
          break;
	}
	/* fall through */
      default:
	msgwarn ("syntax error in configuration file");
      }
      wordfree (&p);
    }
    if (!feof (conf))
      errwarn ("error accessing configuration");
    if (fclose (conf))
      errwarn ("error accessing configuration");
    free (text);
  }
  if (!allowed_output.head)
  {
    char *dflt = strdup (OUTPUT_DEFAULT);
    list_assign_split (&allowed_output, dflt);
    free (dflt);
  }
}


/* From information supplied by the kernel:
 *  + get the names of the available devices
 *  + populate our capability lists
 * Order is significant: device item N maps to each capability item N.
 */
static void
populate_capability_lists (void)
{
  FILE *info = fopen (CDROM_INFO, "r");
  if (!info)
  {
    if (errno == ENOENT)
      exit (0);
    errexit ("error accessing CD/DVD info");
  }

  char *text = 0;
  size_t textlen = 0;

  while (getline (&text, &textlen, info) != -1)
  {
    if (!strncasecmp (text, "drive name", 10))
      list_assign_split (&Devices, text);
    else if (!strncasecmp (text, "Can write DVD-RAM", 17))
      list_assign_split (&cap_DVDRAM, text);
    else if (!strncasecmp (text, "Can write DVD-R", 15))
      list_assign_split (&cap_DVDRW, text);
    else if (!strncasecmp (text, "Can read DVD", 12))
      list_assign_split (&cap_DVD, text);
    else if (!strncasecmp (text, "Can write CD-RW", 15))
      list_assign_split (&cap_CDRW, text);
    else if (!strncasecmp (text, "Can write CD-R", 14))
      list_assign_split (&cap_CDR, text);
    else if (!strncasecmp (text, "Can read MRW", 14))
      list_assign_split (&cap_CDMRW, text);
    else if (!strncasecmp (text, "Can write MRW", 14))
      list_assign_split (&cap_CDWMRW, text);
  }
  if (!feof (info))
    errexit ("error accessing CD/DVD info");
  fclose (info);
  free (text);
}


/* Write out the links of type LINK which should be created for device NAME,
 * taking into account existing links and the capability list for type LINK.
 */
static void
do_output (const char *name, const char *link, const struct list_t *dev)
{
  const struct list_item_t *i = (const struct list_item_t *)dev;
  if (!i->next)
    return;

  errno = 0;

  size_t link_len = strlen (link);
  DIR *dir = opendir ("/dev");
  if (!dir)
    errexit ("error reading /dev");

  struct list_t devls = {0};	/* symlinks whose name matches LINK */
  struct list_t devlinks = {0};	/* those symlinks' targets */
  struct dirent *entry;
  while ((entry = readdir (dir)) != NULL)
  {
    if (strncmp (entry->d_name, link, link_len))
      continue; /* wrong name: ignore it */

    /* The rest of the name must be null or consist entirely of digits. */
    const char *p = entry->d_name + link_len - 1;
    while (*++p)
      if (!isdigit (*p))
        break;
    if (*p)
      continue; /* wrong format - ignore */

    /* Assume that it's a symlink and try to read its target. */
    char buf[sizeof (entry->d_name)];
    int r = readlink (entry->d_name, buf, sizeof (buf) - 1);
    if (r < 0)
    {
      if (errno == EINVAL)
        continue; /* not a symlink - ignore */
      errexit ("error reading link in /dev");
    }
    /* We have the name and the target, so update our lists. */
    buf[r] = 0;
    list_append (&devls, entry->d_name);
    list_append (&devlinks, buf);
  }
  if (errno)
    errexit ("error reading /dev");
  if (closedir (dir))
    errexit ("error closing /dev");

  /* Now we write our output... */
  size_t count = 0;
  while ((i = i->next) != NULL)
  {
    int isdev = !strcmp (name, i->data); /* current dev == target dev? */
    int present = 0;
    size_t li = -1;
    const struct list_item_t *l = (const struct list_item_t *)&devlinks;

    /* First, we look for existing symlinks to the target device. */
    while (++li, (l = l->next) != NULL)
    {
      if (strcmp (l->data, i->data))
        continue;
      /* Existing symlink found - don't output a new one.
       * If ISDEV, we output the name of the existing symlink.
       */
      present = 1;
      if (isdev)
        printf (" %s", list_nth (&devls, li)->data);
    }

    /* If we found no existing symlinks for the target device... */
    if (!present)
    {
      char buf[256];
      snprintf (buf, sizeof (buf), count ? "%s%d" : "%s", link, count);
      /* Find the next available (not present) symlink name.
       * We always need to do this for reasons of output consistency: if a
       * symlink is created by udev as a result of use of this program, we
       * DON'T want different output!
       */
      while (list_search (&devls, buf))
        snprintf (buf, sizeof (buf), "%s%d", link, ++count);
      /* If ISDEV, output it. */
      if (isdev && (numbered_links || count == 0))
        printf (" %s", buf);
      /* If the link isn't in our "existing links" list, add it and increment
       * our counter.
       */
      if (!list_search (&devls, buf))
      {
        list_append (&devls, buf);
        ++count;
      }
    }
  }

  list_delete (&devls);
  list_delete (&devlinks);
}


/* Populate a device list from a capabilities list. */
static void
populate_device_list (struct list_t *out, const struct list_t *caps)
{
  const struct list_item_t *cap, *dev;
  cap = (const struct list_item_t *)caps;
  dev = (const struct list_item_t *)&Devices;
  while ((cap = cap->next) != NULL && (dev = dev->next) != NULL)
    if (cap->data[0] != '0')
      list_append (out, dev->data);
}


int
main (int argc, char *argv[])
{
  progname = argv[0];
  debug = argc > 2 && !strcmp (argv[2], "-d");

  if (argc < 2 || argc > 2 + debug)
    msgexit ("usage: cdsymlinks DEVICE [-d]");

  if (chdir ("/dev"))
    errexit ("can't chdir /dev");

  read_defaults ();
  populate_capability_lists ();

  /* Construct the device lists from the capability lists. */
  populate_device_list (&dev_DVDRAM, &cap_DVDRAM);
  populate_device_list (&dev_DVDRW, &cap_DVDRW);
  populate_device_list (&dev_DVD, &cap_DVD);
  populate_device_list (&dev_CDRW, &cap_CDRW);
  populate_device_list (&dev_CDR, &cap_CDR);
  populate_device_list (&dev_CDWMRW, &cap_CDWMRW);
  populate_device_list (&dev_CDMRW, &cap_CDMRW);
  /* (All devices can read CDs.) */

  if (debug)
  {
#define printdev(DEV) \
	printf ("%-7s:", #DEV); \
        list_print (&cap_##DEV, stdout); \
        list_print (&dev_##DEV, stdout); \
	puts ("");

    printf ("Devices:");
    const struct list_item_t *item = (const struct list_item_t *)&Devices;
    while ((item = item->next) != NULL)
      printf (" %s", item->data);
    puts ("");

    printdev (DVDRAM);
    printdev (DVDRW);
    printdev (DVD);
    printdev (CDRW);
    printdev (CDR);
    printdev (CDWMRW);
    printdev (CDMRW);

    printf ("CDROM  : (all)");
    item = (const struct list_item_t *)&dev_CD;
    while ((item = item->next) != NULL)
      printf (" %s", item->data);
    puts ("");
  }

  /* Write the symlink names. */
  if (list_search (&allowed_output, "CD"))
    do_output (argv[1], "cdrom",  &dev_CD);
  if (list_search (&allowed_output, "CDR"))
    do_output (argv[1], "cd-r",   &dev_CDR);
  if (list_search (&allowed_output, "CDRW"))
    do_output (argv[1], "cdrw",   &dev_CDRW);
  if (list_search (&allowed_output, "DVD"))
    do_output (argv[1], "dvd",    &dev_DVD);
  if (list_search (&allowed_output, "DVDRW"))
    do_output (argv[1], "dvdrw",  &dev_DVDRW);
  if (list_search (&allowed_output, "DVDRAM"))
    do_output (argv[1], "dvdram", &dev_DVDRAM);
  if (list_search (&allowed_output, "CDMRW"))
    do_output (argv[1], "cdmrw",   &dev_CDMRW);
  if (list_search (&allowed_output, "CDWMRW"))
    do_output (argv[1], "cdwmrw",   &dev_CDWMRW);
  puts ("");

  return 0;
}
