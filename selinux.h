#ifndef SELINUX_H
#define SELINUX_H

#ifndef USE_SELINUX

static inline void selinux_setfilecon(char *file, unsigned int mode) { }
static inline void selinux_setfscreatecon(char *file, unsigned int mode) {}
static inline void selinux_init(void) {}
static inline void selinux_restore(void) {}

#else

#include <selinux/selinux.h>
#include <stdio.h>
#include <limits.h>
#include <ctype.h>


static int selinux_enabled=-1;
static security_context_t prev_scontext=NULL;

static inline int is_selinux_running(void) {
	if ( selinux_enabled==-1 ) 
		return selinux_enabled=is_selinux_enabled()>0;
	return selinux_enabled;
}

static inline int selinux_get_media(char *path, int mode, char **media)
{
  FILE *fp;
  char buf[PATH_MAX];
  char mediabuf[PATH_MAX];
  *media=NULL;
  if (!( mode && S_IFBLK )) {
	  return -1;
  }
  snprintf(buf,sizeof(buf), "/proc/ide/%s/media", basename(path));
  fp=fopen(buf,"r");
  if (fp) {
	  if (fgets(mediabuf,sizeof(mediabuf), fp)) {
		  int size=strlen(mediabuf);
		  while (size-- > 0) {
			  if (isspace(mediabuf[size])) {
				  mediabuf[size]='\0';
			  } else {
				  break;
			  }
		  }
		  *media=strdup(mediabuf);
		  info("selinux_get_media(%s)->%s \n", path, *media);
	  }
    fclose(fp);
    return 0;
  } else {
    return -1;
  }
}

static inline void selinux_setfilecon(char *file, unsigned int mode) { 
	if (is_selinux_running()) {
		security_context_t scontext=NULL;
		char *media;
		int ret=selinux_get_media(file, mode, &media);
		if ( ret== 0) {
			ret = matchmediacon(media, &scontext);
			free(media);
		} 
		if (ret==-1) 
			if (matchpathcon(file, mode, &scontext) < 0) {
				dbg("matchpathcon(%s) failed\n", file);
				return;
			} 
		if (setfilecon(file, scontext) < 0)
			dbg("setfiles %s failed with error '%s'",
			    file, strerror(errno));
		freecon(scontext);
	}
}

static inline void selinux_setfscreatecon(char *file, unsigned int mode) {
	int retval = 0;
	security_context_t scontext=NULL;

	if (is_selinux_running()) {
		char *media;
		int ret=selinux_get_media(file, mode, &media);
		if ( ret== 0) {
			ret = matchmediacon(media, &scontext);
			free(media);
		} 

		if (ret==-1) 
			if (matchpathcon(file, mode, &scontext) < 0) {
				dbg("matchpathcon(%s) failed\n", file);
				return;
			} 

		retval=setfscreatecon(scontext);
		if (retval < 0)
			dbg("setfiles %s failed with error '%s'",
			    file, strerror(errno));
		freecon(scontext);
	}
}
static inline void selinux_init(void) {
	/* record the present security context, for file-creation
	 * restoration creation purposes.
	 *
	 */

	if (is_selinux_running())
	{
		if (getfscreatecon(&prev_scontext) < 0) {
			dbg("getfscreatecon failed\n");
		}
		prev_scontext=NULL;
	}
}
static inline void selinux_restore(void) {
	if (is_selinux_running()) {
		/* reset the file create context to its former glory */
		if ( setfscreatecon(prev_scontext) < 0 )
			dbg("setfscreatecon failed\n");
		if (prev_scontext) {
			freecon(prev_scontext);
			prev_scontext=NULL;
		}
	}
}
#endif /* USE_SELINUX */
#endif /* SELINUX_H */
