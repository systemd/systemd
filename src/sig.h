/* Public domain. */

#ifndef SIG_H
#define SIG_H

extern int sig_alarm;
extern int sig_child;
extern int sig_cont;
extern int sig_hangup;
extern int sig_int;
extern int sig_pipe;
extern int sig_term;

extern void (*sig_defaulthandler)();
extern void (*sig_ignorehandler)();

extern void sig_catch(int,void (*)());
#define sig_ignore(s) (sig_catch((s),sig_ignorehandler))
#define sig_uncatch(s) (sig_catch((s),sig_defaulthandler))

extern void sig_block(int);
extern void sig_unblock(int);
extern void sig_blocknone(void);
extern void sig_pause(void);

extern void sig_dfl(int);

#endif
