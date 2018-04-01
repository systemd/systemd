Features Scheduled for Removal
==============================

The following is a list of files and features that are going to be removed in
the source tree.  Every entry should contain what exactly is going away, why it
is happening, and who is going to be doing the work.  When the feature is
removed, it should also be removed from this file.

# Service pause action

When: 1.0

Why: The same affect can be obtained with the --nodeps option to stop.

Who:

# start-stop-daemon options --startas, --chuid , --oknodo

When: 1.0

Why: Obsolete or replaced by other options.

* --startas => use --name or --exec
* --chuid => use --user
* --oknodo => ignore return code instead

Who:

# runscript and rc symbolic links

When: 1.0

Why: Deprecated in favor of openrc-run and openrc due to naming
	 conflicts with other software.

Who:

# support for the opts variable in service scripts

When: 1.0

Why: Deprecated in favor of extra_commands, extra_started_commands
	 and extra_stopped_commands.

Who:

# support for local_start and local_stop

When: 1.0

Why: Deprecated in favor of executable scripts in @SYSCONFDIR@/local.d

Who:

# the mtab service script

When: force /etc/mtab to link to /proc/self/mounts in 1.0, remove
	  service in 2.0

Why: /etc/mtab should be a symbolic link to /proc/self/mounts on modern
	 Linux systems

Who:

# C API Functions in rc.h

If you have a c program that links to librc and uses functions from
there, this section will list API functions which are deprecated and
will be removed along with the reason they are being removed.

## rc_getline()

When: 1.0

Why: The getline() function was standardized in POSIX.1-2008, so it
	 should be available on POSIX systems.

Who:

