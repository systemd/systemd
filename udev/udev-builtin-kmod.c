/*
 * load kernel modules
 *
 * Copyright (C) 2011 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libkmod.h>

#include "udev.h"

static struct kmod_ctx *ctx;

static int command_do(struct kmod_module *module, const char *type, const char *command, const char *cmdline_opts)
{
	const char *modname = kmod_module_get_name(module);
	char *p, *cmd = NULL;
	size_t cmdlen, cmdline_opts_len, varlen;
	int ret = 0;

	if (cmdline_opts == NULL)
		cmdline_opts = "";
	cmdline_opts_len = strlen(cmdline_opts);

	cmd = strdup(command);
	if (cmd == NULL)
		return -ENOMEM;
	cmdlen = strlen(cmd);
	varlen = sizeof("$CMDLINE_OPTS") - 1;
	while ((p = strstr(cmd, "$CMDLINE_OPTS")) != NULL) {
		size_t prefixlen = p - cmd;
		size_t suffixlen = cmdlen - prefixlen - varlen;
		size_t slen = cmdlen - varlen + cmdline_opts_len;
		char *suffix = p + varlen;
		char *s = malloc(slen + 1);
		if (s == NULL) {
			free(cmd);
			return -ENOMEM;
		}
		memcpy(s, cmd, p - cmd);
		memcpy(s + prefixlen, cmdline_opts, cmdline_opts_len);
		memcpy(s + prefixlen + cmdline_opts_len, suffix, suffixlen);
		s[slen] = '\0';

		free(cmd);
		cmd = s;
		cmdlen = slen;
	}

	setenv("MODPROBE_MODULE", modname, 1);
	ret = system(cmd);
	unsetenv("MODPROBE_MODULE");
	if (ret == -1 || WEXITSTATUS(ret)) {
		//LOG("Error running %s command for %s\n", type, modname);
		if (ret != -1)
			ret = -WEXITSTATUS(ret);
	}

end:
	free(cmd);
	return ret;
}

static int insmod_do_dependencies(struct kmod_module *parent);
static int insmod_do_soft_dependencies(struct kmod_module *mod, struct kmod_list *deps);

static int insmod_do_deps_list(struct kmod_module *parent, struct kmod_list *deps, unsigned stop_on_errors)
{
	struct kmod_list *d;
	int err = 0;

	kmod_list_foreach(d, deps) {
		struct kmod_module *dm = kmod_module_get_module(d);
		struct kmod_list *pre = NULL, *post = NULL;
		const char *cmd, *opts, *dmname = kmod_module_get_name(dm);
		int state;
		int r;

		r = insmod_do_dependencies(dm);
		if (r < 0) {
			//WRN("could not insert dependencies of '%s': %s\n", dmname, strerror(-r));
			goto dep_error;
		}

		r = kmod_module_get_softdeps(dm, &pre, &post);
		if (r < 0) {
			//WRN("could not get softdeps of '%s': %s\n", dmname, strerror(-r));
			goto dep_done;
		}

		r = insmod_do_soft_dependencies(dm, pre);
		if (r < 0) {
			//WRN("could not insert pre softdeps of '%s': %s\n", dmname, strerror(-r));
			goto dep_error;
		}

		state = kmod_module_get_initstate(dm);
		if (state == KMOD_MODULE_LIVE ||
				state == KMOD_MODULE_COMING ||
				state == KMOD_MODULE_BUILTIN)
			goto dep_done;

		cmd = kmod_module_get_install_commands(dm);
		if (cmd) {
			r = command_do(dm, "install", cmd, NULL);
			if (r < 0) {
				//WRN("failed to execute install command of '%s':" " %s\n", dmname, strerror(-r));
				goto dep_error;
			} else
				goto dep_done;
		}

		opts = kmod_module_get_options(dm);

		r = kmod_module_insert_module(dm, 0, opts);
		if (r < 0) {
			//WRN("could not insert '%s': %s\n", dmname, strerror(-r));
			goto dep_error;
		}

	dep_done:
		r = insmod_do_soft_dependencies(dm, post);
		if (r < 0) {
			//WRN("could not insert post softdeps of '%s': %s\n", dmname, strerror(-r));
			goto dep_error;
		}

		kmod_module_unref_list(pre);
		kmod_module_unref_list(post);
		kmod_module_unref(dm);
		continue;

	dep_error:
		err = r;
		kmod_module_unref_list(pre);
		kmod_module_unref_list(post);
		kmod_module_unref(dm);
		if (stop_on_errors)
			break;
		else
			continue;
	}

	return err;
}

static int insmod_do_soft_dependencies(struct kmod_module *mod, struct kmod_list *deps)
{
	return insmod_do_deps_list(mod, deps, 0);
}

static int insmod_do_dependencies(struct kmod_module *parent)
{
	struct kmod_list *deps = kmod_module_get_dependencies(parent);
	int err = insmod_do_deps_list(parent, deps, 1);
	kmod_module_unref_list(deps);
	return err;
}

static int insmod_do(struct kmod_module *mod, const char *extra_opts)
{
	const char *modname = kmod_module_get_name(mod);
	const char *conf_opts = kmod_module_get_options(mod);
	struct kmod_list *pre = NULL, *post = NULL;
	char *opts = NULL;
	const char *cmd;
	int state;
	int err;

	err = kmod_module_get_softdeps(mod, &pre, &post);
	if (err < 0) {
		//WRN("could not get softdeps of '%s': %s\n", modname, strerror(-err));
		return err;
	}

	err = insmod_do_soft_dependencies(mod, pre);
	if (err < 0) {
		//WRN("could not insert pre softdeps of '%s': %s\n", modname, strerror(-err));
		goto error;
	}

	cmd = kmod_module_get_install_commands(mod);
	if (cmd != NULL) {
		err = command_do(mod, "install", cmd, extra_opts);
		goto done;
	}

	state = kmod_module_get_initstate(mod);
	if (state == KMOD_MODULE_BUILTIN || state == KMOD_MODULE_LIVE)
		return 0;

	/*
	 * At this point it's not possible to be a install/remove command
	 * anymore. So if we can't get module's path, it's because it was
	 * really intended to be a module and it doesn't exist
	 */
	if (kmod_module_get_path(mod) == NULL) {
		//LOG("Module %s not found.\n", modname);
		return -ENOENT;
	}

	err = insmod_do_dependencies(mod);
	if (err < 0)
		return err;

	if (conf_opts || extra_opts) {
		if (conf_opts == NULL)
			opts = strdup(extra_opts);
		else if (extra_opts == NULL)
			opts = strdup(conf_opts);
		else if (asprintf(&opts, "%s %s", conf_opts, extra_opts) < 0)
			opts = NULL;

		if (opts == NULL) {
			err = -ENOMEM;
			goto error;
		}
	}

	err = kmod_module_insert_module(mod, 0, opts);
	if (err == -EEXIST)
		err = 0;

done:
	err = insmod_do_soft_dependencies(mod, post);
	if (err < 0) {
		//WRN("could not insert post softdeps of '%s': %s\n", modname, strerror(-err));
		goto error;
	}

error:
	kmod_module_unref_list(pre);
	kmod_module_unref_list(post);
	free(opts);
	return err;
}

static int insmod_path(struct kmod_ctx *ctx, const char *path, const char *extra_options)
{
	struct kmod_module *mod;
	int err;

	err = kmod_module_new_from_path(ctx, path, &mod);
	if (err < 0) {
		//LOG("Module %s not found.\n", path);
		return err;
	}
	err = insmod_do(mod, extra_options);
	kmod_module_unref(mod);
	return err;
}

static int insmod_alias(struct kmod_ctx *ctx, const char *alias, const char *extra_options)
{
	struct kmod_list *l, *list = NULL;
	struct kmod_list *filtered = NULL;
	int err;

	err = kmod_module_new_from_lookup(ctx, alias, &list);
	if (err < 0)
		return err;

	if (list == NULL) {
		//LOG("Module %s not found.\n", alias);
		return err;
	}

	err = kmod_module_get_filtered_blacklist(ctx, list, &filtered);
	kmod_module_unref_list(list);
	if (err < 0) {
		//LOG("Could not filter alias list!\n");
		return err;
	}
	list = filtered;

	kmod_list_foreach(l, list) {
		struct kmod_module *mod = kmod_module_get_module(l);
		err = insmod_do(mod, extra_options);
		kmod_module_unref(mod);
		if (err < 0)
			break;
	}

	kmod_module_unref_list(list);
	return err;
}

static int insmod(struct kmod_ctx *ctx, const char *name, const char *extra_options)
{
	struct stat st;
	if (stat(name, &st) == 0)
		return insmod_path(ctx, name, extra_options);
	else
		return insmod_alias(ctx, name, extra_options);
}

static int builtin_kmod(struct udev_device *dev, int argc, char *argv[], bool test)
{
	struct udev *udev = udev_device_get_udev(dev);
	int i;

	if (!ctx)
		return EXIT_FAILURE;

	if (argc < 3) {
		err(udev, "missing command + argument\n");
		return EXIT_FAILURE;
	}

	for (i = 2; argv[i]; i++) {
		info(udev, "%s '%s'\n", argv[1], argv[i]);
		insmod(ctx, argv[i], NULL);
	}

	return EXIT_SUCCESS;
}

static int builtin_kmod_load(struct udev *udev)
{
	kmod_unref(ctx);
	ctx = kmod_new(NULL, NULL);
	if (!ctx)
		return -ENOMEM;

	info(udev, "load module index\n");
	return 0;
}

static int builtin_kmod_unload(struct udev *udev)
{
	kmod_unref(ctx);
	info(udev, "unload module index\n");
	return 0;
}

const struct udev_builtin udev_builtin_kmod = {
	.name = "kmod",
	.cmd = builtin_kmod,
	.load = builtin_kmod_load,
	.unload = builtin_kmod_unload,
	.help = "kernel module loader",
	.run_once = false,
};
