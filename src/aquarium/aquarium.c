// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2023 Aymeric Wibo

#include <aquarium.h>
#include "util.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char* template = "amd64.aquabsd.0.1.1-beta";
static char* kernel_template = NULL;

static char* out_path = NULL;
static char* path = NULL;

static void usage(void) {
	fprintf(stderr,
		"usage: %1$s [-r base]\n"
		"       %1$s [-r base] -c path [-t template] [-k kernel_template]\n"
		"       %1$s [-r base] [-d rulesets] [-j jailparams] [-m max_children] [-Dp] [-v interface] [-h hostname] -e path\n"
		"       %1$s [-r base] -i path -o image\n"
		"       %1$s [-r base] -I drive [-t template] [-k kernel_template]\n"
		"       %1$s [-r base] -l\n"
		"       %1$s [-r base] -s\n"
		"       %1$s [-r base] -T path -o template\n"
		"       %1$s [-r base] -y path source_file ... target_directory\n",
	getprogname());

	exit(EXIT_FAILURE);
}

// actions

static int do_list(aquarium_opts_t* opts) {
	FILE* fp = fopen(opts->db_path, "r");

	if (!fp) {
		errx(EXIT_FAILURE, "fopen: failed to open %s for reading: %s", opts->db_path, strerror(errno));
	}

	printf("POINTER\tAQUARIUM\n");

	char buf[1024];
	aquarium_db_ent_t ent;

	while (aquarium_db_next_ent(opts, &ent, sizeof buf, buf, fp, true)) {
		printf("%s\t%s\n", ent.pointer_path, ent.aquarium_path);
	}

	fclose(fp);

	return EXIT_SUCCESS;
}

static inline void __list_templates_dir(const char* path, const char* kind) {
	DIR* dp = opendir(path);

	if (!dp) {
		errx(EXIT_FAILURE, "opendir: failed to open template directory %s: %s", path, strerror(errno));
	}

	printf("ARCH\tOS\tVERS\t(%s)\n", kind);

	struct dirent* ent;

	while ((ent = readdir(dp))) {
		char* name = ent->d_name;

		if (!strcmp(name, ".") || !strcmp(name, "..")) {
			continue;
		}

		enum {
			ARCH, OS, VERS, SENTINEL
		} kind = 0;

		char* tok;

		while ((tok = strsep(&name, "."))) {
			printf("%s", tok);

			if (++kind >= SENTINEL) {
				char* const last_dot = strrchr(name, '.');

				if (last_dot != NULL) {
					*last_dot = '\0';
					printf(".%s", name);
				}

				break;
			}

			printf("\t");
		}

		printf("\n");
	}

	closedir(dp);
}

static int do_list_templates(aquarium_opts_t* opts) {
	__list_templates_dir(opts->templates_path, "BASE");
	__list_templates_dir(opts->kernels_path, "KERNEL");

	return EXIT_SUCCESS;
}

static int do_create(aquarium_opts_t* opts) {
	if (!path) {
		usage();
	}

	if (aquarium_create(opts, path, template, kernel_template) < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int do_install(aquarium_opts_t* opts) {
	if (!path) {
		usage();
	}

	char* const target = path;

	// find our drive

	aquarium_drive_t* drives = NULL;
	size_t drives_len = 0;

	if (aquarium_drives_read(&drives, &drives_len) < 0) {
		return EXIT_FAILURE;
	}

	aquarium_drive_t* const drive = aquarium_drives_find(drives, drives_len, target);

	if (!drive) {
		return EXIT_FAILURE;
	}

	// create partition table on target

	if (aquarium_format_new_table(opts, drive) < 0) {
		return EXIT_FAILURE;
	}

	// create ZFS filesystem on target

	char const* const root = "/mnt";

	if (aquarium_format_create_zfs(opts, drive, root) < 0) {
		return EXIT_FAILURE;
	}

	// extract templates

	if (template && aquarium_extract_template(opts, root, template, AQUARIUM_TEMPLATE_KIND_BASE) < 0) {
		return EXIT_FAILURE;
	}

	if (kernel_template && aquarium_extract_template(opts, root, kernel_template, AQUARIUM_TEMPLATE_KIND_KERNEL) < 0) {
		return EXIT_FAILURE;
	}

	// create ESP on target

	if (aquarium_format_create_esp(opts, drive, root) < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int enter_cb(__attribute__((unused)) void* param) {
	// unfortunately we kinda need to use execlp here
	// different OS' may have different locations for the 'env' binary
	// we use it instead of starting the shell directly to clear any environment variables that we shouldn't have access to (and which anyway isn't super relevant to us)
	// the one exception is the TERM variable, which we read and then pass on to env

	char* const term_env = getenv("TERM");
	char* term_arg;

	if (term_env) {
		if (asprintf(&term_arg, "TERM=%s", term_env)) {} // we don't concern ourselves with freeing this
	}

	else {
		term_arg = "";
	}

	execlp("env", "env", "-i", term_arg, "sh", NULL);
	_exit(EXIT_FAILURE);
}

static int do_enter(aquarium_opts_t* opts) {
	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	if (aquarium_enter(opts, aquarium_path, enter_cb, NULL) < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int do_sweep(aquarium_opts_t* opts) {
	return aquarium_sweep(opts, true) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int do_out(aquarium_opts_t* opts) {
	if (!out_path) {
		usage();
	}

	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	return aquarium_template_out(opts, aquarium_path, out_path) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int do_img_out(aquarium_opts_t* opts) {
	if (!out_path) {
		usage();
	}

	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	return aquarium_img_out(opts, aquarium_path, out_path) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static char** copy_args = NULL;
static size_t copy_args_len = 0;

static int do_copy(aquarium_opts_t* opts) {
	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	char* const target = copy_args[--copy_args_len];

	// make sure target directory doesn't refer to $HOME
	// we have no [easy] way of getting the $HOME of the aquarium, and even if we did, what user should we assume?
	// this doesn't stop shells from expanding '~', but it's better than nothing

	if (*target == '~') {
		warnx("target directory '%s' refers to $HOME ('~'), which is unsupported", target);
		return EXIT_FAILURE;
	}

	// also make sure it doesn't contain any ".."'s, as that can be used to copy to outside of the aquarium
	// XXX technically we could count these and path components to see if we really do break out of the aquarium, but that's a lot of work

	if (strstr(target, "..")) {
		warnx("target directory '%s' contains '..', which is unsupported", target);
		return EXIT_FAILURE;
	}

	// make sure all files are (recursively) readable by the user

	for (size_t i = 0; i < copy_args_len; i++) {
		char* const source = copy_args[i];

		if (!can_read_all(source)) {
			warnx("user can't read all of \"%s\"", source);
			return EXIT_FAILURE;
		}
	}

	// once we're sure all the files are readable, setuid
	// no need to set the UID back; from here on out, we stay as superuser

	if (opts->initial_uid && setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		return EXIT_FAILURE;
	}

	// create target directory if it doesn't yet exist

	char* abs_target;
	if (asprintf(&abs_target, "%s/%s", aquarium_path, target)) {}

	if (mkdir_recursive(abs_target) < 0) {
		return EXIT_FAILURE;
	}

	// then, actually copy all the files recursively

	while (copy_args_len --> 0) {
		char* const source = copy_args[copy_args_len];

		if (copy_recursive(source, abs_target)) {
			return EXIT_FAILURE;
		}

		// recursively set UID and GID of all copied files to 0
		// this is probably not what the user wants, but better be safe than sorry - I don't see a better way for handling this ATM

		if (chown_recursive(abs_target, 0, 0) < 0) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

static void parse_rulesets(aquarium_opts_t* opts, char* rulesets) {
	char* tok;

	while ((tok = strsep(&rulesets, ","))) {
		aquarium_devfs_ruleset_t const ruleset = strtoul(tok, NULL, 10);
		aquarium_opts_add_devfs_ruleset(opts, ruleset);
	}
}

static void parse_jailparams(aquarium_opts_t* opts, char* jailparams) {
	char* tok;

	while ((tok = strsep(&jailparams, ","))) {
		char* const pre_val = strchr(tok, '=');

		if (pre_val == NULL) {
			warnx("jailparam '%s' has no equals sign ('='), skipping", tok);
			continue;
		}

		*pre_val = '\0';
		char* val = pre_val + 1;

		if (strcmp(val, "NULL") == 0) {
			val = NULL;
		}

		aquarium_opts_add_jailparam(opts, tok, val);
	}
}

// main function

typedef int (*action_t) (aquarium_opts_t* opts);

int main(int argc, char* argv[]) {
	action_t action = do_list;
	aquarium_opts_t* const opts = aquarium_opts_create();
	bool default_ruleset = true;

	if (!opts) {
		return EXIT_FAILURE;
	}

	// parse options

	int c;

	while ((c = getopt(argc, argv, "c:d:De:fh:i:I:j:k:lm:o:pr:st:T:v:y:")) != -1) {
		// general options

		if (c == 'd') {
			default_ruleset = false;
			parse_rulesets(opts, optarg);
		}

		else if (c == 'D') {
			opts->dhcp = true;
		}

		else if (c == 'h') {
			opts->hostname = optarg;
		}

		else if (c == 'j') {
			parse_jailparams(opts, optarg);
		}

		else if (c == 'm') {
			opts->max_children = strtoul(optarg, NULL, 10);
		}

		else if (c == 'p') {
			opts->persist = true;
		}

		else if (c == 'r') {
			aquarium_opts_set_base_path(opts, optarg);
		}

		else if (c == 'v') {
			opts->vnet_bridge = optarg;
		}

		// action options

		else if (c == 'c') {
			action = do_create;
			path = optarg;
		}

		else if (c == 'e') {
			action = do_enter;
			path = optarg;
		}

		else if (c == 'i') {
			action = do_img_out;
			path = optarg;
		}

		else if (c == 'I') {
			action = do_install;
			path = optarg;
		}

		else if (c == 'l') {
			action = do_list_templates;
		}

		else if (c == 's') {
			action = do_sweep;
		}

		else if (c == 'T') {
			action = do_out;
			path = optarg;
		}

		else if (c == 'y') {
			action = do_copy;
			path = optarg;
		}

		// name-passing options

		else if (c == 'k') {
			kernel_template = optarg;
		}

		else if (c == 't') {
			template = optarg;
		}

		else if (c == 'o') {
			out_path = optarg;
		}

		else {
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (action == do_copy) {
		copy_args = argv;
		copy_args_len = argc;
	}

	else if (argc) {
		usage();
	}

	// bunch of sanity checks

	if (opts->dhcp && !opts->vnet_bridge) {
		errx(EXIT_FAILURE, "can't use -D without using -v");
	}

	// a non-zero amount of children means we want to allow nesting
	// that means we also probably want to also allow FS mounting
	// this will overwrite jailparams, so use children.max instead of -m if that's not what you want!

	if (opts->max_children) {
		aquarium_opts_add_jailparam(opts, "allow.mount", "true");
		aquarium_opts_add_jailparam(opts, "enforce_statfs", "1");

		aquarium_opts_add_jailparam(opts, "allow.mount.tmpfs", "true");
		aquarium_opts_add_jailparam(opts, "allow.mount.devfs", "true");
		aquarium_opts_add_jailparam(opts, "allow.mount.fdescfs", "true");
		aquarium_opts_add_jailparam(opts, "allow.mount.procfs", "true");
		aquarium_opts_add_jailparam(opts, "allow.mount.linsysfs", "true");
		aquarium_opts_add_jailparam(opts, "allow.mount.linprocfs", "true");
	}

	if (default_ruleset) {
		aquarium_opts_add_devfs_ruleset(opts, AQUARIUM_DEVFS_RULESET_UNHIDE_BASIC);
		aquarium_opts_add_devfs_ruleset(opts, AQUARIUM_DEVFS_RULESET_UNHIDE_LOGIN);

		if (opts->vnet_bridge) {
			aquarium_opts_add_devfs_ruleset(opts, AQUARIUM_DEVFS_RULESET_JAIL_VNET);
		}
	}

	if (aquarium_create_struct(opts) < 0) {
		return EXIT_FAILURE;
	}

	if (aquarium_sweep(opts, false) < 0) {
		return EXIT_FAILURE;
	}

	// finally actually execute the action we were here for

	return action(opts);
}
