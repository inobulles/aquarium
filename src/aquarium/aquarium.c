// This Source Form is subject to the terms of the AQUA Software License, v. 1.0.
// Copyright (c) 2024 Aymeric Wibo

#include <aquarium.h>

#include "util.h"

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char* template = "amd64.freebsd.14-2-release";
static char* kernel_template = NULL;
static char* overlay_templates = NULL;

static char* out_path = NULL;
static char* path = NULL;

static void usage(void) {
	// clang-format off
	fprintf(stderr,
		"usage: %1$s [-r base]\n"
		"       %1$s [-r base] [-t template] [-k kernel_template] [-O overlay_templates] create path\n"
		"       %1$s [-r base] [-d rulesets] [-j jailparams] [-m max_children] [-Dp] [-v interface] [-h hostname] enter path\n"
		"       %1$s [-r base] kill path\n"
		"       %1$s [-r base] image path image\n"
		"       %1$s [-r base] tmpls\n"
		"       %1$s [-r base] sweep\n"
		"       %1$s [-r base] export path template\n"
		"       %1$s [-r base] mount path target mount_path\n"
		"       %1$s [-r base] cp path source_file ... target_directory\n",
	getprogname());
	// clang-format on

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

static inline void __list_templates_dir(char const* path, char const* kind) {
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
			ARCH,
			OS,
			VERS,
			SENTINEL
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
	__list_templates_dir(opts->overlays_path, "OVERLAY");

	return EXIT_SUCCESS;
}

static int do_create(aquarium_opts_t* opts) {
	if (!path) {
		usage();
	}

	char** overlays = NULL;
	size_t overlay_count = 0;

	if (overlay_templates != NULL) {
		char* tok;

		while ((tok = strsep(&overlay_templates, ","))) {
			overlays = realloc(overlays, ++overlay_count * sizeof *overlays);
			assert(overlays != NULL);
			overlays[overlay_count - 1] = tok;
		}
	}

	if (aquarium_create(opts, path, template, kernel_template, (void*) overlays, overlay_count) < 0) {
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

static void validate_target(char* target) {
	// make sure target directory doesn't refer to $HOME
	// we have no [easy] way of getting the $HOME of the aquarium, and even if we did, what user should we assume?
	// this doesn't stop shells from expanding '~', but it's better than nothing

	if (*target == '~') {
		errx(EXIT_FAILURE, "target directory '%s' refers to $HOME ('~'), which is unsupported", target);
	}

	// also make sure it doesn't contain any ".."'s, as that can be used to copy to outside of the aquarium
	// XXX technically we could count these and path components to see if we really do break out of the aquarium, but that's a lot of work

	if (strstr(target, "..")) {
		errx(EXIT_FAILURE, "target directory '%s' contains '..', which is unsupported", target);
	}
}

static char* mount_target = NULL;
static char* mount_path = NULL;

static int do_mount(aquarium_opts_t* opts) {
	char* const src_aq = aquarium_db_read_pointer_file(opts, path);

	if (!src_aq) {
		return EXIT_FAILURE;
	}

	char* const target_aq = aquarium_db_read_pointer_file(opts, mount_target);

	if (!target_aq) {
		return EXIT_FAILURE;
	}

	validate_target(mount_path);

	if (opts->initial_uid && setuid(0) < 0) {
		errx(EXIT_FAILURE, "setuid(0): %s", strerror(errno));
	}

	char* full_target = NULL;
	asprintf(&full_target, "%s/%s", target_aq, mount_path);
	assert(full_target != NULL);

	struct iovec iov_fd[] = {
		__AQUARIUM_IOV("fstype", "nullfs"),
		__AQUARIUM_IOV("from", src_aq),
		__AQUARIUM_IOV("fspath", full_target),
	};

	if (nmount(iov_fd, sizeof(iov_fd) / sizeof(*iov_fd), 0) < 0 && errno != ENOENT) {
		errx(EXIT_FAILURE, "nmount: failed to bind mount \"%s\" to \"%s\": %s", src_aq, full_target, strerror(errno));
	}

	return 0;
}

static char** copy_args = NULL;
static size_t copy_args_len = 0;

static int do_copy(aquarium_opts_t* opts) {
	char* const aquarium_path = aquarium_db_read_pointer_file(opts, path);

	if (!aquarium_path) {
		return EXIT_FAILURE;
	}

	char* const target = copy_args[--copy_args_len];
	validate_target(target);

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

	while (copy_args_len-- > 0) {
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

typedef int (*action_t)(aquarium_opts_t* opts);

int main(int argc, char* argv[]) {
	action_t action = do_list;
	aquarium_opts_t* const opts = aquarium_opts_create();
	bool default_ruleset = true;

	if (!opts) {
		return EXIT_FAILURE;
	}

	// parse options

	int c;

	while ((c = getopt(argc, argv, "d:Dfh:j:k:m:o:O:pr:t:v:")) != -1) {
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

		else if (c == 'O') {
			overlay_templates = optarg;
		}

		else {
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		argc--;
		char* const instr = *argv++;

		if (strcmp(instr, "create") == 0) {
			action = do_create;
			path = *argv++;
			argc--;
		}

		else if (strcmp(instr, "enter") == 0) {
			action = do_enter;
			path = *argv++;
			argc--;
		}

		else if (strcmp(instr, "image") == 0) {
			action = do_img_out;
			path = *argv++;
			out_path = *argv++;
			argc -= 2;
		}

		else if (strcmp(instr, "tmpls") == 0) {
			action = do_list_templates;
		}

		else if (strcmp(instr, "sweep") == 0) {
			action = do_sweep;
		}

		else if (strcmp(instr, "export") == 0) {
			action = do_out;
			path = *argv++;
			out_path = *argv++;
			argc -= 2;
		}

		else if (strcmp(instr, "mount") == 0) {
			action = do_mount;
			path = *argv++;

			mount_target = *argv++;
			mount_path = *argv++;

			argc -= 3;
		}

		else if (strcmp(instr, "cp") == 0) {
			action = do_copy;

			path = *argv++;
			argc--;

			copy_args = argv;
			copy_args_len = argc;

			argc = 0;
		}

		else {
			usage();
		}
	}

	if (argc != 0) {
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
