#include <aquarium.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void usage(void) {
	fprintf(stderr,
		"usage: %1$s -t target\n",
	getprogname());

	exit(EXIT_FAILURE);
}

// options

static char* target = NULL;

// actions

static int do_list(__attribute__((unused)) aquarium_opts_t* opts) {
	aquarium_drive_t* drives = NULL;
	size_t drives_len = 0;

	if (aquarium_drives_read(&drives, &drives_len) < 0) {
		return EXIT_FAILURE;
	}

	for (size_t i = 0; i < drives_len; i++) {
		printf("%s\n", drives->name);
	}

	return EXIT_SUCCESS;
}

static int do_install(aquarium_opts_t* opts) {
	if (!target) {
		usage();
	}

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

	// create filesystem on target

	// TODO download & extract template to target

	return EXIT_FAILURE;
}

// main function

typedef int (*action_t) (aquarium_opts_t* opts);

int main(int argc, char* argv[]) {
	aquarium_opts_t* opts = aquarium_opts_create();

	if (!opts) {
		return EXIT_FAILURE;
	}

	action_t action = do_list;

	// parse options

	int c;

	while ((c = getopt(argc, argv, "t:")) != -1) {
		if (c == 't') {
			action = do_install;
			target = optarg;
		}

		else {
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	return action(opts);
}
