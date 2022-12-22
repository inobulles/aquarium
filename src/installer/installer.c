// #include <aquarium.h>
#include "../aquarium.h"
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

static int do_list(void) {
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

static int do_install(void) {
	if (!target) {
		usage();
	}

	// create filesystem on target

	// TODO download & extract template to target

	return EXIT_FAILURE;
}

// main function

typedef int (*action_t) (void);

int main(int argc, char* argv[]) {
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

	return action();
}
