// #include <aquarium.h>
#include "../aquarium.h"
#include <stdlib.h>
#include <unistd.h>

static void usage(void) {
	fprintf(stderr,
		"usage: %1$s -t target\n",
	getprogname());

	exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
	aquarium_opts_t* opts = aquarium_opts_create();
	char* target = NULL;

	// parse options

	int c;

	while ((c = getopt(argc, argv, "t:")) != -1) {
		if (c == 't') {
			target = optarg;
		}

		else {
			usage();
		}
	}

	if (!target) {
		usage();
	}

	// create filesystem on target

	// TODO download & extract template to target

	usage();

	aquarium_opts_free(opts);
	return EXIT_SUCCESS;
}
