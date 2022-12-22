// #include <aquarium.h>
#include "../aquarium.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int aquarium_img_out(aquarium_opts_t* opts, char const* _path, char const* out) {
	char* const path = aquarium_db_read_pointer_file(opts, _path);

	if (!path) {
		return -1;
	}

	// TODO make sure aquarium is unmounted, once I've implemented all the entering stuff
	// TODO check the OS is actually supported

	return 0;
}
