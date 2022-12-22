// #include <aquarium.h>
#include "../aquarium.h"
#include "sanctioned.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ILLEGAL_TEMPLATE_PREFIX '.'

static int ensure_struct(aquarium_opts_t* opts) {
	int rv = -1;

	// build filestructure if it doesn't yet exist for convenience
	// also create a sanctioned templates file with some default and trusted entries

	uid_t const uid = getuid();

	if (setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		return -1;
	}

	// try making the directory structure 

	mode_t const MODE = 0770; // rwx for owner (root), rwx for group (stoners, execute access is required to list directory)

	#define SET_PERMS(path) \
		if (opts->stoners_gid && chown((path), 0, opts->stoners_gid) < 0) { \
			warnx("chown(\"%s\", 0, %d): %s", (path), opts->stoners_gid, strerror(errno)); \
			goto err; \
		} \
		\
		if (chmod((path), MODE) < 0) { \
			warnx("chmod(\"%s\", 0, 0%o): %s", (path), MODE, strerror(errno)); \
			goto err; \
		}

	#define TRY_MKDIR(path) \
		if (mkdir((path), MODE) < 0 && errno != EEXIST) { \
			warnx("mkdir(\"%s\", 0%o): %s", (path), MODE, strerror(errno)); \
			goto err; \
		} \
		\
		SET_PERMS((path))

	TRY_MKDIR(opts->base_path)
	TRY_MKDIR(opts->templates_path)
	TRY_MKDIR(opts->kernels_path)
	TRY_MKDIR(opts->aquariums_path)

	// try creating sanctioned templates file

	if (access(opts->sanctioned_path, R_OK) < 0) {
		FILE* fp = fopen(opts->sanctioned_path, "wx");

		if (!fp) {
			warnx("fopen(\"%s\"): %s", opts->sanctioned_path, strerror(errno));
			goto err;
		}

		fprintf(fp, SANCTIONED);
		fclose(fp);
	}

	SET_PERMS(opts->sanctioned_path)

	// try creating aquarium database file

	if (access(opts->db_path, R_OK) < 0) {
		int fd = creat(opts->db_path, MODE);

		if (!fd) {
			warnx("creat(\"%s\", 0%o): %s", opts->db_path, MODE, strerror(errno));
		}

		close(fd);
	}

	SET_PERMS(opts->db_path)

	// success

	rv = 0;

err:

	if (setuid(uid) < 0) {
		warnx("setuid(%d): %s", uid, strerror(errno));
		rv = -1;
	}

	return rv;
}

int create_aquarium(char const* path, char const* template, aquarium_opts_t* opts) {
	// make sure aquarium structure exists

	if (ensure_struct(opts) < 0) {
		return -1;
	}

	// make sure our template is legal

	if (*template == ILLEGAL_TEMPLATE_PREFIX) {
		return -1;
	}

	// remember our current working directory for later

	char* cwd = getcwd(NULL, 0);

	if (!cwd) {
		errx(EXIT_FAILURE, "getcwd: %s", strerror(errno));
	}

	(void) path;
	return -1;

	// generate final aquarium path

	char* aquarium_path;
	if (asprintf(&aquarium_path, "%s%s-XXXXXXX", opts->aquariums_path, template)) {}

	free(cwd);

	return 0;
}
