// #include <aquarium.h>
#include "../aquarium.h" 
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <unistd.h>

int aquarium_enter(aquarium_opts_t* opts, char const* path) {
	int rv = -1;

	// remember our current working directory for later

	char* const cwd = getcwd(NULL, 0);

	if (!cwd) {
		warnx("getcwd: %s", strerror(errno));
		goto getcwd_err;
	}

	// change into the aquarium directory

	if (chdir(path) < 0) {
		warnx("chdir(\"%s\"): %s", path, strerror(errno));
		goto chdir_err;
	}

	// setuid root

	uid_t const uid = getuid();

	if (setuid(0) < 0) {
		warnx("setuid(0): %s", strerror(errno));
		goto setuid_root_err;
	}

	// success

	rv = 0;

	if (setuid(uid) < 0) {
		warnx("setuid(%d): %s", uid, strerror(errno));
		rv = -1;
	}

setuid_root_err:

	if (chdir(cwd) < 0) {
		warnx("chdir(\"%s\"): %s", cwd, strerror(errno));
		rv = -1;
	}

chdir_err:

	free(cwd);

getcwd_err:

	return rv;
}
